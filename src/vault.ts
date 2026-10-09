// The encrypted store (docs/failure-modes.md V1-V8, P1-P4, L1-L6). One JSON
// record holds the ciphertexts. Keys and plain values live only in memory,
// after unlock, until the lock time.
import { canonicalJson, memoryStore, parsePattern, type PublicSuffix, type Store } from "foxgate";
import { MIN_ITERATIONS, fromBase64, newDeviceKey, passphraseKey, randomBytes, seal, toBase64, unseal, type Sealed } from "./crypto.js";
import { VaultError } from "./errors.js";
import { memoryKeyStore, type KeyStore } from "./keystore.js";
import { redactText } from "./redact.js";

const RECORD = "foxvault";
const CHECK = "foxvault:check";
const HANDLE = /^vault:([a-z0-9][a-z0-9._-]{0,63})$/;
const MIN_PASSPHRASE = 12;

export interface VaultOptions {
  /** Where the ciphertexts live. Default: memoryStore(). In Firefox, storageAreaStore(browser.storage.local). */
  store?: Store;
  /** Where device mode keeps its key. Default: memoryKeyStore(). In Firefox, indexedDbKeyStore(). */
  keyStore?: KeyStore;
  /** PBKDF2 iterations for a new passphrase vault. Default and minimum: 600,000. */
  iterations?: number;
  /** Needed for "*." domain patterns. In Firefox 153+, pass browser.publicSuffix. */
  publicSuffix?: PublicSuffix;
  /** The clock, in ms since 1970. Default: Date.now. */
  now?: () => number;
  /** The vault locks this long after unlock. Default: 15 minutes. */
  autoLockMs?: number;
  /** Runs before each release. If it throws, foxvault does not release the value. */
  onEvent?: (event: VaultEvent) => void | Promise<void>;
}

/** One release of a value. It never holds the value. */
export interface VaultEvent {
  type: "release";
  kind: "use";
  handle: string;
  at: number;
}

/** What `list` shows. It never holds the value. */
export interface SecretInfo {
  handle: string;
  domains: string[];
  createdAt: number;
}

interface StoredSecret extends Sealed {
  domains: string[];
  createdAt: number;
}
interface VaultRecord {
  version: 1;
  mode: "device" | "passphrase";
  kdf?: { iterations: number; salt: string };
  check: Sealed;
  secrets: Record<string, StoredSecret>;
}
interface Open {
  key: CryptoKey;
  lockAt: number;
  values: Map<string, { value: string; info: SecretInfo }>;
}

const corrupt = (why: string) => new VaultError("corrupt", `The stored vault is corrupt: ${why}. foxvault does not change it.`);
const isSealed = (v: unknown): v is Sealed => typeof (v as Sealed)?.iv === "string" && typeof (v as Sealed)?.data === "string";
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

function parseRecord(raw: unknown): VaultRecord | undefined {
  if (raw === undefined) return undefined;
  if (!isObject(raw) || raw.version !== 1) throw corrupt("unknown version");
  const { mode, kdf, check, secrets } = raw;
  if (mode !== "device" && mode !== "passphrase") throw corrupt("unknown mode");
  if (mode === "passphrase" && (!isObject(kdf) || typeof kdf.iterations !== "number" || typeof kdf.salt !== "string")) throw corrupt("no key settings");
  if (!isSealed(check) || !isObject(secrets)) throw corrupt("missing fields");
  for (const s of Object.values(secrets)) {
    const ok = isSealed(s) && Array.isArray((s as StoredSecret).domains) && typeof (s as StoredSecret).createdAt === "number";
    if (!ok) throw corrupt("a secret has the wrong shape");
  }
  return raw as unknown as VaultRecord;
}

/** The name in a handle (`vault:openai-key` -> `openai-key`). Throws `bad-handle`. */
export function handleName(handle: unknown): string {
  const match = typeof handle === "string" ? HANDLE.exec(handle) : null;
  if (!match?.[1]) throw new VaultError("bad-handle", "A handle is vault: plus 1-64 lowercase letters, digits, '.', '_', or '-'.");
  return match[1];
}

/** Additional data for AES-GCM: the ciphertext only opens for this handle and these domains. */
const aadOf = (name: string, domains: string[]) => canonicalJson({ domains, handle: `vault:${name}` });

export function createVault(options: VaultOptions = {}) {
  const store = options.store ?? memoryStore();
  const keyStore = options.keyStore ?? memoryKeyStore();
  const autoLockMs = options.autoLockMs ?? 15 * 60_000;
  let open: Open | undefined;
  let latest = -Infinity;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let tail: Promise<unknown> = Promise.resolve();

  // The latest time seen, so a clock that goes back does not extend the unlock (L1).
  function clock(): number {
    const t = (options.now ?? Date.now)();
    if (!Number.isFinite(t)) return Number.NaN;
    return (latest = Math.max(latest, t));
  }

  function lock(): void {
    open = undefined;
    clearTimeout(timer);
  }

  // Keys and values live in memory only, so a new vault object starts locked (L2).
  function opened(key: CryptoKey, values: Open["values"]): Open {
    lock();
    const at = clock();
    open = { key, values, lockAt: at + autoLockMs };
    // The timer only drops memory early. Every operation checks the clock itself (L1).
    timer = setTimeout(lock, autoLockMs);
    (timer as { unref?: () => void }).unref?.();
    return open;
  }

  // The open state, or undefined after the lock time.
  function current(): Open | undefined {
    const t = clock();
    if (open && !(t < open.lockAt)) lock();
    return open;
  }

  // Every operation runs after the one before it (V6).
  function serial<T>(fn: () => Promise<T>): Promise<T> {
    const run = tail.then(fn, fn);
    tail = run.catch(() => undefined);
    return run;
  }

  const read = async () => parseRecord(await store.get(RECORD));
  async function readInitialized(): Promise<VaultRecord> {
    const record = await read();
    if (!record) throw new VaultError("not-initialized", "The vault has no key yet. Call initialize first.");
    return record;
  }

  function domainsOf(input: unknown): string[] {
    if (!Array.isArray(input) || input.length === 0) throw new VaultError("bad-domain", "Give at least one allowed domain.");
    return input.map((domain, i) => {
      try {
        const pattern = parsePattern(domain as string, options.publicSuffix);
        if (pattern.host !== "localhost" && !pattern.host.includes(".")) throw new Error("one label");
        return pattern.kind === "exact" ? pattern.host : `*.${pattern.host}`;
      } catch {
        // The input is not echoed: a user can paste a secret into the wrong field (V8).
        throw new VaultError("bad-domain", `Domain ${i + 1} is not a host name or a "*." pattern.`);
      }
    });
  }

  async function unlockWith(record: VaultRecord, passphrase?: string): Promise<Open> {
    let key: CryptoKey | undefined;
    if (record.mode === "passphrase") {
      if (typeof passphrase !== "string") throw new VaultError("locked", "The vault is locked. Unlock it with the passphrase.");
      if (record.kdf!.iterations < MIN_ITERATIONS) throw new VaultError("weak-kdf", "The stored key settings use too few PBKDF2 iterations.");
      key = await passphraseKey(passphrase, fromBase64(record.kdf!.salt), record.kdf!.iterations);
    } else {
      key = await keyStore.load();
      if (!key) throw new VaultError("key-lost", "The device key is gone, so the stored secrets cannot be read.");
    }
    await unseal(key, record.check, CHECK).catch(() => {
      throw record.mode === "passphrase" ? new VaultError("bad-passphrase", "The passphrase is wrong.") : corrupt("the device key does not match");
    });
    const values: Open["values"] = new Map();
    for (const [name, secret] of Object.entries(record.secrets)) {
      const value = await unseal(key, secret, aadOf(name, secret.domains)).catch(() => {
        throw corrupt(`vault:${name} does not decrypt`);
      });
      values.set(name, { value, info: { handle: `vault:${name}`, domains: [...secret.domains], createdAt: secret.createdAt } });
    }
    return opened(key, values);
  }

  // Device mode unlocks by itself: it has no passphrase to ask for.
  async function ensureOpen(record: VaultRecord): Promise<Open> {
    const state = current();
    if (state) return state;
    if (record.mode === "device") return unlockWith(record);
    throw new VaultError("locked", "The vault is locked. Unlock it with the passphrase.");
  }

  return {
    /** `new` before initialize, then `locked` or `unlocked`. Throws `corrupt` for an unreadable record. */
    status: () => serial(async () => ((await read()) ? (current() ? "unlocked" : "locked") : "new") as "new" | "locked" | "unlocked"),

    /** Make the vault key. With a passphrase: PBKDF2. Without: a device key in the key store. */
    initialize: (init: { passphrase?: string } = {}) =>
      serial(async () => {
        if (await read()) throw new VaultError("already-initialized", "The vault already has a key.");
        let key: CryptoKey;
        let kdf: VaultRecord["kdf"];
        if (init.passphrase !== undefined) {
          const iterations = options.iterations ?? MIN_ITERATIONS;
          if (!Number.isSafeInteger(iterations) || iterations < MIN_ITERATIONS) throw new VaultError("weak-kdf", `Use at least ${MIN_ITERATIONS} PBKDF2 iterations.`);
          if (typeof init.passphrase !== "string" || [...init.passphrase].length < MIN_PASSPHRASE) {
            throw new VaultError("weak-passphrase", `Use a passphrase of at least ${MIN_PASSPHRASE} characters.`);
          }
          const salt = randomBytes(16);
          key = await passphraseKey(init.passphrase, salt, iterations);
          kdf = { iterations, salt: toBase64(salt) };
        } else {
          key = await newDeviceKey();
          await keyStore.save(key);
        }
        const record: VaultRecord = { version: 1, mode: kdf ? "passphrase" : "device", check: await seal(key, CHECK, CHECK), secrets: {} };
        if (kdf) record.kdf = kdf;
        await store.set(RECORD, record);
        opened(key, new Map());
      }),

    /** Decrypt every secret into memory. Device mode needs no passphrase. */
    unlock: (passphrase?: string) =>
      serial(async () => {
        lock();
        await unlockWith(await readInitialized(), passphrase);
      }),

    /** Drop the key and the values from memory. */
    lock,

    /** Store a new secret. Its handle and domains are bound to the ciphertext. */
    set: (handle: string, value: string, settings: { domains: string[] }) =>
      serial(async (): Promise<SecretInfo> => {
        const name = handleName(handle);
        if (typeof value !== "string" || value.length < 8 || value.length > 4096) {
          throw new VaultError("bad-value", "A value is a string of 8 to 4096 characters.");
        }
        const domains = domainsOf(settings?.domains);
        const record = await readInitialized();
        const state = await ensureOpen(record);
        if (record.secrets[name]) throw new VaultError("exists", `vault:${name} exists. Remove it first.`);
        const info = { handle: `vault:${name}`, domains, createdAt: Date.now() };
        record.secrets[name] = { ...(await seal(state.key, value, aadOf(name, domains))), domains, createdAt: info.createdAt };
        await store.set(RECORD, record);
        state.values.set(name, { value, info });
        return { ...info, domains: [...domains] };
      }),

    /** Delete a secret. Returns false when it does not exist. */
    remove: (handle: string) =>
      serial(async () => {
        const name = handleName(handle);
        const record = await readInitialized();
        if (!record.secrets[name]) return false;
        delete record.secrets[name];
        await store.set(RECORD, record);
        open?.values.delete(name);
        return true;
      }),

    /** Every handle with its domains. It works while locked, and it holds no values. */
    list: () =>
      serial(async (): Promise<SecretInfo[]> => {
        const record = await readInitialized();
        return Object.entries(record.secrets)
          .map(([name, s]) => ({ handle: `vault:${name}`, domains: [...s.domains], createdAt: s.createdAt }))
          .toSorted((a, b) => a.handle.localeCompare(b.handle));
      }),

    /** Replace every stored value, and its usual encodings, with its handle. Throws `locked` rather than skip a value. */
    redact: (text: string) =>
      serial(async () => {
        if (typeof text !== "string") throw new VaultError("bad-value", "redact takes a string.");
        const state = await ensureOpen(await readInitialized());
        return redactText(text, [...state.values.values()].map(({ value, info }) => ({ handle: info.handle, value })));
      }),

    /** Give the value to host code. Never call this for the AI planner. */
    async use<T>(handle: string, fn: (value: string, info: SecretInfo) => T | Promise<T>): Promise<T> {
      const secret = await serial(async () => {
        const name = handleName(handle);
        const found = (await ensureOpen(await readInitialized())).values.get(name);
        if (!found) throw new VaultError("not-found", `vault:${name} does not exist.`);
        try {
          await options.onEvent?.({ type: "release", kind: "use", handle: found.info.handle, at: clock() });
        } catch {
          throw new VaultError("hook-failed", "The onEvent hook threw, so foxvault did not release the value.");
        }
        return found;
      });
      try {
        return await fn(secret.value, { ...secret.info, domains: [...secret.info.domains] });
      } catch {
        // The message and the cause can hold the value, so they are dropped (L4).
        throw new VaultError("use-failed", "The function given to use threw. foxvault drops its message, because it can hold the value.");
      }
    },
  };
}

export type Vault = ReturnType<typeof createVault>;
