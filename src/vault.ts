// The encrypted store (docs/failure-modes.md V1-V11). One JSON record holds
// the ciphertexts. Keys and plain values live only in memory, after unlock.
import { canonicalJson, memoryStore, parsePattern, type PublicSuffix, type Store } from "foxgate";
import { newDeviceKey, seal, unseal, type Sealed } from "./crypto.js";
import { VaultError } from "./errors.js";
import { memoryKeyStore, type KeyStore } from "./keystore.js";

const RECORD = "foxvault";
const CHECK = "foxvault:check";
const HANDLE = /^vault:([a-z0-9][a-z0-9._-]{0,63})$/;

export interface VaultOptions {
  /** Where the ciphertexts live. Default: memoryStore(). In Firefox, storageAreaStore(browser.storage.local). */
  store?: Store;
  /** Where device mode keeps its key. Default: memoryKeyStore(). In Firefox, indexedDbKeyStore(). */
  keyStore?: KeyStore;
  /** Needed for "*." domain patterns. In Firefox 153+, pass browser.publicSuffix. */
  publicSuffix?: PublicSuffix;
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
  mode: "device";
  check: Sealed;
  secrets: Record<string, StoredSecret>;
}
interface Open {
  key: CryptoKey;
  values: Map<string, { value: string; info: SecretInfo }>;
}

const corrupt = (why: string) => new VaultError("corrupt", `The stored vault is corrupt: ${why}. foxvault does not change it.`);
const isSealed = (v: unknown): v is Sealed => typeof (v as Sealed)?.iv === "string" && typeof (v as Sealed)?.data === "string";
const isObject = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);

function parseRecord(raw: unknown): VaultRecord | undefined {
  if (raw === undefined) return undefined;
  if (!isObject(raw) || raw.version !== 1) throw corrupt("unknown version");
  const { mode, check, secrets } = raw;
  if (mode !== "device") throw corrupt("unknown mode");
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
  let open: Open | undefined;
  let tail: Promise<unknown> = Promise.resolve();

  // Every operation runs after the one before it (V9).
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

  async function unlockWith(record: VaultRecord): Promise<Open> {
    const key = await keyStore.load();
    if (!key) throw new VaultError("key-lost", "The device key is gone, so the stored secrets cannot be read.");
    await unseal(key, record.check, CHECK).catch(() => {
      throw corrupt("the device key does not match");
    });
    const values: Open["values"] = new Map();
    for (const [name, secret] of Object.entries(record.secrets)) {
      const value = await unseal(key, secret, aadOf(name, secret.domains)).catch(() => {
        throw corrupt(`vault:${name} does not decrypt`);
      });
      values.set(name, { value, info: { handle: `vault:${name}`, domains: [...secret.domains], createdAt: secret.createdAt } });
    }
    return { key, values };
  }

  // Device mode unlocks by itself: it has no passphrase to ask for.
  async function ensureOpen(record: VaultRecord): Promise<Open> {
    return (open ??= await unlockWith(record));
  }

  return {
    /** `new` before initialize, then `locked` or `unlocked`. Throws `corrupt` for an unreadable record. */
    status: () => serial(async () => ((await read()) ? (open ? "unlocked" : "locked") : "new") as "new" | "locked" | "unlocked"),

    /** Make the device key and keep it in the key store. */
    initialize: () =>
      serial(async () => {
        if (await read()) throw new VaultError("already-initialized", "The vault already has a key.");
        const key = await newDeviceKey();
        await keyStore.save(key);
        await store.set(RECORD, { version: 1, mode: "device", check: await seal(key, CHECK, CHECK), secrets: {} } satisfies VaultRecord);
        open = { key, values: new Map() };
      }),

    /** Decrypt every secret into memory. */
    unlock: () =>
      serial(async () => {
        open = undefined;
        open = await unlockWith(await readInitialized());
      }),

    /** Drop the key and the values from memory. */
    lock(): void {
      open = undefined;
    },

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

    /** Every handle with its domains. It works while locked, and it holds no values. */
    list: () =>
      serial(async (): Promise<SecretInfo[]> => {
        const record = await readInitialized();
        return Object.entries(record.secrets)
          .map(([name, s]) => ({ handle: `vault:${name}`, domains: [...s.domains], createdAt: s.createdAt }))
          .toSorted((a, b) => a.handle.localeCompare(b.handle));
      }),

    /** Give the value to host code. Never call this for the AI planner. */
    async use<T>(handle: string, fn: (value: string, info: SecretInfo) => T | Promise<T>): Promise<T> {
      const secret = await serial(async () => {
        const name = handleName(handle);
        const found = (await ensureOpen(await readInitialized())).values.get(name);
        if (!found) throw new VaultError("not-found", `vault:${name} does not exist.`);
        return found;
      });
      return fn(secret.value, { ...secret.info, domains: [...secret.info.domains] });
    },
  };
}

export type Vault = ReturnType<typeof createVault>;
