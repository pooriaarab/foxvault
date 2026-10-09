// Failure modes P1-P4 and L1-L7 in docs/failure-modes.md.
import { memoryStore } from "foxgate";
import { describe, expect, it, vi } from "vitest";
import { createVault, memoryKeyStore, VaultError, type VaultEvent } from "../src/index.js";

const VALUE = "sk-test-0123456789abcdefXYZ";
const PASS = "correct horse battery staple";

async function code(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(VaultError);
    return (error as VaultError).code;
  }
  return "no error";
}

async function deviceVault() {
  const store = memoryStore();
  const keyStore = memoryKeyStore();
  const vault = createVault({ store, keyStore });
  await vault.initialize();
  return { store, keyStore, vault };
}

type RecordShape = {
  kdf?: { iterations: number };
  secrets: Record<string, { iv: string; data: string; domains: string[] }>;
};
const record = async (store: ReturnType<typeof memoryStore>) => structuredClone((await store.get("foxvault")) as RecordShape);

describe("passphrase", () => {
  it("P1: the passphrase key is not extractable", async () => {
    // Watch every key that the passphrase path derives.
    const keys: CryptoKey[] = [];
    const derive = crypto.subtle.deriveKey.bind(crypto.subtle);
    const spy = vi.spyOn(crypto.subtle, "deriveKey").mockImplementation(async (...args) => {
      const k = await derive(...args);
      keys.push(k);
      return k;
    });
    const vault = createVault();
    await vault.initialize({ passphrase: PASS });
    await vault.set("vault:k", VALUE, { domains: ["api.example.com"] });
    vault.lock();
    await vault.unlock(PASS);
    spy.mockRestore();
    expect(keys.length).toBeGreaterThan(0);
    for (const k of keys) {
      expect(k.extractable).toBe(false);
      await expect(crypto.subtle.exportKey("raw", k)).rejects.toThrow();
    }
  });

  it("P2: a wrong passphrase does not unlock", async () => {
    const store = memoryStore();
    const vault = createVault({ store });
    await vault.initialize({ passphrase: PASS });
    await vault.set("vault:k", VALUE, { domains: ["api.example.com"] });
    vault.lock();
    expect(await code(vault.unlock("correct horse battery stapler"))).toBe("bad-passphrase");
    expect(await vault.status()).toBe("locked");
    expect(await code(vault.use("vault:k", (v) => v))).toBe("locked");
    await vault.unlock(PASS);
    expect(await vault.use("vault:k", (v) => v)).toBe(VALUE);
  });

  it("P3: PBKDF2 uses 600,000 iterations and refuses fewer", async () => {
    expect(await code(createVault({ iterations: 100_000 }).initialize({ passphrase: PASS }))).toBe("weak-kdf");
    const store = memoryStore();
    const vault = createVault({ store });
    await vault.initialize({ passphrase: PASS });
    const stored = await record(store);
    expect(stored.kdf?.iterations).toBe(600_000);
    stored.kdf!.iterations = 1000;
    await store.set("foxvault", stored);
    expect(await code(createVault({ store }).unlock(PASS))).toBe("weak-kdf");
  });

  it("P4: a short passphrase is refused", async () => {
    expect(await code(createVault().initialize({ passphrase: "short pass" }))).toBe("weak-passphrase");
  });
});

describe("lock and release", () => {
  it("L1: auto-lock fires by the clock, with no timer", async () => {
    let now = 1_000_000;
    const store = memoryStore();
    const vault = createVault({ store, now: () => now, autoLockMs: 60_000 });
    await vault.initialize({ passphrase: PASS });
    await vault.set("vault:k", VALUE, { domains: ["api.example.com"] });
    now += 59_000;
    expect(await vault.use("vault:k", (v) => v.length)).toBe(VALUE.length);
    now += 1_000;
    expect(await code(vault.use("vault:k", (v) => v))).toBe("locked");
    expect(await vault.status()).toBe("locked");

    await vault.unlock(PASS);
    now += 30_000;
    await vault.use("vault:k", () => 1);
    now -= 120_000; // the clock goes back
    expect(await vault.use("vault:k", () => 1)).toBe(1);
    now += 120_000 + 30_000; // 60 s after unlock by the latest time seen
    expect(await code(vault.use("vault:k", (v) => v))).toBe("locked");

    await vault.unlock(PASS);
    now = Number.NaN;
    expect(await code(vault.use("vault:k", (v) => v))).toBe("locked");
  });

  it("L2: a new vault object on the same storage starts locked", async () => {
    const store = memoryStore();
    const vault = createVault({ store });
    await vault.initialize({ passphrase: PASS });
    await vault.set("vault:k", VALUE, { domains: ["api.example.com"] });
    expect(await vault.status()).toBe("unlocked");
    const after = createVault({ store });
    expect(await after.status()).toBe("locked");
    expect(await code(after.use("vault:k", (v) => v))).toBe("locked");
  });

  it("L3: a removed handle gives no value, and a new one has only its own domains", async () => {
    const { vault } = await deviceVault();
    await vault.set("vault:k", VALUE, { domains: ["old.example.com"] });
    expect(await vault.remove("vault:k")).toBe(true);
    expect(await code(vault.use("vault:k", (v) => v))).toBe("not-found");
    expect(await vault.remove("vault:k")).toBe(false);
    await vault.set("vault:k", "a-new-secret-value", { domains: ["new.example.com"] });
    expect(await vault.list()).toEqual([expect.objectContaining({ handle: "vault:k", domains: ["new.example.com"] })]);
    expect(await code(vault.set("vault:k", VALUE, { domains: ["x.example"] }))).toBe("exists");
  });

  it("L4: errors never hold the value", async () => {
    const { vault } = await deviceVault();
    const messages: string[] = [];
    const grab = async (p: Promise<unknown>) => p.catch((e: Error) => messages.push(`${e.message} ${String(e.cause ?? "")} ${e.stack ?? ""}`));
    await grab(vault.set("vault:BAD", VALUE, { domains: ["a.example"] }));
    await grab(vault.set("vault:k", `${VALUE}\u0000`.repeat(300), { domains: ["a.example"] }));
    await grab(vault.set("vault:k", VALUE, { domains: [VALUE] }));
    await vault.set("vault:k", VALUE, { domains: ["a.example"] });
    await grab(vault.use("vault:k", (v) => { throw new Error(`failed with ${v}`, { cause: v }); }));
    expect(messages.length).toBe(4);
    for (const m of messages) expect(m).not.toContain(VALUE);
    expect(await code(vault.use("vault:k", (v) => { throw new Error(v); }))).toBe("use-failed");
  });

  it("L5: lock drops the values from memory", async () => {
    const store = memoryStore();
    const vault = createVault({ store });
    await vault.initialize({ passphrase: PASS });
    await vault.set("vault:k", VALUE, { domains: ["a.example"] });
    vault.lock();
    expect(await code(vault.use("vault:k", (v) => v))).toBe("locked");
    const list = await vault.list();
    expect(list).toEqual([{ handle: "vault:k", domains: ["a.example"], allowHttp: false, createdAt: expect.any(Number) }]);
    expect(JSON.stringify(list)).not.toContain(VALUE);
  });

  it("L6: each release emits an event with no value, and a failing hook stops the release", async () => {
    const events: VaultEvent[] = [];
    let fail = false;
    const vault = createVault({
      onEvent: (e) => {
        if (fail) throw new Error("audit log is down");
        events.push(e);
      },
    });
    await vault.initialize();
    await vault.set("vault:k", VALUE, { domains: ["a.example"] });
    await vault.use("vault:k", () => 1);
    expect(events).toEqual([expect.objectContaining({ type: "release", kind: "use", handle: "vault:k", at: expect.any(Number) })]);
    expect(JSON.stringify(events)).not.toContain(VALUE);
    fail = true;
    let ran = false;
    expect(await code(vault.use("vault:k", () => { ran = true; }))).toBe("hook-failed");
    expect(ran).toBe(false);
  });

  it("L7: lock during an unlock wins", async () => {
    const vault = createVault();
    await vault.initialize({ passphrase: PASS });
    await vault.set("vault:k", VALUE, { domains: ["a.example"] });
    vault.lock();
    const pending = vault.unlock(PASS); // PBKDF2 takes far longer than 5 ms
    await new Promise((done) => setTimeout(done, 5));
    vault.lock();
    expect(await code(pending)).toBe("locked");
    expect(await vault.status()).toBe("locked");
    expect(await code(vault.use("vault:k", (v) => v))).toBe("locked");
    await vault.unlock(PASS);
    expect(await vault.status()).toBe("unlocked");
  });
});
