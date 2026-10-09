// Failure modes V1-V8 in docs/failure-modes.md.
import { memoryStore } from "foxgate";
import { describe, expect, it } from "vitest";
import { createVault, memoryKeyStore, VaultError } from "../src/index.js";

const VALUE = "sk-test-0123456789abcdefXYZ";

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

describe("store and keys", () => {
  it("V1: the device key is not extractable", async () => {
    const { keyStore } = await deviceVault();
    const key = await keyStore.load();
    expect(key).toBeDefined();
    expect(key!.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("raw", key!)).rejects.toThrow();
  });

  it("V2: the stored record holds no form of the value", async () => {
    const { store, vault } = await deviceVault();
    await vault.set("vault:k", VALUE, { domains: ["api.example.com"] });
    const text = JSON.stringify(await store.get("foxvault"));
    const bytes = Buffer.from(VALUE);
    for (const form of [VALUE, bytes.toString("base64"), bytes.toString("base64url"), bytes.toString("hex"), encodeURIComponent(VALUE)]) {
      expect(text).not.toContain(form);
    }
  });

  it("V3: changed ciphertext, widened domains, or swapped ciphertexts are corrupt", async () => {
    for (const change of ["data", "domains", "swap"] as const) {
      const { store, keyStore, vault } = await deviceVault();
      await vault.set("vault:a", VALUE, { domains: ["api.example.com"] });
      await vault.set("vault:b", "another-secret-value", { domains: ["api.example.com"] });
      const stored = await record(store);
      const a = stored.secrets["a"]!;
      const b = stored.secrets["b"]!;
      if (change === "data") a.data = (a.data[0] === "A" ? "B" : "A") + a.data.slice(1);
      if (change === "domains") a.domains = ["api.example.com", "evil.example"];
      if (change === "swap") [stored.secrets["a"], stored.secrets["b"]] = [b, a];
      await store.set("foxvault", stored);
      const fresh = createVault({ store, keyStore });
      expect(await code(fresh.unlock()), change).toBe("corrupt");
      expect(await code(fresh.use("vault:a", (v) => v)), change).toBe("corrupt");
    }
  });

  it("V4: an unreadable record is never overwritten", async () => {
    for (const bad of ["not json", { version: 99 }, { version: 1, mode: "device", secrets: "x" }]) {
      const store = memoryStore();
      await store.set("foxvault", bad);
      const vault = createVault({ store });
      expect(await code(vault.status())).toBe("corrupt");
      expect(await code(vault.initialize())).toBe("corrupt");
      expect(await code(vault.set("vault:k", VALUE, { domains: ["a.example"] }))).toBe("corrupt");
      expect(await store.get("foxvault")).toEqual(bad);
    }
  });

  it("V5: bad handles, values, and domains are refused", async () => {
    const { vault } = await deviceVault();
    for (const h of ["openai", "vault:", "vault:A", "vault:a b", "vault:../x", `vault:${"a".repeat(65)}`, 7]) {
      expect(await code(vault.set(h as string, VALUE, { domains: ["a.example"] })), String(h)).toBe("bad-handle");
    }
    for (const v of ["", "short", "x".repeat(4097), 12345678, null]) {
      expect(await code(vault.set("vault:k", v as string, { domains: ["a.example"] }))).toBe("bad-value");
    }
    for (const d of [[], ["https://a.example"], ["a.example:443"], "a.example", [""], ["*.com"]]) {
      expect(await code(vault.set("vault:k", VALUE, { domains: d as string[] })), JSON.stringify(d)).toBe("bad-domain");
    }
    expect(await vault.list()).toEqual([]);
  });

  it("V6: parallel writes are all kept", async () => {
    const { vault } = await deviceVault();
    await Promise.all(Array.from({ length: 10 }, (_, i) => vault.set(`vault:k${i}`, `${VALUE}-${i}`, { domains: ["a.example"] })));
    expect((await vault.list()).length).toBe(10);
    expect(await vault.use("vault:k7", (v) => v)).toBe(`${VALUE}-7`);
  });

  it("V7: a lost device key is reported, not replaced", async () => {
    const { store, keyStore, vault } = await deviceVault();
    await vault.set("vault:k", VALUE, { domains: ["a.example"] });
    const before = JSON.stringify(await store.get("foxvault"));
    await keyStore.clear();
    const fresh = createVault({ store, keyStore });
    expect(await code(fresh.unlock())).toBe("key-lost");
    expect(await code(fresh.set("vault:j", VALUE, { domains: ["a.example"] }))).toBe("key-lost");
    expect(await keyStore.load()).toBeUndefined();
    expect(JSON.stringify(await store.get("foxvault"))).toBe(before);
  });

  it("V8: a second initialize is refused", async () => {
    const { vault } = await deviceVault();
    await vault.set("vault:k", VALUE, { domains: ["a.example"] });
    expect(await code(vault.initialize())).toBe("already-initialized");
    expect(await vault.use("vault:k", (v) => v)).toBe(VALUE);
  });
});
