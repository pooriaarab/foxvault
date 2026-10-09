// Failure modes R1-R11 in docs/failure-modes.md.
import { describe, expect, it } from "vitest";
import { createVault, VaultError } from "../src/index.js";

const VALUE = "sk-test-0123456789abcdefXYZ";

async function vaultWith(secrets: Record<string, string>) {
  const vault = createVault();
  await vault.initialize();
  for (const [handle, value] of Object.entries(secrets)) await vault.set(handle, value, { domains: ["api.example.com"] });
  return vault;
}

const b64 = (bytes: Uint8Array | string) => Buffer.from(bytes).toString("base64");

describe("redact", () => {
  it("R1: the plain value becomes the handle", async () => {
    const vault = await vaultWith({ "vault:k": VALUE });
    expect(await vault.redact(`Use key ${VALUE} now.`)).toBe("Use key vault:k now.");
    expect(await vault.redact("nothing secret here")).toBe("nothing secret here");
  });

  it("R2: values split by lines, spaces, or dashes still match", async () => {
    const vault = await vaultWith({ "vault:k": VALUE, "vault:card": "4242424242424242" });
    expect(await vault.redact(`key: ${VALUE.slice(0, 10)}\n${VALUE.slice(10)}`)).toBe("key: vault:k");
    expect(await vault.redact(`key: ${VALUE.slice(0, 5)} \r\n  ${VALUE.slice(5)}!`)).toBe("key: vault:k!");
    expect(await vault.redact("card 4242 4242 4242 4242.")).toBe("card vault:card.");
    expect(await vault.redact("card 4242-4242-4242-4242.")).toBe("card vault:card.");
  });

  it("R3: base64 forms match, also wrapped and for non-ASCII values", async () => {
    const other = "pässwörd-ünïcode-1";
    const vault = await vaultWith({ "vault:k": VALUE, "vault:u": other });
    const std = b64(VALUE);
    for (const form of [std, std.replace(/=+$/, ""), Buffer.from(VALUE).toString("base64url"), `${std.slice(0, 16)}\n${std.slice(16)}`, b64(other)]) {
      const out = await vault.redact(`x ${form} y`);
      expect(out, form).toMatch(/^x vault:[ku] y$/);
    }
  });

  it("R4: the value inside a longer base64 text is replaced at each offset", async () => {
    const vault = await vaultWith({ "vault:k": VALUE });
    for (const prefix of ["user:", "user1:", "user12:"]) {
      const encoded = b64(prefix + VALUE + "|tail");
      const out = await vault.redact(`Authorization: Basic ${encoded}`);
      expect(out).toContain("vault:k");
      expect(out, prefix).not.toContain(encoded.slice(12, -12));
    }
  });

  it("R5: URL-encoded and form-encoded values match", async () => {
    const value = "p@ss/w0rd+key=1 x&y";
    const vault = await vaultWith({ "vault:p": value });
    const url = encodeURIComponent(value);
    for (const form of [url, url.replace(/%20/g, "+"), url.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase())]) {
      expect(await vault.redact(`?q=${form}&n=1`), form).toBe("?q=vault:p&n=1");
    }
  });

  it("R6: hex and JSON-escaped values match", async () => {
    const value = 'quote"slash\\back/key-1';
    const vault = await vaultWith({ "vault:k": VALUE, "vault:j": value });
    const hex = Buffer.from(VALUE).toString("hex");
    expect(await vault.redact(`h=${hex}`)).toBe("h=vault:k");
    expect(await vault.redact(`h=${hex.toUpperCase()}`)).toBe("h=vault:k");
    expect(await vault.redact(JSON.stringify({ key: value }))).toBe('{"key":"vault:j"}');
  });

  it("R7: a locked vault refuses to redact", async () => {
    const vault = createVault();
    await vault.initialize({ passphrase: "correct horse battery staple" });
    await vault.set("vault:k", VALUE, { domains: ["api.example.com"] });
    vault.lock();
    await expect(vault.redact(`key ${VALUE}`)).rejects.toMatchObject({ code: "locked" });
  });

  it("R8: a secret inside a longer secret leaves nothing behind", async () => {
    const vault = await vaultWith({ "vault:short": "abcdefgh12", "vault:long": "abcdefgh12-and-more-text" });
    expect(await vault.redact("a abcdefgh12-and-more-text b abcdefgh12 c")).toBe("a vault:long b vault:short c");
  });

  it("R9: regular expression characters are plain characters", async () => {
    const vault = await vaultWith({ "vault:r": "a.b.c.d.e(+)*" });
    expect(await vault.redact("aXbXcXdXe(+)*")).toBe("aXbXcXdXe(+)*");
    expect(await vault.redact("[a.b.c.d.e(+)*]")).toBe("[vault:r]");
  });

  it("R10: a long text with many secrets stays fast", async () => {
    const secrets = Object.fromEntries(Array.from({ length: 20 }, (_, i) => [`vault:s${i}`, `secret-${i}-${"q".repeat(30)}`]));
    const vault = await vaultWith(secrets);
    const text = `${"q - ".repeat(250_000)}secret-7-${"q".repeat(30)}`;
    const started = performance.now();
    const out = await vault.redact(text);
    expect(performance.now() - started).toBeLessThan(2000);
    expect(out.endsWith("vault:s7")).toBe(true);
  });

  it("R11: input that is not a string is refused", async () => {
    const vault = await vaultWith({ "vault:k": VALUE });
    for (const bad of [undefined, 42, { text: VALUE }]) {
      const error = await vault.redact(bad as unknown as string).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(VaultError);
      expect((error as VaultError).code).toBe("bad-value");
    }
  });
});
