// Failure modes H1-H11 in docs/failure-modes.md.
import { memoryStore } from "foxgate";
import { describe, expect, it } from "vitest";
import { createVault, memoryKeyStore, VaultError, type VaultEvent, type VaultOptions } from "../src/index.js";

const VALUE = "sk-test-0123456789abcdefXYZ";
const EXT = "moz-extension://4b1d/";
type Header = { name: string; value?: string };

// A stand-in for browser.publicSuffix: the last two labels.
const publicSuffix = { getDomain: (host: string) => (host.split(".").length > 2 ? host.split(".").slice(-2).join(".") : host.includes(".") ? host : null) };

async function setup(options: VaultOptions = {}) {
  const vault = createVault({ publicSuffix, ...options });
  await vault.initialize();
  await vault.set("vault:k", VALUE, { domains: ["api.example.com", "*.example.org"] });
  await vault.injectHeader({ handle: "vault:k", header: "Authorization", hosts: ["api.example.com"], format: "Bearer {secret}" });
  return vault;
}

type V = Awaited<ReturnType<typeof setup>>;
async function send(vault: V, url: string, originUrl: string | undefined = `${EXT}popup.html`, requestHeaders: Header[] = []) {
  const result = await vault.headersFor({ url, originUrl, requestHeaders }, EXT);
  return result?.requestHeaders ?? requestHeaders;
}
const auth = (headers: Header[]) => headers.filter((h) => h.name.toLowerCase() === "authorization").map((h) => h.value);

async function code(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    expect(error).toBeInstanceOf(VaultError);
    return (error as VaultError).code;
  }
  return "no error";
}

describe("header injection", () => {
  it("H1: only a host in the rule gets the header", async () => {
    const vault = await setup();
    expect(auth(await send(vault, "https://api.example.com/v1/chat"))).toEqual([`Bearer ${VALUE}`]);
    for (const url of ["https://other.example.com/", "https://api.example.com.evil.test/", "https://x.example.org/", "https://evil.test/?api.example.com"]) {
      expect(auth(await send(vault, url)), url).toEqual([]);
    }
  });

  it("H2: a rule cannot reach past the secret's domains", async () => {
    const store = memoryStore();
    const keyStore = memoryKeyStore();
    const vault = await setup({ store, keyStore });
    const rule = { handle: "vault:k", header: "X-Key" };
    expect(await code(vault.injectHeader({ ...rule, hosts: ["evil.test"] }))).toBe("bad-rule");
    expect(await code(vault.injectHeader({ ...rule, hosts: ["*.example.com"] }))).toBe("bad-rule");
    expect(await code(vault.injectHeader({ ...rule, hosts: [] }))).toBe("bad-rule");
    expect(await code(vault.injectHeader({ ...rule, handle: "vault:none", hosts: ["api.example.com"] }))).toBe("not-found");
    await vault.injectHeader({ ...rule, hosts: ["a.b.example.org", "*.b.example.org"] });

    // Someone edits the stored rule to add a host.
    const stored = structuredClone((await store.get("foxvault")) as { rules: Record<string, { hosts: string[] }> });
    for (const r of Object.values(stored.rules)) r.hosts.push("evil.test");
    await store.set("foxvault", stored);
    const fresh = createVault({ store, keyStore, publicSuffix });
    expect(auth(await send(fresh, "https://evil.test/"))).toEqual([]);
    expect(auth(await send(fresh, "https://api.example.com/"))).toEqual([`Bearer ${VALUE}`]);
  });

  it("H3: a request to another host loses a header that holds the value", async () => {
    const vault = await setup();
    const carried = [{ name: "authorization", value: `Bearer ${VALUE}` }, { name: "Accept", value: "*/*" }];
    const out = await send(vault, "https://evil.test/after-redirect", `${EXT}popup.html`, carried);
    expect(auth(out)).toEqual([]);
    expect(out).toEqual([{ name: "Accept", value: "*/*" }]);
  });

  it("H4: a request from a web page or another extension gets nothing", async () => {
    const vault = await setup();
    for (const origin of ["https://evil.test/page.html", "moz-extension://other/popup.html", "moz-extension://4b1d.evil/", ""]) {
      expect(auth(await send(vault, "https://api.example.com/", origin)), origin).toEqual([]);
    }
    expect(await vault.headersFor({ url: "https://api.example.com/", requestHeaders: [] }, EXT)).toBeUndefined();
  });

  it("H5: plain http gets the header only with allowHttp", async () => {
    const vault = await setup();
    expect(auth(await send(vault, "http://api.example.com/"))).toEqual([]);
    await vault.injectHeader({ handle: "vault:k", header: "X-Key", hosts: ["api.example.com"], allowHttp: true });
    const out = await send(vault, "http://api.example.com/");
    expect(out.find((h) => h.name === "X-Key")?.value).toBe(VALUE);
    expect(auth(out)).toEqual([]);
  });

  it("H6: bad names, bad formats, and line breaks are refused", async () => {
    const vault = await setup();
    const rule = { handle: "vault:k", hosts: ["api.example.com"] };
    for (const header of ["", "Bad Header", "X-Key\r\nX-Evil", "Authorization:"]) {
      expect(await code(vault.injectHeader({ ...rule, header })), header).toBe("bad-rule");
    }
    for (const format of ["Bearer", "{secret} {secret}", "Bearer {secret}\r\nX-Evil: 1"]) {
      expect(await code(vault.injectHeader({ ...rule, header: "X-Key", format })), format).toBe("bad-rule");
    }
    await vault.set("vault:crlf", "line-one\r\nX-Evil: 1", { domains: ["api.example.com"] });
    await vault.injectHeader({ handle: "vault:crlf", header: "X-Crlf", hosts: ["api.example.com"] });
    const out = await send(vault, "https://api.example.com/");
    expect(out.some((h) => h.name === "X-Crlf" || /X-Evil/.test(h.value ?? ""))).toBe(false);
    expect(auth(out)).toEqual([`Bearer ${VALUE}`]);
  });

  it("H7: a locked passphrase vault sends no header and does not throw", async () => {
    const vault = createVault();
    await vault.initialize({ passphrase: "correct horse battery staple" });
    await vault.set("vault:k", VALUE, { domains: ["api.example.com"] });
    await vault.injectHeader({ handle: "vault:k", header: "Authorization", hosts: ["api.example.com"] });
    vault.lock();
    expect(await vault.headersFor({ url: "https://api.example.com/", originUrl: EXT, requestHeaders: [] }, EXT)).toBeUndefined();
  });

  it("H8: remove deletes the rules of the secret", async () => {
    const vault = await setup();
    await vault.remove("vault:k");
    expect(await vault.headerRules()).toEqual([]);
    await vault.set("vault:k", "a-brand-new-value", { domains: ["api.example.com"] });
    expect(auth(await send(vault, "https://api.example.com/"))).toEqual([]);
  });

  it("H9: an existing header with the same name is replaced", async () => {
    const vault = await setup();
    const out = await send(vault, "https://api.example.com/", `${EXT}popup.html`, [{ name: "AUTHORIZATION", value: "Bearer planner-made" }]);
    expect(auth(out)).toEqual([`Bearer ${VALUE}`]);
  });

  it("H10: each injection emits an event, and a failing hook stops it", async () => {
    const events: VaultEvent[] = [];
    let fail = false;
    const vault = await setup({
      onEvent: (e) => {
        if (fail) throw new Error("audit log is down");
        events.push(e);
      },
    });
    await send(vault, "https://api.example.com/");
    expect(events).toEqual([expect.objectContaining({ type: "release", kind: "header", handle: "vault:k", host: "api.example.com" })]);
    expect(JSON.stringify(events)).not.toContain(VALUE);
    fail = true;
    expect(auth(await send(vault, "https://api.example.com/"))).toEqual([]);
  });

  it("H11: rules survive a new vault object on the same storage", async () => {
    const store = memoryStore();
    const keyStore = memoryKeyStore();
    const vault = await setup({ store, keyStore });
    expect((await vault.headerRules()).length).toBe(1);
    const after = createVault({ store, keyStore, publicSuffix });
    expect(auth(await send(after, "https://api.example.com/"))).toEqual([`Bearer ${VALUE}`]);
    const [rule] = await after.headerRules();
    expect(await after.removeHeader(rule!.id)).toBe(true);
    expect(auth(await send(after, "https://api.example.com/"))).toEqual([]);
  });
});
