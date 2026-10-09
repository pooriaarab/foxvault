// Failure modes F1-F14 in docs/failure-modes.md.
import { createFoxgate, type Action, type GrantInput } from "foxgate";
import { describe, expect, it } from "vitest";
import { createVault, FILL_TOOL, type FillBrowser, type VaultEvent, type VaultOptions } from "../src/index.js";

const VALUE = "4242424242424242";

// A stand-in browser: one tab with a top document, and a record of each script call.
function fakeBrowser(page: { url: string; documentId?: string; result?: string; fail?: boolean }) {
  const calls: { target: unknown; args: unknown[] }[] = [];
  const browser: FillBrowser = {
    webNavigation: {
      getFrame: async ({ frameId }) => (frameId === 0 ? { url: page.url, documentId: page.documentId ?? "doc-1" } : null),
    },
    scripting: {
      executeScript: async (injection) => {
        calls.push({ target: injection.target, args: injection.args });
        if (page.fail) throw new Error("No document with that ID");
        return [{ result: page.result ?? "filled" }];
      },
    },
  };
  return { browser, calls };
}

async function setup(page: Parameters<typeof fakeBrowser>[0], grant?: Partial<GrantInput> | null, options: VaultOptions = {}) {
  const { gate, host } = createFoxgate({ tools: { [FILL_TOOL]: "fill" } });
  if (grant !== null) await host.addGrant({ scope: "fill", domains: ["pay.example.com", "evil.test"], ...grant });
  const { browser, calls } = fakeBrowser(page);
  const vault = createVault({ gate, browser, ...options });
  await vault.initialize();
  await vault.set("vault:card", VALUE, { domains: ["pay.example.com"] });
  return { vault, calls, host };
}
const request = { handle: "vault:card", tabId: 7, selector: "#card" };

describe("fill", () => {
  it("F1: a host outside the secret's domains is refused", async () => {
    const { vault, calls } = await setup({ url: "https://evil.test/checkout" });
    expect(await vault.fill(request)).toEqual({ status: "refused", reason: "domain" });
    expect(calls).toEqual([]);
  });

  it("F2: a foxgate deny stops the fill", async () => {
    const { vault, calls } = await setup({ url: "https://pay.example.com/checkout" }, { domains: ["other.example.com"] });
    expect(await vault.fill(request)).toEqual({ status: "refused", reason: "no-grant" });
    expect(calls).toEqual([]);
  });

  it("F3: an ask waits for a token that fits only the exact action", async () => {
    const { vault, calls, host } = await setup({ url: "https://pay.example.com/checkout" }, { approval: "always" });
    const asked = await vault.fill(request);
    expect(asked).toEqual({ status: "ask", requestId: expect.any(String) });
    expect(calls).toEqual([]);
    const token = await host.approve((asked as { requestId: string }).requestId);
    expect(await vault.fill({ ...request, selector: "#other", token })).toEqual({ status: "refused", reason: "action-changed" });
    const asked2 = (await vault.fill(request)) as { requestId: string };
    const token2 = await host.approve(asked2.requestId);
    expect(await vault.fill({ ...request, token: token2 })).toEqual({ status: "filled", host: "pay.example.com" });
    expect(calls.length).toBe(1);
  });

  it("F4: only the top document, pinned by documentId, is filled", async () => {
    const { vault, calls } = await setup({ url: "https://pay.example.com/checkout", documentId: "doc-42" });
    expect(await vault.fill(request)).toEqual({ status: "filled", host: "pay.example.com" });
    expect(calls).toEqual([{ target: { tabId: 7, documentIds: ["doc-42"] }, args: ["#card", VALUE, "pay.example.com"] }]);
  });

  it("F5: a page change between the check and the fill is refused", async () => {
    expect(await (await setup({ url: "https://pay.example.com/", fail: true })).vault.fill(request)).toEqual({ status: "refused", reason: "frame-changed" });
    expect(await (await setup({ url: "https://pay.example.com/", result: "host-changed" })).vault.fill(request)).toEqual({ status: "refused", reason: "host-changed" });
    expect(await (await setup({ url: "https://pay.example.com/", documentId: "" })).vault.fill(request)).toEqual({ status: "refused", reason: "frame-changed" });
  });

  it("F6: a missing field or a field that is not text is refused", async () => {
    for (const result of ["not-found", "not-a-field"]) {
      const { vault } = await setup({ url: "https://pay.example.com/", result });
      expect(await vault.fill(request)).toEqual({ status: "refused", reason: result });
    }
  });

  it("F7: fills and refusals emit events, and a failing hook stops the fill", async () => {
    const events: VaultEvent[] = [];
    let fail = false;
    const onEvent = (e: VaultEvent) => {
      if (fail) throw new Error("audit log is down");
      events.push(e);
    };
    const { vault, calls } = await setup({ url: "https://pay.example.com/" }, {}, { onEvent });
    await vault.fill(request);
    await vault.fill({ ...request, tabId: -1 });
    expect(events).toEqual([
      expect.objectContaining({ type: "release", kind: "fill", handle: "vault:card", host: "pay.example.com" }),
      expect.objectContaining({ type: "refuse", kind: "fill", handle: "vault:card", reason: "bad-input" }),
    ]);
    expect(JSON.stringify(events)).not.toContain(VALUE);
    fail = true;
    expect(await vault.fill(request)).toEqual({ status: "refused", reason: "hook-failed" });
    expect(calls.length).toBe(1);
  });

  it("F8: with no gate, nothing is filled", async () => {
    const { browser, calls } = fakeBrowser({ url: "https://pay.example.com/" });
    const vault = createVault({ browser });
    await vault.initialize();
    await vault.set("vault:card", VALUE, { domains: ["pay.example.com"] });
    expect(await vault.fill(request)).toEqual({ status: "refused", reason: "no-gate" });
    expect(calls).toEqual([]);
  });

  it("F9: a page that is not http or https is refused", async () => {
    for (const url of ["about:blank", "file:///pay.example.com/form.html", "moz-extension://abc/popup.html", "data:text/html,x"]) {
      const { vault, calls } = await setup({ url });
      expect(await vault.fill(request), url).toEqual({ status: "refused", reason: "domain" });
      expect(calls).toEqual([]);
    }
  });

  it("F10: a bad tab ID or selector is refused", async () => {
    const { vault, calls } = await setup({ url: "https://pay.example.com/" });
    for (const bad of [{ tabId: -1 }, { tabId: 1.5 }, { tabId: "7" }, { selector: "" }, { selector: 5 }, { selector: "x".repeat(1025) }]) {
      expect(await vault.fill({ ...request, ...(bad as object) }), JSON.stringify(bad)).toEqual({ status: "refused", reason: "bad-input" });
    }
    expect(await vault.fill({ ...request, handle: "card" })).toEqual({ status: "refused", reason: "bad-input" });
    expect(calls).toEqual([]);
  });

  it("F11: a secret that changes during the decision is checked again", async () => {
    const { browser, calls } = fakeBrowser({ url: "https://pay.example.com/" });
    let vault: ReturnType<typeof createVault>;
    const gate = {
      check: async (action: Action) => {
        await vault.remove("vault:card");
        await vault.set("vault:card", VALUE, { domains: ["other.example.com"] });
        return { decision: "allow" as const, grantId: "g", action };
      },
      redeem: async () => ({ decision: "deny" as const, reason: "bad-token" as const, message: "" }),
    };
    vault = createVault({ gate, browser });
    await vault.initialize();
    await vault.set("vault:card", VALUE, { domains: ["pay.example.com"] });
    expect(await vault.fill(request)).toEqual({ status: "refused", reason: "domain" });
    expect(calls).toEqual([]);
  });

  it("F12: a bad handle is not echoed in the event", async () => {
    const events: VaultEvent[] = [];
    const { vault } = await setup({ url: "https://pay.example.com/" }, {}, { onEvent: (e) => void events.push(e) });
    await vault.fill({ ...request, handle: "sk-live-pasted-by-mistake" });
    expect(events).toEqual([expect.objectContaining({ type: "refuse", handle: "", reason: "bad-input" })]);
  });

  it("F13: an http page needs allowHttp on the secret", async () => {
    const { vault, calls } = await setup({ url: "http://pay.example.com/checkout" });
    expect(await vault.fill(request)).toEqual({ status: "refused", reason: "http" });
    expect(calls).toEqual([]);
    await vault.remove("vault:card");
    await vault.set("vault:card", VALUE, { domains: ["pay.example.com"], allowHttp: true });
    expect(await vault.list()).toEqual([expect.objectContaining({ handle: "vault:card", allowHttp: true })]);
    expect(await vault.fill(request)).toEqual({ status: "filled", host: "pay.example.com" });
  });

  it("F14: a locked passphrase vault refuses instead of throwing", async () => {
    const { gate, host } = createFoxgate({ tools: { [FILL_TOOL]: "fill" } });
    await host.addGrant({ scope: "fill", domains: ["pay.example.com"] });
    const { browser, calls } = fakeBrowser({ url: "https://pay.example.com/" });
    const vault = createVault({ gate, browser });
    await vault.initialize({ passphrase: "correct horse battery staple" });
    await vault.set("vault:card", VALUE, { domains: ["pay.example.com"] });
    vault.lock();
    expect(await vault.fill(request)).toEqual({ status: "refused", reason: "locked" });
    expect(calls).toEqual([]);
  });
});
