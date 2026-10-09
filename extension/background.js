// The demo background (an MV3 event page). It runs foxvault with the real
// storage.local, a device key in IndexedDB, and the blocking header
// listener. fill asks foxgate first. The popup never gets a value back:
// only handles, hashes from the echo server, and redacted text.
import { createFoxgate, storageAreaStore } from "foxgate";
import { FILL_TOOL, attachHeaderInjection, createVault, indexedDbKeyStore } from "../src/index.ts";

const events = [];
const store = storageAreaStore(browser.storage.local);
// The host registers the fill tool. Each secret gets a fill grant for its hosts.
const { gate, host } = createFoxgate({ tools: { [FILL_TOOL]: "fill" }, store, publicSuffix: browser.publicSuffix });
const vault = createVault({
  gate,
  browser,
  store,
  keyStore: indexedDbKeyStore(),
  publicSuffix: browser.publicSuffix,
  onEvent: (event) => {
    events.unshift(event);
    events.length = Math.min(events.length, 20);
  },
});
// At the top level, so Firefox wakes this page for the first request too.
attachHeaderInjection(vault, browser);

async function ready() {
  if ((await vault.status()) === "new") await vault.initialize();
}

const split = (text) => String(text ?? "").split(/[\s,]+/).filter(Boolean);

const handlers = {
  async add({ handle, value, hosts, header, format, allowHttp }) {
    const domains = split(hosts);
    await vault.set(handle, value, { domains });
    if (header) await vault.injectHeader({ handle, header, hosts: domains, format, allowHttp });
    await host.addGrant({ scope: "fill", domains, tools: [FILL_TOOL] });
    return `added ${handle}`;
  },
  async remove({ handle }) {
    return (await vault.remove(handle)) ? `removed ${handle}` : `no ${handle}`;
  },
  async state() {
    return { secrets: await vault.list(), rules: await vault.headerRules(), events };
  },
  redact: ({ text }) => vault.redact(text),
  fill: ({ handle, tabId, selector }) => vault.fill({ handle, tabId, selector }),
  // Shows that the stored key cannot leave Firefox as bytes, and that a new
  // vault object can read the secrets with the key from IndexedDB.
  async "key-check"() {
    const key = await indexedDbKeyStore().load();
    const exportRefused = await crypto.subtle.exportKey("raw", key).then(() => false, () => true);
    const fresh = createVault({ store, keyStore: indexedDbKeyStore() });
    const reopened = await fresh.unlock().then(() => true, () => false);
    return { type: key.type, algorithm: key.algorithm.name, extractable: key.extractable, exportRefused, reopened };
  },
};

browser.runtime.onMessage.addListener(async (message, sender) => {
  if (sender.id !== browser.runtime.id || !Object.hasOwn(handlers, message?.type)) return undefined;
  await ready();
  try {
    return await handlers[message.type](message);
  } catch (error) {
    return { error: error.code ?? "error", message: error.message };
  }
});
