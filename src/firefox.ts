// Firefox glue: the device key in IndexedDB, and the blocking header
// listener. The E2E test checks both in a real Firefox (docs/failure-modes.md
// K1-K3, E1-E6).
import type { KeyStore } from "./keystore.js";
import type { RequestDetails } from "./headers.js";

const STORE = "keys";
const KEY = "device";

const done = <T>(request: IDBRequest<T>) =>
  new Promise<T>((resolve, reject) => {
    request.addEventListener("success", () => resolve(request.result));
    request.addEventListener("error", () => reject(request.error ?? new Error("IndexedDB request failed")));
  });

/**
 * Keep the device key in IndexedDB. IndexedDB stores the CryptoKey object
 * itself, so the key stays non-extractable. storage.local cannot hold it.
 */
export function indexedDbKeyStore(name = "foxvault"): KeyStore {
  const open = () => {
    const request = indexedDB.open(name, 1);
    request.addEventListener("upgradeneeded", () => request.result.createObjectStore(STORE));
    return done(request);
  };
  const run = async <T>(mode: IDBTransactionMode, fn: (store: IDBObjectStore) => IDBRequest<T>) => {
    const db = await open();
    try {
      return await done(fn(db.transaction(STORE, mode).objectStore(STORE)));
    } finally {
      db.close();
    }
  };
  return {
    load: async () => ((await run("readonly", (s) => s.get(KEY))) as CryptoKey | undefined) ?? undefined,
    save: async (key) => void (await run("readwrite", (s) => s.put(key, KEY))),
    clear: async () => void (await run("readwrite", (s) => s.delete(KEY))),
  };
}

/** The parts of the WebExtension `browser` object that header injection uses. */
export interface HeaderBrowser {
  runtime: { getURL(path: string): string };
  webRequest: {
    onBeforeSendHeaders: {
      addListener(
        listener: (details: RequestDetails) => Promise<{ requestHeaders: { name: string; value?: string }[] } | undefined>,
        filter: { urls: string[] },
        extraInfoSpec: string[],
      ): void;
    };
  };
}

/**
 * Register the blocking listener. Call it at the top level of the background
 * script, so that Firefox wakes the event page for the first request too.
 */
export function attachHeaderInjection(vault: { headersFor(details: RequestDetails, extensionOrigin: string): Promise<unknown> }, browser: HeaderBrowser): void {
  const origin = browser.runtime.getURL("");
  browser.webRequest.onBeforeSendHeaders.addListener(
    (details) => vault.headersFor(details, origin) as Promise<{ requestHeaders: { name: string; value?: string }[] } | undefined>,
    { urls: ["<all_urls>"] },
    ["blocking", "requestHeaders"],
  );
}
