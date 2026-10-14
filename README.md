# foxvault

[![npm version](https://img.shields.io/npm/v/foxvault)](https://www.npmjs.com/package/foxvault)
[![Downloads/month](https://img.shields.io/npm/dm/foxvault)](https://www.npmjs.com/package/foxvault)
[![License: MIT](https://img.shields.io/npm/l/foxvault)](https://github.com/pooriaarab/foxvault/blob/main/LICENSE)

[Setup](#store-your-first-secret) · [API reference](#runtime-surfaces) · [Comparisons](#compare) · [npm](https://www.npmjs.com/package/foxvault)

foxvault is an open-source encrypted secret vault for AI agent applications in Node.js and Firefox extensions.
Applications refer to secrets by handles and redact known values before sending text to a model.
It provides Firefox header injection, gated form filling, and a callback for trusted host code.

## Install

```bash
npm install foxvault
```

Use Node.js 24 or later for the core example. Firefox extension paths use browser APIs; the demo requires Firefox 153 or later.
TypeScript declarations are included. foxgate is the only direct runtime dependency.

## Store your first secret

Save this example as `vault.mjs`. No API credentials or environment variables are required.

```js
import { createVault } from "foxvault";

const vault = createVault();
await vault.initialize();
await vault.set("vault:demo-key", "example-secret-123", {
  domains: ["api.example.com"],
});
console.log(await vault.redact("Use example-secret-123"));
console.log((await vault.list())[0].handle);
vault.lock();
```

Run `node vault.mjs`. Success prints `Use vault:demo-key`, then `vault:demo-key`.
The defaults keep ciphertexts and the device key in memory. Configure persistent stores when secrets must survive a restart.
Send the redacted text to the model from your application code.

## How it works

```text
Secret -> AES-GCM ciphertext + allowed domains -> store
               |
          vault:handle
               |
       application chooses a release path
        /               |                 \
Firefox header    foxgate + top-frame fill    trusted callback
               |
       onEvent runs before release
```

AES-GCM means Advanced Encryption Standard in Galois/Counter Mode.
Device mode uses a non-extractable key. Passphrase mode derives a key with PBKDF2-SHA-256 and at least 600,000 iterations.
PBKDF2 means Password-Based Key Derivation Function 2. New passphrases must contain at least twelve characters.
The ciphertext authenticates its handle, allowed domains, and HTTP setting.

There are two key modes, two key-store implementations, and three release paths.
Header injection checks the request origin and allowed hosts. Form filling also requires a foxgate decision.
`use()` gives the value to your callback; that callback controls any later network request.

## Why it exists

Agent planners often need to name credentials without receiving their values.
foxvault supplies handles and explicit release operations for trusted application code.
keytar reads passwords from operating-system keychains. conf persists application configuration with optional encryption.

## Compare

Checked on 2026-10-14 against [keytar's API](https://github.com/atom/node-keytar)
and [conf's README](https://github.com/sindresorhus/conf).

| Scope | foxvault | keytar | conf |
|---|---|---|---|
| Main surface | Secret handles and controlled release operations | Operating-system keychain access | Application configuration persistence |
| Storage/key surface | Web Crypto, configured store, memory or IndexedDB keys | System keychain | Config file and optional supplied encryption key |
| Value access | Callback, Firefox header, or gated fill | getPassword returns a password | get returns a stored value |

## Coverage

| Integration or surface | Status | Scope |
|---|---|---|
| Node.js / Web Crypto | ✓ | Core vault, redaction, trusted callback |
| Mozilla Firefox | ✓ | Blocking header listener and top-document form filling |
| IndexedDB | ✓ | Persistent device-key store |
| foxgate | ✓ | Storage interface, domain patterns, fill decisions |
| OpenAI / Google APIs | — | User-configured allowed hosts; no provider adapters |
| foxlink / foxpay / foxtrail | — | Application wiring required; no built-in adapters |

These four implemented surfaces are source-checked, with local tests for vault and release behavior.
No provider credentials were checked. The package contains no provider registry or scaffold provider adapter.
The two key stores are `memoryKeyStore` and `indexedDbKeyStore`.

## Common use cases

1. Firefox extension authors: attach API headers to requests from their own extension.
2. Browser-agent builders: request foxgate permission before filling a secret into a top-document field.
3. Node.js tool authors: keep credentials behind handles and release them to trusted callbacks.
4. AI application authors: redact known credentials from text before passing it to a model.
5. Audit-tool authors: record handle-only release events through `onEvent` and their own foxtrail wiring.

## Features

- **Encrypted storage:** choose device or passphrase mode with [createVault](#runtime-surfaces).
- **Handle redaction:** replace known values and supported encodings with [redact](#vault-methods).
- **Header injection:** restrict Firefox request headers through [header rules](#vault-methods).
- **Gated form filling:** require domain checks and foxgate decisions through [fill](#vault-methods).
- **Release hooks:** run `onEvent` before release using [vault options](#createvaultoptions).

## Runtime surfaces

The core runs in Node.js or a browser with Web Crypto.
Firefox adapters need the corresponding extension APIs. There is no CLI or Model Context Protocol (MCP) server.

### `createVault(options)`

| Option | Default | What it does |
|---|---|---|
| `store` | `memoryStore()` from foxgate | Where the ciphertexts and header rules live. In Firefox, `storageAreaStore(browser.storage.local)` from foxgate. |
| `keyStore` | `memoryKeyStore()` | Where device mode keeps its key. In Firefox, `indexedDbKeyStore()`. |
| `iterations` | 600,000 | PBKDF2 iterations for a new passphrase vault. Fewer throws `weak-kdf`. |
| `autoLockMs` | 15 minutes | The vault locks this long after unlock. |
| `now` | `Date.now` | The clock. A clock that goes back does not extend the unlock. |
| `publicSuffix` | none | `{ getDomain(host) }`, needed for `*.` patterns. In Firefox, `browser.publicSuffix`. |
| `onEvent` | none | `(event) => void \| Promise<void>`. Runs before each release. If it throws, the value does not go out. |
| `gate` | none | A foxgate `Gate`. `fill` refuses with no gate. |
| `browser` | none | For `fill`: an object with `webNavigation.getFrame` and `scripting.executeScript`. In Firefox, pass `browser`. |

### Vault methods

Keep the vault object in your host code, for example the background page. Give
the planner only handles.

| Method | What it does |
|---|---|
| `initialize({ passphrase? })` | Makes the vault key. With a passphrase: passphrase mode. Without: device mode. |
| `unlock(passphrase?)` | Decrypts every secret into memory. Device mode unlocks by itself when needed. |
| `lock()` | Drops the key and the values from memory. |
| `status()` | `"new"`, `"locked"`, or `"unlocked"`. |
| `set(handle, value, { domains, allowHttp? })` | Stores a new secret. A handle is `vault:` plus 1-64 of `a-z 0-9 . _ -`. A value has 8 to 4096 characters. `allowHttp: true` lets `fill` write it into a plain `http:` page. |
| `remove(handle)` | Deletes the secret and its header rules. |
| `list()` | Handles, domains, `allowHttp`, and creation times. No values. It works while locked. |
| `redact(text)` | Replaces each value and its usual encodings with its handle. Throws `locked` rather than skip a value. |
| `use(handle, fn)` | Calls `fn(value, info)` and returns its result. If `fn` throws, foxvault throws `use-failed` with no message from `fn`. |
| `injectHeader({ handle, header, hosts, format?, allowHttp? })` | Stores a header rule. `format` holds `{secret}` one time, for example `Bearer {secret}`. `http:` needs `allowHttp: true`. |
| `removeHeader(id)`, `headerRules()` | Delete a rule, or list them. |
| `headersFor(details, extensionOrigin)` | The body of a blocking `onBeforeSendHeaders` listener. It never throws. While the vault is locked, it adds nothing and removes each rule header from a request that the rule does not allow. |
| `fill({ handle, tabId, selector, token?, documentId? })` | Fills an input or textarea in the top document of the tab. With `documentId`, it fills only that document, and refuses `page-changed` when the tab shows another one. Pass it when your code already checked the page, for example its total. Returns `{ status: "filled", host }`, `{ status: "ask", requestId }`, or `{ status: "refused", reason }`. |

Fill reasons: `bad-input`, `no-gate`, `no-browser`, `no-tab`, `domain`, `http`,
`locked`, `not-found`, `frame-changed`, `page-changed`, `host-changed`, `not-a-field`, `hook-failed`,
and every foxgate deny reason, for example `no-grant` or `action-changed`.

### Other exports

| Export | What it does |
|---|---|
| `attachHeaderInjection(vault, browser)` | Registers the blocking listener for `<all_urls>`. Call it at the top level of the background script. |
| `indexedDbKeyStore(name?)` | A key store in IndexedDB. Default database name: `foxvault`. |
| `memoryKeyStore()` | A key store in memory. |
| `FILL_TOOL` | `"foxvault.fill"`. Register it in foxgate with scope `fill`. |
| `fillField` | The bundled function that `fill` runs in the page. |
| `handleName(handle)` | The name part of a handle. Throws `bad-handle`. |
| `MIN_ITERATIONS` | 600,000. |
| `VaultError` | Has a `code`: `not-initialized`, `already-initialized`, `locked`, `bad-passphrase`, `weak-passphrase`, `weak-kdf`, `corrupt`, `key-lost`, `not-found`, `exists`, `bad-handle`, `bad-value`, `bad-domain`, `bad-rule`, `use-failed`, or `hook-failed`. No message holds a value. |

## Delivery/behavior limits

- While the vault is unlocked, the values are in the memory of the
  background page. Code that runs in your extension, or a compromised
  extension, can read them. Your application must send only handles and redacted text to the model.
  It is not a guard against your own extension.
- `use` gives the value to your function. foxvault cannot stop that function
  from sending the value somewhere else.
- In device mode, the key file is in the Firefox profile. A person who copies
  the whole profile can decrypt the secrets. Use passphrase mode when that
  matters.
- foxvault does not slow down repeated wrong passphrases. The defense is the
  PBKDF2 cost and the minimum passphrase length.
- `fill` sends the value to the page that it fills. The page scripts can read
  the field, as they can with any form field.
- `fill` works only in the top document of a tab. A form inside an iframe
  cannot be filled.
- Header rules match host names, not ports. Any port on an allowed host gets
  the header.
- `redact` finds values of 8 characters or more. Each character can be
  plain, a JSON `\uXXXX` escape, `%XX` or `%25XX`, or an HTML entity, with
  whitespace or dashes between characters. It also finds base64 and hex, and
  the NFC and NFD forms of the value. It does not find a value that changed
  letter case, was encrypted, was encoded in another way (for example
  base64 of a URL-encoded value), or was cut into parts with other text in
  between.
- Use one vault object for each store, in the background page. Two vault
  objects on the same storage do not see each other's changes in memory.
- The add-on can reach only `http://127.0.0.1` and `http://localhost`. The
  default MV3 extension CSP upgrades other `http:` requests to `https:`. The
  E2E build (`build-ext.mjs --e2e`) also adds `http://*.localhost/*`, because
  the test uses two host names.
- There is no import, export, or backup of the vault.

## Integration guides

### Firefox extension setup

```js
import { createFoxgate, storageAreaStore } from "foxgate";
import { FILL_TOOL, attachHeaderInjection, createVault, indexedDbKeyStore } from "foxvault";

const store = storageAreaStore(browser.storage.local);
const { gate, host } = createFoxgate({ tools: { [FILL_TOOL]: "fill" }, store, publicSuffix: browser.publicSuffix });
const vault = createVault({ store, keyStore: indexedDbKeyStore(), publicSuffix: browser.publicSuffix, gate, browser });
attachHeaderInjection(vault, browser); // at the top level of the event page
```

The extension needs the permissions `storage`, `webRequest`,
`webRequestBlocking`, `scripting`, and `webNavigation`, and host permissions
for the API hosts and the form hosts.

### Demo extension

`extension/` is a demo for Firefox 153+. The popup adds a secret with its
allowed hosts and a header rule, calls a local echo server, fills a field in
the active tab, and redacts a prompt. The echo server returns a hash of the
`Authorization` header, never the header.

```bash
pnpm install
node e2e/echo.mjs  # the test API on http://127.0.0.1:8787/echo
pnpm build:ext     # builds dist-ext/; load it from about:debugging
pnpm e2e           # loads the demo in Firefox and checks every E2E failure mode
```

## Status

Version 0.1.3 is an early release. APIs and stored formats can change before 1.0.
[Report issues on GitHub](https://github.com/pooriaarab/foxvault/issues).
Public case studies are not yet published in this repository.

## FAQ

### What is foxvault?

foxvault stores encrypted secrets behind handles for trusted application code.
It provides redaction and explicit callback, Firefox header, and gated form release paths.

### Which integrations are verified?

foxvault implements Node.js/Web Crypto, Firefox adapters, IndexedDB keys, and foxgate integration.
This rewrite checks source and local tests, without verifying OpenAI or Google API credentials.

### Does foxvault provide a managed secret service?

foxvault runs in your application or Firefox extension.
It does not provide a managed vault endpoint or remote key service.

### How is foxvault different from keytar?

foxvault adds secret handles, redaction, domain rules, and gated Firefox release operations.
keytar provides native operating-system keychain access and returns password strings to callers.

### How is foxvault different from conf?

foxvault focuses on secrets and explicit release paths.
conf persists application configuration and offers optional file encryption with an application-supplied key.

### Does foxvault automatically remove secrets from model context?

foxvault redacts text only when your application calls `redact`.
Send handles and redacted text to the model; do not expose the vault object or callback results to it.

### Can a filled page read the secret?

foxvault writes the value into a page field after its checks pass.
The receiving page's scripts can read that field.

### Does locking device mode require a passphrase next time?

foxvault drops in-memory values when locked.
Device mode can unlock automatically from its key store; passphrase mode requires the passphrase.

### Does foxvault restrict where a use callback sends a secret?

foxvault gives the value to trusted host code through `use`.
Your callback must enforce any destination policy for its own requests.

## Part of the fox primitives

foxvault depends on foxgate for fill decisions, storage, canonical JSON, and domain rules.
Applications can connect release events to foxtrail through `onEvent`; no foxtrail adapter is bundled.

## License

[MIT](https://github.com/pooriaarab/foxvault/blob/main/LICENSE)
