# Failure modes

This file lists every way foxvault can fail. We wrote each list before the
code. Each row names the test that proves the wanted behaviour. Tests in
`tests/` run in Node with `pnpm test`. Checks named `E…` run in a real Firefox
with `pnpm e2e`.

## Store and keys (V)

| # | Failure mode | Wanted behaviour | Test |
|---|---|---|---|
| V1 | The device key is extractable, so code can export its bytes. | The device key is a non-extractable AES-GCM key. `exportKey` rejects. | `store.test.ts` V1 |
| V2 | A value is stored as plain text, or as base64 or hex of the plain text. | The stored record holds only AES-GCM ciphertext. It does not contain the value in any of these forms. | `store.test.ts` V2 |
| V3 | Storage corruption: changed ciphertext, a widened domain list, or two ciphertexts swapped between handles. | AES-GCM fails because the handle and the domains are bound as additional data. The vault throws `corrupt` and returns no value. | `store.test.ts` V3 |
| V4 | Storage corruption: the record is not JSON or has the wrong shape. A later write then replaces it, and the user loses every secret. | Every read and write throws `corrupt`. foxvault never overwrites a record that it cannot read. | `store.test.ts` V4 |
| V5 | A bad handle, value, or domain list goes into the store. | `bad-handle` for a name that is not `vault:` plus lowercase letters, digits, `.`, `_`, or `-`. `bad-value` for a value that is not a string of 8 to 4096 characters. `bad-domain` for an empty or invalid domain list. | `store.test.ts` V5 |
| V6 | Two writes at the same time, and one is lost. | Writes run one at a time. Ten parallel `set` calls store ten secrets. | `store.test.ts` V6 |
| V7 | Device mode: the stored key is gone (for example, IndexedDB was cleared). foxvault makes a new key, and the old secrets can never be read again. | `unlock` throws `key-lost`. foxvault does not make a new key and does not overwrite the record. | `store.test.ts` V7 |
| V8 | `initialize` runs a second time and replaces the key, so the old secrets can never be read again. | The second call throws `already-initialized`. | `store.test.ts` V8 |

## Passphrase (P)

| # | Failure mode | Wanted behaviour | Test |
|---|---|---|---|
| P1 | The passphrase key is extractable, so code can export its bytes. | The key from PBKDF2 is a non-extractable AES-GCM key. `exportKey` rejects. | `lock.test.ts` P1 |
| P2 | A wrong passphrase unlocks the vault, or returns garbage values. | `unlock` throws `bad-passphrase`. The vault stays locked. | `lock.test.ts` P2 |
| P3 | Passphrase brute force: a low PBKDF2 iteration count makes each guess cheap. | PBKDF2-SHA-256 with 600,000 iterations and a random 16-byte salt. A lower `iterations` option throws `weak-kdf`. A stored record with fewer iterations throws `weak-kdf` at unlock. | `lock.test.ts` P3 |
| P4 | A short passphrase makes brute force easy even with many iterations. | A passphrase under 12 characters throws `weak-passphrase`. | `lock.test.ts` P4 |

## Lock and release (L)

| # | Failure mode | Wanted behaviour | Test |
|---|---|---|---|
| L1 | Auto-lock does not fire because a timer did not run (for example, the event page was suspended). | Every operation compares the clock with the lock time first. After `autoLockMs` from unlock, it throws `locked`, with or without a timer. A clock that goes back does not extend the unlock. A clock that is not a finite number counts as locked. | `lock.test.ts` L1 |
| L2 | Auto-lock does not fire after the event page unloads, because unlocked state was saved. | Unlocked keys and values live only in memory. A new vault object on the same storage starts locked. | `lock.test.ts` L2 |
| L3 | Stale handle: a handle still gives a value after `remove`. Or a new secret with the same handle gets the old allowed domains. | `use` throws `not-found` after `remove`. A new secret with the same handle has only its own domains. | `lock.test.ts` L3 |
| L4 | An error message holds the value: from bad input, or from the function in `use`. | foxvault errors never hold a value. When the `use` function throws, foxvault throws `use-failed` and drops the original message and cause. | `lock.test.ts` L4 |
| L5 | `lock` leaves values in memory. | After `lock`, `use` throws `locked` in passphrase mode. `list` still shows handles and domains, but no values. | `lock.test.ts` L5 |
| L6 | A release is not recorded, or the event holds the value. | Each release calls `onEvent` with the handle and the kind, and no value. When `onEvent` throws, foxvault does not release the value. | `lock.test.ts` L6 |
| L7 | `lock` runs while an unlock is still deriving the key, and the unlock then opens the vault anyway. | `lock` wins. The unlock that was running throws `locked`, and `status` stays `locked`. | `lock.test.ts` L7 |

## Redact (R)

| # | Failure mode | Wanted behaviour | Test |
|---|---|---|---|
| R1 | The plain value goes to the model or a log. | `redact` puts the handle where the value was. | `redact.test.ts` R1 |
| R2 | The value is split across lines, or has spaces or dashes in it (for example, a card number `4242 4242 4242 4242`). | Whitespace and dashes between the characters still match. | `redact.test.ts` R2 |
| R3 | The value is in base64 (standard or URL-safe, with or without padding), or the base64 is wrapped across lines. | Each form matches. The value is UTF-8 first, so non-ASCII values match too. | `redact.test.ts` R3 |
| R4 | The value is inside a longer base64 text, for example `Basic base64(user:key)`, at any byte offset. | The part of the base64 that comes only from the value is replaced, at each of the 3 offsets. | `redact.test.ts` R4 |
| R5 | The value is URL-encoded, form-encoded (`+` for a space), or uses lowercase `%` codes. | Each form matches. | `redact.test.ts` R5 |
| R6 | The value is in hex (lowercase or uppercase), or JSON-escaped. | Each form matches. | `redact.test.ts` R6 |
| R7 | The vault is locked, so `redact` cannot know the values and returns the text unchanged. | `redact` throws `locked`. It never returns text that it did not check. | `redact.test.ts` R7 |
| R8 | One secret is part of a longer secret, so a part of the longer one is left. | Longer forms are replaced first. No part of either value is left. | `redact.test.ts` R8 |
| R9 | A value has regular expression characters, so `redact` matches other text or crashes. | Each character is escaped. `a.b.c.d.e` does not match `aXbXcXdXe`. | `redact.test.ts` R9 |
| R10 | A long text makes `redact` slow (catastrophic backtracking). | 1 MB of text with 20 secrets takes under 2 seconds. | `redact.test.ts` R10 |
| R11 | `redact` gets something that is not a string and returns it unchanged. | It throws `bad-value`. | `redact.test.ts` R11 |

## Header injection (H)

`headersFor` is the body of the blocking `webRequest.onBeforeSendHeaders`
listener. The E2E test checks H1, H3, and H4 again in a real Firefox.

| # | Failure mode | Wanted behaviour | Test |
|---|---|---|---|
| H1 | The header goes to a host that is not in the rule. | Only a request to a host in the rule gets the header. | `headers.test.ts` H1, E2E |
| H2 | A rule names a host that the secret does not allow, or the stored rule is changed to add one. | `injectHeader` throws `bad-rule`. At request time, the host must also match the secret's domains, which are bound to its ciphertext. | `headers.test.ts` H2 |
| H3 | A redirect to another host carries the header there. | The redirected request is checked again. foxvault removes a header that holds the value from a request to a host that is not allowed. | `headers.test.ts` H3, E2E |
| H4 | A web page (not the extension) sends a request to the allowed host and gets the user's key. | Only a request whose `originUrl` is in this extension gets the header. | `headers.test.ts` H4, E2E |
| H5 | The key goes over plain `http:`. | Only `https:` gets the header, unless the rule sets `allowHttp`. | `headers.test.ts` H5 |
| H6 | A bad header name or format, or a value with a line break, lets a request carry extra headers. | `bad-rule` for a header name that is not an HTTP token, or a format without exactly one `{secret}`. A value with a control character is not sent. | `headers.test.ts` H6 |
| H7 | A locked passphrase vault makes the listener throw, or sends a stale value. | The request goes on with no header. | `headers.test.ts` H7 |
| H8 | Stale rule: after `remove`, a new secret with the same handle is sent by the old rule. | `remove` deletes the secret's rules too. | `headers.test.ts` H8 |
| H9 | The request already has a header with the same name, in any letter case, so two values go out. | foxvault replaces it. The request has one header with that name. | `headers.test.ts` H9 |
| H10 | An injection is not recorded, or the event holds the value. | Each injection calls `onEvent` with kind `header`, the handle, and the host. If `onEvent` throws, the header is not sent. | `headers.test.ts` H10 |
| H11 | The event page unloads, and the rules are gone after it wakes up. | Rules are stored with the secrets. A new vault object on the same storage sends the header. | `headers.test.ts` H11 |
| H12 | A passphrase vault locks, and then a redirect carries the header to another host. foxvault cannot compare values while locked, so it does not remove the header. | While locked, or when the vault cannot open, each stored rule still runs strip-only: a request to a host outside the rule (or plain http without `allowHttp`) loses every header with the rule's name. Nothing is added. | `headers.test.ts` H12 |

## Fill (F)

`fill` writes a value into a form field with `scripting.executeScript` and a
bundled function. The Node tests use a stand-in `browser` object that records
each call. The E2E test checks F1, F4, and F6 in a real Firefox.

| # | Failure mode | Wanted behaviour | Test |
|---|---|---|---|
| F1 | The tab is on a host that the secret does not allow. | `refused` with reason `domain`. The value never goes to the tab. | `fill.test.ts` F1, E2E |
| F2 | foxgate denies the action. | `refused` with the foxgate reason. The value never goes to the tab. | `fill.test.ts` F2 |
| F3 | foxgate asks a human, or the approved action is not the one that runs. | `ask` with the request ID and no fill. With a token, foxgate redeems it for the exact action, so another selector gets `action-changed`. | `fill.test.ts` F3 |
| F4 | The field is in a cross-origin iframe, or the allowed page is inside a frame of another site. | foxvault fills only the top document of the tab, pinned by its `documentId`, and checks the host of that document. | `fill.test.ts` F4, E2E |
| F5 | The tab goes to another page between the check and the fill. | The `documentId` pin makes the call fail: `refused` with reason `frame-changed`. The bundled function checks the host again: `host-changed`. | `fill.test.ts` F5 |
| F6 | The selector finds nothing, or finds something that is not a text field. | `refused` with reason `not-found` or `not-a-field`. | `fill.test.ts` F6, E2E |
| F7 | A fill is not recorded, or the event holds the value. | Each fill and each refusal calls `onEvent` with kind `fill`, the handle, and the host. If `onEvent` throws before a fill, nothing is filled. | `fill.test.ts` F7 |
| F8 | No gate is set, so fills run with no policy. | `refused` with reason `no-gate`. | `fill.test.ts` F8 |
| F9 | The tab shows a page that is not `http:` or `https:` (for example `about:` or `file:`). | `refused` with reason `domain`. | `fill.test.ts` F9 |
| F10 | The planner sends a bad tab ID or selector. | `refused` with reason `bad-input`. | `fill.test.ts` F10 |
| F11 | The secret changes while foxgate decides (for example, it is removed and added again for another host). The released value was never checked against the page host. | foxvault reads the domains and the value in one step after the decision, and checks the host again. A host that no longer matches gets `refused: domain`. | `fill.test.ts` F11 |
| F12 | A refused fill puts a bad handle (which can be anything the planner wrote) into the event. | When the handle is not valid, the event has an empty handle. | `fill.test.ts` F12 |
| F13 | `fill` sends a card number to a page that came over plain `http:`. | An `http:` page gets `refused: http`, unless the secret was stored with `allowHttp: true`. `allowHttp` is bound to the ciphertext like the domains. | `fill.test.ts` F13 |
| F14 | A locked passphrase vault throws after foxgate used up the approval token. | `fill` returns `refused: locked`. | `fill.test.ts` F14 |

## Firefox key store (K)

`pnpm e2e` checks these in a real Firefox, in the demo extension.

| # | Failure mode | Wanted behaviour | Test |
|---|---|---|---|
| K1 | IndexedDB in this Firefox cannot keep a `CryptoKey`, so the key is gone when the event page unloads. | A new vault object with a new `indexedDbKeyStore` unlocks the stored secrets. | E2E K1 |
| K2 | The key that IndexedDB gives back is extractable. | It is a secret AES-GCM key with `extractable: false`. `exportKey` rejects. | E2E K2 |
| K3 | `storage.local` holds the value as plain text, base64, or hex. | It holds only ciphertext. | E2E K3 |

## Demo in Firefox (E)

The test starts two local echo servers on two host names: `api.localhost` (A)
and `other.localhost` (B). Firefox sends each `*.localhost` name to the
loopback address. The echo servers log a SHA-256 hash of each
`Authorization` header that arrives. They never return the header itself.

| # | Failure mode | Wanted behaviour | Test |
|---|---|---|---|
| E1 | The header does not reach the allowed host, or the extension page sees the value. | A logs the hash of `Bearer <value>`. The popup shows only that the header arrived. The popup HTML never holds the value. | E2E E1 |
| E2 | A second local host gets the header. | B logs no `Authorization` header. | E2E E2 |
| E3 | A redirect from A to B carries the header to B. | A gets the header. B, after the redirect, does not. | E2E E3 |
| E4 | A web page on B sends a request to A and gets the key added. | A logs that request with no header. | E2E E4 |
| E5 | `redact` misses the value in a sample prompt. | The value, its base64, and the value split across two lines all become the handle. | E2E E5 |
| E6 | A header release is not recorded, or is recorded for the wrong host. | The release events name A only. | E2E E6 |

### Fill in Firefox

The page `form.html` has a card field. With `?frame=`, it also shows that URL
in an iframe. `frame.html` has a card field and a field named `#frame-only`.

| # | Failure mode | Wanted behaviour | Test |
|---|---|---|---|
| E7 | `fill` does not reach the field on the allowed host, or the bundled function does not run in Firefox. | The card field on A shows the value. | E2E E7 |
| E8 | `fill` writes into a cross-origin iframe. | A field that is only in the iframe gives `not-found`, and the iframe fields stay empty. | E2E E8 |
| E9 | `fill` writes on another host, also when that host frames the allowed page. | `refused` with reason `domain`. The page fields and the framed A fields stay empty. | E2E E9 |
