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
