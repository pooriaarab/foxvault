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
