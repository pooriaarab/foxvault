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
