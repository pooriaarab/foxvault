export { VaultError, type VaultErrorCode } from "./errors.js";
export { MIN_ITERATIONS } from "./crypto.js";
export { memoryKeyStore, type KeyStore } from "./keystore.js";
export { createVault, handleName, type SecretInfo, type Vault, type VaultEvent, type VaultOptions } from "./vault.js";
export type { HeaderRule, HeaderRuleInput, RequestDetails } from "./headers.js";
export { FILL_TOOL, fillField, type FillBrowser, type FillRequest, type FillResult } from "./fill.js";
export { attachHeaderInjection, indexedDbKeyStore, type HeaderBrowser } from "./firefox.js";
