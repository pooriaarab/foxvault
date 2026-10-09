/** Why foxvault refused. Callers can switch on `code`. Messages never hold a secret value. */
export type VaultErrorCode =
  | "not-initialized"
  | "already-initialized"
  | "locked"
  | "corrupt"
  | "key-lost"
  | "not-found"
  | "exists"
  | "bad-handle"
  | "bad-value"
  | "bad-domain";

export class VaultError extends Error {
  readonly code: VaultErrorCode;
  constructor(code: VaultErrorCode, message: string) {
    super(message);
    this.name = "VaultError";
    this.code = code;
  }
}
