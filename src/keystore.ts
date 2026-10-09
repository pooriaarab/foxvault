/** Where device mode keeps its non-extractable key. */
export interface KeyStore {
  load(): Promise<CryptoKey | undefined>;
  save(key: CryptoKey): Promise<void>;
  clear(): Promise<void>;
}

/** A key store in memory. The key, and so every secret, is gone when the process stops. */
export function memoryKeyStore(): KeyStore {
  let key: CryptoKey | undefined;
  return {
    load: async () => key,
    save: async (k) => {
      key = k;
    },
    clear: async () => {
      key = undefined;
    },
  };
}
