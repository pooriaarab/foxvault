// AES-GCM with Web Crypto (docs/failure-modes.md V1-V3). Every
// key that this file makes is non-extractable.
const encoder = new TextEncoder();
const decoder = new TextDecoder();

/** One AES-GCM ciphertext: a 12-byte IV and the data with its tag, both base64. */
export interface Sealed {
  iv: string;
  data: string;
}

export function toBase64(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
}

/** Throws for text that is not base64. */
export function fromBase64(text: string): Uint8Array<ArrayBuffer> {
  const raw = atob(text);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

export const randomBytes = (length: number) => crypto.getRandomValues(new Uint8Array(length));

export const newDeviceKey = () =>
  crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]) as Promise<CryptoKey>;

export async function seal(key: CryptoKey, text: string, aad: string): Promise<Sealed> {
  const iv = randomBytes(12);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: encoder.encode(aad) }, key, encoder.encode(text));
  return { iv: toBase64(iv), data: toBase64(new Uint8Array(data)) };
}

/** Throws when the key, the data, or the additional data is not the one sealed. */
export async function unseal(key: CryptoKey, sealed: Sealed, aad: string): Promise<string> {
  const iv = fromBase64(sealed.iv);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv, additionalData: encoder.encode(aad) }, key, fromBase64(sealed.data));
  return decoder.decode(plain);
}
