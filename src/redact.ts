// Replace every stored value, and the usual encodings of it, with its handle
// (docs/failure-modes.md R1-R11).
import { toBase64 } from "./crypto.js";

const encoder = new TextEncoder();
const escape = (ch: string) => ch.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");

// A pattern that allows the separators between any two characters (R2, R3).
const spaced = (form: string, separators: string) => [...form].map(escape).join(separators);

// The base64 characters that come only from the value, when the value starts
// at byte offset 0, 1, or 2 of a longer base64 text (R4).
function base64Cores(bytes: Uint8Array): string[] {
  const cores: string[] = [];
  for (let offset = 0; offset < 3; offset++) {
    const padded = new Uint8Array(offset + bytes.length);
    padded.set(bytes, offset);
    const text = toBase64(padded);
    const end = Math.floor(padded.length / 3) * 4;
    cores.push(text.slice(offset === 0 ? 0 : 4, end));
  }
  return cores;
}

/** Every form of one value that redact looks for, as regular expression sources. */
export function formsOf(value: string): { source: string; length: number }[] {
  const bytes = encoder.encode(value);
  const std = toBase64(bytes);
  const url = encodeURIComponent(value);
  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  const base64 = [std, std.replace(/=+$/, ""), ...base64Cores(bytes)].flatMap((f) => [f, f.replace(/\+/g, "-").replace(/\//g, "_")]);
  const encoded = [
    url,
    url.replace(/%20/g, "+"),
    url.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase()),
    hex,
    hex.toUpperCase(),
    JSON.stringify(value).slice(1, -1),
    ...base64,
  ];
  const forms = new Map<string, number>([[spaced(value, "[\\s-]*"), value.length]]);
  for (const form of encoded) if (form.length >= 8 && form !== value) forms.set(spaced(form, "\\s*"), form.length);
  return [...forms].map(([source, length]) => ({ source, length }));
}

/** Replace each value with its handle. Longer forms go first, so no part of a longer value is left (R8). */
export function redactText(text: string, secrets: { handle: string; value: string }[]): string {
  const all = secrets.flatMap(({ handle, value }) => formsOf(value).map((form) => ({ ...form, handle })));
  all.sort((a, b) => b.length - a.length);
  let out = text;
  for (const { source, handle } of all) out = out.replace(new RegExp(source, "gu"), handle);
  return out;
}
