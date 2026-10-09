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

// A hex digit pattern that takes either letter case.
const hexAnyCase = (hex: string) => hex.replace(/[a-f]/gi, (d) => `[${d.toLowerCase()}${d.toUpperCase()}]`);
const NAMED: Record<string, string[]> = { "&": ["amp"], "<": ["lt"], ">": ["gt"], '"': ["quot"], "'": ["apos"] };
const JSON_ESCAPES: Record<string, string> = { '"': '\\"', "\\": "\\\\", "/": "\\/", "\n": "\\n", "\r": "\\r", "\t": "\\t" };

// One character of the value, plain or in any encoding that a log or a page
// can give it: JSON \uXXXX, %XX and %25XX, HTML entities (R12, R13, R15).
function charPattern(ch: string): string {
  const cp = ch.codePointAt(0)!;
  const alts = [escape(ch)];
  alts.push([...Array(ch.length).keys()].map((i) => `\\\\u${hexAnyCase(ch.charCodeAt(i).toString(16).padStart(4, "0"))}`).join(""));
  const bytes = [...encoder.encode(ch)].map((b) => hexAnyCase(b.toString(16).padStart(2, "0")));
  alts.push(bytes.map((b) => `%${b}`).join(""), bytes.map((b) => `%25${b}`).join(""));
  alts.push(`&#0*${cp};`, `&#[xX]0*${hexAnyCase(cp.toString(16))};`, ...(NAMED[ch] ?? []).map((n) => `&${n};`));
  if (JSON_ESCAPES[ch]) alts.push(escape(JSON_ESCAPES[ch]));
  if (ch === " ") alts.push("\\+");
  return `(?:${alts.join("|")})`;
}

// Whitespace, or the two characters \n or \r that JSON writes for a line break (R14).
const WRAP = "(?:\\s|\\\\[nr])*";

/** Every form of one value that redact looks for, as regular expression sources. */
export function formsOf(value: string): { source: string; length: number }[] {
  const forms = new Map<string, number>();
  // The stored, NFC, and NFD forms, so a text in the other Unicode form still matches (R16).
  for (const variant of new Set([value, value.normalize("NFC"), value.normalize("NFD")])) {
    const bytes = encoder.encode(variant);
    const std = toBase64(bytes);
    const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
    const base64 = [std, std.replace(/=+$/, ""), ...base64Cores(bytes)].flatMap((f) => [f, f.replace(/\+/g, "-").replace(/\//g, "_")]);
    forms.set([...variant].map(charPattern).join("[\\s-]*"), variant.length);
    for (const form of [hex, hex.toUpperCase(), ...base64]) if (form.length >= 8) forms.set(spaced(form, WRAP), form.length);
  }
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
