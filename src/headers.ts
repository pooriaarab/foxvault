// Header rules and the body of the blocking onBeforeSendHeaders listener
// (docs/failure-modes.md H1-H11). The listener adds the header only for an
// allowed host, and only for a request that this extension made.
import { matchesPattern, parsePattern, type DomainPattern, type PublicSuffix } from "foxgate";
import { VaultError } from "./errors.js";

const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
// oxlint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f]/;

export interface HeaderRuleInput {
  handle: string;
  /** An HTTP header name, for example `Authorization`. */
  header: string;
  /** Exact hosts or "*." patterns. Each must be inside the secret's domains. */
  hosts: string[];
  /** The header value, with `{secret}` one time. Default: `{secret}`. */
  format?: string;
  /** Also send the header over plain http. Default: false. */
  allowHttp?: boolean;
}
export interface HeaderRule extends Required<HeaderRuleInput> {
  id: string;
}
/** The part of webRequest.onBeforeSendHeaders details that foxvault reads. */
export interface RequestDetails {
  url: string;
  originUrl?: string;
  requestHeaders?: { name: string; value?: string }[];
}

export const toPattern = (domain: string): DomainPattern =>
  domain.startsWith("*.") ? { kind: "subdomains", host: domain.slice(2) } : { kind: "exact", host: domain };

const covers = (outer: DomainPattern, inner: DomainPattern) =>
  inner.kind === "exact" ? matchesPattern(inner.host, outer) : outer.kind === "subdomains" && (inner.host === outer.host || matchesPattern(inner.host, outer));

const badRule = (why: string) => new VaultError("bad-rule", `The header rule is not valid: ${why}.`);

/** Check a rule against the secret's domains. Returns the rule without its id and handle. */
export function checkRule(input: HeaderRuleInput, secretDomains: string[], publicSuffix?: PublicSuffix) {
  const { header, format = "{secret}", allowHttp = false } = input;
  if (typeof header !== "string" || !TOKEN.test(header)) throw badRule("the header name is not an HTTP token");
  if (typeof format !== "string" || format.split("{secret}").length !== 2 || CONTROL.test(format)) {
    throw badRule("the format needs {secret} exactly one time and no control characters");
  }
  if (!Array.isArray(input.hosts) || input.hosts.length === 0) throw badRule("give at least one host");
  const allowed = secretDomains.map(toPattern);
  const hosts = input.hosts.map((host) => {
    let pattern: DomainPattern;
    try {
      pattern = parsePattern(host, publicSuffix);
    } catch {
      throw badRule("a host is not a host name or a \"*.\" pattern");
    }
    if (!allowed.some((outer) => covers(outer, pattern))) throw badRule(`${host} is not in the secret's domains`);
    return pattern.kind === "exact" ? pattern.host : `*.${pattern.host}`;
  });
  return { header, hosts, format, allowHttp: allowHttp === true };
}

/** True when a request from this URL is one that the extension made. */
export function fromExtension(originUrl: unknown, extensionOrigin: string): boolean {
  const base = extensionOrigin.endsWith("/") ? extensionOrigin : `${extensionOrigin}/`;
  return typeof originUrl === "string" && base.startsWith("moz-extension://") && originUrl.startsWith(base);
}

/**
 * The new request headers, or undefined when nothing changes. `release`
 * runs before each header goes out; when it returns false, the header does not.
 */
export async function applyRules(
  details: RequestDetails,
  rules: HeaderRule[],
  secret: (handle: string) => { value: string; domains: string[] } | undefined,
  release: (rule: HeaderRule, host: string) => Promise<boolean>,
) {
  const url = new URL(details.url);
  const host = url.hostname;
  let headers = [...(details.requestHeaders ?? [])];
  let changed = false;
  for (const rule of rules) {
    const found = secret(rule.handle);
    if (!found) continue;
    const value = rule.format.replace("{secret}", () => found.value);
    const schemeOk = url.protocol === "https:" || (url.protocol === "http:" && rule.allowHttp);
    const hostOk = rule.hosts.some((p) => matchesPattern(host, toPattern(p))) && found.domains.some((p) => matchesPattern(host, toPattern(p)));
    const send = schemeOk && hostOk && !CONTROL.test(value) && (await release(rule, host));
    const name = rule.header.toLowerCase();
    const kept = headers.filter((h) => !(h.name.toLowerCase() === name && (send || (h.value ?? "").includes(found.value))));
    changed ||= kept.length !== headers.length;
    headers = kept;
    if (send) {
      headers.push({ name: rule.header, value });
      changed = true;
    }
  }
  return changed ? { requestHeaders: headers } : undefined;
}

/**
 * For a vault that cannot open (locked, or a failed unlock): add nothing, and
 * remove every header with a rule's name from a request that the rule does
 * not allow, because the value cannot be compared (H12).
 */
export function stripOnly(details: RequestDetails, rules: HeaderRule[], domainsOf: (handle: string) => string[] | undefined) {
  const url = new URL(details.url);
  const host = url.hostname;
  const before = details.requestHeaders ?? [];
  let headers = [...before];
  for (const rule of rules) {
    const domains = domainsOf(rule.handle) ?? [];
    const schemeOk = url.protocol === "https:" || (url.protocol === "http:" && rule.allowHttp);
    const hostOk = rule.hosts.some((p) => matchesPattern(host, toPattern(p))) && domains.some((p) => matchesPattern(host, toPattern(p)));
    if (!schemeOk || !hostOk) headers = headers.filter((h) => h.name.toLowerCase() !== rule.header.toLowerCase());
  }
  return headers.length === before.length ? undefined : { requestHeaders: headers };
}
