// Fill a form field with a secret, after the secret's domains and a foxgate
// decision allow it (docs/failure-modes.md F1-F10).
import type { Gate } from "foxgate";
import { matchesPattern } from "foxgate";
import { toPattern } from "./headers.js";

/** The tool name to register in foxgate: `createFoxgate({ tools: { [FILL_TOOL]: "fill" } })`. */
export const FILL_TOOL = "foxvault.fill";

/** The parts of the WebExtension `browser` object that fill uses. */
export interface FillBrowser {
  webNavigation: {
    getFrame(details: { tabId: number; frameId: number }): Promise<{ url: string; documentId?: string } | null | undefined>;
  };
  scripting: {
    executeScript(injection: {
      target: { tabId: number; documentIds: string[] };
      func: (selector: string, value: string, host: string) => string;
      args: string[];
    }): Promise<{ result?: unknown }[]>;
  };
}

export interface FillRequest {
  handle: string;
  tabId: number;
  /** A CSS selector for an input or textarea in the top document of the tab. */
  selector: string;
  /** The foxgate token, after a human approved the fill. */
  token?: string;
  /** The top document that the caller checked. When given, fill writes only into it. */
  documentId?: string;
}

export type FillResult = { status: "filled"; host: string } | { status: "ask"; requestId: string } | { status: "refused"; reason: string };

/**
 * Runs in the page through scripting.executeScript. Firefox sends it as
 * source text, so it must not use anything from outside its own body.
 */
export function fillField(selector: string, value: string, host: string): string {
  if (location.hostname !== host) return "host-changed";
  let field: Element | null = null;
  try {
    field = document.querySelector(selector);
  } catch {
    return "not-found";
  }
  if (!field) return "not-found";
  if (!(field instanceof HTMLInputElement || field instanceof HTMLTextAreaElement)) return "not-a-field";
  field.focus();
  field.value = value;
  field.dispatchEvent(new Event("input", { bubbles: true }));
  field.dispatchEvent(new Event("change", { bubbles: true }));
  return "filled";
}

interface Settings {
  domains: string[];
  allowHttp: boolean;
}

/** Why this page cannot get the secret, or undefined when it can. */
function pageBlocked(url: URL, secret: Settings): string | undefined {
  if (url.protocol === "http:" && !secret.allowHttp) return "http";
  return secret.domains.some((d) => matchesPattern(url.hostname, toPattern(d))) ? undefined : "domain";
}

export interface FillDeps {
  gate?: Gate;
  browser?: FillBrowser;
  /** The secret's stored settings, or undefined when it does not exist. */
  settings(handle: string): Promise<Settings | undefined>;
  /** The value with its settings, read in one step. Throws `locked` when the vault is locked. */
  release(handle: string): Promise<(Settings & { value: string }) | undefined>;
  /** Throws when onEvent throws. */
  emit(type: "release" | "refuse", handle: string, host?: string, reason?: string): Promise<void>;
  validHandle(handle: unknown): boolean;
}

export async function runFill(deps: FillDeps, request: FillRequest): Promise<FillResult> {
  const { handle, tabId, selector, token, documentId } = request ?? {};
  let host: string | undefined;
  const refuse = async (reason: string): Promise<FillResult> => {
    // A handle that is not valid can be anything the planner wrote, so it is not echoed (F12).
    await deps.emit("refuse", deps.validHandle(handle) ? handle : "", host, reason).catch(() => undefined);
    return { status: "refused", reason };
  };
  const goodInput = deps.validHandle(handle) && Number.isSafeInteger(tabId) && tabId >= 0 && typeof selector === "string" && selector.length > 0 && selector.length <= 1024;
  const goodDocument = documentId === undefined || (typeof documentId === "string" && documentId.length > 0 && documentId.length <= 256);
  if (!goodInput || !goodDocument || (token !== undefined && typeof token !== "string")) return refuse("bad-input");
  if (!deps.gate) return refuse("no-gate");
  if (!deps.browser) return refuse("no-browser");

  // The top document of the tab. Frames are never filled (F4).
  const frame = await deps.browser.webNavigation.getFrame({ tabId, frameId: 0 }).catch(() => undefined);
  if (!frame) return refuse("no-tab");
  // The caller's document must still be the top document of the tab (F15).
  if (documentId !== undefined && frame.documentId !== documentId) return refuse("page-changed");
  let url: URL;
  try {
    url = new URL(frame.url);
  } catch {
    return refuse("domain");
  }
  if (url.protocol !== "https:" && url.protocol !== "http:") return refuse("domain");
  host = url.hostname;
  const settings = await deps.settings(handle);
  if (!settings) return refuse("not-found");
  const blocked = pageBlocked(url, settings);
  if (blocked) return refuse(blocked);

  const action = { tool: FILL_TOOL, scope: "fill" as const, domain: host, args: { handle, selector } };
  const decision = token === undefined ? await deps.gate.check(action) : await deps.gate.redeem(token, action);
  if (decision.decision === "ask") return { status: "ask", requestId: decision.requestId };
  if (decision.decision === "deny") return refuse(decision.reason);
  if (!frame.documentId) return refuse("frame-changed");

  // The secret can change while foxgate decides, so check the released one again (F11).
  let secret: Awaited<ReturnType<FillDeps["release"]>>;
  try {
    secret = await deps.release(handle);
  } catch (error) {
    if ((error as { code?: string }).code === "locked") return refuse("locked");
    throw error;
  }
  if (!secret) return refuse("not-found");
  const again = pageBlocked(url, secret);
  if (again) return refuse(again);
  const value = secret.value;
  try {
    await deps.emit("release", handle, host);
  } catch {
    return { status: "refused", reason: "hook-failed" };
  }
  let result: unknown;
  try {
    // documentIds pins the call to the document that was checked (F5).
    const results = await deps.browser.scripting.executeScript({ target: { tabId, documentIds: [frame.documentId] }, func: fillField, args: [selector, value, host] });
    result = results[0]?.result;
  } catch {
    return refuse(documentId === undefined ? "frame-changed" : "page-changed");
  }
  if (result === "filled") return { status: "filled", host };
  return refuse(typeof result === "string" ? result : "not-found");
}
