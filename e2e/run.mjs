// The E2E test: install the built demo extension (dist-ext/) in a real
// Firefox, drive its popup, and write artifacts/e2e-<date>.json. It checks
// failure modes K1-K3 and E1-E9 in docs/failure-modes.md.
// Usage: pnpm e2e [--headed]. Env: FIREFOX (the Firefox binary).
//
// The hosts are api.localhost (A) and other.localhost (B). Firefox sends
// *.localhost to the loopback address, and it does not upgrade them to
// https: the default MV3 extension CSP has upgrade-insecure-requests, which
// breaks plain http to any other name.
//
// With FOXKIT_BROWSER=ichabod the browser is on Ichabod and cannot reach
// 127.0.0.1, so each echo server gets a public https URL on a Cloudflare
// quick tunnel. One process has one tunnel origin, and the checks need A and
// B to be two origins, so A is on this process's tunnel and B is on a tunnel
// that a child process (e2e/tunnel-child.mjs) opens. Then the secret is
// added with allowHttp off: https needs no plain-http opt-in.
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { createInterface } from "node:readline";
import { fileURLToPath } from "node:url";
import { browserMode, launch, poll, tunnel, writeArtifact } from "create-foxkit/e2e";
import { startEcho } from "./echo.mjs";

const VALUE = "sk-fvt-e2e-7f3a9c1b5d2e8f4a6b0c";
const HANDLE = "vault:test-key";
const CARD = "4242424242424242";
const record = { startedAt: new Date().toISOString(), checks: [] };
const check = (name, expected, actual) => record.checks.push({ name, expected, actual, ok: JSON.stringify(actual) === JSON.stringify(expected) });
const sha256 = (text) => createHash("sha256").update(text).digest("hex");
const forms = [VALUE, Buffer.from(VALUE).toString("base64"), Buffer.from(VALUE).toString("hex"), CARD];

// Click a button, wait until the output counts one more answer, and return it.
async function press(page, button, output) {
  const before = await page.evaluate((o) => Number(document.querySelector(o).dataset.runs ?? 0), output);
  await page.evaluate((b) => document.querySelector(b).click(), button);
  await poll(page, ([o, b]) => Number(document.querySelector(o).dataset.runs ?? 0) > b, [output, before]);
  return page.evaluate((o) => document.querySelector(o).textContent, output);
}
const setValues = (page, values) =>
  page.evaluate((v) => {
    for (const [selector, value] of Object.entries(v)) {
      const el = document.querySelector(selector);
      if (el.type === "checkbox") el.checked = value;
      else el.value = value;
    }
  }, values);
const entry = (echo, id) => echo.log.find((e) => e.id === id);
// The header hash that a server logged for a request, or "missing" when the request never came.
const hashAt = (echo, id) => (entry(echo, id) ? entry(echo, id).sha256 : "missing");
const waitFor = async (fn) => {
  for (let i = 0; i < 100 && !fn(); i++) await new Promise((r) => setTimeout(r, 100));
  return fn();
};

const value = (frame, selector) => frame.evaluate((s) => document.querySelector(s).value, selector);
// The loaded iframe whose URL is under `base` (A or B).
const frameOf = async (page, base) => {
  const frame = await waitFor(() => page.frames().find((f) => f.url().startsWith(`${base}/`)));
  await poll(frame, () => document.readyState === "complete" && document.querySelector("#card") !== null);
  return frame;
};

// Open a tunnel for `port` in a child process, so that it gets an origin of its own.
async function childTunnel(port) {
  const child = spawn(process.execPath, [fileURLToPath(new URL("tunnel-child.mjs", import.meta.url)), String(port)], { stdio: ["pipe", "pipe", "inherit"] });
  const lines = createInterface({ input: child.stdout });
  const close = () => {
    child.kill("SIGTERM");
    child.stdin.end();
  };
  const timer = setTimeout(close, 120_000);
  const [line] = await Promise.race([
    new Promise((done) => lines.once("line", (l) => done([l]))),
    new Promise((done) => child.once("exit", (code) => done([JSON.stringify({ error: `the tunnel child exited with code ${code}` })]))),
  ]);
  clearTimeout(timer);
  const answer = JSON.parse(line);
  if (!answer.url) {
    close();
    throw new Error(`no tunnel for B: ${answer.error}`);
  }
  return { url: answer.url, close };
}

const remote = browserMode() === "ichabod";
record.mode = remote ? "ichabod" : "local";
const a = await startEcho();
const b = await startEcho();
let A = `http://api.localhost:${a.port}`;
let B = `http://other.localhost:${b.port}`;
let tunnelB;
let fox;
try {
  if (remote) {
    A = (await tunnel(a.port)).url;
    tunnelB = await childTunnel(b.port);
    B = tunnelB.url;
    record.notes = ["A and B are https tunnel origins, so the secrets are added with allowHttp off: the plain-http opt-in has nothing to allow."];
  }
  // The host names that the vault and the events see, and a tabs.query pattern for the pages under A.
  const hostA = new URL(A).hostname;
  const hostB = new URL(B).hostname;
  const tabsA = remote ? `${A}/*` : "http://api.localhost/*";
  record.hosts = { A: hostA, B: hostB };
  fox = await launch({
    extension: "dist-ext",
    headless: !process.argv.includes("--headed"),
  });
  record.firefox = await fox.browser.version();
  const popup = await fox.openExtensionPage("popup.html");
  await poll(popup, () => document.body.dataset.ready === "1");

  // Add the secret through the popup form, as a user does.
  await setValues(popup, { "#handle": HANDLE, "#value": VALUE, "#hosts": hostA, "#header": "Authorization", "#format": "Bearer {secret}", "#allow-http": !remote });
  check("add: the popup adds the secret", "added vault:test-key", await press(popup, "#add", "#add-result"));
  check("add: the value field is empty after add", "", await popup.evaluate(() => document.querySelector("#value").value));

  const call = async (url) => {
    await setValues(popup, { "#url": url });
    return JSON.parse(await press(popup, "#call", "#call-result"));
  };
  const e1 = await call(`${A}/echo?id=e1`);
  check("E1: A gets Authorization: Bearer <value>", sha256(`Bearer ${VALUE}`), hashAt(a, "e1"));
  check("E1: the popup sees that the header arrived", true, e1.received);
  const e2 = await call(`${B}/echo?id=e2`);
  check("E2: B gets no Authorization header", null, hashAt(b, "e2"));
  check("E2: the popup sees no header at B", false, e2.received);
  await call(`${A}/redirect?id=e3a&to=${encodeURIComponent(`${B}/echo?id=e3b`)}`);
  check("E3: A gets the header before the redirect", sha256(`Bearer ${VALUE}`), hashAt(a, "e3a"));
  check("E3: B gets no header after the redirect", null, hashAt(b, "e3b"));
  check("E1: the popup HTML never holds the value", false, await popup.evaluate((f) => f.some((x) => document.documentElement.outerHTML.includes(x)), forms));

  const attack = await fox.open(`${B}/attack.html?target=${encodeURIComponent(`${A}/echo?id=e4`)}`);
  await poll(attack, () => document.body.dataset.done === "1");
  await waitFor(() => entry(a, "e4"));
  check("E4: a request from a web page on B reaches A with no header", null, hashAt(a, "e4"));
  await attack.close();

  const prompt = `Call the API with ${VALUE}. Basic: ${forms[1]}. Split: ${VALUE.slice(0, 11)}\n${VALUE.slice(11)}.`;
  await setValues(popup, { "#prompt": prompt });
  const redacted = await press(popup, "#redact", "#redacted");
  check("E5: redact leaves no form of the value", false, forms.some((f) => redacted.includes(f)) || redacted.includes(VALUE.slice(11)));
  check("E5: redact puts the handle in 3 places", 3, redacted.split(HANDLE).length - 1);

  // Fill: a card number for A only, through foxgate.
  const add = (message) => popup.evaluate((m) => browser.runtime.sendMessage({ type: "add", ...m }), message);
  check("fill: the card secret is added", "added vault:card", await add({ handle: "vault:card", value: CARD, hosts: hostA, header: "", allowHttp: !remote }));
  const fill = async (url, pattern, selector) => {
    const page = await fox.open(url);
    const tabId = await popup.evaluate((u) => browser.tabs.query({ url: u }).then((tabs) => tabs.at(-1).id), pattern);
    const result = await popup.evaluate((m) => browser.runtime.sendMessage({ type: "fill", ...m }), { handle: "vault:card", tabId, selector });
    return { page, result };
  };

  const onA = await fill(`${A}/form.html?frame=${encodeURIComponent(`${B}/frame.html`)}`, tabsA, "#card");
  check("E7: fill on A works", { status: "filled", host: hostA }, onA.result);
  check("E7: the card field on A holds the value", CARD, await value(onA.page, "#card"));
  check("E8: the cross-origin iframe card field stays empty", "", await value(await frameOf(onA.page, B), "#card"));
  const frameOnly = await popup.evaluate((m) => browser.runtime.sendMessage({ type: "fill", ...m }), { handle: "vault:card", tabId: await popup.evaluate((u) => browser.tabs.query({ url: u }).then((t) => t.at(-1).id), tabsA), selector: "#frame-only" });
  check("E8: a field only in the iframe is not found", { status: "refused", reason: "not-found" }, frameOnly);
  check("E8: the iframe-only field stays empty", "", await value(await frameOf(onA.page, B), "#frame-only"));
  await onA.page.close();

  // F15 in Firefox: a documentId from before a navigation does not get the value.
  const pinned = await fox.open(`${A}/form.html`);
  const pinnedTab = await popup.evaluate((u) => browser.tabs.query({ url: u }).then((t) => t.at(-1).id), tabsA);
  const frameNow = () => popup.evaluate((t) => browser.webNavigation.getFrame({ tabId: t, frameId: 0 }).then((f) => f.documentId), pinnedTab);
  const before = await frameNow();
  await pinned.goto(`${A}/form.html?next=1`, { waitUntil: "load" });
  const pinFill = (documentId) => popup.evaluate((m) => browser.runtime.sendMessage({ type: "fill", ...m }), { handle: "vault:card", tabId: pinnedTab, selector: "#card", documentId });
  check("F15: an old documentId is refused after a navigation", { status: "refused", reason: "page-changed" }, await pinFill(before));
  check("F15: the new page stays empty", "", await value(pinned, "#card"));
  check("F15: the current documentId fills", { status: "filled", host: hostA }, await pinFill(await frameNow()));
  await pinned.close();

  const onB = await fill(`${B}/form.html?frame=${encodeURIComponent(`${A}/frame.html`)}`, remote ? `${B}/*` : "http://other.localhost/*", "#card");
  check("E9: fill on B is refused", { status: "refused", reason: "domain" }, onB.result);
  check("E9: the card field on B stays empty", "", await value(onB.page, "#card"));
  check("E9: the framed A field inside B stays empty", "", await value(await frameOf(onB.page, A), "#card"));
  await onB.page.close();

  const state = await popup.evaluate(() => browser.runtime.sendMessage({ type: "state" }));
  const hosts = [...new Set(state.events.filter((e) => e.kind === "header").map((e) => e.host))];
  check("E6: header releases name only A", [hostA], hosts);
  check("E6: no event holds the value", false, forms.some((f) => JSON.stringify(state.events).includes(f)));
  const fills = state.events.filter((e) => e.kind === "fill").map((e) => `${e.type} ${e.host ?? ""} ${e.reason ?? ""}`.trim());
  check("E7-E9: fill events name each release and refusal", [`refuse ${hostB} domain`, `release ${hostA}`, "refuse  page-changed", `refuse ${hostA} not-found`, `release ${hostA}`, `release ${hostA}`], fills);

  const key = await popup.evaluate(() => browser.runtime.sendMessage({ type: "key-check" }));
  check("K1: a new vault object unlocks with the key from IndexedDB", true, key.reopened);
  check("K2: the stored key is a non-extractable AES-GCM key", { type: "secret", algorithm: "AES-GCM", extractable: false, exportRefused: true }, {
    type: key.type,
    algorithm: key.algorithm,
    extractable: key.extractable,
    exportRefused: key.exportRefused,
  });
  const stored = JSON.stringify(await popup.evaluate(() => browser.storage.local.get(null)));
  check("K3: storage.local holds no form of the value", false, forms.some((f) => stored.includes(f)));
} catch (error) {
  record.error = error instanceof Error ? error.message : String(error);
} finally {
  await fox?.close();
  tunnelB?.close();
  await a.close();
  await b.close();
}
record.passed = !record.error && record.checks.length >= 30 && record.checks.every((c) => c.ok);
const path = writeArtifact("artifacts", "e2e", record);
for (const c of record.checks) console.log(`${c.ok ? "ok " : "BAD"} ${c.name}: ${JSON.stringify(c.actual)}`);
console.log(`${record.passed ? "PASS" : "FAIL"}${record.error ? `: ${record.error}` : ""} | ${path}`);
process.exitCode = record.passed ? 0 : 1;
