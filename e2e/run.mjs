// The E2E test: install the built demo extension (dist-ext/) in a real
// Firefox, drive its popup, and write artifacts/e2e-<date>.json. It checks
// failure modes K1-K3 and E1-E6 in docs/failure-modes.md.
// Usage: pnpm e2e [--headed]. Env: FIREFOX (the Firefox binary).
//
// The hosts are api.localhost (A) and other.localhost (B). Firefox sends
// *.localhost to the loopback address, and it does not upgrade them to
// https: the default MV3 extension CSP has upgrade-insecure-requests, which
// breaks plain http to any other name.
import { createHash } from "node:crypto";
import { launch, poll, writeArtifact } from "create-foxkit/e2e";
import { startEcho } from "./echo.mjs";

const VALUE = "sk-fvt-e2e-7f3a9c1b5d2e8f4a6b0c";
const HANDLE = "vault:test-key";
const record = { startedAt: new Date().toISOString(), checks: [] };
const check = (name, expected, actual) => record.checks.push({ name, expected, actual, ok: JSON.stringify(actual) === JSON.stringify(expected) });
const sha256 = (text) => createHash("sha256").update(text).digest("hex");
const forms = [VALUE, Buffer.from(VALUE).toString("base64"), Buffer.from(VALUE).toString("hex")];

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

const a = await startEcho();
const b = await startEcho();
const A = `http://api.localhost:${a.port}`;
const B = `http://other.localhost:${b.port}`;
let fox;
try {
  fox = await launch({
    extension: "dist-ext",
    headless: !process.argv.includes("--headed"),
  });
  record.firefox = await fox.browser.version();
  const popup = await fox.openExtensionPage("popup.html");
  await poll(popup, () => document.body.dataset.ready === "1");

  // Add the secret through the popup form, as a user does.
  await setValues(popup, { "#handle": HANDLE, "#value": VALUE, "#hosts": "api.localhost", "#header": "Authorization", "#format": "Bearer {secret}", "#allow-http": true });
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

  const state = await popup.evaluate(() => browser.runtime.sendMessage({ type: "state" }));
  const hosts = [...new Set(state.events.filter((e) => e.kind === "header").map((e) => e.host))];
  check("E6: header releases name only A", ["api.localhost"], hosts);
  check("E6: no event holds the value", false, forms.some((f) => JSON.stringify(state.events).includes(f)));

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
  await a.close();
  await b.close();
}
record.passed = !record.error && record.checks.length >= 17 && record.checks.every((c) => c.ok);
const path = writeArtifact("artifacts", "e2e", record);
for (const c of record.checks) console.log(`${c.ok ? "ok " : "BAD"} ${c.name}: ${JSON.stringify(c.actual)}`);
console.log(`${record.passed ? "PASS" : "FAIL"}${record.error ? `: ${record.error}` : ""} | ${path}`);
process.exitCode = record.passed ? 0 : 1;
