// A local echo server for the demo and the E2E test. It logs a SHA-256 hash
// of each Authorization header that arrives and never sends the header back.
// GET /echo?id=..          -> { host, received, sha256, length }
// GET /redirect?to=<url>   -> 302 to <url>
// Other paths              -> files from e2e/site/
// Usage: node e2e/echo.mjs [port]   (default 8787, on 127.0.0.1)
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { join, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const SITE = resolve(fileURLToPath(new URL("site", import.meta.url)));

export async function startEcho(port = 0) {
  const log = [];
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://x");
    const auth = req.headers.authorization;
    const sha256 = auth ? createHash("sha256").update(auth).digest("hex") : null;
    log.push({ id: url.searchParams.get("id"), path: url.pathname, host: req.headers.host, sha256 });
    const cors = { "access-control-allow-origin": "*" };
    if (url.pathname === "/echo") {
      const body = { host: req.headers.host, received: Boolean(auth), sha256: sha256?.slice(0, 16) ?? null, length: auth?.length ?? 0 };
      res.writeHead(200, { ...cors, "content-type": "application/json" }).end(JSON.stringify(body));
      return;
    }
    if (url.pathname === "/redirect") {
      res.writeHead(302, { ...cors, location: url.searchParams.get("to") ?? "/" }).end();
      return;
    }
    const file = resolve(join(SITE, url.pathname));
    if (!file.startsWith(SITE + sep) || !existsSync(file)) {
      res.writeHead(404, cors).end("Not found");
      return;
    }
    res.writeHead(200, { ...cors, "content-type": "text/html; charset=utf-8" }).end(readFileSync(file));
  });
  await new Promise((done) => server.listen(port, "127.0.0.1", done));
  return {
    port: server.address().port,
    log,
    close: () => new Promise((done) => {
      server.close(() => done());
      server.closeAllConnections();
    }),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const echo = await startEcho(Number(process.argv[2] ?? 8787));
  console.log(`Echo server on http://127.0.0.1:${echo.port}/echo`);
}
