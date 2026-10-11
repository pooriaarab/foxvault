// Gives one local port its own public origin. A process has one Cloudflare
// quick tunnel, so every tunnel() in it shares one origin; the E2E test runs
// this in a child process to get a second origin for host B.
// Usage: node e2e/tunnel-child.mjs <port>. It prints {"url": ...} as one
// line and keeps the tunnel open until it gets SIGTERM or its stdin closes.
import { closeTunnels, tunnel } from "create-foxkit/e2e";

const port = Number(process.argv[2]);
const stop = () => closeTunnels().finally(() => process.exit(0));
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
// The parent holds stdin open; when the parent dies, stdin ends and this stops too.
process.stdin.on("end", stop).resume();
try {
  const { url } = await tunnel(port);
  process.stdout.write(`${JSON.stringify({ url })}\n`);
} catch (error) {
  process.stdout.write(`${JSON.stringify({ error: error instanceof Error ? error.message : String(error) })}\n`);
  process.exit(1);
}
