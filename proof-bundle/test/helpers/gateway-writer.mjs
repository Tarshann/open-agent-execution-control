// Child process for test/gateway-live.test.mjs: a REAL governed MCP server
// (@strixgov/mcp-adapter over @strixgov/tool-gateway) that keeps appending
// receipts and outcomes to a store while the parent exports from it.
//   node gateway-writer.mjs <node_modules/@strixgov> <storeDir> <keyRoot> <count>
import path from "node:path";
import { pathToFileURL } from "node:url";

const [nm, storeDir, keyRoot, count] = process.argv.slice(2);
const load = (p) => import(pathToFileURL(path.join(nm, p)).href);
const { loadOrCreateKeyRing } = await load("tool-gateway/src/index.mjs");
const { governMCPServer } = await load("mcp-adapter/src/index.mjs");

const keyRing = await loadOrCreateKeyRing({ root: keyRoot, kid: "live-key-1" });
const governed = governMCPServer(
  { read_note: async (args) => ({ content: [{ type: "text", text: JSON.stringify(args) }] }) },
  {
    serverId: "live",
    capabilities: [{ id: "mcp.live.read_note", name: "read_note", risk: "LOW", mode: "READ", description: "read" }],
    policy: { rules: { "mcp.live.read_note": "ALLOW" }, default: "DENY" },
    storagePath: storeDir,
    keyRing,
  },
);
for (let i = 0; i < Number(count); i++) {
  const r = await governed.executeTool("read_note", { n: i });
  if (i === 0) process.stdout.write(`FIRST ${r.authorizationReceipt.receiptId}\n`);
  if (i === Math.floor(Number(count) / 2)) {
    await governed.gateway.rotateKey({ kid: "live-key-2" });
    process.stdout.write("ROTATED\n");
  }
  if (i === Number(count) - 1) process.stdout.write(`LAST ${r.authorizationReceipt.receiptId}\n`);
}
