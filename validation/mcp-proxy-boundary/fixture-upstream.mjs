// Disposable upstream MCP server. Every tool is inert: the only side effect is
// a line appended to FIXTURE_SANDBOX_FILE inside the throwaway work dir.
// Every handler invocation (and nothing else) appends to FIXTURE_HANDLER_LOG,
// so the log is the ground truth for "what actually ran".
import { appendFileSync } from "node:fs";
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { CallToolRequestSchema, ListToolsRequestSchema } from "@modelcontextprotocol/sdk/types.js";

const HANDLER_LOG = process.env.FIXTURE_HANDLER_LOG;
const SANDBOX = process.env.FIXTURE_SANDBOX_FILE;
if (!HANDLER_LOG || !SANDBOX) throw new Error("FIXTURE_HANDLER_LOG and FIXTURE_SANDBOX_FILE are required");

const obj = { type: "object", properties: { note: { type: "string" } }, required: ["note"] };
const tools = [
  { name: "read_note", description: "Read a synthetic note (read-only).", inputSchema: obj },
  { name: "write_note", description: "Append a synthetic note to the sandbox file.", inputSchema: obj },
  { name: "delete_note", description: "Pretend-delete a synthetic note (inert).", inputSchema: obj },
];

const server = new Server({ name: "boundary-fixture-upstream", version: "0.0.1" }, { capabilities: { tools: {} } });
server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools }));
server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const { name, arguments: args = {} } = req.params;
  appendFileSync(HANDLER_LOG, JSON.stringify({ at: new Date().toISOString(), pid: process.pid, handler: name, args }) + "\n");
  if (name === "write_note") appendFileSync(SANDBOX, `${args.note}\n`);
  return { content: [{ type: "text", text: JSON.stringify({ handler: name, ran: true, note: args.note }) }] };
});
await server.connect(new StdioServerTransport());
