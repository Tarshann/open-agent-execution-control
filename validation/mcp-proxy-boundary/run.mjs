#!/usr/bin/env node
// Boundary validation for @strixgov/mcp-proxy against a disposable stdio MCP fixture.
// Drives the REAL CLI (bin/strix-mcp-proxy.mjs) over stdio, then reads what the
// upstream handler actually executed and verifies the signed records independently.
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, cpSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { verifyReceiptChain } from "@strixgov/verifier";
import { verifyExecutionOutcomeRecord } from "@strixgov/verifier/execution-outcome";

const here = path.dirname(fileURLToPath(import.meta.url));
const lock = JSON.parse(readFileSync(path.join(here, "package-lock.json"), "utf8"));
const ver = (n) => ({ version: lock.packages[`node_modules/${n}`]?.version, integrity: lock.packages[`node_modules/${n}`]?.integrity });
const proxyBin = path.join(here, "node_modules/@strixgov/mcp-proxy/bin/strix-mcp-proxy.mjs");
const fixture = path.join(here, "fixture-upstream.mjs");

const work = mkdtempSync(path.join(tmpdir(), "strix-boundary-"));
const handlerLog = path.join(work, "handler.log.jsonl");
const sandboxFile = path.join(work, "sandbox-notes.txt");
const store = path.join(work, "store");
const keys = path.join(work, "keys");
const approvals = path.join(work, "approvals");
for (const d of [store, keys, approvals]) mkdirSync(d, { recursive: true });
writeFileSync(handlerLog, "");
writeFileSync(sandboxFile, "");

const cfg = {
  serverId: "boundary",
  upstream: {
    command: process.execPath,
    args: [fixture],
    env: { ...process.env, FIXTURE_HANDLER_LOG: handlerLog, FIXTURE_SANDBOX_FILE: sandboxFile },
  },
  capabilities: [
    { id: "mcp.boundary.read_note", name: "read_note", risk: "LOW", mode: "READ", description: "read" },
    { id: "mcp.boundary.write_note", name: "write_note", risk: "MEDIUM", mode: "WRITE", description: "write" },
    { id: "mcp.boundary.delete_note", name: "delete_note", risk: "CRITICAL", mode: "WRITE", description: "delete" },
  ],
  policy: {
    rules: {
      "mcp.boundary.read_note": "ALLOW",
      "mcp.boundary.write_note": "APPROVAL_REQUIRED",
      "mcp.boundary.delete_note": "DENY",
    },
    default: "DENY",
  },
  approval: { enabled: true, type: "file", requestDir: approvals, timeoutMs: 3000 },
  storagePath: store,
  keyPath: keys,
};
const cfgPath = path.join(work, "proxy-config.json");
writeFileSync(cfgPath, JSON.stringify(cfg, null, 2));

const handlerRuns = () =>
  readFileSync(handlerLog, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
const text = (r) => (r.content ?? []).map((c) => c.text).join("");

async function withClient(command, args, env, fn) {
  const client = new Client({ name: "boundary-harness", version: "0.0.1" });
  const transport = new StdioClientTransport({ command, args, env: { ...process.env, ...env }, stderr: "pipe" });
  transport.stderr?.on("data", () => {});
  await client.connect(transport);
  try {
    return await fn(client);
  } finally {
    await client.close();
  }
}

// Out-of-band approver: only runs during step D.
function startApprover() {
  const seen = new Set();
  let stopped = false;
  const timer = setInterval(() => {
    if (stopped) return;
    for (const f of existsSync(approvals) ? readdirSync(approvals) : []) {
      if (!f.endsWith(".request.json") || seen.has(f)) continue;
      seen.add(f);
      const id = f.replace(/\.request\.json$/, "");
      writeFileSync(
        path.join(approvals, `${id}.response.json`),
        JSON.stringify({ approved: true, approvedBy: "validation-harness", reason: "synthetic test approval" }),
      );
    }
  }, 100);
  return () => {
    stopped = true;
    clearInterval(timer);
  };
}

const steps = [];
async function step(id, label, fn) {
  const before = handlerRuns().length;
  let outcome;
  const t0 = Date.now();
  try {
    outcome = await fn();
  } catch (e) {
    outcome = { thrown: String(e?.message ?? e) };
  }
  outcome.elapsedMs = Date.now() - t0;
  steps.push({ id, label, ...outcome, handlerInvocationsDuringStep: handlerRuns().slice(before).map((r) => r.handler) });
}

await withClient(process.execPath, [proxyBin, "--config", cfgPath], {}, async (c) => {
  const listed = (await c.listTools()).tools.map((t) => t.name);
  steps.push({ id: "0", label: "tools/list through proxy", tools: listed });
  await step("A", "routed read_note (policy ALLOW)", async () => {
    const r = await c.callTool({ name: "read_note", arguments: { note: "A" } });
    return { isError: !!r.isError, response: text(r) };
  });
  await step("B", "routed delete_note (policy DENY)", async () => {
    const r = await c.callTool({ name: "delete_note", arguments: { note: "B" } });
    return { isError: !!r.isError, response: text(r) };
  });
  await step("C", "routed write_note, nobody approves (timeoutMs=3000)", async () => {
    const r = await c.callTool({ name: "write_note", arguments: { note: "C-timeout" } });
    return { isError: !!r.isError, response: text(r) };
  });
  const stopApprover = startApprover();
  await step("D", "routed write_note, out-of-band approver approves", async () => {
    const r = await c.callTool({ name: "write_note", arguments: { note: "D-approved" } });
    return { isError: !!r.isError, response: text(r) };
  });
  stopApprover();
});

// Outside the proxy: same fixture, same tool, no Strix in the path.
await withClient(
  process.execPath,
  [fixture],
  { FIXTURE_HANDLER_LOG: handlerLog, FIXTURE_SANDBOX_FILE: sandboxFile },
  async (c) => {
    await step("E", "OUTSIDE PROXY: delete_note called on the upstream directly", async () => {
      const r = await c.callTool({ name: "delete_note", arguments: { note: "E-bypass" } });
      return { isError: !!r.isError, response: text(r) };
    });
  },
);

// ---- Records & independent verification --------------------------------
const jsonl = (f) =>
  existsSync(f) ? readFileSync(f, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : [];
const files = readdirSync(store);
const receipts = jsonl(path.join(store, "receipts.jsonl"));
const outcomes = jsonl(path.join(store, "execution-outcomes.jsonl"));
const pub = JSON.parse(readFileSync(path.join(keys, "public-jwk.json"), "utf8"));
const jwks = "keys" in pub ? pub : { keys: [pub] };
const chain = await verifyReceiptChain(receipts, { jwks });
const byId = new Map(receipts.map((r) => [r.receiptId, r]));
const outcomeChecks = outcomes.map((o) =>
  verifyExecutionOutcomeRecord(o, { jwks, authorizationReceipt: byId.get(o.authorizationReceiptId) ?? null }),
);

// Negative control: tamper with one receipt and require verification to fail.
const tampered = structuredClone(receipts);
if (tampered[0]) tampered[0].decision = tampered[0].decision === "ALLOW" ? "DENY" : "ALLOW";
const tamperChain = await verifyReceiptChain(tampered, { jwks });

const out = {
  generatedAt: new Date().toISOString(),
  node: process.version,
  packages: {
    "@strixgov/mcp-proxy": ver("@strixgov/mcp-proxy"),
    "@strixgov/verifier": ver("@strixgov/verifier"),
    "@strixgov/tool-gateway": ver("@strixgov/tool-gateway"),
    "@strixgov/mcp-adapter": ver("@strixgov/mcp-adapter"),
  },
  config: { ...cfg, upstream: { command: "node", args: ["fixture-upstream.mjs"], env: "(redacted)" } },
  steps,
  handlerLog: handlerRuns(),
  sandboxFileLines: readFileSync(sandboxFile, "utf8").split("\n").filter(Boolean),
  storeFiles: files,
  receiptCount: receipts.length,
  outcomeCount: outcomes.length,
  receiptsRaw: receipts,
  outcomesRaw: outcomes,
  verification: {
    chainValid: chain.chainValid,
    count: chain.count,
    receipts: chain.receipts.map((r) => ({ receiptId: r.receiptId, status: r.verificationStatus })),
    executionOutcomes: outcomeChecks.map((o) => ({ outcomeId: o.outcomeId, status: o.verificationStatus, error: o.error })),
    tamperNegativeControl: {
      chainValid: tamperChain.chainValid,
      firstReceiptStatus: tamperChain.receipts?.[0]?.verificationStatus,
    },
  },
};

// ---- Expectations (each is a hard check; the run exits non-zero if any fails) ----
const S = Object.fromEntries(steps.map((x) => [x.id, x]));
const rByCap = (cap) => receipts.filter((r) => r.capabilityId === `mcp.boundary.${cap}`);
const hasOutcome = (rid) => outcomes.some((o) => o.authorizationReceiptId === rid);
const [rRead] = rByCap("read_note");
const [rDel] = rByCap("delete_note");
const [rTimeout, rApproved] = rByCap("write_note");
const checks = [
  ["A routed allow: handler ran once, ALLOW receipt, SUCCEEDED outcome",
    S.A.handlerInvocationsDuringStep.join() === "read_note" && rRead?.decision === "ALLOW" && hasOutcome(rRead.receiptId)],
  ["B routed deny: handler did NOT run, DENY receipt, no execution outcome",
    S.B.handlerInvocationsDuringStep.length === 0 && rDel?.decision === "DENY" && !hasOutcome(rDel.receiptId)],
  ["C approval timeout: waited >= timeoutMs, handler did NOT run, DENY receipt with approvalReason TIMEOUT, no outcome",
    S.C.elapsedMs >= 2900 && S.C.handlerInvocationsDuringStep.length === 0 && rTimeout?.decision === "DENY" &&
    rTimeout?.approvalReason === "TIMEOUT" && !hasOutcome(rTimeout.receiptId)],
  ["D approved: handler ran once, ALLOW receipt approvedBy harness (USER_APPROVED), SUCCEEDED outcome, sandbox has only the approved note",
    S.D.handlerInvocationsDuringStep.join() === "write_note" && rApproved?.decision === "ALLOW" &&
    rApproved?.approvalReason === "USER_APPROVED" && hasOutcome(rApproved.receiptId) &&
    JSON.stringify(readFileSync(sandboxFile, "utf8").split(String.fromCharCode(10)).filter(Boolean)) === JSON.stringify(["D-approved"])],
  ["E outside proxy: handler RAN and no new receipt/outcome was produced (control is not in this path)",
    S.E.handlerInvocationsDuringStep.join() === "delete_note" && receipts.length === 4 && outcomes.length === 2],
  ["Independent verify: every receipt and outcome VERIFIED",
    chain.receipts.every((r) => r.verificationStatus === "VERIFIED") && outcomeChecks.every((o) => o.verificationStatus === "VERIFIED")],
  ["Negative control: a tampered receipt is reported TAMPERED",
    tamperChain.receipts?.[0]?.verificationStatus === "TAMPERED"],
];
out.checks = checks.map(([name, ok]) => ({ name, pass: !!ok }));
out.observations = {
  tamperedChainValidFlag: tamperChain.chainValid,
  note: "chainValid stayed true for a chain containing a TAMPERED receipt; gate on per-receipt verificationStatus, not chainValid alone.",
};
const evDir = path.join(here, "evidence");
mkdirSync(evDir, { recursive: true });
writeFileSync(path.join(evDir, "raw-run.json"), JSON.stringify(out, null, 2));
cpSync(handlerLog, path.join(evDir, "handler.log.jsonl"));
cpSync(path.join(keys, "public-jwk.json"), path.join(evDir, "public-jwk.json"));
for (const f of files) cpSync(path.join(store, f), path.join(evDir, "store-" + f));
console.log(
  JSON.stringify(
    {
      steps,
      handlerLog: out.handlerLog.map((h) => h.handler),
      storeFiles: files,
      receiptCount: receipts.length,
      outcomeCount: outcomes.length,
      verification: out.verification,
    },
    null,
    2,
  ),
);
console.log(out.checks.map((c) => (c.pass ? "PASS " : "FAIL ") + c.name).join(String.fromCharCode(10)));
rmSync(work, { recursive: true, force: true });
if (out.checks.some((c) => !c.pass)) process.exit(1);
