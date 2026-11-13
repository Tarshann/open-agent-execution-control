#!/usr/bin/env node
// End-to-end validation for Portable Proof Bundle v1.
//
//   1. Drives the REAL strix-mcp-proxy CLI (the published @strixgov/mcp-proxy)
//      over stdio in front of a disposable fixture tool server. The proxy makes
//      the policy decisions and signs the records; nothing here fabricates one.
//   2. Creates a DEMO issuer root (offline authority tool), authorizes the
//      proxy's key for tenant/environment "local", and exports each recorded
//      governed action with the exporter CLI, signing the manifest with the
//      proxy's own key and attaching the authorization.
//   3. Verifies every bundle with the offline verifier in a child process whose
//      network primitives are blocked, and cross-checks the native records with
//      the independently published @strixgov/verifier.
//   4. Runs negative controls, then DESTROYS both private keys (proxy and root).
//
// The relying party's trust store in this run holds ONLY the issuer root.
//
// The workload is synthetic (inert fixture tools); the governance runtime,
// records, signatures and key handling are the real ones.
//
// Usage: node run.mjs            verify only if examples already exist
//        node run.mjs --refresh  delete and regenerate ../../proof-bundle/examples
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, rmSync, cpSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { verifyReceiptChain } from "@strixgov/verifier";
import { verifyExecutionOutcomeRecord } from "@strixgov/verifier/execution-outcome";

const here = path.dirname(fileURLToPath(import.meta.url));
const pkgRoot = path.resolve(here, "../../proof-bundle");
const exporter = path.join(pkgRoot, "exporter/strix-proof-export.mjs");
const verifier = path.join(pkgRoot, "verifier/strix-proof-verify.mjs");
const authority = path.join(pkgRoot, "authority/strix-proof-authorize.mjs");
const examples = path.join(pkgRoot, "examples");
const lock = JSON.parse(readFileSync(path.join(here, "package-lock.json"), "utf8"));
const ver = (n) => ({ version: lock.packages[`node_modules/${n}`]?.version, integrity: lock.packages[`node_modules/${n}`]?.integrity });
const proxyBin = path.join(here, "node_modules/@strixgov/mcp-proxy/bin/strix-mcp-proxy.mjs");
const fixture = path.join(here, "fixture-upstream.mjs");
const refresh = process.argv.includes("--refresh");

if (existsSync(examples) && !refresh) {
  console.error("examples already exist. Re-run with --refresh to regenerate them from a fresh proxy run (new key, new ids).");
  process.exit(2);
}

const work = mkdtempSync(path.join(tmpdir(), "strix-ppb-"));
const handlerLog = path.join(work, "handler.log.jsonl");
const sandboxFile = path.join(work, "sandbox-notes.txt");
const store = path.join(work, "store");
const keys = path.join(work, "keys");
const approvals = path.join(work, "approvals");
const netLog = path.join(work, "network-attempts.log");
for (const d of [store, keys, approvals]) mkdirSync(d, { recursive: true });
for (const f of [handlerLog, sandboxFile, netLog]) writeFileSync(f, "");

const policy = {
  rules: {
    "mcp.demo.read_note": "ALLOW",
    "mcp.demo.archive_note": "ALLOW",
    "mcp.demo.write_note": "APPROVAL_REQUIRED",
    "mcp.demo.delete_note": "DENY",
  },
  default: "DENY",
};
const cfg = {
  serverId: "demo",
  upstream: { command: process.execPath, args: [fixture], env: { ...process.env, FIXTURE_HANDLER_LOG: handlerLog, FIXTURE_SANDBOX_FILE: sandboxFile } },
  capabilities: [
    { id: "mcp.demo.read_note", name: "read_note", risk: "LOW", mode: "READ", description: "read" },
    { id: "mcp.demo.archive_note", name: "archive_note", risk: "LOW", mode: "WRITE", description: "archive" },
    { id: "mcp.demo.write_note", name: "write_note", risk: "MEDIUM", mode: "WRITE", description: "write" },
    { id: "mcp.demo.delete_note", name: "delete_note", risk: "CRITICAL", mode: "WRITE", description: "delete" },
  ],
  policy,
  approval: { enabled: true, type: "file", requestDir: approvals, timeoutMs: 3000 },
  storagePath: store,
  keyPath: keys,
};
const cfgPath = path.join(work, "proxy-config.json");
writeFileSync(cfgPath, JSON.stringify(cfg, null, 2));

const handlerRuns = () => readFileSync(handlerLog, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
const text = (r) => (r.content ?? []).map((c) => c.text).join("");

async function withClient(command, args, env, fn) {
  const client = new Client({ name: "ppb-harness", version: "0.0.1" });
  const transport = new StdioClientTransport({ command, args, env: { ...process.env, ...env }, stderr: "pipe" });
  transport.stderr?.on("data", () => {});
  await client.connect(transport);
  try {
    return await fn(client);
  } finally {
    await client.close();
  }
}
function startApprover() {
  const seen = new Set();
  const timer = setInterval(() => {
    for (const f of existsSync(approvals) ? readdirSync(approvals) : []) {
      if (!f.endsWith(".request.json") || seen.has(f)) continue;
      seen.add(f);
      writeFileSync(path.join(approvals, f.replace(/\.request\.json$/, ".response.json")), JSON.stringify({ approved: true, approvedBy: "validation-harness", reason: "synthetic test approval" }));
    }
  }, 100);
  return () => clearInterval(timer);
}

const steps = [];
async function step(id, label, args, fn) {
  const before = handlerRuns().length;
  let outcome;
  try {
    outcome = await fn();
  } catch (e) {
    outcome = { thrown: String(e?.message ?? e) };
  }
  steps.push({ id, label, args, ...outcome, handlerInvocationsDuringStep: handlerRuns().slice(before).map((r) => r.handler) });
}
const call = (c, name, args) => async () => {
  const r = await c.callTool({ name, arguments: args });
  return { isError: !!r.isError, response: text(r) };
};

// ---- 1. real governed actions through the real proxy -------------------------
await withClient(process.execPath, [proxyBin, "--config", cfgPath], {}, async (c) => {
  await step("A", "read_note, policy ALLOW", { note: "A" }, call(c, "read_note", { note: "A" }));
  await step("B", "delete_note, policy DENY", { note: "B" }, call(c, "delete_note", { note: "B" }));
  await step("C", "write_note, approval required, nobody approves", { note: "C-timeout" }, call(c, "write_note", { note: "C-timeout" }));
  const stop = startApprover();
  await step("D", "write_note, approval required, approved out of band", { note: "D-approved" }, call(c, "write_note", { note: "D-approved" }));
  stop();
  await step("F", "archive_note, policy ALLOW, tool reports an error", { note: "F" }, call(c, "archive_note", { note: "F" }));
});
// Outside the proxy: the action the proxy DENIED in step B, performed directly.
await withClient(process.execPath, [fixture], { FIXTURE_HANDLER_LOG: handlerLog, FIXTURE_SANDBOX_FILE: sandboxFile }, async (c) => {
  await step("E", "OUTSIDE PROXY: delete_note called on the upstream directly", { note: "B" }, call(c, "delete_note", { note: "B" }));
});

const jsonl = (f) => (existsSync(f) ? readFileSync(f, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)) : []);
const receipts = jsonl(path.join(store, "receipts.jsonl"));
const outcomes = jsonl(path.join(store, "execution-outcomes.jsonl"));
const pubJwk = JSON.parse(readFileSync(path.join(keys, "public-jwk.json"), "utf8"));
const byStep = { A: receipts[0], B: receipts[1], C: receipts[2], D: receipts[3], F: receipts[4] };

// ---- 2. export ---------------------------------------------------------------
const node = (args, opts = {}) => spawnSync(process.execPath, args, { encoding: "utf8", ...opts });
if (refresh) rmSync(examples, { recursive: true, force: true });
mkdirSync(path.join(examples, "reports"), { recursive: true });
const policyFile = path.join(work, "policy.json");
writeFileSync(policyFile, JSON.stringify(policy));
// Issuer authority (offline ceremony, DEMO root): the relying party will trust only this root.
const rootDir = path.join(work, "issuer-root");
const day = 86400000;
node([authority, "init-root", "--root-dir", rootDir, "--key-id", "strix-demo-issuer-root"]);
const trustStorePath = path.join(examples, "trust-store.demo.json");
writeFileSync(trustStorePath, node([authority, "trust-store", "--root-dir", rootDir, "--owner", "DEMO issuer root generated by validation/proof-bundle/run.mjs (private key destroyed after the run) - not a Strix key"]).stdout);
const authFile = path.join(work, "authorization.json");
const issued = node([authority, "issue", "--root-dir", rootDir, "--issuer", "DEMO issuer (validation harness)", "--gateway-id", "mcp-proxy-demo", "--gateway-jwk", path.join(keys, "public-jwk.json"), "--tenant", "local", "--environment", "local",
  "--not-before", new Date(Date.now() - day).toISOString(), "--not-after", new Date(Date.now() + 365 * day).toISOString(), "--authorization-id", "ia_demo-mcp-proxy"]);
writeFileSync(authFile, issued.stdout);
// The older model, kept as a second example: the gateway key listed directly.
const directStorePath = path.join(examples, "trust-store.demo-direct.json");
writeFileSync(directStorePath, node([exporter, "trust-store", "--key-dir", keys, "--owner", "Strix MCP proxy - DEMO key generated by validation/proof-bundle/run.mjs (private key destroyed after the run)", "--tenant", "local"]).stdout);

const plan = [
  { step: "A", dir: "01-allow-succeeded", disclose: true, carrier: true },
  { step: "B", dir: "02-deny", disclose: true },
  { step: "C", dir: "03-approval-timeout-deny", disclose: false },
  { step: "D", dir: "04-approved-succeeded", disclose: true },
  { step: "F", dir: "05-allow-tool-failed", disclose: true },
];
const exportsDone = [];
for (const p of plan) {
  const r = byStep[p.step];
  const args = [exporter, "export", "--store", store, "--key-dir", keys, "--receipt-id", r.receiptId, "--tenant", "local", "--out", path.join(examples, p.dir), "--issuer-authorization", authFile];
  if (p.disclose) {
    const inv = path.join(work, `inv-${p.step}.json`);
    writeFileSync(inv, JSON.stringify({ args: steps.find((s) => s.id === p.step).args }));
    args.push("--disclose-invocation", inv, "--disclose-policy", policyFile);
  }
  if (p.carrier) args.push("--carrier", path.join(examples, `${p.dir}.ppb.json`));
  const x = node(args);
  exportsDone.push({ ...p, receiptId: r.receiptId, exit: x.status, stderr: x.stderr.trim(), summary: x.status === 0 ? JSON.parse(x.stdout) : null });
}

// ---- 3. offline verification, network blocked ---------------------------------
const blocked = (args) => node(["--import", "file://" + path.join(here, "block-network.mjs").replace(/\\/g, "/"), verifier, ...args], { env: { ...process.env, NETWORK_ATTEMPT_LOG: netLog } });
const verifications = [];
for (const p of plan) {
  const dir = path.join(examples, p.dir);
  const j = blocked(["verify", dir, "--trust-store", trustStorePath, "--json"]);
  const t = blocked(["verify", dir, "--trust-store", trustStorePath]);
  writeFileSync(path.join(examples, "reports", `${p.dir}.report.json`), j.stdout);
  writeFileSync(path.join(examples, "reports", `${p.dir}.report.txt`), t.stdout);
  const rep = JSON.parse(j.stdout);
  verifications.push({ bundle: p.dir, exit: j.status, overall: rep.result.overall, claims: Object.fromEntries(rep.claims.map((c) => [c.id, `${c.classification}/${c.status}`])) });
}
const carrier = blocked(["verify", path.join(examples, "01-allow-succeeded.ppb.json"), "--trust-store", trustStorePath, "--json"]);
const directResults = plan.map((p) => blocked(["verify", path.join(examples, p.dir), "--trust-store", directStorePath, "--json"]).status);
const authorityOf = JSON.parse(blocked(["verify", path.join(examples, "01-allow-succeeded"), "--trust-store", trustStorePath, "--json"]).stdout).result.signerTrust.records.map((r) => `${r.authority}:${r.issuerRootKeyId}:${r.authorizationId}`);
// Revocation, and a bundle that carries no authorization.
const revClean = path.join(work, "revocations-clean.json");
writeFileSync(revClean, node([authority, "revoke", "--root-dir", rootDir, "--issuer", "DEMO issuer (validation harness)", "--authorization-id", "ia_unrelated"]).stdout);
const revHit = path.join(work, "revocations-hit.json");
writeFileSync(revHit, node([authority, "revoke", "--root-dir", rootDir, "--issuer", "DEMO issuer (validation harness)", "--authorization-id", "ia_demo-mcp-proxy", "--previous", revClean]).stdout);
const noAuthDir = path.join(work, "no-authorization");
node([exporter, "export", "--store", store, "--key-dir", keys, "--receipt-id", byStep.A.receiptId, "--tenant", "local", "--out", noAuthDir, "--audit-log", "none"]);

// Cross-check the native records inside the bundles with the published verifier.
const jwks = { keys: [pubJwk] };
const bundled = plan.map((p) => JSON.parse(readFileSync(path.join(examples, p.dir, "evidence/authorization-receipt.json"), "utf8")));
const chain = await verifyReceiptChain(bundled, { jwks });
const bundledOutcomes = plan
  .filter((p) => existsSync(path.join(examples, p.dir, "evidence/execution-outcome.json")))
  .map((p) => ({ o: JSON.parse(readFileSync(path.join(examples, p.dir, "evidence/execution-outcome.json"), "utf8")), r: JSON.parse(readFileSync(path.join(examples, p.dir, "evidence/authorization-receipt.json"), "utf8")) }));
const outcomeChecks = bundledOutcomes.map(({ o, r }) => verifyExecutionOutcomeRecord(o, { jwks, authorizationReceipt: r }));

// ---- 4. negative controls -----------------------------------------------------
const neg = path.join(work, "neg");
const copy = (name) => {
  const d = path.join(neg, name);
  cpSync(path.join(examples, "01-allow-succeeded"), d, { recursive: true });
  return d;
};
const exitOf = (dir, extra = ["--trust-store", trustStorePath]) => {
  const r = blocked(["verify", dir, ...extra, "--json"]);
  let rep = null;
  try {
    rep = JSON.parse(r.stdout);
  } catch {}
  return { exit: r.status, overall: rep?.result?.overall, codes: (rep?.failures ?? []).map((f) => f.code), claims: rep?.result?.claims?.status };
};
const flipByte = (f) => {
  const b = readFileSync(f);
  b[Math.floor(b.length / 2)] ^= 0x01;
  writeFileSync(f, b);
};
const d1 = copy("one-byte");
flipByte(path.join(d1, "evidence/execution-outcome.json"));
const d2 = copy("manifest-field");
writeFileSync(path.join(d2, "manifest.json"), readFileSync(path.join(d2, "manifest.json"), "utf8").replace('"tenantId": "local"', '"tenantId": "other"'));
const otherKey = path.join(work, "other-trust.json");
writeFileSync(otherKey, JSON.stringify({ keys: [{ kty: "OKP", crv: "Ed25519", kid: pubJwk.kid, x: Buffer.alloc(32, 7).toString("base64url") }] }));
const unknownKey = path.join(work, "unknown-trust.json");
writeFileSync(unknownKey, JSON.stringify({ keys: [{ kty: "OKP", crv: "Ed25519", kid: "someone-else", x: Buffer.alloc(32, 7).toString("base64url") }] }));
const negatives = {
  oneByteFlippedInEvidence: exitOf(d1),
  manifestFieldEdited: exitOf(d2),
  noTrustStore: exitOf(path.join(examples, "01-allow-succeeded"), []),
  trustStoreSameKidDifferentKey: exitOf(path.join(examples, "01-allow-succeeded"), ["--trust-store", otherKey]),
  trustStoreWithoutSignerKey: exitOf(path.join(examples, "01-allow-succeeded"), ["--trust-store", unknownKey]),
  wrongTenantExpected: exitOf(path.join(examples, "01-allow-succeeded"), ["--trust-store", trustStorePath, "--expect-tenant", "acme"]),
  authorizationRevoked: exitOf(path.join(examples, "01-allow-succeeded"), ["--trust-store", trustStorePath, "--revocations", revHit]),
  revocationCheckedClean: exitOf(path.join(examples, "01-allow-succeeded"), ["--trust-store", trustStorePath, "--revocations", revClean]),
  noAuthorizationRootOnlyStore: exitOf(noAuthDir),
  noAuthorizationButSuppliedOutOfBand: exitOf(noAuthDir, ["--trust-store", trustStorePath, "--issuer-authorizations", authFile]),
};
const crossTenant = node([exporter, "export", "--store", store, "--key-dir", keys, "--receipt-id", byStep.A.receiptId, "--tenant", "acme", "--out", path.join(work, "x1"), "--audit-log", "none"]);
const overwrite = node([exporter, "export", "--store", store, "--key-dir", keys, "--receipt-id", byStep.A.receiptId, "--tenant", "local", "--out", path.join(examples, "01-allow-succeeded"), "--audit-log", "none"]);
const badInv = path.join(work, "bad-inv.json");
writeFileSync(badInv, JSON.stringify({ args: { note: "not what was asked" } }));
const wrongDisclosure = node([exporter, "export", "--store", store, "--key-dir", keys, "--receipt-id", byStep.A.receiptId, "--tenant", "local", "--out", path.join(work, "x2"), "--disclose-invocation", badInv, "--audit-log", "none"]);
// A stored receipt altered after issuance must not be laundered through a fresh manifest signature.
const store2 = path.join(work, "store-tampered");
cpSync(store, store2, { recursive: true });
writeFileSync(path.join(store2, "receipts.jsonl"), readFileSync(path.join(store2, "receipts.jsonl"), "utf8").replace('"decision":"DENY"', '"decision":"ALLOW"'));
const laundering = node([exporter, "export", "--store", store2, "--key-dir", keys, "--receipt-id", byStep.B.receiptId, "--tenant", "local", "--out", path.join(work, "x3"), "--audit-log", "none"]);
const exporterRefusals = {
  crossTenantExport: { exit: crossTenant.status, stderr: crossTenant.stderr.trim() },
  overwriteExistingBundle: { exit: overwrite.status, stderr: overwrite.stderr.trim() },
  disclosureThatDoesNotMatch: { exit: wrongDisclosure.status, stderr: wrongDisclosure.stderr.trim() },
  storedReceiptTamperedBeforeExport: { exit: laundering.status, stderr: laundering.stderr.trim() },
};
const auditLog = jsonl(path.join(store, "proof-bundle-exports.jsonl"));
const networkAttempts = readFileSync(netLog, "utf8").split("\n").filter(Boolean);

// ---- 5. checks ----------------------------------------------------------------
const S = Object.fromEntries(steps.map((x) => [x.id, x]));
const V = Object.fromEntries(verifications.map((v) => [v.bundle, v]));
const bodyOf = (f) => readFileSync(f, "utf8").split("\n").filter((l) => l && !l.startsWith("-----")).join("");
const keyBody = bodyOf(path.join(keys, "signing-key.pem"));
const rootBody = bodyOf(path.join(rootDir, "issuer-root-key.pem"));
const allExampleBytes = [];
const walk = (d) => {
  for (const n of readdirSync(d, { withFileTypes: true })) n.isDirectory() ? walk(path.join(d, n.name)) : allExampleBytes.push(readFileSync(path.join(d, n.name), "utf8"));
};
walk(examples);
const checks = [
  ["proxy produced 5 receipts and 3 execution outcomes", receipts.length === 5 && outcomes.length === 3],
  ["ground truth: handler ran for A, D, F; did NOT run for B, C", ["A", "D", "F"].every((k) => S[k].handlerInvocationsDuringStep.length === 1) && ["B", "C"].every((k) => S[k].handlerInvocationsDuringStep.length === 0)],
  ["every export succeeded", exportsDone.every((e) => e.exit === 0)],
  ["every bundle verifies PASSED (exit 0) offline with a trust store that holds ONLY the demo issuer root", verifications.every((v) => v.exit === 0 && v.overall === "PASSED") && JSON.parse(readFileSync(trustStorePath, "utf8")).keys.every((k) => k.role === "issuer-root")],
  ["signer standing comes from the root's authorization, for every signature", authorityOf.length === 3 && authorityOf.every((a) => a === "ISSUER_AUTHORIZATION:strix-demo-issuer-root:ia_demo-mcp-proxy")],
  ["every bundle also verifies with the gateway key listed directly (older model)", directResults.every((s) => s === 0)],
  ["revoked authorization => FAILED (SIGNER_REVOKED), no claims", negatives.authorizationRevoked.exit === 1 && negatives.authorizationRevoked.codes.includes("SIGNER_REVOKED") && negatives.authorizationRevoked.claims === "NOT_EVALUATED"],
  ["revocation list that does not name it => still PASSED", negatives.revocationCheckedClean.exit === 0],
  ["valid signatures but no authorization, root-only store => FAILED (issuer not established)", negatives.noAuthorizationRootOnlyStore.exit === 1 && negatives.noAuthorizationRootOnlyStore.codes.includes("SIGNER_UNTRUSTED")],
  ["same bundle with the authorization supplied out of band => PASSED", negatives.noAuthorizationButSuppliedOutOfBand.exit === 0],
  ["single-file carrier verifies PASSED", carrier.status === 0],
  ["A: decision ASSERTED, outcome ASSERTED (SUCCEEDED), enforcement NOT_ESTABLISHED", V["01-allow-succeeded"].claims["PPB-C10"] === "SOURCE_ASSERTION/ASSERTED" && V["01-allow-succeeded"].claims["PPB-C09"] === "NOT_ESTABLISHED/NOT_ESTABLISHED"],
  ["B: DENY bundle never claims prevention (enforcement NOT_ESTABLISHED, outcome NOT_APPLICABLE)", V["02-deny"].claims["PPB-C09"] === "NOT_ESTABLISHED/NOT_ESTABLISHED" && V["02-deny"].claims["PPB-C10"] === "NOT_ESTABLISHED/NOT_APPLICABLE"],
  ["E: the denied action DID run outside the proxy, and the DENY bundle still verifies - a decision record is not prevention", S.E.handlerInvocationsDuringStep.join() === "delete_note" && V["02-deny"].overall === "PASSED"],
  ["C: no disclosure => invocation binding NOT_ESTABLISHED", V["03-approval-timeout-deny"].claims["PPB-C06"] === "NOT_ESTABLISHED/NOT_ESTABLISHED"],
  ["D: approval reported as SOURCE_ASSERTION", V["04-approved-succeeded"].claims["PPB-C08"] === "SOURCE_ASSERTION/ASSERTED"],
  ["F: allowed action whose tool failed is reported FAILED, not success", JSON.parse(readFileSync(path.join(examples, "05-allow-tool-failed/evidence/execution-outcome.json"), "utf8")).executionStatus === "FAILED"],
  ["independent @strixgov/verifier agrees: every bundled receipt and outcome VERIFIED", chain.receipts.every((r) => r.verificationStatus === "VERIFIED") && outcomeChecks.every((o) => o.verificationStatus === "VERIFIED")],
  ["tamper: one flipped byte => FAILED (exit 1), claims NOT_EVALUATED", negatives.oneByteFlippedInEvidence.exit === 1 && negatives.oneByteFlippedInEvidence.codes.includes("DIGEST_MISMATCH") && negatives.oneByteFlippedInEvidence.claims === "NOT_EVALUATED"],
  ["tamper: edited manifest field => FAILED (exit 1)", negatives.manifestFieldEdited.exit === 1],
  ["no trust store => INCOMPLETE (exit 3), never PASSED", negatives.noTrustStore.exit === 3 && negatives.noTrustStore.overall === "INCOMPLETE"],
  ["trust store with a different key under the same kid => FAILED", negatives.trustStoreSameKidDifferentKey.exit === 1 && negatives.trustStoreSameKidDifferentKey.codes.includes("SIGNATURE_INVALID")],
  ["trust store without the signer's key => FAILED (untrusted)", negatives.trustStoreWithoutSignerKey.exit === 1 && negatives.trustStoreWithoutSignerKey.codes.includes("SIGNER_UNTRUSTED")],
  ["--expect-tenant mismatch => FAILED", negatives.wrongTenantExpected.exit === 1],
  ["exporter refuses a cross-tenant export", exporterRefusals.crossTenantExport.exit === 1 && exporterRefusals.crossTenantExport.stderr.includes("RECEIPT_NOT_FOUND")],
  ["exporter refuses to overwrite an existing bundle", exporterRefusals.overwriteExistingBundle.exit === 1 && exporterRefusals.overwriteExistingBundle.stderr.includes("OUTPUT_EXISTS")],
  ["exporter refuses a disclosure that does not match the signed hash", exporterRefusals.disclosureThatDoesNotMatch.exit === 1 && exporterRefusals.disclosureThatDoesNotMatch.stderr.includes("DISCLOSURE_MISMATCH")],
  ["exporter refuses to re-sign a stored receipt that fails its own signature", exporterRefusals.storedReceiptTamperedBeforeExport.exit === 1 && exporterRefusals.storedReceiptTamperedBeforeExport.stderr.includes("REFUSED_UNVERIFIED_RECORD")],
  ["verifier made zero network attempts", networkAttempts.length === 0],
  ["no private key material (gateway or issuer root) in any exported file", !allExampleBytes.some((t) => t.includes(keyBody) || t.includes(rootBody) || t.includes("PRIVATE KEY"))],
  ["export audit log has one EXPORTED line per bundle and no evidence content", auditLog.filter((l) => l.result === "EXPORTED").length === plan.length && !JSON.stringify(auditLog).includes("D-approved")],
];

const out = {
  generatedAt: new Date().toISOString(),
  node: process.version,
  platform: process.platform,
  nature: "Real @strixgov/mcp-proxy runtime, real signatures, ephemeral demo gateway key authorized by an ephemeral DEMO issuer root; synthetic inert workload. Not a production or customer event, and not a Strix-issued authorization.",
  issuerRoot: JSON.parse(readFileSync(trustStorePath, "utf8")).keys[0],
  authorization: JSON.parse(Buffer.from(JSON.parse(issued.stdout).payload, "base64").toString("utf8")),
  packages: Object.fromEntries(["@strixgov/mcp-proxy", "@strixgov/tool-gateway", "@strixgov/mcp-adapter", "@strixgov/verifier"].map((n) => [n, ver(n)])),
  policy,
  steps,
  handlerLog: handlerRuns(),
  receipts: receipts.map((r) => ({ receiptId: r.receiptId, action: r.action, decision: r.decision, approvalReason: r.approvalReason ?? null })),
  outcomes: outcomes.map((o) => ({ outcomeId: o.outcomeId, authorizationReceiptId: o.authorizationReceiptId, executionStatus: o.executionStatus, errorCode: o.errorCode })),
  signerPublicJwk: pubJwk,
  exports: exportsDone,
  verifications,
  independentVerifier: { receipts: chain.receipts.map((r) => ({ receiptId: r.receiptId, status: r.verificationStatus })), outcomes: outcomeChecks.map((o) => ({ outcomeId: o.outcomeId, status: o.verificationStatus })) },
  negatives,
  exporterRefusals,
  exportAuditLog: auditLog,
  networkAttemptsByVerifier: networkAttempts,
  privateKeyDestroyed: true,
  checks: checks.map(([name, ok]) => ({ name, pass: !!ok })),
};
mkdirSync(path.join(here, "evidence"), { recursive: true });
writeFileSync(path.join(here, "evidence", "results.json"), JSON.stringify(out, null, 2) + "\n");
writeFileSync(path.join(examples, "PROVENANCE.json"), JSON.stringify({ generatedAt: out.generatedAt, nature: out.nature, generatedBy: "validation/proof-bundle/run.mjs", packages: out.packages, signerPublicJwk: pubJwk, issuerRootKeyId: "strix-demo-issuer-root", authorizationId: "ia_demo-mcp-proxy", privateKeyDestroyed: true, issuerRootKeyDestroyed: true, bundles: exportsDone.map((e) => ({ dir: e.dir, receiptId: e.receiptId, bundleId: e.summary?.bundleId })) }, null, 2) + "\n");
rmSync(work, { recursive: true, force: true }); // destroys the gateway key and the issuer root key
console.log(out.checks.map((c) => (c.pass ? "PASS " : "FAIL ") + c.name).join("\n"));
if (out.checks.some((c) => !c.pass)) process.exit(1);
