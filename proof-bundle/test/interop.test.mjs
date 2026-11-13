// Interoperability with the independently published Strix packages. Needs
// `npm ci` in validation/proof-bundle; SKIPPED (visibly) when they are absent,
// so the rest of the suite stays dependency-free.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { canonicalJSON, outcomeHashOf, receiptSignedBytes } from "../verifier/strix-proof-verify.mjs";
import { POLICY, invocationOf, issueOutcome, issueReceipt, policyVersionOf, testKey } from "./helpers/synth.mjs";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const nm = path.resolve(root, "..", "validation", "proof-bundle", "node_modules", "@strixgov");
const have = fs.existsSync(path.join(nm, "verifier")) && fs.existsSync(path.join(nm, "tool-gateway"));
const skip = have ? false : "@strixgov packages not installed (run npm ci in validation/proof-bundle)";
const load = (p) => import(pathToFileURL(path.join(nm, p)).href);

test("published @strixgov/verifier accepts records from the synthetic test issuer", { skip }, async () => {
  const { verifyReceiptChain } = await load("verifier/src/index.mjs");
  const { verifyExecutionOutcomeRecord } = await load("verifier/src/execution-outcome.mjs");
  const K = testKey("interop", "interop-key");
  const r = issueReceipt(K, { capabilityId: "vec.read", action: "tool:read", args: { a: 1 }, receiptId: "rcpt_interop01", decision: "ALLOW" });
  const o = issueOutcome(K, r);
  const jwks = { keys: [K.jwk] };
  assert.equal((await verifyReceiptChain([r], { jwks })).receipts[0].verificationStatus, "VERIFIED");
  assert.equal(verifyExecutionOutcomeRecord(o, { jwks, authorizationReceipt: r }).verificationStatus, "VERIFIED");
});

test("this package's canonical forms equal the gateway's own", { skip }, async () => {
  const gw = await load("tool-gateway/src/index.mjs");
  const canon = await load("tool-gateway/src/canonical.mjs");
  const outcomes = await load("tool-gateway/src/outcomes.mjs");
  const K = testKey("interop", "interop-key");
  const inv = { capabilityId: "vec.read", action: "tool:read", args: { "😀": [1.5, 1e21], "￿": "x", b: { z: 1, a: null } }, actorId: "u", actorRole: "r" };
  const r = issueReceipt(K, { ...inv, receiptId: "rcpt_interop02", decision: "ALLOW" });
  assert.equal(canonicalJSON(inv), canon.canonicalJSON(inv));
  assert.equal(r.invocationHash, gw.computeInvocationHash(inv));
  assert.equal(policyVersionOf(POLICY), gw.computePolicyVersion(POLICY));
  assert.equal(receiptSignedBytes(r).toString("utf8"), canon.canonicalReceiptPayload(r));
  const o = issueOutcome(K, r, { result: { ok: true } });
  assert.equal(outcomeHashOf(o), outcomes.computeExecutionOutcomeHash(o));
  assert.deepEqual(invocationOf(inv), inv);
});

test("fields the gateway's receipt signature does not cover (documented in docs/BASELINE.md)", { skip }, async () => {
  const { verifyReceiptChain } = await load("verifier/src/index.mjs");
  const ex = path.join(root, "examples", "04-approved-succeeded");
  const receipt = JSON.parse(fs.readFileSync(path.join(ex, "evidence", "authorization-receipt.json"), "utf8"));
  const jwks = JSON.parse(fs.readFileSync(path.join(ex, "trust", "embedded-signer-keys.json"), "utf8"));
  const forged = { ...receipt, approvedBy: "someone-else", approvalReason: "FORGED", tool: "x", actorId: "mallory" };
  // The native verifier still says VERIFIED: these fields are outside the signed payload.
  assert.equal((await verifyReceiptChain([forged], { jwks })).receipts[0].verificationStatus, "VERIFIED");
  assert.equal((await verifyReceiptChain([{ ...receipt, decision: "DENY" }], { jwks })).receipts[0].verificationStatus, "TAMPERED");
});
