// Exporter behaviour against a synthetic gateway store on disk (same file
// layout the real gateway writes: receipts.jsonl, execution-outcomes.jsonl,
// keys/signing-key.pem + public-jwk.json).
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ExportError, buildBundle, main, toCarrier, writeBundleDir } from "../exporter/strix-proof-export.mjs";
import { loadBundle, loadCarrier, parseTrustStore, verifyBundle, PATHS } from "../verifier/strix-proof-verify.mjs";
import { POLICY, issueOutcome, issueReceipt, testKey } from "./helpers/synth.mjs";

const K = testKey("exporter-test", "exp-key");
const K_OLD = testKey("exporter-test-old", "exp-key-old");
const NOW = "2026-02-01T00:00:00.000Z";

function fixture({ withKey = true } = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ppb-exp-"));
  const store = path.join(dir, "store");
  const keys = path.join(dir, "keys");
  fs.mkdirSync(store);
  fs.mkdirSync(keys);
  const rs = {
    allow: issueReceipt(K, { capabilityId: "vec.read", action: "tool:read", args: { id: 1 }, receiptId: "rcpt_a1", decision: "ALLOW" }),
    deny: issueReceipt(K, { capabilityId: "vec.delete", action: "tool:delete", args: { id: 1 }, receiptId: "rcpt_d1", decision: "DENY", risk: "CRITICAL", mode: "WRITE" }),
    pending: issueReceipt(K, { capabilityId: "vec.read", action: "tool:read", args: { id: 2 }, receiptId: "rcpt_p1", decision: "ALLOW" }),
    other: issueReceipt(K, { capabilityId: "vec.read", action: "tool:read", args: { id: 3 }, receiptId: "rcpt_t2", decision: "ALLOW", tenantId: "globex" }),
    old: issueReceipt(K_OLD, { capabilityId: "vec.read", action: "tool:read", args: { id: 4 }, receiptId: "rcpt_o1", decision: "ALLOW" }),
  };
  const outs = [issueOutcome(K, rs.allow), issueOutcome(K, rs.other)];
  fs.writeFileSync(path.join(store, "receipts.jsonl"), Object.values(rs).map((r) => JSON.stringify(r)).join("\n") + "\n");
  fs.writeFileSync(path.join(store, "execution-outcomes.jsonl"), outs.map((o) => JSON.stringify(o)).join("\n") + "\n");
  if (withKey) {
    fs.writeFileSync(path.join(keys, "signing-key.pem"), K.privateKey.export({ format: "pem", type: "pkcs8" }));
    fs.writeFileSync(path.join(keys, "public-jwk.json"), JSON.stringify(K.jwk));
  }
  return { dir, store, keys, rs, outs, base: { storeDir: store, keyDir: keys, tenantId: "acme", now: NOW } };
}
const refusal = (fn) => {
  try {
    fn();
  } catch (e) {
    assert.ok(e instanceof ExportError, String(e));
    return e.code;
  }
  return "NO_REFUSAL";
};
const trust = parseTrustStore({ keys: [K.jwk] });
const cli = (...args) => {
  let out = "";
  let err = "";
  const exit = main(args, { out: (s) => (out += s), err: (s) => (err += s) });
  return { exit, out, err };
};

test("export: allowed action with outcome -> bundle that verifies, with truthful evidence states", () => {
  const f = fixture();
  const { files, manifest } = buildBundle({ ...f.base, receiptId: "rcpt_a1" });
  assert.deepEqual(manifest.evidence, { authorizationDecision: "PRESENT", executionOutcome: "PRESENT", enforcementObservation: "NOT_CAPTURED", invocationDisclosure: "NOT_DISCLOSED", policyDisclosure: "NOT_DISCLOSED" });
  assert.equal(verifyBundle(files, { trustStore: trust }).result.overall, "PASSED");
  assert.equal(verifyBundle(loadCarrier(toCarrier(files)), { trustStore: trust }).result.overall, "PASSED");
});

test("export: missing evidence is stated, never filled in", () => {
  const f = fixture();
  assert.equal(buildBundle({ ...f.base, receiptId: "rcpt_p1" }).manifest.evidence.executionOutcome, "ABSENT");
  const deny = buildBundle({ ...f.base, receiptId: "rcpt_d1" });
  assert.equal(deny.manifest.evidence.executionOutcome, "NOT_APPLICABLE");
  assert.ok(!deny.files.has(PATHS.outcome));
});

test("export: bundle identity is a function of the evidence snapshot", () => {
  const f = fixture();
  const a = buildBundle({ ...f.base, receiptId: "rcpt_p1" });
  const b = buildBundle({ ...f.base, receiptId: "rcpt_p1", now: "2026-03-01T00:00:00.000Z" });
  assert.equal(a.manifest.bundleId, b.manifest.bundleId, "same evidence, later export -> same bundleId");
  // The outcome arrives after the first export: a new, distinct bundle; the old one keeps its meaning.
  fs.appendFileSync(path.join(f.store, "execution-outcomes.jsonl"), JSON.stringify(issueOutcome(K, f.rs.pending)) + "\n");
  const c = buildBundle({ ...f.base, receiptId: "rcpt_p1" });
  assert.notEqual(c.manifest.bundleId, a.manifest.bundleId);
  assert.equal(c.manifest.evidence.executionOutcome, "PRESENT");
  assert.equal(verifyBundle(a.files, { trustStore: trust }).result.overall, "PASSED");
});

test("export: tenant boundary", () => {
  const f = fixture();
  // Another tenant's receipt is indistinguishable from one that does not exist.
  assert.equal(refusal(() => buildBundle({ ...f.base, receiptId: "rcpt_t2" })), "RECEIPT_NOT_FOUND");
  assert.equal(refusal(() => buildBundle({ ...f.base, receiptId: "rcpt_a1", tenantId: "globex" })), "RECEIPT_NOT_FOUND");
  assert.equal(refusal(() => buildBundle({ ...f.base, receiptId: "rcpt_a1", tenantId: undefined })), "USAGE");
  assert.equal(refusal(() => buildBundle({ ...f.base, receiptId: "rcpt_a1", environment: "staging" })), "RECEIPT_NOT_FOUND");
  const listed = JSON.parse(cli("list", "--store", f.store, "--tenant", "acme").out);
  assert.ok(!listed.some((r) => r.receiptId === "rcpt_t2"));
  // The refusal for another tenant's receipt reveals nothing about it.
  const r = cli("export", "--store", f.store, "--key-dir", f.keys, "--receipt-id", "rcpt_t2", "--tenant", "acme", "--out", path.join(f.dir, "o"), "--audit-log", "none");
  assert.equal(r.exit, 1);
  assert.doesNotMatch(r.err, /globex/);
});

test("export: refuses unknown, ambiguous, contradictory or unverifiable records", () => {
  const f = fixture();
  assert.equal(refusal(() => buildBundle({ ...f.base, receiptId: "rcpt_missing" })), "RECEIPT_NOT_FOUND");
  assert.equal(refusal(() => buildBundle({ ...f.base, receiptId: "rcpt_o1" })), "REFUSED_UNVERIFIED_RECORD");
  fs.appendFileSync(path.join(f.store, "receipts.jsonl"), JSON.stringify(f.rs.allow) + "\n");
  assert.equal(refusal(() => buildBundle({ ...f.base, receiptId: "rcpt_a1" })), "AMBIGUOUS_RECEIPT");

  const g = fixture();
  fs.appendFileSync(path.join(g.store, "execution-outcomes.jsonl"), JSON.stringify(issueOutcome(K, g.rs.allow, { outcomeId: "out_second" })) + "\n");
  assert.equal(refusal(() => buildBundle({ ...g.base, receiptId: "rcpt_a1" })), "AMBIGUOUS_OUTCOME");

  const h = fixture();
  fs.appendFileSync(path.join(h.store, "execution-outcomes.jsonl"), JSON.stringify(issueOutcome(K, h.rs.deny)) + "\n");
  assert.equal(refusal(() => buildBundle({ ...h.base, receiptId: "rcpt_d1" })), "CONTRADICTORY_RECORDS");

  const i = fixture();
  fs.writeFileSync(path.join(i.store, "receipts.jsonl"), fs.readFileSync(path.join(i.store, "receipts.jsonl"), "utf8").replace('"decision":"DENY"', '"decision":"ALLOW"'));
  assert.equal(refusal(() => buildBundle({ ...i.base, receiptId: "rcpt_d1" })), "REFUSED_UNVERIFIED_RECORD");

  const j = fixture();
  fs.writeFileSync(path.join(j.store, "execution-outcomes.jsonl"), fs.readFileSync(path.join(j.store, "execution-outcomes.jsonl"), "utf8").replace('"executionStatus":"SUCCEEDED"', '"executionStatus":"FAILED"'));
  assert.equal(refusal(() => buildBundle({ ...j.base, receiptId: "rcpt_a1" })), "REFUSED_UNVERIFIED_RECORD");
});

test("export: records from before a key rotation need the old public key, and verify with both trusted", () => {
  const f = fixture();
  const hist = path.join(f.dir, "old.json");
  fs.writeFileSync(hist, JSON.stringify({ keys: [K_OLD.jwk] }));
  const { files } = buildBundle({ ...f.base, receiptId: "rcpt_o1", historicalKeys: hist });
  assert.equal(verifyBundle(files, { trustStore: parseTrustStore({ keys: [K.jwk, K_OLD.jwk] }) }).result.overall, "PASSED");
  assert.equal(verifyBundle(files, { trustStore: trust }).result.overall, "FAILED");
});

test("export: signing unavailable is a refusal, and the exporter never creates a key", () => {
  const f = fixture({ withKey: false });
  assert.equal(refusal(() => buildBundle({ ...f.base, receiptId: "rcpt_a1" })), "SIGNING_UNAVAILABLE");
  assert.deepEqual(fs.readdirSync(f.keys), []);
  const g = fixture();
  fs.writeFileSync(path.join(g.keys, "public-jwk.json"), JSON.stringify(K_OLD.jwk));
  assert.equal(refusal(() => buildBundle({ ...g.base, receiptId: "rcpt_a1" })), "SIGNING_UNAVAILABLE");
});

test("export: disclosures are included only when they match the signed hashes", () => {
  const f = fixture();
  const inv = path.join(f.dir, "inv.json");
  const pol = path.join(f.dir, "pol.json");
  fs.writeFileSync(inv, JSON.stringify({ args: { id: 1 } }));
  fs.writeFileSync(pol, JSON.stringify(POLICY));
  const ok = buildBundle({ ...f.base, receiptId: "rcpt_a1", discloseInvocation: inv, disclosePolicy: pol });
  assert.equal(ok.manifest.evidence.invocationDisclosure, "PRESENT");
  const rep = verifyBundle(ok.files, { trustStore: trust });
  assert.equal(rep.claims.find((c) => c.id === "PPB-C06").classification, "CORROBORATED");
  assert.equal(rep.claims.find((c) => c.id === "PPB-C05").classification, "CORROBORATED");
  fs.writeFileSync(inv, JSON.stringify({ args: { id: 999 } }));
  assert.equal(refusal(() => buildBundle({ ...f.base, receiptId: "rcpt_a1", discloseInvocation: inv })), "DISCLOSURE_MISMATCH");
  fs.writeFileSync(pol, JSON.stringify({ ...POLICY, default: "ALLOW" }));
  assert.equal(refusal(() => buildBundle({ ...f.base, receiptId: "rcpt_a1", disclosePolicy: pol })), "DISCLOSURE_MISMATCH");
});

test("export: no private key material, no undisclosed arguments in the bundle", () => {
  const f = fixture();
  const { files } = buildBundle({ ...f.base, receiptId: "rcpt_a1" });
  const pem = fs.readFileSync(path.join(f.keys, "signing-key.pem"), "utf8").split("\n").filter((l) => l && !l.startsWith("-----")).join("");
  for (const [p, buf] of files) {
    const s = buf.toString("utf8");
    assert.ok(!s.includes(pem) && !s.includes("PRIVATE KEY"), p);
    assert.ok(!s.includes('"args"'), `${p} leaks arguments that were not disclosed`);
  }
});

test("export CLI: writes once, never overwrites, audits without evidence content, tolerates a torn final line", () => {
  const f = fixture();
  fs.appendFileSync(path.join(f.store, "receipts.jsonl"), '{"receiptId":"rcpt_torn","dec');
  const out = path.join(f.dir, "bundle");
  const carrier = path.join(f.dir, "bundle.ppb.json");
  const a = cli("export", "--store", f.store, "--key-dir", f.keys, "--receipt-id", "rcpt_a1", "--tenant", "acme", "--out", out, "--carrier", carrier);
  assert.equal(a.exit, 0, a.err);
  assert.equal(verifyBundle(loadBundle(out), { trustStore: trust }).result.overall, "PASSED");
  assert.equal(verifyBundle(loadBundle(carrier), { trustStore: trust }).result.overall, "PASSED");
  const before = fs.readFileSync(path.join(out, "manifest.json"));
  const b = cli("export", "--store", f.store, "--key-dir", f.keys, "--receipt-id", "rcpt_d1", "--tenant", "acme", "--out", out);
  assert.equal(b.exit, 1);
  assert.match(b.err, /^REFUSED OUTPUT_EXISTS/);
  assert.ok(fs.readFileSync(path.join(out, "manifest.json")).equals(before));
  assert.equal(refusal(() => writeBundleDir(new Map(), out)), "OUTPUT_EXISTS");
  const log = fs.readFileSync(path.join(f.store, "proof-bundle-exports.jsonl"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
  assert.deepEqual(log.map((l) => l.result), ["EXPORTED", "REFUSED"]);
  assert.equal(log[1].code, "OUTPUT_EXISTS");
  assert.ok(!JSON.stringify(log).includes("signature"));
  assert.equal(cli("export", "--store", f.store).exit, 2);
  assert.equal(cli("bogus", "--store", f.store).exit, 2);
  // A corrupt line that is NOT a torn tail is a refusal, not a silent skip.
  fs.writeFileSync(path.join(f.store, "receipts.jsonl"), "not json\n" + fs.readFileSync(path.join(f.store, "receipts.jsonl"), "utf8"));
  assert.match(cli("export", "--store", f.store, "--key-dir", f.keys, "--receipt-id", "rcpt_a1", "--tenant", "acme", "--out", path.join(f.dir, "b2"), "--audit-log", "none").err, /^REFUSED STORE_CORRUPT/);
  assert.ok(!fs.existsSync(path.join(f.dir, "b2")));
});

test("trust-store command emits a store the verifier accepts, scoped to the tenant", () => {
  const f = fixture();
  const r = cli("trust-store", "--key-dir", f.keys, "--owner", "Example signer", "--tenant", "acme");
  assert.equal(r.exit, 0);
  const store = parseTrustStore(r.out);
  assert.deepEqual(store.get("exp-key").tenants, ["acme"]);
  const { files } = buildBundle({ ...f.base, receiptId: "rcpt_a1" });
  assert.equal(verifyBundle(files, { trustStore: store }).result.overall, "PASSED");
  assert.ok(!r.out.includes("PRIVATE"));
});
