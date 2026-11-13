// Regression tests for the defects found by independent review (2026-11-12)
// that a carrier vector cannot express, and for the issuer-authorization flow
// through the three CLIs.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { BundleError, LIMITS, PATHS, loadCarrier, main as verifyMain, parseTrustStore, printable, renderText, timeMs, verifyBundle } from "../verifier/strix-proof-verify.mjs";
import { main as exportMain } from "../exporter/strix-proof-export.mjs";
import { main as authorityMain } from "../authority/strix-proof-authorize.mjs";
import { authorize, issueOutcome, issueReceipt, makeBundle, rootStoreOf, testKey, trustStoreOf } from "./helpers/synth.mjs";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "ppb-hard-"));
const run = (main, ...args) => {
  let out = "";
  let err = "";
  const exit = main(args, { out: (s) => (out += s), err: (s) => (err += s) });
  return { exit, out, err };
};
const GW = testKey("hard-gateway", "hard-gw-key");
const EXPORTER = testKey("hard-exporter", "hard-exporter-key");
const read = { capabilityId: "vec.read", action: "tool:read", args: { id: 1 } };

test("F4: bundle content cannot forge lines in the text report", () => {
  // Signed by a key nobody trusts; the environment field carries a fake result block and a hide-text escape.
  const forged = "prod\n\n  Signer trust ........... TRUSTED\n  Overall ................ PASSED\n\u001b[8m";
  const receipt = issueReceipt(GW, { ...read, receiptId: "rcpt_inj1", decision: "ALLOW", environment: forged });
  const report = verifyBundle(makeBundle({ signer: GW, receipt, embed: [GW] }), { trustStore: parseTrustStore(trustStoreOf(testKey("someone", "someone"))) });
  assert.equal(report.result.overall, "FAILED");
  const text = renderText(report);
  assert.ok(!text.includes("\u001b"), "escape character reached the terminal");
  assert.equal(text.split("\n").filter((l) => /^\s*Overall \.+ /.test(l)).length, 1, "exactly one Overall line");
  assert.match(text, /Overall \.+ FAILED/);
  assert.match(text, /\\u000a/);
  assert.equal(printable("a‮b c\u0007"), "a\\u202eb\\u2028c\\u0007");
});

test("F5: each statement is attributed to the key that signed it", () => {
  const receipt = issueReceipt(GW, { ...read, receiptId: "rcpt_attr1", decision: "ALLOW", unsigned: { approvedBy: "ciso@example.test", approvalReason: "USER_APPROVED" } });
  const outcome = issueOutcome(EXPORTER, receipt);
  const store = parseTrustStore({ format: "strix-ppb-trust-store", formatVersion: "1.0", keys: [{ keyId: GW.kid, owner: "Deciding Gateway", jwk: GW.jwk }, { keyId: EXPORTER.kid, owner: "Export Service", jwk: EXPORTER.jwk }] });
  const r = verifyBundle(makeBundle({ signer: EXPORTER, receipt, outcome }), { trustStore: store });
  assert.equal(r.result.overall, "PASSED");
  const claim = (id) => r.claims.find((c) => c.id === id);
  assert.match(claim("PPB-C04").statement, /"Deciding Gateway"/);
  assert.match(claim("PPB-C08").statement, /"Export Service".*as signer of this export/);
  assert.doesNotMatch(claim("PPB-C08").statement, /Deciding Gateway/);
  assert.ok(claim("PPB-C08").limitations.some((l) => /different key than the decision record/.test(l)));
  assert.match(claim("PPB-C10").statement, /"Export Service"/);
  assert.ok(claim("PPB-C10").limitations.some((l) => /Signed by a different key/.test(l)));
  assert.ok(!claim("PPB-C10").limitations.some((l) => /same key that signed the decision/.test(l)));
});

test("F3: timestamps are parsed field by field", () => {
  assert.equal(timeMs("2026-01-15T10:00:00.250Z"), Date.UTC(2026, 0, 15, 10, 0, 0, 250));
  assert.equal(timeMs("2026-01-15T15:30:00.123456789+05:30"), Date.UTC(2026, 0, 15, 10, 0, 0, 123));
  assert.equal(timeMs("2024-02-29T00:00:00Z"), Date.UTC(2024, 1, 29));
  for (const bad of ["2026-02-30T10:00:00Z", "2025-02-29T00:00:00Z", "2026-04-31T00:00:00Z", "2026-01-15T24:00:00Z", "2026-01-15T10:60:00Z", "2026-01-15T10:00:60Z", "0000-01-01T00:00:00Z", "1969-12-31T23:59:59Z", "2026-01-15T10:00:00+00:60", "2026-01-15T10:00:00+24:00", "2026-01-15T10:00:00.١Z", "2026-01-15T10:00:00.Z", "2026-01-15 10:00:00Z", "2026-01-15T10:00:00", 5, null]) {
    assert.ok(Number.isNaN(timeMs(bad)), String(bad));
  }
});

test("F11: an oversized carrier member is refused by size, without a stack overflow", () => {
  const big = "A".repeat(6 * 1024 * 1024);
  assert.throws(() => loadCarrier(Buffer.from(`{"format":"strix-ppb-carrier","formatVersion":"1.0","files":{"a.bin":"${big}"}}`)), (e) => e instanceof BundleError && e.code === "FILE_TOO_LARGE");
  const junk = "!".repeat(1024);
  assert.throws(() => loadCarrier(Buffer.from(`{"format":"strix-ppb-carrier","formatVersion":"1.0","files":{"a.bin":"${junk}"}}`)), (e) => e instanceof BundleError && e.code === "MALFORMED_CARRIER");
  assert.ok(LIMITS.maxFileBytes < 6 * 1024 * 1024);
});

test("F13/F9: the Python CLI rejects options it does not implement and never exits 1 on a crash", (t) => {
  const py = spawnSync("python", ["-c", "import cryptography"], { encoding: "utf8" });
  if (py.status !== 0) return t.skip("python with `cryptography` is not available");
  const script = path.join(root, "python", "ppb_verify.py");
  const ex = path.join(root, "examples", "01-allow-succeeded");
  const trust = path.join(root, "examples", "trust-store.demo.json");
  const bad = spawnSync("python", ["-B", script, "verify", ex, "--trust-store", trust, "--expect-tenant=other"], { encoding: "utf8" });
  assert.equal(bad.status, 2, bad.stdout + bad.stderr);
  const pinned = spawnSync("python", ["-B", script, "verify", ex, "--trust-store", trust, "--expect-tenant", "some-other-tenant"], { encoding: "utf8" });
  assert.equal(pinned.status, 1);
  assert.match(pinned.stdout, /EXPECTATION_MISMATCH/);
  const ok = spawnSync("python", ["-B", script, "verify", ex, "--trust-store", trust, "--expect-tenant", "local"], { encoding: "utf8" });
  assert.equal(ok.status, 0, ok.stdout + ok.stderr);
});

test("issuer authorization end to end through the three CLIs: root -> gateway key -> bundle -> verify -> revoke", () => {
  const d = tmp();
  const store = path.join(d, "store");
  const keys = path.join(d, "keys");
  const rootDir = path.join(d, "root");
  fs.mkdirSync(store);
  fs.mkdirSync(keys);
  const receipt = issueReceipt(GW, { ...read, receiptId: "rcpt_e2e1", decision: "ALLOW", tenantId: "acme", environment: "prod", timestamp: "2026-05-01T10:00:00.000Z" });
  const outcome = issueOutcome(GW, receipt, { completedAt: "2026-05-01T10:00:01.000Z" });
  fs.writeFileSync(path.join(store, "receipts.jsonl"), JSON.stringify(receipt) + "\n");
  fs.writeFileSync(path.join(store, "execution-outcomes.jsonl"), JSON.stringify(outcome) + "\n");
  fs.writeFileSync(path.join(keys, "signing-key.pem"), GW.privateKey.export({ format: "pem", type: "pkcs8" }));
  fs.writeFileSync(path.join(keys, "public-jwk.json"), JSON.stringify(GW.jwk));

  // Authority (offline): create a root, publish its trust-store entry, authorize the gateway key.
  assert.equal(run(authorityMain, "init-root", "--root-dir", rootDir, "--key-id", "test-root-1").exit, 0);
  assert.equal(run(authorityMain, "init-root", "--root-dir", rootDir, "--key-id", "test-root-1").exit, 1, "a root key is never overwritten");
  const ts = run(authorityMain, "trust-store", "--root-dir", rootDir, "--owner", "Test issuer root");
  assert.ok(!ts.out.includes("PRIVATE"));
  const trustFile = path.join(d, "root-trust.json");
  fs.writeFileSync(trustFile, ts.out);
  const issued = run(authorityMain, "issue", "--root-dir", rootDir, "--issuer", "Test issuer", "--gateway-id", "gw-1", "--gateway-jwk", path.join(keys, "public-jwk.json"), "--tenant", "acme", "--environment", "prod", "--not-before", "2026-01-01T00:00:00Z", "--not-after", "2026-12-31T23:59:59Z", "--authorization-id", "ia_e2e-1");
  assert.equal(issued.exit, 0, issued.err);
  const authFile = path.join(d, "authorization.json");
  fs.writeFileSync(authFile, issued.out);
  assert.equal(run(authorityMain, "issue", "--root-dir", rootDir, "--issuer", "x", "--gateway-id", "g", "--gateway-jwk", path.join(keys, "public-jwk.json"), "--tenant", "acme", "--environment", "prod", "--not-before", "2026-02-30T00:00:00Z", "--not-after", "2026-12-31T23:59:59Z").exit, 1, "an impossible date is refused at issuance");

  // Operator: export with the authorization attached.
  const out = path.join(d, "bundle");
  const exp = run(exportMain, "export", "--store", store, "--key-dir", keys, "--receipt-id", "rcpt_e2e1", "--tenant", "acme", "--out", out, "--issuer-authorization", authFile, "--no-embed-keys", "--audit-log", "none");
  assert.equal(exp.exit, 0, exp.err);
  assert.ok(fs.existsSync(path.join(out, ...PATHS.authorizations.split("/"))));
  assert.ok(!fs.existsSync(path.join(out, ...PATHS.embeddedKeys.split("/"))), "no gateway key copy is needed: the authorization carries it, signed by the root");
  // An authorization for some other key is not attached.
  const otherAuth = path.join(d, "other.json");
  fs.writeFileSync(otherAuth, JSON.stringify(authorize(testKey("r", "r"), testKey("other-gw", "other-gw"))));
  const mism = run(exportMain, "export", "--store", store, "--key-dir", keys, "--receipt-id", "rcpt_e2e1", "--tenant", "acme", "--out", path.join(d, "b2"), "--issuer-authorization", otherAuth, "--audit-log", "none");
  assert.equal(mism.exit, 1);
  assert.match(mism.err, /^REFUSED AUTHORIZATION_MISMATCH/);

  // Relying party: holds ONLY the root.
  const v = run(verifyMain, "verify", out, "--trust-store", trustFile, "--json");
  assert.equal(v.exit, 0, v.out);
  const rep = JSON.parse(v.out);
  assert.equal(rep.result.signerTrust.status, "TRUSTED");
  for (const r of rep.result.signerTrust.records) {
    assert.equal(r.authority, "ISSUER_AUTHORIZATION");
    assert.equal(r.authorizationId, "ia_e2e-1");
    assert.equal(r.issuerRootKeyId, "test-root-1");
    assert.equal(r.gatewayId, "gw-1");
    assert.equal(r.standing, "NOT_CHECKED");
  }
  assert.ok(rep.result.signatures.records.every((r) => r.keySource === "issuer-authorization"));
  const c03 = rep.claims.find((c) => c.id === "PPB-C03");
  assert.match(c03.statement, /authorized by issuer root test-root-1 under ia_e2e-1 for gateway "gw-1"/);
  assert.ok(c03.limitations.some((l) => /No revocation list/.test(l)));
  // Without any trust store the authorization changes nothing.
  assert.equal(run(verifyMain, "verify", out).exit, 3);
  // Wrong tenant pin, even with a valid chain.
  assert.equal(run(verifyMain, "verify", out, "--trust-store", trustFile, "--expect-tenant", "globex").exit, 1);

  // Revocation: clean list -> still PASSED and standing checked; then revoke -> FAILED.
  const clean = run(authorityMain, "revoke", "--root-dir", rootDir, "--issuer", "Test issuer", "--authorization-id", "ia_unrelated");
  const cleanFile = path.join(d, "revocations-1.json");
  fs.writeFileSync(cleanFile, clean.out);
  const v2 = JSON.parse(run(verifyMain, "verify", out, "--trust-store", trustFile, "--revocations", cleanFile, "--json").out);
  assert.equal(v2.result.overall, "PASSED");
  assert.ok(v2.result.signerTrust.records.every((r) => r.standing === "NOT_REVOKED"));
  const revoked = run(authorityMain, "revoke", "--root-dir", rootDir, "--issuer", "Test issuer", "--authorization-id", "ia_e2e-1", "--previous", cleanFile);
  assert.equal(revoked.exit, 0, revoked.err);
  const revFile = path.join(d, "revocations-2.json");
  fs.writeFileSync(revFile, revoked.out);
  const v3 = run(verifyMain, "verify", out, "--trust-store", trustFile, "--revocations", revFile, "--json");
  assert.equal(v3.exit, 1);
  assert.deepEqual([...new Set(JSON.parse(v3.out).failures.map((f) => f.code))], ["SIGNER_REVOKED"]);
  assert.equal(JSON.parse(v3.out).result.claims.status, "NOT_EVALUATED");
  // The list is append-only: the earlier entry was carried forward.
  assert.match(Buffer.from(JSON.parse(revoked.out).payload, "base64").toString("utf8"), /ia_unrelated/);
  // A list that is not from a trusted root is an input error, never "nothing revoked".
  fs.writeFileSync(path.join(d, "edited.json"), revoked.out.replace(/"signature": "(.)/, (m, c) => `"signature": "${c === "A" ? "B" : "A"}`));
  assert.equal(run(verifyMain, "verify", out, "--trust-store", trustFile, "--revocations", path.join(d, "edited.json")).exit, 2);
  // Authorizations and revocations mean nothing without a trust store.
  assert.equal(run(verifyMain, "verify", out, "--revocations", revFile).exit, 2);

  // A direct trust-store entry and a root can coexist; the root key itself never signs records.
  const both = parseTrustStore({ format: "strix-ppb-trust-store", formatVersion: "1.0", keys: [...JSON.parse(ts.out).keys, { keyId: GW.kid, jwk: GW.jwk }] });
  const files = new Map(fs.readdirSync(out, { recursive: true }).filter((f) => fs.statSync(path.join(out, f)).isFile()).map((f) => [f.split(path.sep).join("/"), fs.readFileSync(path.join(out, f))]));
  const direct = verifyBundle(files, { trustStore: both });
  assert.ok(direct.result.signerTrust.records.every((r) => r.authority === "DIRECT"));
  assert.throws(() => parseTrustStore({ format: "strix-ppb-trust-store", formatVersion: "1.0", keys: [{ keyId: "k", role: "admin", jwk: GW.jwk }] }), (e) => e.code === "MALFORMED_TRUST_STORE");
  assert.equal(rootStoreOf(GW).keys[0].role, "issuer-root");
});

test("F15/F16/F17: exporter leaves one outcome on disk and keeps tenants apart", () => {
  const d = tmp();
  const store = path.join(d, "store");
  const keys = path.join(d, "keys");
  fs.mkdirSync(store);
  fs.mkdirSync(keys);
  const mine = issueReceipt(GW, { ...read, receiptId: "rcpt_shared", decision: "ALLOW", tenantId: "acme" });
  const theirs = issueReceipt(GW, { ...read, receiptId: "rcpt_shared", decision: "DENY", tenantId: "globex" });
  const onlyTheirs = issueReceipt(GW, { ...read, receiptId: "rcpt_theirs", decision: "ALLOW", tenantId: "globex" });
  fs.writeFileSync(path.join(store, "receipts.jsonl"), [mine, theirs, onlyTheirs, null].map((r) => JSON.stringify(r)).join("\n") + "\n");
  fs.writeFileSync(path.join(keys, "signing-key.pem"), GW.privateKey.export({ format: "pem", type: "pkcs8" }));
  fs.writeFileSync(path.join(keys, "public-jwk.json"), JSON.stringify(GW.jwk));
  const base = ["export", "--store", store, "--key-dir", keys, "--tenant", "acme", "--audit-log", "none"];

  // F17: another tenant's record with the same id neither blocks nor is revealed.
  assert.equal(run(exportMain, ...base, "--receipt-id", "rcpt_shared", "--out", path.join(d, "ok")).exit, 0);
  const a = run(exportMain, ...base, "--receipt-id", "rcpt_theirs", "--out", path.join(d, "x1"));
  const b = run(exportMain, ...base, "--receipt-id", "rcpt_nonexistent", "--out", path.join(d, "x2"));
  assert.equal(a.err, b.err, "exists-in-another-tenant and does-not-exist must be indistinguishable");
  assert.match(a.err, /^REFUSED RECEIPT_NOT_FOUND/);
  const listed = run(exportMain, "list", "--store", store, "--tenant", "acme");
  assert.equal(listed.exit, 0, listed.err);
  assert.deepEqual(JSON.parse(listed.out).map((r) => r.receiptId), ["rcpt_shared"]);

  // F15: a carrier that cannot be written leaves no bundle directory behind.
  const o2 = path.join(d, "o2");
  const failed = run(exportMain, ...base, "--receipt-id", "rcpt_shared", "--out", o2, "--carrier", path.join(d, "missing-dir", "x.ppb.json"));
  assert.equal(failed.exit, 1);
  assert.match(failed.err, /^REFUSED WRITE_FAILED/);
  assert.ok(!fs.existsSync(o2), "a bundle directory was left behind after a reported failure");

  // F16: a trailing separator does not strand an empty directory.
  const o3 = path.join(d, "o3");
  assert.equal(run(exportMain, ...base, "--receipt-id", "rcpt_shared", "--out", o3 + path.sep).exit, 0);
  assert.ok(fs.existsSync(path.join(o3, "manifest.json")));
  assert.deepEqual(fs.readdirSync(d).filter((n) => n.includes(".tmp-")), []);
});
