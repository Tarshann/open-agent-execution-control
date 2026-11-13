#!/usr/bin/env node
// Deterministic generator for the public Portable Proof Bundle v1 test vectors.
//
// Every vector is SYNTHETIC: records are issued by test/helpers/synth.mjs with
// test keys whose private halves are derivable from that file. Output is
// byte-reproducible (fixed keys, ids, timestamps; Ed25519 is deterministic).
//
//   node vectors/generate.mjs           rewrite vectors/
//   node vectors/generate.mjs --check   fail if vectors/ differs from what would be generated
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { PATHS } from "../verifier/strix-proof-verify.mjs";
import { POLICY, authorizationsDoc, authorize, carrierBytes, invocationOf, issueOutcome, issueReceipt, jsonBytes, makeBundle, revocationList, rootStoreOf, sha256Hex, signManifest, testKey, trustStoreOf } from "../test/helpers/synth.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const K1 = testKey("vector-signer-2026", "vec-signer-2026");
const K0 = testKey("vector-signer-2025", "vec-signer-2025"); // "previous" key for rotation vectors
const EVIL = testKey("attacker", "vec-signer-2026"); // attacker key reusing the real key id
const OTHER = testKey("unrelated", "someone-else");
const ROOT = testKey("issuer-root", "vec-issuer-root"); // test issuer root
const EVILROOT = testKey("attacker-root", "vec-issuer-root"); // attacker root reusing the real root's key id
const OTHERROOT = testKey("other-root", "some-other-root");

const read = { capabilityId: "vec.read", action: "tool:read", args: { path: "notes/a.txt" } };
const del = { capabilityId: "vec.delete", action: "tool:delete", args: { path: "notes/a.txt" }, risk: "CRITICAL", mode: "WRITE" };
const write = { capabilityId: "vec.write", action: "tool:write", args: { path: "notes/a.txt", body: "hi" }, risk: "MEDIUM", mode: "WRITE" };
const archive = { capabilityId: "vec.archive", action: "tool:archive", args: { path: "notes/a.txt" }, mode: "WRITE" };

const rAllow = issueReceipt(K1, { ...read, receiptId: "rcpt_000000000000000000000001", decision: "ALLOW" });
const oAllow = issueOutcome(K1, rAllow);
const rDeny = issueReceipt(K1, { ...del, receiptId: "rcpt_000000000000000000000002", decision: "DENY" });
const rApproved = issueReceipt(K1, { ...write, receiptId: "rcpt_000000000000000000000003", decision: "ALLOW", unsigned: { approvedBy: "ops@example.test", approvalReason: "USER_APPROVED" } });
const oApproved = issueOutcome(K1, rApproved);
const rFail = issueReceipt(K1, { ...archive, receiptId: "rcpt_000000000000000000000004", decision: "ALLOW" });
const oFail = issueOutcome(K1, rFail, { executionStatus: "FAILED" });
const uni = { capabilityId: "vec.read", action: "tool:read", args: { "é": 1, "😀": [true, null, -0.5, 1e21], "￿": "tab\there \"q\"   \u0001", z: { b: 2, a: 1 }, A: "café" }, actorId: "svc-üser", actorRole: "reader" };
const rUni = issueReceipt(K1, { ...uni, receiptId: "rcpt_000000000000000000000005", decision: "ALLOW" });
const rOld = issueReceipt(K0, { ...read, receiptId: "rcpt_000000000000000000000006", decision: "ALLOW", timestamp: "2025-12-30T10:00:00.000Z" });
const oOld = issueOutcome(K0, rOld, { completedAt: "2025-12-30T10:00:00.250Z" });
const rV1 = issueReceipt(K1, { ...read, receiptId: "rcpt_000000000000000000000007", decision: "ALLOW", schemaVersion: "1" });
const rDenyPolicyAllow = issueReceipt(K1, { ...del, receiptId: "rcpt_000000000000000000000008", decision: "ALLOW" });

const full = () => makeBundle({ signer: K1, receipt: rAllow, outcome: oAllow, invocation: invocationOf(read), ruleset: POLICY, embed: [K1], extraFiles: { "README.md": "Explanatory only. SYNTHETIC test vector.\n" } });
const mutate = (files, fn) => {
  const m = new Map(files);
  fn(m);
  return m;
};
const editManifest = (files, fn) => mutate(files, (m) => {
  const man = JSON.parse(m.get(PATHS.manifest).toString("utf8"));
  fn(man);
  m.set(PATHS.manifest, jsonBytes(man));
});
const rawCarrier = (text) => Buffer.from(text, "utf8");
const b64 = (s) => Buffer.from(s, "utf8").toString("base64");

const T = {
  trusted: trustStoreOf(K1),
  both: trustStoreOf(K1, { keyId: K0.kid, owner: "SYNTHETIC TEST SIGNER (retired key) - never trust", status: "retired", notAfter: "2025-12-31T23:59:59.000Z", jwk: K0.jwk }),
  jwks: { keys: [K1.jwk] },
  unrelated: trustStoreOf(OTHER),
  wrongKeySameId: { keys: [EVIL.jwk] },
  revoked: trustStoreOf({ keyId: K1.kid, owner: "SYNTHETIC", status: "revoked", jwk: K1.jwk }),
  expired: trustStoreOf({ keyId: K1.kid, owner: "SYNTHETIC", status: "active", notAfter: "2026-01-01T00:00:00.000Z", jwk: K1.jwk }),
  otherTenant: trustStoreOf({ keyId: K1.kid, owner: "SYNTHETIC", status: "active", tenants: ["globex"], jwk: K1.jwk }),
};

// ---- issuer authorizations (root -> gateway key)
const A1 = authorize(ROOT, K1);
const A0 = authorize(ROOT, K0, { notBefore: "2025-01-01T00:00:00.000Z", notAfter: "2025-12-31T23:59:59.000Z", issuedAt: "2025-01-01T00:00:00.000Z" });
const authd = (extra = {}) => makeBundle({ signer: K1, receipt: rAllow, outcome: oAllow, embed: [K1], authorizations: [A1], ...extra });
const reencode = (env, fn) => {
  const p = JSON.parse(Buffer.from(env.payload, "base64").toString("utf8"));
  fn(p);
  return { ...env, payload: Buffer.from(JSON.stringify(p, null, 2) + "\n").toString("base64") };
};
const evilReceipt = issueReceipt(EVIL, { ...read, receiptId: "rcpt_000000000000000000000001", decision: "ALLOW" });
Object.assign(T, {
  rootOnly: rootStoreOf(ROOT),
  rootRevoked: rootStoreOf(ROOT, { status: "revoked" }),
  rootExpired: rootStoreOf(ROOT, { notAfter: "2025-06-01T00:00:00.000Z" }),
  nullStatus: { format: "strix-ppb-trust-store", formatVersion: "1.0", keys: [{ keyId: K1.kid, status: null, jwk: K1.jwk }] },
  noJwk: { format: "strix-ppb-trust-store", formatVersion: "1.0", keys: [{ keyId: K1.kid }] },
});
/** Extra relying-party inputs: authorizations held out of band, and revocation lists. */
const X = {
  a1: authorizationsDoc([A1]),
  revokesA1: revocationList(ROOT, ["ia_vec-signer-2026"]),
  revokesOther: revocationList(ROOT, ["ia_something-else"]),
  revocationsForged: revocationList(EVILROOT, []),
  revocationsOtherRoot: revocationList(OTHERROOT, ["ia_vec-signer-2026"]),
};
const B64URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const strayBit = (sig) => sig.slice(0, -1) + B64URL_ALPHABET[B64URL_ALPHABET.indexOf(sig.slice(-1)) | 1];
const timed = (timestamp) => makeBundle({ signer: K1, receipt: issueReceipt(K1, { ...read, receiptId: "rcpt_00000000000000000000000b", decision: "ALLOW", timestamp }), createdAt: "2026-06-01T00:00:00.000Z" });
const rawReceipt = (text) => {
  const f = makeBundle({ signer: K1, receipt: rAllow });
  const rec = Buffer.from(text);
  const man = JSON.parse(f.get(PATHS.manifest).toString("utf8"));
  const a = man.artifacts.find((x) => x.path === PATHS.receipt);
  a.size = rec.length;
  a.sha256 = sha256Hex(rec);
  return signManifest(mutate(f, (m) => m.set(PATHS.receipt, rec)), man, K1);
};

const C = (o) => o; // readability
const pass = (claims = {}) => ({ overall: "PASSED", exit: 0, failureCodes: [], claims });
const failed = (...codes) => ({ overall: "FAILED", exit: 1, failureCodes: codes.sort() });
const error = (code) => ({ overall: "ERROR", exit: 2, errorCode: code });

/** [name, description, bundle (Map | Buffer), trust-store key | null, expectation, optional verifier options] */
const V = [
  // ---- valid
  ["valid-allow-succeeded", "ALLOW with a SUCCEEDED outcome, invocation and policy disclosed.", full(), "trusted",
    pass({ "PPB-C04": "SOURCE_ASSERTION/ASSERTED", "PPB-C05": "CORROBORATED/ESTABLISHED", "PPB-C06": "CORROBORATED/ESTABLISHED", "PPB-C09": "NOT_ESTABLISHED/NOT_ESTABLISHED", "PPB-C10": "SOURCE_ASSERTION/ASSERTED" })],
  ["valid-allow-succeeded-jwks-trust", "Same bundle, trust supplied as a plain JWKS.", full(), "jwks", pass()],
  ["valid-allow-no-outcome", "ALLOW decision, no execution record in the store: execution is NOT established.", makeBundle({ signer: K1, receipt: rAllow, embed: [K1] }), "trusted",
    pass({ "PPB-C06": "NOT_ESTABLISHED/NOT_ESTABLISHED", "PPB-C10": "NOT_ESTABLISHED/NOT_ESTABLISHED" })],
  ["valid-deny", "DENY decision: prevention is NOT established, outcome NOT_APPLICABLE.", makeBundle({ signer: K1, receipt: rDeny, invocation: invocationOf(del), ruleset: POLICY, embed: [K1] }), "trusted",
    pass({ "PPB-C04": "SOURCE_ASSERTION/ASSERTED", "PPB-C09": "NOT_ESTABLISHED/NOT_ESTABLISHED", "PPB-C10": "NOT_ESTABLISHED/NOT_APPLICABLE" })],
  ["valid-allow-tool-failed", "ALLOW decision whose execution FAILED.", makeBundle({ signer: K1, receipt: rFail, outcome: oFail, embed: [K1] }), "trusted", pass({ "PPB-C10": "SOURCE_ASSERTION/ASSERTED" })],
  ["valid-approved", "Approval fields present: reported as an export-time source assertion.", makeBundle({ signer: K1, receipt: rApproved, outcome: oApproved, embed: [K1] }), "trusted", pass({ "PPB-C08": "SOURCE_ASSERTION/ASSERTED" })],
  ["valid-unicode-disclosure", "Disclosed arguments with non-ASCII keys (incl. astral), escapes and non-integer numbers.", makeBundle({ signer: K1, receipt: rUni, invocation: invocationOf(uni), embed: [K1] }), "trusted", pass({ "PPB-C06": "CORROBORATED/ESTABLISHED" })],
  ["valid-rotated-keys", "Records signed by a retired key, manifest by the current key; both trusted.", makeBundle({ signer: K1, receipt: rOld, outcome: oOld, embed: [K0, K1] }), "both", pass()],
  ["valid-receipt-schema-1", "Receipt schema 1 carries no tenant: subject says UNSPECIFIED.", makeBundle({ signer: K1, receipt: rV1, embed: [K1] }), "trusted", pass()],
  ["valid-no-embedded-keys", "No convenience key copy in the bundle.", makeBundle({ signer: K1, receipt: rAllow, outcome: oAllow }), "trusted", pass()],
  // ---- trust
  ["trust-none-supplied", "Valid bundle, no trust store: mathematics only, origin not authenticated.", full(), null,
    C({ overall: "INCOMPLETE", exit: 3, failureCodes: [], claims: { "PPB-C03": "TRUST_EVALUATION/NOT_ESTABLISHED", "PPB-C04": "SOURCE_ASSERTION/ASSERTED_BY_UNTRUSTED_KEY", "PPB-C10": "SOURCE_ASSERTION/ASSERTED_BY_UNTRUSTED_KEY" } })],
  ["trust-none-supplied-no-embedded", "No trust store and no embedded key: signatures cannot even be checked.", makeBundle({ signer: K1, receipt: rAllow, outcome: oAllow }), null, C({ overall: "INCOMPLETE", exit: 3, failureCodes: [], noClaims: true })],
  ["trust-signer-not-in-store", "Trust store does not contain the signer.", full(), "unrelated", failed("SIGNER_UNTRUSTED")],
  ["trust-wrong-key-same-id", "Trust store has a different key under the signer's key id.", full(), "wrongKeySameId", failed("SIGNATURE_INVALID")],
  ["trust-revoked", "Signer key is marked revoked in the trust store.", full(), "revoked", failed("SIGNER_REVOKED")],
  ["trust-outside-validity", "Signer key used after its notAfter.", full(), "expired", failed("SIGNER_OUTSIDE_VALIDITY")],
  ["trust-other-tenant", "Signer key is scoped to another tenant (cross-tenant confusion).", full(), "otherTenant", failed("SIGNER_TENANT_NOT_AUTHORIZED")],
  ["trust-rotation-old-key-missing", "Rotated bundle, trust store lacks the retired key.", makeBundle({ signer: K1, receipt: rOld, outcome: oOld, embed: [K0, K1] }), "trusted", failed("SIGNER_UNTRUSTED")],
  ["trust-attacker-resigned", "Whole bundle produced by an attacker key that reuses the real key id and embeds its own public key.",
    makeBundle({ signer: EVIL, receipt: issueReceipt(EVIL, { ...read, receiptId: "rcpt_000000000000000000000001", decision: "ALLOW" }), embed: [EVIL] }), "trusted", failed("SIGNATURE_INVALID")],
  ["trust-attacker-resigned-no-store", "The same attacker bundle with no trust store: valid mathematics, never PASSED.",
    makeBundle({ signer: EVIL, receipt: issueReceipt(EVIL, { ...read, receiptId: "rcpt_000000000000000000000001", decision: "ALLOW" }), embed: [EVIL] }), null, C({ overall: "INCOMPLETE", exit: 3, failureCodes: [], claims: { "PPB-C03": "TRUST_EVALUATION/NOT_ESTABLISHED" } })],
  ["expect-wrong-receipt", "Relying party expected a different receipt id (action substitution / replay of another bundle).", full(), "trusted", failed("EXPECTATION_MISMATCH"), { receiptId: "rcpt_ffffffffffffffffffffffff" }],
  // ---- tampering after signing
  ["tamper-evidence-byte", "One byte of an evidence artifact changed.", mutate(full(), (m) => { const b = Buffer.from(m.get(PATHS.outcome)); b[40] ^= 1; m.set(PATHS.outcome, b); }), "trusted", failed("DIGEST_MISMATCH")],
  ["tamper-manifest-field", "A manifest field edited after signing.", editManifest(full(), (m) => { m.evidence.enforcementObservation = "PRESENT"; }), "trusted", failed("EVIDENCE_STATE_MISMATCH", "SIGNATURE_INVALID")],
  ["tamper-manifest-digest-and-artifact", "Artifact replaced and its manifest digest updated to match, without the signing key.",
    (() => { const f = full(); const repl = jsonBytes(rDeny); return editManifest(mutate(f, (m) => m.set(PATHS.receipt, repl)), (m) => { const a = m.artifacts.find((x) => x.path === PATHS.receipt); a.sha256 = "d".repeat(64); }); })(), "trusted", failed("DIGEST_MISMATCH")],
  ["tamper-artifact-replaced", "Receipt replaced by another validly signed receipt from the same signer.", mutate(full(), (m) => m.set(PATHS.receipt, jsonBytes(rDeny))), "trusted", failed("DIGEST_MISMATCH")],
  ["tamper-artifact-removed", "A listed artifact deleted.", mutate(full(), (m) => m.delete(PATHS.outcome)), "trusted", failed("MISSING_ARTIFACT")],
  ["tamper-artifact-inserted", "An unlisted file added that tries to supply enforcement evidence.", mutate(full(), (m) => m.set("evidence/enforcement-observation.json", Buffer.from('{"enforced":true}\n'))), "trusted", failed("UNEXPECTED_ARTIFACT")],
  ["tamper-signature-swapped", "manifest.sig.json taken from a different valid bundle.", mutate(full(), (m) => m.set(PATHS.signature, makeBundle({ signer: K1, receipt: rDeny }).get(PATHS.signature))), "trusted", failed("SIGNATURE_INVALID")],
  ["tamper-signature-removed", "manifest.sig.json deleted.", mutate(full(), (m) => m.delete(PATHS.signature)), "trusted", failed("MISSING_SIGNATURE")],
  ["tamper-embedded-key-swapped", "Embedded convenience key replaced with an attacker key.", mutate(full(), (m) => m.set(PATHS.embeddedKeys, jsonBytes({ keys: [EVIL.jwk] }))), "trusted", failed("DIGEST_MISMATCH")],
  ["tamper-native-receipt-field", "Receipt decision flipped and manifest re-listed by someone without the key.",
    (() => { const forged = { ...rDeny, decision: "ALLOW" }; return makeBundle({ signer: EVIL, receipt: forged, embed: [EVIL] }); })(), "trusted", failed("RECEIPT_HASH_MISMATCH", "SIGNATURE_INVALID")],
  // ---- validly signed, but the signed content contradicts itself
  ["signed-subject-substituted", "Signed manifest names a different receipt than the one it carries.", makeBundle({ signer: K1, receipt: rAllow, tweak: (m) => { m.subject.receiptId = "rcpt_00000000000000000000beef"; } }), "trusted", failed("SUBJECT_MISMATCH")],
  ["signed-tenant-substituted", "Signed manifest names a different tenant than the receipt.", makeBundle({ signer: K1, receipt: rAllow, tweak: (m) => { m.subject.tenantId = "globex"; } }), "trusted", failed("SUBJECT_MISMATCH")],
  ["signed-bundle-id-wrong", "bundleId is not the derived identifier.", makeBundle({ signer: K1, receipt: rAllow, tweakFinal: (m) => { m.bundleId = "ppb_" + "0".repeat(32); } }), "trusted", failed("BUNDLE_ID_MISMATCH")],
  ["signed-deny-with-outcome", "A DENY receipt accompanied by an execution outcome.", makeBundle({ signer: K1, receipt: rDeny, outcome: issueOutcome(K1, rDeny) }), "trusted", failed("CONTRADICTORY_RECORDS")],
  ["signed-outcome-of-other-action", "Outcome belongs to a different authorization.", makeBundle({ signer: K1, receipt: rAllow, outcome: oApproved }), "trusted", failed("OUTCOME_LINK_MISMATCH")],
  ["signed-outcome-incoherent", "Outcome says SUCCEEDED and carries an error code.", makeBundle({ signer: K1, receipt: rAllow, outcome: issueOutcome(K1, rAllow, { overrideCore: { errorCode: "BOOM" } }) }), "trusted", failed("CONTRADICTORY_RECORDS")],
  ["signed-outcome-before-decision", "Outcome completion time precedes the decision.", makeBundle({ signer: K1, receipt: rAllow, outcome: issueOutcome(K1, rAllow, { completedAt: "2026-01-15T09:00:00.000Z" }) }), "trusted", failed("TIMESTAMP_ORDER")],
  ["signed-evidence-state-overclaims", "Manifest claims an enforcement observation that v1 cannot carry.", makeBundle({ signer: K1, receipt: rDeny, tweak: (m) => { m.evidence.enforcementObservation = "PRESENT"; } }), "trusted", failed("EVIDENCE_STATE_MISMATCH")],
  ["signed-missing-outcome-called-not-applicable", "ALLOW with no outcome, manifest says NOT_APPLICABLE instead of ABSENT.", makeBundle({ signer: K1, receipt: rAllow, tweak: (m) => { m.evidence.executionOutcome = "NOT_APPLICABLE"; } }), "trusted", failed("EVIDENCE_STATE_MISMATCH")],
  ["signed-disclosure-mismatch", "Disclosed arguments are not the ones the receipt was issued for.", makeBundle({ signer: K1, receipt: rAllow, invocation: invocationOf({ ...read, args: { path: "notes/other.txt" } }) }), "trusted", failed("DISCLOSURE_MISMATCH")],
  ["signed-policy-disclosure-mismatch", "Disclosed policy is not the version in the receipt.", makeBundle({ signer: K1, receipt: rAllow, ruleset: { ...POLICY, default: "ALLOW" } }), "trusted", failed("DISCLOSURE_MISMATCH")],
  ["signed-policy-says-deny-decision-allow", "Disclosed policy maps the capability to DENY but the decision is ALLOW.", makeBundle({ signer: K1, receipt: rDenyPolicyAllow, ruleset: POLICY }), "trusted", failed("CONTRADICTORY_RECORDS")],
  ["signed-receipt-hash-incoherent", "Receipt evidenceHash does not match its own fields.", makeBundle({ signer: K1, receipt: issueReceipt(K1, { ...read, receiptId: "rcpt_000000000000000000000009", decision: "ALLOW", overrideSigned: { evidenceHash: "a".repeat(64) } }) }), "trusted", failed("RECEIPT_HASH_MISMATCH")],
  ["signed-unrecognized-decision", "Decision value not defined in v1.", makeBundle({ signer: K1, receipt: issueReceipt(K1, { ...read, receiptId: "rcpt_00000000000000000000000a", decision: "MAYBE" }) }), "trusted", failed("UNRECOGNIZED_DECISION")],
  ["signed-export-before-decision", "Bundle created before the decision it describes.", makeBundle({ signer: K1, receipt: rAllow, createdAt: "2026-01-01T00:00:00.000Z" }), "trusted", failed("TIMESTAMP_ORDER")],
  // ---- issuer authorization: trust in a root, standing for the gateway key
  ["auth-valid-root-only", "Relying party trusts only the issuer root; the bundle carries the gateway key's authorization.", authd(), "rootOnly", pass({ "PPB-C03": "TRUST_EVALUATION/ESTABLISHED", "PPB-C04": "SOURCE_ASSERTION/ASSERTED" })],
  ["auth-valid-supplied-out-of-band", "Bundle has no authorization; the relying party supplies the one it holds.", full(), "rootOnly", pass(), null, { authorizations: "a1" }],
  ["auth-valid-revocation-checked", "Revocation list from the root supplied; this authorization is not on it.", authd(), "rootOnly", pass(), null, { revocations: "revokesOther" }],
  ["auth-valid-second-authorization", "Two authorizations for the key; the first by id is expired, the second covers the record.", authd({ authorizations: [authorize(ROOT, K1, { id: "ia_a-old", notBefore: "2025-01-01T00:00:00.000Z", notAfter: "2025-12-31T23:59:59.000Z" }), A1] }), "rootOnly", pass()],
  ["auth-valid-rotation", "Records under the previous gateway key, manifest under the current one; each key has its own authorization.", makeBundle({ signer: K1, receipt: rOld, outcome: oOld, authorizations: [A0, A1] }), "rootOnly", pass()],
  ["auth-missing", "Valid signatures, root trusted, but nothing authorizes this gateway key: issuer not established.", full(), "rootOnly", failed("SIGNER_UNTRUSTED")],
  ["auth-no-trust-store", "Authorization present, no trust store: it proves nothing by itself.", authd(), null, C({ overall: "INCOMPLETE", exit: 3, failureCodes: [], claims: { "PPB-C03": "TRUST_EVALUATION/NOT_ESTABLISHED" } })],
  ["auth-issuer-root-unknown", "Authorization signed by a root that is not in the trust store.", authd({ authorizations: [authorize(OTHERROOT, K1)] }), "rootOnly", failed("SIGNER_UNTRUSTED")],
  ["auth-issuer-root-impersonated", "Authorization signed by an attacker key that reuses the real root's key id.", authd({ authorizations: [authorize(EVILROOT, K1)] }), "rootOnly", failed("SIGNER_AUTHORIZATION_INVALID")],
  ["auth-gateway-key-substituted", "Attacker signs with its own key under the gateway's key id and attaches the genuine authorization.", makeBundle({ signer: EVIL, receipt: evilReceipt, embed: [EVIL], authorizations: [A1] }), "rootOnly", failed("SIGNATURE_INVALID")],
  ["auth-scope-widened-by-gateway", "Gateway edits its own authorization (adds a tenant) and re-signs the bundle; the root's signature no longer matches.", authd({ authorizations: [reencode(A1, (p) => p.scope.tenants.push("globex"))] }), "rootOnly", failed("SIGNER_AUTHORIZATION_INVALID")],
  ["auth-expired", "Record time is after the authorization's notAfter.", authd({ authorizations: [authorize(ROOT, K1, { notAfter: "2026-01-10T00:00:00.000Z" })] }), "rootOnly", failed("SIGNER_OUTSIDE_VALIDITY")],
  ["auth-not-yet-valid", "Record time is before the authorization's notBefore.", authd({ authorizations: [authorize(ROOT, K1, { notBefore: "2026-03-01T00:00:00.000Z" })] }), "rootOnly", failed("SIGNER_OUTSIDE_VALIDITY")],
  ["auth-wrong-tenant", "Authorization covers another tenant.", authd({ authorizations: [authorize(ROOT, K1, { tenants: ["globex"] })] }), "rootOnly", failed("SIGNER_TENANT_NOT_AUTHORIZED")],
  ["auth-wrong-environment", "Authorization covers another environment.", authd({ authorizations: [authorize(ROOT, K1, { environments: ["staging"] })] }), "rootOnly", failed("SIGNER_TENANT_NOT_AUTHORIZED")],
  ["auth-record-kind-not-authorized", "Key is authorized for receipts and manifests, not execution outcomes.", authd({ authorizations: [authorize(ROOT, K1, { records: ["manifest", "authorization-receipt"] })] }), "rootOnly", failed("SIGNER_RECORD_NOT_AUTHORIZED")],
  ["auth-revoked", "The root's revocation list names this authorization.", authd(), "rootOnly", failed("SIGNER_REVOKED"), null, { revocations: "revokesA1" }],
  ["auth-root-revoked", "The issuer root itself is marked revoked in the trust store.", authd(), "rootRevoked", failed("SIGNER_REVOKED")],
  ["auth-root-outside-validity", "Authorization issued after the root's own notAfter.", authd(), "rootExpired", failed("SIGNER_OUTSIDE_VALIDITY")],
  ["auth-rotation-old-key-unauthorized", "Rotation, but only the current key carries an authorization.", makeBundle({ signer: K1, receipt: rOld, outcome: oOld, authorizations: [A1] }), "rootOnly", failed("SIGNER_UNTRUSTED")],
  ["auth-receipt-signer-unauthorized", "Manifest signer is authorized; the receipt was signed by a key nothing authorizes.", makeBundle({ signer: K1, receipt: issueReceipt(OTHER, { ...read, receiptId: "rcpt_00000000000000000000000c", decision: "ALLOW" }), embed: [K1, OTHER], authorizations: [A1] }), "rootOnly", failed("SIGNER_UNTRUSTED")],
  ["auth-root-used-as-record-signer", "Bundle signed directly with the issuer root key: a root authorizes, it does not sign records.", makeBundle({ signer: ROOT, receipt: issueReceipt(ROOT, { ...read, receiptId: "rcpt_00000000000000000000000d", decision: "ALLOW" }), embed: [ROOT] }), "rootOnly", failed("SIGNER_UNTRUSTED")],
  ["error-auth-unknown-field", "Authorization payload with a field v1 does not define.", authd({ authorizations: [reencode(A1, (p) => { p.scope.capabilities = ["*"]; })] }), "rootOnly", error("MALFORMED_AUTHORIZATION")],
  ["error-auth-algorithm", "Authorization envelope declares RS256.", authd({ authorizations: [{ ...A1, signatures: [{ ...A1.signatures[0], algorithm: "RS256" }] }] }), "rootOnly", error("UNSUPPORTED_ALGORITHM")],
  ["error-revocation-list-forged", "Revocation list signed by a key that is not the trusted root (same key id).", authd(), "rootOnly", error("REVOCATION_LIST_INVALID"), null, { revocations: "revocationsForged" }],
  ["error-revocation-list-other-root", "Revocation list signed by a root you do not trust.", authd(), "rootOnly", error("REVOCATION_LIST_INVALID"), null, { revocations: "revocationsOtherRoot" }],
  // ---- found by independent review: each of these once passed, crashed, or diverged between implementations
  ["signed-risk-names-object-property", "risk 'constructor' with a default-DENY policy and an ALLOW decision.", makeBundle({ signer: K1, receipt: issueReceipt(K1, { capabilityId: "vec.unlisted", action: "tool:x", args: null, risk: "constructor", receiptId: "rcpt_00000000000000000000000e", decision: "ALLOW" }), ruleset: POLICY }), "trusted", failed("CONTRADICTORY_RECORDS")],
  ["valid-artifact-named-constructor", "An explanatory file called 'constructor'.", makeBundle({ signer: K1, receipt: rAllow, extraFiles: { constructor: "explanatory\n" } }), "trusted", pass()],
  ["valid-embedded-keys-malformed", "Embedded key file with an entry that has no jwk: ignored, never fatal, never trusted.", makeBundle({ signer: K1, receipt: rAllow, extraFiles: { [PATHS.embeddedKeys]: '{"format":"strix-ppb-trust-store","formatVersion":"1.0","keys":[{"keyId":"vec-signer-2026"}]}\n' } }), "trusted", pass()],
  ["error-receipt-schema-names-object-property", "Receipt schemaVersion 'constructor'.", makeBundle({ signer: K1, receipt: { ...rAllow, schemaVersion: "constructor" } }), "trusted", error("UNSUPPORTED_RECORD_VERSION")],
  ["error-receipt-schema-number", "Receipt schemaVersion is the number 2, not the string.", makeBundle({ signer: K1, receipt: { ...rAllow, schemaVersion: 2 } }), "trusted", error("UNSUPPORTED_RECORD_VERSION")],
  ["error-receipt-declares-algorithm", "Receipt declares signatureAlgorithm RS256.", makeBundle({ signer: K1, receipt: { ...rAllow, signatureAlgorithm: "RS256" } }), "trusted", error("UNSUPPORTED_ALGORITHM")],
  ["error-schema-1-receipt-with-tenant", "Schema-1 receipt with an (unsigned) tenantId written beside it.", makeBundle({ signer: K1, receipt: { ...rV1, tenantId: "victim-tenant", environment: "prod" } }), "trusted", error("MALFORMED_RECORD")],
  ["error-receipt-hash-not-hex", "invocationHash is not 64 hex characters.", makeBundle({ signer: K1, receipt: issueReceipt(K1, { ...read, receiptId: "rcpt_00000000000000000000000f", decision: "ALLOW", overrideSigned: { invocationHash: "not-a-hash" } }) }), "trusted", error("MALFORMED_RECORD")],
  ["error-receipt-lone-surrogate", "A string containing an unpaired surrogate escape.", rawReceipt(JSON.stringify({ ...rAllow, tool: "x" }, null, 2).replace('"tool": "x"', '"tool": "\\ud800"') + "\n"), "trusted", error("MALFORMED_JSON")],
  ["error-policy-rule-not-a-decision", "Disclosed policy with a rule value that is not ALLOW, DENY or APPROVAL_REQUIRED.", makeBundle({ signer: K1, receipt: rAllow, ruleset: { rules: {}, riskOverrides: { LOW: [] }, default: "DENY" } }), "trusted", error("MALFORMED_RECORD")],
  ["error-invocation-disclosure-extra-field", "Invocation disclosure with a sixth field.", makeBundle({ signer: K1, receipt: rAllow, invocation: { ...invocationOf(read), note: "x" } }), "trusted", error("MALFORMED_RECORD")],
  ["signed-invocation-names-other-action", "Receipt for tool:read whose invocationHash commits to a delete; the delete is disclosed.", makeBundle({ signer: K1, receipt: issueReceipt(K1, { ...read, receiptId: "rcpt_000000000000000000000010", decision: "ALLOW", hashOver: invocationOf(del) }), invocation: invocationOf(del) }), "trusted", failed("CONTRADICTORY_RECORDS")],
  ["signed-time-february-30", "Receipt timestamp 2026-02-30.", timed("2026-02-30T10:00:00.000Z"), "trusted", failed("BAD_TIMESTAMP")],
  ["signed-time-hour-24", "Receipt timestamp with hour 24.", timed("2026-01-15T24:00:00Z"), "trusted", failed("BAD_TIMESTAMP")],
  ["signed-time-offset-minute-60", "Receipt timestamp with offset +00:60.", timed("2026-01-15T10:00:00+00:60"), "trusted", failed("BAD_TIMESTAMP")],
  ["signed-time-non-ascii-digits", "Receipt timestamp with Arabic-Indic fraction digits.", timed("2026-01-15T10:00:00.١٢٣Z"), "trusted", failed("BAD_TIMESTAMP")],
  ["valid-time-with-offset", "Receipt timestamp with a +05:30 offset and nine fraction digits.", timed("2026-01-15T15:30:00.123456789+05:30"), "trusted", pass()],
  ["error-created-at-february-30", "Manifest createdAt 2026-02-30.", makeBundle({ signer: K1, receipt: rAllow, createdAt: "2026-02-30T10:00:00.000Z" }), "trusted", error("MALFORMED_MANIFEST")],
  ["signed-signature-encoding-not-canonical", "Receipt signature re-encoded with a stray trailing bit.", makeBundle({ signer: K1, receipt: { ...rAllow, signature: strayBit(rAllow.signature) } }), "trusted", failed("SIGNATURE_INVALID")],
  ["error-trust-store-null-status", "Trust store entry with status null.", full(), "nullStatus", error("MALFORMED_TRUST_STORE")],
  ["error-trust-store-entry-without-jwk", "Trust store entry with no jwk.", full(), "noJwk", error("MALFORMED_TRUST_STORE")],
  // ---- input that cannot be evaluated
  ["error-unsupported-format-version", "formatVersion 2.0.", makeBundle({ signer: K1, receipt: rAllow, tweak: (m) => { m.formatVersion = "2.0"; } }), "trusted", error("UNSUPPORTED_VERSION")],
  ["error-unknown-critical-extension", "A critical extension this verifier does not implement.", makeBundle({ signer: K1, receipt: rAllow, tweak: (m) => { m.critical = ["x-attested-enforcement"]; } }), "trusted", error("UNKNOWN_CRITICAL_EXTENSION")],
  ["error-digest-algorithm-downgrade", "digestAlgorithm md5.", makeBundle({ signer: K1, receipt: rAllow, tweak: (m) => { m.digestAlgorithm = "md5"; } }), "trusted", error("UNSUPPORTED_ALGORITHM")],
  ["error-signature-algorithm-none", "Manifest signer algorithm 'none'.", makeBundle({ signer: K1, receipt: rAllow, tweak: (m) => { m.signer.algorithm = "none"; } }), "trusted", error("UNSUPPORTED_ALGORITHM")],
  ["error-signature-envelope-algorithm", "Signature envelope declares HS256.", makeBundle({ signer: K1, receipt: rAllow, sigTweak: (s) => { s.signatures[0].algorithm = "HS256"; } }), "trusted", error("UNSUPPORTED_ALGORITHM")],
  ["error-two-signatures", "Signature envelope with two signatures (ambiguous in v1).", makeBundle({ signer: K1, receipt: rAllow, sigTweak: (s) => { s.signatures.push({ ...s.signatures[0] }); } }), "trusted", error("MALFORMED_SIGNATURE")],
  ["error-unknown-manifest-field", "Unknown top-level manifest field.", makeBundle({ signer: K1, receipt: rAllow, tweak: (m) => { m.enforcementVerified = true; } }), "trusted", error("MALFORMED_MANIFEST")],
  ["error-role-on-wrong-path", "Evidence role claimed by a file at a non-standard path.", makeBundle({ signer: K1, receipt: rAllow, extraFiles: { "evidence/extra.json": "{}" }, tweak: (m) => { m.artifacts.find((a) => a.path === "evidence/extra.json").role = "execution-outcome"; } }), "trusted", error("MALFORMED_MANIFEST")],
  ["error-unsupported-receipt-schema", "Receipt schemaVersion 3.", makeBundle({ signer: K1, receipt: { ...rAllow, schemaVersion: "3" } }), "trusted", error("UNSUPPORTED_RECORD_VERSION")],
  ["error-outcome-unsigned-extra-field", "Outcome carries a field its signature does not cover.", makeBundle({ signer: K1, receipt: rAllow, outcome: { ...oAllow, note: "everything was enforced" } }), "trusted", error("MALFORMED_RECORD")],
  ["error-malformed-manifest-json", "manifest.json is not JSON.", mutate(full(), (m) => m.set(PATHS.manifest, Buffer.from('{"format": "strix-portable-proof-bundle", '))), "trusted", error("MALFORMED_JSON")],
  ["error-duplicate-key-manifest", "manifest.json repeats a key.", mutate(full(), (m) => m.set(PATHS.manifest, Buffer.from(m.get(PATHS.manifest).toString("utf8").replace('"critical": [],', '"critical": [],\n  "critical": [],')))), "trusted", error("MALFORMED_JSON")],
  ["error-duplicate-key-receipt", "Receipt repeats 'decision' (DENY then ALLOW).", (() => { const txt = JSON.stringify(rDeny, null, 2).replace('"decision": "DENY",', '"decision": "DENY",\n  "decision": "ALLOW",') + "\n"; const rec = Buffer.from(txt); const f = makeBundle({ signer: K1, receipt: rDeny }); return signManifest(mutate(f, (m) => m.set(PATHS.receipt, rec)), (() => { const man = JSON.parse(f.get(PATHS.manifest).toString("utf8")); const a = man.artifacts.find((x) => x.path === PATHS.receipt); a.size = rec.length; a.sha256 = "PLACEHOLDER"; return man; })(), K1); })(), "trusted", null],
  ["error-bom-manifest", "manifest.json starts with a byte-order mark.", mutate(full(), (m) => m.set(PATHS.manifest, Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), m.get(PATHS.manifest)]))), "trusted", error("MALFORMED_JSON")],
  ["error-invalid-utf8-manifest", "manifest.json is not valid UTF-8.", mutate(full(), (m) => m.set(PATHS.manifest, Buffer.concat([m.get(PATHS.manifest), Buffer.from([0xff])]))), "trusted", error("MALFORMED_JSON")],
  ["error-missing-manifest", "No manifest.json.", mutate(full(), (m) => m.delete(PATHS.manifest)), "trusted", error("NOT_A_BUNDLE")],
  ["error-path-traversal", "Carrier entry '../outside.json'.", rawCarrier(`{"format":"strix-ppb-carrier","formatVersion":"1.0","files":{"../outside.json":"${b64("{}")}"}}`), "trusted", error("UNSAFE_PATH")],
  ["error-path-absolute", "Carrier entry '/etc/passwd'.", rawCarrier(`{"format":"strix-ppb-carrier","formatVersion":"1.0","files":{"/etc/passwd":"${b64("x")}"}}`), "trusted", error("UNSAFE_PATH")],
  ["error-path-backslash", "Carrier entry 'evidence\\\\..\\\\x'.", rawCarrier(`{"format":"strix-ppb-carrier","formatVersion":"1.0","files":{"evidence\\\\..\\\\x":"${b64("x")}"}}`), "trusted", error("UNSAFE_PATH")],
  ["error-duplicate-key-carrier", "Carrier repeats a file name.", rawCarrier(`{"format":"strix-ppb-carrier","formatVersion":"1.0","files":{"manifest.json":"${b64("{}")}","manifest.json":"${b64("[]")}"}}`), "trusted", error("MALFORMED_JSON")],
  ["error-case-colliding-paths", "Two entries that differ only by case.", rawCarrier(`{"format":"strix-ppb-carrier","formatVersion":"1.0","files":{"README.md":"${b64("a")}","readme.md":"${b64("b")}"}}`), "trusted", error("DUPLICATE_PATH")],
  ["error-carrier-not-base64", "Carrier file content is not canonical base64.", rawCarrier('{"format":"strix-ppb-carrier","formatVersion":"1.0","files":{"manifest.json":"e30"}}'), "trusted", error("MALFORMED_CARRIER")],
  ["error-not-a-carrier", "A JSON file that is not a carrier.", rawCarrier('{"hello":"world"}'), "trusted", error("NOT_A_BUNDLE")],
];

// The duplicate-key receipt vector needs a real digest for the forged file.
{
  const v = V.find((x) => x[0] === "error-duplicate-key-receipt");
  const f = v[2];
  const man = JSON.parse(f.get(PATHS.manifest).toString("utf8"));
  const { createHash } = await import("node:crypto");
  man.artifacts.find((a) => a.path === PATHS.receipt).sha256 = createHash("sha256").update(f.get(PATHS.receipt)).digest("hex");
  v[2] = signManifest(f, man, K1);
  v[4] = error("MALFORMED_JSON");
}

export function generate() {
  const out = new Map();
  for (const [name, store] of Object.entries(T)) out.set(`trust/${name}.json`, jsonBytes(store));
  for (const [name, doc] of Object.entries(X)) out.set(`inputs/${name}.json`, jsonBytes(doc));
  const index = {
    description: "Public test vectors for Strix Portable Proof Bundle v1. ALL SYNTHETIC: issued with test keys derivable from test/helpers/synth.mjs. Never add these keys to a real trust store.",
    formatVersion: "1.0",
    generatedBy: "vectors/generate.mjs",
    vectors: V.map(([name, description, bundle, trust, expect, expectOpts, inputs]) => {
      out.set(`bundles/${name}.ppb.json`, Buffer.isBuffer(bundle) ? bundle : carrierBytes(bundle));
      return {
        name, description, bundle: `bundles/${name}.ppb.json`, trustStore: trust ? `trust/${trust}.json` : null,
        ...(inputs?.authorizations ? { issuerAuthorizations: `inputs/${inputs.authorizations}.json` } : {}),
        ...(inputs?.revocations ? { revocations: `inputs/${inputs.revocations}.json` } : {}),
        ...(expectOpts ? { expectOptions: expectOpts } : {}), expect,
      };
    }),
  };
  out.set("index.json", jsonBytes(index));
  return out;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const files = generate();
  if (process.argv.includes("--check")) {
    let bad = 0;
    for (const [p, buf] of files) {
      const abs = path.join(here, p);
      if (!fs.existsSync(abs) || !fs.readFileSync(abs).equals(buf)) {
        console.error(`DIFFERS ${p}`);
        bad++;
      }
    }
    console.log(bad ? `${bad} file(s) differ` : `${files.size} vector files reproduce byte-for-byte`);
    process.exit(bad ? 1 : 0);
  }
  for (const d of ["bundles", "trust", "inputs"]) fs.rmSync(path.join(here, d), { recursive: true, force: true });
  for (const [p, buf] of files) {
    fs.mkdirSync(path.dirname(path.join(here, p)), { recursive: true });
    fs.writeFileSync(path.join(here, p), buf);
  }
  console.log(`wrote ${files.size} files (${V.length} vectors)`);
}
