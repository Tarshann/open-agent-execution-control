// TEST-ONLY synthetic issuer. Produces records in the published
// @strixgov/tool-gateway formats (receipt schema 1/2, execution-outcome 1)
// with DETERMINISTIC TEST KEYS whose private halves are derivable from this
// file. Nothing made here is a real governed action, and none of these keys
// may ever appear in a real trust store.
//
// test/interop.test.mjs checks that records issued here are accepted by the
// real @strixgov/verifier, so this file cannot drift from the real format
// unnoticed.
import crypto from "node:crypto";
import { issueAuthorization, issueRevocations } from "../../authority/strix-proof-authorize.mjs";
import {
  AUTHORIZATIONS_FORMAT, FORMAT, MANIFEST_PAYLOAD_TYPE, PATHS, SIGNATURE_FORMAT, CARRIER_FORMAT,
  canonicalJSON, computeBundleId, manifestSignedBytes, outcomeHashOf, outcomeSignedBytes,
} from "../../verifier/strix-proof-verify.mjs";

export const sha256Hex = (b) => crypto.createHash("sha256").update(b).digest("hex");
export const jsonBytes = (v) => Buffer.from(JSON.stringify(v, null, 2) + "\n", "utf8");

/** Deterministic Ed25519 key from a label (seed = SHA-256 of the label). */
export function testKey(label, kid = label) {
  const seed = crypto.createHash("sha256").update(`strix-ppb-TEST-KEY:${label}`).digest();
  const privateKey = crypto.createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
  const der = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const x = der.subarray(der.length - 32).toString("base64url");
  return { kid, privateKey, jwk: { kty: "OKP", crv: "Ed25519", kid, x } };
}
const sign = (key, bytes) => crypto.sign(null, bytes, key.privateKey).toString("base64url");

export const POLICY = { rules: { "vec.read": "ALLOW", "vec.archive": "ALLOW", "vec.write": "APPROVAL_REQUIRED", "vec.delete": "DENY" }, riskOverrides: {}, default: "DENY" };
export const policyVersionOf = (p) => `sha256:${sha256Hex(Buffer.from(canonicalJSON({ rules: p.rules ?? {}, riskOverrides: p.riskOverrides ?? {}, default: p.default ?? null }), "utf8"))}`;

export function invocationOf({ capabilityId, action, args = null, actorId = "", actorRole = "" }) {
  return { capabilityId, action, args, actorId, actorRole };
}

const RAW_RECEIPT_ORDER = {
  1: ["schemaVersion", "receiptId", "capabilityId", "action", "decision", "risk", "mode", "invocationHash", "evidenceHash", "proofChainHash", "timestamp"],
  2: ["schemaVersion", "receiptId", "capabilityId", "action", "decision", "risk", "mode", "policyVersion", "tenantId", "environment", "invocationHash", "evidenceHash", "proofChainHash", "timestamp"],
};

/** Authorization receipt, as @strixgov/tool-gateway issueReceipt() would produce it. */
export function issueReceipt(key, o) {
  const inv = o.hashOver ?? invocationOf(o); // hashOver: a receipt whose hash commits to some OTHER invocation
  const invocationHash = sha256Hex(Buffer.from(canonicalJSON(inv), "utf8"));
  const timestamp = o.timestamp ?? "2026-01-15T10:00:00.000Z";
  const evidenceHash = sha256Hex(Buffer.from(`${invocationHash}|${o.decision}|${timestamp}`, "utf8"));
  const proofChainHash = sha256Hex(Buffer.from(`${o.prev ?? "0".repeat(64)}|${evidenceHash}`, "utf8"));
  const schemaVersion = o.schemaVersion ?? "2";
  const r = { schemaVersion, receiptId: o.receiptId, capabilityId: o.capabilityId, action: o.action, decision: o.decision, risk: o.risk ?? "LOW", mode: o.mode ?? "READ" };
  if (schemaVersion === "2") Object.assign(r, { policyVersion: o.policyVersion ?? policyVersionOf(POLICY), tenantId: o.tenantId ?? "acme", environment: o.environment ?? "prod" });
  Object.assign(r, { invocationHash, evidenceHash, proofChainHash, timestamp });
  Object.assign(r, o.overrideSigned ?? {});
  // Signed with a raw serializer, not the verifier's: a test issuer must be able to sign
  // receipts the verifier is meant to refuse.
  const order = RAW_RECEIPT_ORDER[schemaVersion] ?? RAW_RECEIPT_ORDER["2"];
  const signature = sign(key, Buffer.from(`{${order.map((f) => `${JSON.stringify(f)}:${JSON.stringify(r[f])}`).join(",")}}`, "utf8"));
  return { ...r, signingKeyId: key.kid, signature, tool: "strix-gateway", ...(o.unsigned ?? {}) };
}

/** Execution outcome, as issueExecutionOutcome() would produce it. */
export function issueOutcome(key, receipt, o = {}) {
  const st = o.executionStatus ?? "SUCCEEDED";
  const core = {
    schemaVersion: "1", outcomeId: o.outcomeId ?? `out_${receipt.receiptId.slice(5)}`,
    authorizationReceiptId: receipt.receiptId, authorizationProofChainHash: receipt.proofChainHash,
    capabilityId: receipt.capabilityId, action: receipt.action, decision: "ALLOW", executionAttempted: true, executionStatus: st,
    invocationHash: receipt.invocationHash, resultHash: st === "SUCCEEDED" ? `sha256:${sha256Hex(Buffer.from(canonicalJSON(o.result ?? { ok: true }), "utf8"))}` : "",
    errorCode: st === "FAILED" ? (o.errorCode ?? "TOOL_REPORTED_ERROR") : "",
    policyVersion: receipt.policyVersion, tenantId: receipt.tenantId, environment: receipt.environment,
    completedAt: o.completedAt ?? "2026-01-15T10:00:00.250Z", signingKeyId: key.kid, signatureAlgorithm: "Ed25519",
    ...(o.overrideCore ?? {}),
  };
  const withHash = { ...core, outcomeHash: outcomeHashOf(core) };
  return { ...withHash, signature: sign(key, outcomeSignedBytes(withHash)) };
}

/** Issuer authorization for a test gateway key, signed by a test root. Deterministic. */
export function authorize(root, gateway, o = {}) {
  return issueAuthorization({
    rootKey: root.privateKey, rootKid: root.kid, issuer: "SYNTHETIC TEST ISSUER", gatewayId: o.gatewayId ?? "gw-test-1", gatewayJwk: gateway.jwk,
    tenants: o.tenants ?? ["acme"], environments: o.environments ?? ["prod"], records: o.records,
    notBefore: o.notBefore ?? "2026-01-01T00:00:00.000Z", notAfter: o.notAfter ?? "2026-12-31T23:59:59.000Z",
    issuedAt: o.issuedAt ?? "2026-01-01T00:00:00.000Z", authorizationId: o.id ?? `ia_${gateway.kid}`,
  });
}
export const revocationList = (root, ids, issuedAt = "2026-06-01T00:00:00.000Z") =>
  issueRevocations({ rootKey: root.privateKey, rootKid: root.kid, issuer: "SYNTHETIC TEST ISSUER", issuedAt, revoked: ids.map((id) => ({ authorizationId: id, revokedAt: issuedAt })) });
export const authorizationsDoc = (envs) => ({ format: AUTHORIZATIONS_FORMAT, formatVersion: "1.0", authorizations: envs });
export const rootStoreOf = (root, extra = {}) => ({ format: "strix-ppb-trust-store", formatVersion: "1.0", keys: [{ keyId: root.kid, role: "issuer-root", owner: "SYNTHETIC TEST ISSUER ROOT - never trust", status: "active", jwk: root.jwk, ...extra }] });

const ROLE = { [PATHS.authorizations]: "issuer-authorizations", [PATHS.receipt]: "authorization-receipt", [PATHS.outcome]: "execution-outcome", [PATHS.invocation]: "invocation-disclosure", [PATHS.policy]: "policy-disclosure", [PATHS.embeddedKeys]: "embedded-signer-keys" };

/**
 * Assemble and sign a bundle WITHOUT the exporter's safety guards, so tests can
 * build bundles that are validly signed yet internally inconsistent.
 * `tweak(manifest)` runs before the bundleId is derived; `tweakFinal(manifest)`
 * runs after it and before signing.
 */
export function makeBundle({ signer, receipt, outcome = null, invocation = null, ruleset = null, embed = [], authorizations = null, extraFiles = {}, createdAt = "2026-01-15T10:05:00.000Z", tweak = null, tweakFinal = null, sigTweak = null }) {
  const files = new Map();
  files.set(PATHS.receipt, jsonBytes(receipt));
  if (outcome) files.set(PATHS.outcome, jsonBytes(outcome));
  if (invocation) files.set(PATHS.invocation, jsonBytes(invocation));
  if (ruleset) files.set(PATHS.policy, jsonBytes(ruleset));
  if (embed.length) files.set(PATHS.embeddedKeys, jsonBytes({ keys: embed.map((k) => k.jwk) }));
  if (authorizations) files.set(PATHS.authorizations, jsonBytes(authorizationsDoc(authorizations)));
  for (const [p, c] of Object.entries(extraFiles)) files.set(p, Buffer.from(c, "utf8"));
  const manifest = {
    format: FORMAT, formatVersion: "1.0", critical: [], bundleId: "", createdAt,
    exporter: { name: "synthetic-test-issuer", version: "0.0.0" },
    subject: { kind: "governed-action", receiptId: receipt.receiptId, tenantId: receipt.tenantId ?? "UNSPECIFIED", environment: receipt.environment ?? "UNSPECIFIED", capabilityId: receipt.capabilityId, action: receipt.action, invocationHash: receipt.invocationHash },
    evidence: {
      authorizationDecision: "PRESENT",
      executionOutcome: outcome ? "PRESENT" : receipt.decision === "ALLOW" ? "ABSENT" : "NOT_APPLICABLE",
      enforcementObservation: "NOT_CAPTURED",
      invocationDisclosure: invocation ? "PRESENT" : "NOT_DISCLOSED",
      policyDisclosure: ruleset ? "PRESENT" : "NOT_DISCLOSED",
    },
    digestAlgorithm: "sha-256",
    artifacts: [...files.keys()].sort().map((p) => ({ path: p, role: Object.hasOwn(ROLE, p) ? ROLE[p] : "explanatory", sha256: sha256Hex(files.get(p)), size: files.get(p).length })),
    signer: { keyId: signer.kid, algorithm: "Ed25519" },
  };
  if (tweak) tweak(manifest);
  manifest.bundleId = computeBundleId(manifest);
  if (tweakFinal) tweakFinal(manifest);
  return signManifest(files, manifest, signer, sigTweak);
}

export function signManifest(files, manifest, signer, sigTweak = null) {
  const out = new Map(files);
  const manifestBytes = jsonBytes(manifest);
  const sigDoc = { format: SIGNATURE_FORMAT, formatVersion: "1.0", payloadType: MANIFEST_PAYLOAD_TYPE, signatures: [{ keyId: signer.kid, algorithm: "Ed25519", signature: sign(signer, manifestSignedBytes(manifestBytes)) }] };
  if (sigTweak) sigTweak(sigDoc);
  out.set(PATHS.manifest, manifestBytes);
  out.set(PATHS.signature, jsonBytes(sigDoc));
  return out;
}

export function carrierBytes(files) {
  const obj = {};
  for (const p of [...files.keys()].sort()) obj[p] = files.get(p).toString("base64");
  return jsonBytes({ format: CARRIER_FORMAT, formatVersion: "1.0", files: obj });
}

export const trustStoreOf = (...entries) => ({ format: "strix-ppb-trust-store", formatVersion: "1.0", keys: entries.map((e) => (e.jwk && e.keyId ? e : { keyId: e.kid, owner: "SYNTHETIC TEST SIGNER - never trust", status: "active", jwk: e.jwk })) });
