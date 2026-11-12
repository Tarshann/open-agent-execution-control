#!/usr/bin/env node
// Strix Portable Proof Bundle v1 — exporter (operator side).
//
// Turns ONE governed action already recorded by a Strix gateway
// (@strixgov/tool-gateway / @strixgov/mcp-proxy store) into a portable bundle.
// It reuses what the gateway already produced and already holds:
//   - the signed authorization receipt        (<store>/receipts.jsonl)
//   - the signed execution outcome, if any    (<store>/execution-outcomes.jsonl)
//   - the gateway's Ed25519 signing key       (<key-dir>/signing-key.pem)
// It makes no policy decision, records no event, and never creates a key.
//
// Zero dependencies beyond the verifier module in this package.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  AUTHORIZATIONS_FORMAT, BundleError, CARRIER_FORMAT, FORMAT, MANIFEST_PAYLOAD_TYPE, PATHS, SIGNATURE_FORMAT, TRUST_STORE_FORMAT,
  canonicalJSON, computeBundleId, manifestSignedBytes, outcomeHashOf, outcomeSignedBytes, parseAuthorization, parseStrictJson,
  parseTrustStore, receiptSignedBytes, verifyBundle, loadBundle,
} from "../verifier/strix-proof-verify.mjs";

export const EXPORTER_NAME = "strix-proof-export";
export const EXPORTER_VERSION = "1.0.0";
const RECEIPTS_FILE = "receipts.jsonl";
const OUTCOMES_FILE = "execution-outcomes.jsonl";
const AUDIT_FILE = "proof-bundle-exports.jsonl";
const MAX_STORE_BYTES = 256 * 1024 * 1024;

/** A refusal to export. `code` is stable; `message` never contains evidence content or key material. */
export class ExportError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

const sha256Hex = (b) => crypto.createHash("sha256").update(b).digest("hex");
const jsonBytes = (v) => Buffer.from(JSON.stringify(v, null, 2) + "\n", "utf8");

function readJsonl(file, label) {
  if (!fs.existsSync(file)) return null;
  if (fs.statSync(file).size > MAX_STORE_BYTES) throw new ExportError("STORE_TOO_LARGE", `${label} exceeds ${MAX_STORE_BYTES} bytes`);
  const text = fs.readFileSync(file, "utf8");
  const lines = text.split("\n");
  const out = [];
  lines.forEach((line, i) => {
    if (!line.trim()) return;
    try {
      out.push(parseStrictJson(line, `${label} line ${i + 1}`));
    } catch {
      // A torn final line is a write in progress, not corruption.
      if (i === lines.length - 1 && !text.endsWith("\n")) return;
      throw new ExportError("STORE_CORRUPT", `${label} line ${i + 1} is not valid JSON`);
    }
  });
  return out;
}

const KID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;

/**
 * Resolve --key-dir to the directory holding the active key, and collect the
 * public JWKs of retired keys. Two layouts exist:
 *   flat    (mcp-proxy):        <dir>/signing-key.pem, public-jwk.json
 *   keyring (gateway KeyRing):  <dir>/active (text: kid), <dir>/<kid>/{signing-key.pem,public-jwk.json,meta.json}
 * Only public JWKs are read from non-active keyring entries.
 */
function resolveKeyDir(keyDir) {
  const unavailable = (m) => new ExportError("SIGNING_UNAVAILABLE", m);
  if (fs.existsSync(path.join(keyDir, "signing-key.pem"))) return { dir: keyDir, retired: [], expectKid: null };
  let kid;
  try {
    kid = fs.readFileSync(path.join(keyDir, "active"), "utf8").trim();
  } catch {
    throw unavailable("the gateway signing key could not be read from --key-dir; nothing was exported");
  }
  // The pointer becomes a path segment: it must be a plain name, never a path.
  if (!KID_RE.test(kid) || kid.endsWith(".")) throw unavailable("the keyring's active pointer is not a valid key id");
  const retired = [];
  for (const ent of fs.readdirSync(keyDir, { withFileTypes: true })) {
    if (!ent.isDirectory() || ent.name === kid || !KID_RE.test(ent.name)) continue;
    let jwk;
    try {
      jwk = parseStrictJson(fs.readFileSync(path.join(keyDir, ent.name, "public-jwk.json")), "public-jwk.json");
    } catch {
      continue; // a directory that is not a key entry
    }
    // In a keyring the directory name is the key id; a mismatch means the ring is damaged.
    if (jwk?.kid !== ent.name) throw unavailable("a keyring entry's public key does not match its directory name");
    retired.push({ kty: jwk.kty, crv: jwk.crv, kid: jwk.kid, x: jwk.x });
  }
  return { dir: path.join(keyDir, kid), retired, expectKid: kid };
}

/** Tenant or environment of a stored receipt. Schema 1 signs neither, so it is always UNSPECIFIED. */
const scopeOf = (r, field) => (r?.schemaVersion === "1" ? "UNSPECIFIED" : typeof r?.[field] === "string" ? r[field] : null);

/** Load the gateway's existing signing key. Never generates one. */
export function loadSigningKey(keyRoot) {
  const { dir: keyDir, retired, expectKid } = resolveKeyDir(keyRoot);
  let pem, jwk;
  try {
    pem = fs.readFileSync(path.join(keyDir, "signing-key.pem"), "utf8");
    jwk = parseStrictJson(fs.readFileSync(path.join(keyDir, "public-jwk.json")), "public-jwk.json");
    if (expectKid && jwk?.kid !== expectKid) jwk = null;
  } catch {
    throw new ExportError("SIGNING_UNAVAILABLE", "the gateway signing key could not be read from --key-dir; nothing was exported");
  }
  let privateKey;
  try {
    privateKey = crypto.createPrivateKey({ key: pem, format: "pem" });
  } catch {
    throw new ExportError("SIGNING_UNAVAILABLE", "the gateway signing key is not a readable private key");
  }
  if (privateKey.asymmetricKeyType !== "ed25519") throw new ExportError("SIGNING_UNAVAILABLE", "the gateway signing key is not Ed25519");
  const der = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
  const x = der.subarray(der.length - 32).toString("base64url");
  if (jwk?.kty !== "OKP" || jwk?.crv !== "Ed25519" || typeof jwk?.kid !== "string" || !jwk.kid || jwk.x !== x) {
    throw new ExportError("SIGNING_UNAVAILABLE", "public-jwk.json does not describe the private key next to it");
  }
  return { kid: jwk.kid, privateKey, jwk: { kty: "OKP", crv: "Ed25519", kid: jwk.kid, x }, retired };
}

function nativeVerify(label, record, bytesFn, keys) {
  let bytes;
  try {
    bytes = bytesFn(record);
  } catch (e) {
    throw new ExportError("REFUSED_UNVERIFIED_RECORD", `the stored ${label} is not a well-formed record (${e.code ?? "MALFORMED_RECORD"})`);
  }
  const key = keys.get(record.signingKeyId);
  if (!key) throw new ExportError("REFUSED_UNVERIFIED_RECORD", `the stored ${label} was signed by a key this exporter was not given (pass it with --historical-keys)`);
  let ok = false;
  try {
    ok = crypto.verify(null, bytes, key.publicKey, Buffer.from(String(record.signature ?? ""), "base64url"));
  } catch {
    ok = false;
  }
  // Signing a manifest over a record that fails its own signature would launder it.
  if (!ok) throw new ExportError("REFUSED_UNVERIFIED_RECORD", `the stored ${label} fails its own signature check; it was not exported`);
}

function readme(m, receipt, outcome) {
  return `# Strix Portable Proof Bundle

This directory is an evidence package for ONE governed action. This file is
explanatory only: the verifier never reads it, and nothing in it is a finding.

| | |
|---|---|
| Bundle | \`${m.bundleId}\` (format ${m.formatVersion}) |
| Action | \`${receipt.action}\` (capability \`${receipt.capabilityId}\`) |
| Receipt | \`${receipt.receiptId}\` |
| Tenant / environment | \`${m.subject.tenantId}\` / \`${m.subject.environment}\` |
| Recorded decision | ${receipt.decision} |
| Execution outcome record | ${outcome ? outcome.executionStatus : m.evidence.executionOutcome} |
| Signed by key | \`${m.signer.keyId}\` |

## Verify it yourself, offline

\`\`\`
node strix-proof-verify.mjs verify <this-directory> --trust-store <your-trust-store.json>
\`\`\`

Use a trust store you obtained from the signer through a channel that is
independent of this bundle. \`trust/embedded-signer-keys.json\` is a
convenience copy and is never treated as trusted.

## What a passing verification means

It means the files are unchanged since they were signed, the signatures are
valid, the signer is one you chose to trust, and the records agree with each
other. It does **not** mean the action was enforced, executed, safe, or
compliant. The verifier prints exactly which statements the evidence supports
and which it does not.
`;
}

/**
 * Build a bundle in memory. Returns { files: Map<path, Buffer>, manifest, summary }.
 * Pure with respect to the store: reads only.
 */
export function buildBundle(opts) {
  const { storeDir, keyDir, receiptId, tenantId } = opts;
  if (!receiptId) throw new ExportError("USAGE", "--receipt-id is required");
  if (!tenantId) throw new ExportError("USAGE", "--tenant is required: an export is always scoped to one tenant");

  const receipts = readJsonl(path.join(storeDir, RECEIPTS_FILE), RECEIPTS_FILE);
  if (receipts === null) throw new ExportError("STORE_NOT_FOUND", "no receipts.jsonl in --store");
  // Tenant boundary first. Records of other tenants are filtered out before any decision is made, so
  // "exists in another tenant" and "does not exist" are the same answer, and another tenant's
  // duplicate id cannot block or reveal anything.
  const matches = receipts.filter((r) => r?.receiptId === receiptId && scopeOf(r, "tenantId") === tenantId && (!opts.environment || scopeOf(r, "environment") === opts.environment));
  if (matches.length === 0) throw new ExportError("RECEIPT_NOT_FOUND", "no governed action with that receipt id for this tenant");
  if (matches.length > 1) throw new ExportError("AMBIGUOUS_RECEIPT", "more than one stored record of this tenant carries that receipt id; refusing to choose");
  const receipt = matches[0];

  const key = loadSigningKey(keyDir);
  const known = parseTrustStore({ keys: [key.jwk] });
  for (const jwk of key.retired) {
    let parsed;
    try {
      parsed = parseTrustStore({ keys: [jwk] });
    } catch {
      throw new ExportError("SIGNING_UNAVAILABLE", "a retired key in the keyring is not a readable Ed25519 public key");
    }
    for (const [kid, entry] of parsed) if (!known.has(kid)) known.set(kid, entry);
  }
  if (opts.historicalKeys) {
    for (const [kid, entry] of parseTrustStore(fs.readFileSync(opts.historicalKeys))) if (!known.has(kid)) known.set(kid, entry);
  }
  nativeVerify("authorization receipt", receipt, receiptSignedBytes, known);

  const outcomesAll = readJsonl(path.join(storeDir, OUTCOMES_FILE), OUTCOMES_FILE) ?? [];
  const outcomes = outcomesAll.filter((o) => o?.authorizationReceiptId === receiptId);
  if (outcomes.length > 1) throw new ExportError("AMBIGUOUS_OUTCOME", "more than one execution outcome is linked to that receipt; v1 describes exactly one execution attempt");
  const outcome = outcomes[0] ?? null;
  if (outcome) {
    if (receipt.decision !== "ALLOW") throw new ExportError("CONTRADICTORY_RECORDS", "the store holds an execution outcome for an action that was not allowed; this needs investigation, not export");
    nativeVerify("execution outcome", outcome, outcomeSignedBytes, known);
    if (outcomeHashOf(outcome) !== outcome.outcomeHash) throw new ExportError("REFUSED_UNVERIFIED_RECORD", "the stored execution outcome fails its own hash check");
  }

  const files = new Map();
  files.set(PATHS.receipt, jsonBytes(receipt));
  if (outcome) files.set(PATHS.outcome, jsonBytes(outcome));

  if (opts.discloseInvocation) {
    const d = parseStrictJson(fs.readFileSync(opts.discloseInvocation), "invocation disclosure");
    const inv = { capabilityId: receipt.capabilityId, action: receipt.action, args: d?.args ?? null, actorId: d?.actorId ?? "", actorRole: d?.actorRole ?? "" };
    if (sha256Hex(Buffer.from(canonicalJSON(inv), "utf8")) !== receipt.invocationHash) {
      throw new ExportError("DISCLOSURE_MISMATCH", "the invocation you asked to disclose is not the one this receipt was issued for");
    }
    files.set(PATHS.invocation, jsonBytes(inv));
  }
  if (opts.disclosePolicy) {
    const d = parseStrictJson(fs.readFileSync(opts.disclosePolicy), "policy disclosure");
    const pol = { rules: d?.rules ?? {}, riskOverrides: d?.riskOverrides ?? {}, default: d?.default ?? null };
    if (`sha256:${sha256Hex(Buffer.from(canonicalJSON(pol), "utf8"))}` !== receipt.policyVersion) {
      throw new ExportError("DISCLOSURE_MISMATCH", "the policy you asked to disclose is not the version this receipt was issued under");
    }
    files.set(PATHS.policy, jsonBytes(pol));
  }
  if (opts.issuerAuthorizations?.length) {
    const used = new Set([key.kid, receipt.signingKeyId, ...(outcome ? [outcome.signingKeyId] : [])]);
    const byId = new Map();
    for (const file of opts.issuerAuthorizations) {
      const doc = parseStrictJson(fs.readFileSync(file), "issuer authorization");
      for (const env of Array.isArray(doc?.authorizations) ? doc.authorizations : [doc]) {
        let a;
        try {
          a = parseAuthorization(env);
        } catch (e) {
          throw new ExportError("AUTHORIZATION_MISMATCH", `an issuer authorization is not well-formed (${e.code ?? "MALFORMED_AUTHORIZATION"})`);
        }
        const k = a.payload.subject.keyId;
        // The exporter cannot judge the issuer root (that is the relying party's trust decision), but it
        // can refuse to attach an authorization for some other key.
        if (!used.has(k) || known.get(k).x !== a.x) throw new ExportError("AUTHORIZATION_MISMATCH", "an issuer authorization names a key that did not sign this bundle's records");
        byId.set(a.payload.authorizationId, env);
      }
    }
    files.set(PATHS.authorizations, jsonBytes({ format: AUTHORIZATIONS_FORMAT, formatVersion: "1.0", authorizations: [...byId.keys()].sort().map((id) => byId.get(id)) }));
  }
  if (opts.embedKeys !== false) {
    const kids = new Set([key.kid, receipt.signingKeyId, ...(outcome ? [outcome.signingKeyId] : [])]);
    files.set(PATHS.embeddedKeys, jsonBytes({ keys: [...kids].sort().map((kid) => ({ kty: "OKP", crv: "Ed25519", kid, x: known.get(kid).x })) }));
  }

  const manifest = {
    format: FORMAT,
    formatVersion: "1.0",
    critical: [],
    bundleId: "",
    createdAt: opts.now ?? new Date().toISOString(),
    exporter: { name: EXPORTER_NAME, version: EXPORTER_VERSION },
    subject: {
      kind: "governed-action",
      receiptId: receipt.receiptId,
      tenantId: scopeOf(receipt, "tenantId"),
      environment: scopeOf(receipt, "environment"),
      capabilityId: receipt.capabilityId,
      action: receipt.action,
      invocationHash: receipt.invocationHash,
    },
    evidence: {
      authorizationDecision: "PRESENT",
      executionOutcome: outcome ? "PRESENT" : receipt.decision === "ALLOW" ? "ABSENT" : "NOT_APPLICABLE",
      enforcementObservation: "NOT_CAPTURED",
      invocationDisclosure: files.has(PATHS.invocation) ? "PRESENT" : "NOT_DISCLOSED",
      policyDisclosure: files.has(PATHS.policy) ? "PRESENT" : "NOT_DISCLOSED",
    },
    digestAlgorithm: "sha-256",
    artifacts: [],
    signer: { keyId: key.kid, algorithm: "Ed25519" },
  };
  // README content depends only on fields fixed above, so it can be listed
  // before the bundleId (which commits to every artifact digest) is known.
  const inventory = () => [...files.keys()].sort().map((p) => ({ path: p, role: roleOf(p), sha256: sha256Hex(files.get(p)), size: files.get(p).length }));
  manifest.artifacts = inventory();
  manifest.bundleId = computeBundleId(manifest);
  if (opts.readme !== false) {
    files.set("README.md", Buffer.from(readme({ ...manifest, bundleId: "(see manifest.json)" }, receipt, outcome), "utf8"));
    manifest.artifacts = inventory();
    manifest.bundleId = computeBundleId(manifest);
  }

  const manifestBytes = jsonBytes(manifest);
  const signature = crypto.sign(null, manifestSignedBytes(manifestBytes), key.privateKey).toString("base64url");
  files.set(PATHS.manifest, manifestBytes);
  files.set(PATHS.signature, jsonBytes({ format: SIGNATURE_FORMAT, formatVersion: "1.0", payloadType: MANIFEST_PAYLOAD_TYPE, signatures: [{ keyId: key.kid, algorithm: "Ed25519", signature }] }));

  // Never hand out a bundle this package's own verifier would not pass.
  const self = verifyBundle(files, { trustStore: known });
  if (self.result.overall !== "PASSED") {
    throw new ExportError("EXPORT_SELF_CHECK_FAILED", `the bundle failed verification before it was written (${self.failures.map((f) => f.code).join(", ")})`);
  }
  return {
    files,
    manifest,
    summary: {
      bundleId: manifest.bundleId,
      receiptId: receipt.receiptId,
      tenantId: manifest.subject.tenantId,
      decision: receipt.decision,
      evidence: manifest.evidence,
      signerKeyId: key.kid,
      issuerAuthorizations: files.has(PATHS.authorizations),
      artifacts: manifest.artifacts.length,
    },
  };
}

const ROLE = { [PATHS.receipt]: "authorization-receipt", [PATHS.outcome]: "execution-outcome", [PATHS.invocation]: "invocation-disclosure", [PATHS.policy]: "policy-disclosure", [PATHS.embeddedKeys]: "embedded-signer-keys", [PATHS.authorizations]: "issuer-authorizations" };
const roleOf = (p) => Object.hasOwn(ROLE, p) ? ROLE[p] : "explanatory";

export function toCarrier(files) {
  const obj = {};
  for (const p of [...files.keys()].sort()) obj[p] = files.get(p).toString("base64");
  return jsonBytes({ format: CARRIER_FORMAT, formatVersion: "1.0", files: obj });
}

/** Write a bundle directory. Refuses to touch an existing path: a bundle is never overwritten. */
export function writeBundleDir(files, outDirArg) {
  const outDir = path.resolve(outDirArg); // also drops a trailing separator, which would put the temp dir inside the target
  if (fs.existsSync(outDir)) throw new ExportError("OUTPUT_EXISTS", "the output path already exists; bundles are never overwritten");
  const tmp = `${outDir}.tmp-${crypto.randomBytes(6).toString("hex")}`;
  try {
    for (const [p, buf] of files) {
      const abs = path.join(tmp, ...p.split("/"));
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, buf, { flag: "wx" });
    }
    fs.renameSync(tmp, outDir);
  } catch (e) {
    fs.rmSync(tmp, { recursive: true, force: true });
    throw e instanceof ExportError ? e : new ExportError("WRITE_FAILED", "the bundle could not be written; nothing was left behind");
  }
}

function audit(file, entry) {
  if (!file) return;
  fs.appendFileSync(file, JSON.stringify({ at: new Date().toISOString(), tool: `${EXPORTER_NAME}/${EXPORTER_VERSION}`, ...entry }) + "\n");
}

const USAGE = `strix-proof-export ${EXPORTER_VERSION} - export one governed action as a Strix Portable Proof Bundle v1

Usage:
  strix-proof-export export --store <dir> --key-dir <dir> --receipt-id <id> --tenant <id> --out <dir> [options]
  strix-proof-export list --store <dir> --tenant <id>
  strix-proof-export pack <bundle-dir> <out.ppb.json>
  strix-proof-export trust-store --key-dir <dir> --owner <text> [--tenant <id>]...

export options:
  --environment <e>             Also require the receipt's environment to match.
  --disclose-invocation <file>  JSON {args, actorId?, actorRole?}. Included only if it hashes to the signed invocationHash.
  --disclose-policy <file>      Policy ruleset JSON. Included only if it hashes to the signed policyVersion.
  --historical-keys <jwks>      Public keys for records signed before a rotation (a keyring's retired keys are found automatically).
  --issuer-authorization <file> Authorization of this gateway's key by an issuer root (repeatable). Included only
                                if it names a key that signed this bundle's records.
  --carrier <file.ppb.json>     Also write the single-file form.
  --no-embed-keys               Do not include the (untrusted) convenience copy of the public key.
  --audit-log <file>            Export audit log (default: <store>/${AUDIT_FILE}; "none" disables).

Exit codes: 0 exported, 1 refused (stable reason code on stderr), 2 usage.
`;

function parseArgs(argv) {
  const o = { _: [], tenants: [], issuerAuthorizations: [] };
  const flags = { "--store": "storeDir", "--key-dir": "keyDir", "--receipt-id": "receiptId", "--tenant": "tenantId", "--environment": "environment", "--out": "out", "--disclose-invocation": "discloseInvocation", "--disclose-policy": "disclosePolicy", "--historical-keys": "historicalKeys", "--carrier": "carrier", "--audit-log": "auditLog", "--owner": "owner", "--issuer-authorization": "issuerAuthorization" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--no-embed-keys") o.embedKeys = false;
    else if (a === "--help" || a === "-h") o.help = true;
    else if (Object.hasOwn(flags, a)) {
      if (i + 1 >= argv.length) throw new ExportError("USAGE", `${a} needs a value`);
      o[flags[a]] = argv[++i];
      if (a === "--tenant") o.tenants.push(o.tenantId);
      if (a === "--issuer-authorization") o.issuerAuthorizations.push(o.issuerAuthorization);
    } else if (a.startsWith("--")) throw new ExportError("USAGE", `unknown option ${a}`);
    else o._.push(a);
  }
  return o;
}

export function main(argv, io = { out: (s) => process.stdout.write(s), err: (s) => process.stderr.write(s) }) {
  let o = null;
  let auditFile = null;
  try {
    o = parseArgs(argv);
    const cmd = o._[0];
    if (o.help || !cmd) {
      io.out(USAGE);
      return o.help ? 0 : 2;
    }
    if (cmd === "pack") {
      if (o._.length !== 3) throw new ExportError("USAGE", "expected: pack <bundle-dir> <out.ppb.json>");
      if (fs.existsSync(o._[2])) throw new ExportError("OUTPUT_EXISTS", "the output path already exists");
      fs.writeFileSync(o._[2], toCarrier(loadBundle(o._[1])), { flag: "wx" });
      io.out(JSON.stringify({ ok: true, carrier: path.basename(o._[2]) }) + "\n");
      return 0;
    }
    if (cmd === "trust-store") {
      if (!o.keyDir || !o.owner) throw new ExportError("USAGE", "trust-store needs --key-dir and --owner");
      // Public halves only: the active key, plus any retired keys a keyring still holds.
      const key = loadSigningKey(o.keyDir);
      const mk = (jwk, status) => ({ keyId: jwk.kid, owner: o.owner, status, ...(o.tenants.length ? { tenants: o.tenants } : {}), jwk: { kty: jwk.kty, crv: jwk.crv, kid: jwk.kid, x: jwk.x } });
      const doc = { format: TRUST_STORE_FORMAT, formatVersion: "1.0", keys: [mk(key.jwk, "active"), ...key.retired.map((j) => mk(j, "retired"))] };
      parseTrustStore(doc);
      io.out(JSON.stringify(doc, null, 2) + "\n");
      return 0;
    }
    if (!o.storeDir) throw new ExportError("USAGE", "--store is required");
    if (cmd === "list") {
      if (!o.tenantId) throw new ExportError("USAGE", "--tenant is required");
      const receipts = readJsonl(path.join(o.storeDir, RECEIPTS_FILE), RECEIPTS_FILE);
      if (receipts === null) throw new ExportError("STORE_NOT_FOUND", "no receipts.jsonl in --store");
      const outcomes = readJsonl(path.join(o.storeDir, OUTCOMES_FILE), OUTCOMES_FILE) ?? [];
      const rows = receipts
        .filter((r) => scopeOf(r, "tenantId") === o.tenantId)
        .map((r) => ({ receiptId: r.receiptId, timestamp: r.timestamp, action: r.action, decision: r.decision, executionOutcome: outcomes.find((x) => x?.authorizationReceiptId === r.receiptId)?.executionStatus ?? null }));
      io.out(JSON.stringify(rows, null, 2) + "\n");
      return 0;
    }
    if (cmd !== "export") throw new ExportError("USAGE", `unknown command ${cmd}`);
    if (!o.keyDir || !o.out) throw new ExportError("USAGE", "export needs --key-dir and --out");
    auditFile = o.auditLog === "none" ? null : (o.auditLog ?? path.join(o.storeDir, AUDIT_FILE));
    if (fs.existsSync(o.out)) throw new ExportError("OUTPUT_EXISTS", "the output path already exists; bundles are never overwritten");
    if (o.carrier && fs.existsSync(o.carrier)) throw new ExportError("OUTPUT_EXISTS", "the carrier path already exists; bundles are never overwritten");
    const { files, summary } = buildBundle(o);
    // Carrier first, under a temporary name: if it cannot be written, no bundle directory is left
    // behind for the audit log to deny.
    const carrierTmp = o.carrier ? `${path.resolve(o.carrier)}.tmp-${crypto.randomBytes(6).toString("hex")}` : null;
    try {
      if (carrierTmp) fs.writeFileSync(carrierTmp, toCarrier(files), { flag: "wx" });
      writeBundleDir(files, o.out);
      if (carrierTmp) fs.renameSync(carrierTmp, path.resolve(o.carrier));
    } catch (e) {
      if (carrierTmp) fs.rmSync(carrierTmp, { force: true });
      if (!(e instanceof ExportError && e.code === "OUTPUT_EXISTS")) fs.rmSync(path.resolve(o.out), { recursive: true, force: true });
      throw e instanceof ExportError ? e : new ExportError("WRITE_FAILED", "the bundle could not be written; nothing was left behind");
    }
    audit(auditFile, { event: "export", result: "EXPORTED", ...summary, disclosedInvocation: !!o.discloseInvocation, disclosedPolicy: !!o.disclosePolicy });
    io.out(JSON.stringify({ ok: true, ...summary }, null, 2) + "\n");
    return 0;
  } catch (e) {
    const code = e instanceof ExportError || e instanceof BundleError ? e.code : "INTERNAL_ERROR";
    const message = e instanceof ExportError || e instanceof BundleError ? e.message : "unexpected failure; nothing was exported";
    try {
      audit(auditFile, { event: "export", result: "REFUSED", code, receiptId: o?.receiptId ?? null, tenantId: o?.tenantId ?? null });
    } catch {
      /* the audit log must not turn a refusal into a crash */
    }
    io.err(`REFUSED ${code}: ${message}\n`);
    return code === "USAGE" ? 2 : 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href) {
  process.exitCode = main(process.argv.slice(2));
}
