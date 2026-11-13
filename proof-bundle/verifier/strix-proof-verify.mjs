#!/usr/bin/env node
// Strix Portable Proof Bundle v1 — offline verifier.
//
// Single file, zero dependencies (Node >= 18 built-ins only). It never opens a
// network connection, never writes bundle contents to disk, and never treats
// key material found inside a bundle as trusted.
//
// Specification: ../docs/SPEC.md. Everything this file does is specified
// there precisely enough to re-implement (see ../python/ppb_verify.py for a
// second implementation that shares no code with this one).

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const VERIFIER_NAME = "strix-proof-verify";
export const VERIFIER_VERSION = "1.0.0";
export const FORMAT = "strix-portable-proof-bundle";
export const SUPPORTED_FORMAT_VERSIONS = Object.freeze(["1.0"]);
export const CARRIER_FORMAT = "strix-ppb-carrier";
export const SIGNATURE_FORMAT = "strix-ppb-signature";
export const TRUST_STORE_FORMAT = "strix-ppb-trust-store";
export const MANIFEST_PAYLOAD_TYPE = "application/vnd.strix.ppb.manifest.v1+json";
export const AUTHORIZATION_PAYLOAD_TYPE = "application/vnd.strix.ppb.issuer-authorization.v1+json";
export const REVOCATIONS_PAYLOAD_TYPE = "application/vnd.strix.ppb.authorization-revocations.v1+json";
export const AUTHORIZATIONS_FORMAT = "strix-ppb-issuer-authorizations";
export const RECORD_KINDS = Object.freeze(["manifest", "authorization-receipt", "execution-outcome"]);

export const LIMITS = Object.freeze({
  maxFileBytes: 1024 * 1024,
  maxFiles: 64,
  maxTotalBytes: 8 * 1024 * 1024,
  maxCarrierBytes: 12 * 1024 * 1024,
  maxJsonDepth: 32,
  maxPathLength: 200,
});

export const PATHS = Object.freeze({
  manifest: "manifest.json",
  signature: "manifest.sig.json",
  receipt: "evidence/authorization-receipt.json",
  outcome: "evidence/execution-outcome.json",
  invocation: "disclosures/invocation.json",
  policy: "disclosures/policy-ruleset.json",
  embeddedKeys: "trust/embedded-signer-keys.json",
  authorizations: "trust/issuer-authorizations.json",
});

// Fixed path <-> role binding. Any other path may only carry "explanatory".
const ROLE_BY_PATH = Object.freeze({
  [PATHS.receipt]: "authorization-receipt",
  [PATHS.outcome]: "execution-outcome",
  [PATHS.invocation]: "invocation-disclosure",
  [PATHS.policy]: "policy-disclosure",
  [PATHS.embeddedKeys]: "embedded-signer-keys",
  [PATHS.authorizations]: "issuer-authorizations",
});

export const EXIT = Object.freeze({ PASSED: 0, FAILED: 1, ERROR: 2, INCOMPLETE: 3 });

/** An input problem that prevents evaluation (malformed / unsafe / unsupported). */
export class BundleError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

const sha256Hex = (buf) => crypto.createHash("sha256").update(buf).digest("hex");
const isObj = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isStr = (v) => typeof v === "string";
const HEX64 = /^[0-9a-f]{64}$/;
const B64URL = /^[A-Za-z0-9_-]+$/;
const TIME_RE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(?:Z|([+-])([0-9]{2}):([0-9]{2}))$/;
const DAYS = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
/** RFC 3339 date-time -> epoch milliseconds (sub-millisecond digits truncated), or NaN. */
export function timeMs(v) {
  // Parsed field by field: Date.parse would roll 02-30 over to March and accept hour 24.
  const m = isStr(v) ? TIME_RE.exec(v) : null;
  if (!m) return NaN;
  const [y, mo, d, h, mi, sec] = m.slice(1, 7).map(Number);
  const leap = y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0);
  if (y < 1970 || mo < 1 || mo > 12 || d < 1 || d > DAYS[mo - 1] + (mo === 2 && leap ? 1 : 0) || h > 23 || mi > 59 || sec > 59) return NaN;
  let offset = 0;
  if (m[8]) {
    const oh = Number(m[9]);
    const om = Number(m[10]);
    if (oh > 23 || om > 59) return NaN;
    offset = (m[8] === "+" ? 1 : -1) * (oh * 60 + om) * 60000;
  }
  return Date.UTC(y, mo - 1, d, h, mi, sec) + Number(((m[7] ?? "") + "000").slice(0, 3)) - offset;
}

// ---------------------------------------------------------------- strict JSON

/**
 * RFC 8259 parser that additionally rejects: a byte-order mark, invalid
 * UTF-8, duplicate object keys, the key "__proto__", and nesting deeper than
 * LIMITS.maxJsonDepth. Duplicate keys matter: two parsers that disagree on
 * which duplicate wins would disagree on what was signed.
 */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;
export function parseStrictJson(input, label = "json") {
  let text;
  if (typeof input === "string") text = input;
  else {
    try {
      text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(input);
    } catch {
      throw new BundleError("MALFORMED_JSON", `${label}: not valid UTF-8`);
    }
  }
  if (text.charCodeAt(0) === 0xfeff) throw new BundleError("MALFORMED_JSON", `${label}: byte-order mark is not allowed`);
  let i = 0;
  const fail = (m) => {
    throw new BundleError("MALFORMED_JSON", `${label}: ${m} at offset ${i}`);
  };
  const ws = () => {
    while (i < text.length && (text[i] === " " || text[i] === "\t" || text[i] === "\n" || text[i] === "\r")) i++;
  };
  const NUM = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;
  const string = () => {
    const start = i;
    i++;
    while (i < text.length) {
      const c = text.charCodeAt(i);
      if (c === 0x22) {
        i++;
        try {
          const str = JSON.parse(text.slice(start, i));
          if (LONE_SURROGATE.test(str)) throw new Error("unpaired surrogate");
          return str;
        } catch {
          i = start;
          fail("invalid string");
        }
      }
      if (c < 0x20) fail("control character in string");
      i += c === 0x5c ? 2 : 1;
    }
    return fail("unterminated string");
  };
  const value = (depth) => {
    if (depth > LIMITS.maxJsonDepth) fail("nesting too deep");
    ws();
    const c = text[i];
    if (c === "{") {
      i++;
      const out = {};
      const seen = new Set();
      ws();
      if (text[i] === "}") {
        i++;
        return out;
      }
      for (;;) {
        ws();
        if (text[i] !== '"') fail("expected object key");
        const k = string();
        if (k === "__proto__") fail("key '__proto__' is not allowed");
        if (seen.has(k)) fail(`duplicate key ${JSON.stringify(k)}`);
        seen.add(k);
        ws();
        if (text[i] !== ":") fail("expected ':'");
        i++;
        out[k] = value(depth + 1);
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "}") {
          i++;
          return out;
        }
        fail("expected ',' or '}'");
      }
    }
    if (c === "[") {
      i++;
      const out = [];
      ws();
      if (text[i] === "]") {
        i++;
        return out;
      }
      for (;;) {
        out.push(value(depth + 1));
        ws();
        if (text[i] === ",") {
          i++;
          continue;
        }
        if (text[i] === "]") {
          i++;
          return out;
        }
        fail("expected ',' or ']'");
      }
    }
    if (c === '"') return string();
    if (text.startsWith("true", i)) return (i += 4), true;
    if (text.startsWith("false", i)) return (i += 5), false;
    if (text.startsWith("null", i)) return (i += 4), null;
    NUM.lastIndex = i;
    const m = NUM.exec(text);
    if (!m) fail("unexpected token");
    i += m[0].length;
    const n = Number(m[0]);
    if (!Number.isFinite(n)) fail("number out of range");
    return n;
  };
  const v = value(0);
  ws();
  if (i !== text.length) fail("trailing content");
  return v;
}

/**
 * Deterministic JSON used by the gateway for invocationHash / policyVersion:
 * object keys sorted by UTF-16 code unit, no whitespace, ECMAScript
 * JSON.stringify for strings and numbers.
 */
export function canonicalJSON(value) {
  if (value === null) return "null";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("canonicalJSON: non-finite number");
    return JSON.stringify(value);
  }
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJSON).join(",")}]`;
  if (typeof value === "object") {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJSON(value[k])}`)
      .join(",")}}`;
  }
  throw new TypeError(`canonicalJSON: unsupported type ${typeof value}`);
}

// ------------------------------------------------------------ bundle loading

const PATH_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*(?:\/[A-Za-z0-9][A-Za-z0-9._-]*)*$/;

export function assertSafePath(p) {
  if (!isStr(p) || p.length === 0 || p.length > LIMITS.maxPathLength || !PATH_RE.test(p) || /\.(\/|$)/.test(p)) {
    throw new BundleError("UNSAFE_PATH", `unsafe or non-canonical path: ${JSON.stringify(String(p).slice(0, 80))}`);
  }
}

function finishFileMap(map) {
  const folded = new Set();
  let total = 0;
  for (const [p, buf] of map) {
    const f = p.toLowerCase();
    if (folded.has(f)) throw new BundleError("DUPLICATE_PATH", `paths collide case-insensitively: ${p}`);
    folded.add(f);
    total += buf.length;
  }
  if (map.size > LIMITS.maxFiles) throw new BundleError("TOO_MANY_FILES", `more than ${LIMITS.maxFiles} files`);
  if (total > LIMITS.maxTotalBytes) throw new BundleError("BUNDLE_TOO_LARGE", `bundle exceeds ${LIMITS.maxTotalBytes} bytes`);
  return map;
}

function loadDirectory(root) {
  const map = new Map();
  let count = 0;
  const walk = (dir, rel) => {
    for (const name of fs.readdirSync(dir).sort()) {
      const abs = path.join(dir, name);
      const relPath = rel ? `${rel}/${name}` : name;
      const st = fs.lstatSync(abs);
      if (st.isSymbolicLink()) throw new BundleError("UNSAFE_PATH", `symbolic link in bundle: ${relPath}`);
      if (st.isDirectory()) {
        assertSafePath(relPath);
        walk(abs, relPath);
      } else if (st.isFile()) {
        assertSafePath(relPath);
        if (++count > LIMITS.maxFiles) throw new BundleError("TOO_MANY_FILES", `more than ${LIMITS.maxFiles} files`);
        if (st.size > LIMITS.maxFileBytes) throw new BundleError("FILE_TOO_LARGE", `${relPath} exceeds ${LIMITS.maxFileBytes} bytes`);
        map.set(relPath, fs.readFileSync(abs));
      } else {
        throw new BundleError("UNSAFE_PATH", `not a regular file: ${relPath}`);
      }
    }
  };
  walk(root, "");
  return finishFileMap(map);
}

/** Standard base64 with padding, accepted only if re-encoding reproduces the input. Returns null otherwise. */
export function decodeCanonicalBase64(v) {
  if (!isStr(v) || v.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(v)) return null;
  const bytes = Buffer.from(v, "base64");
  return bytes.toString("base64") === v ? bytes : null;
}
/** base64url without padding, canonical in the same sense. */
function decodeCanonicalBase64url(v) {
  if (!isStr(v) || !B64URL.test(v)) return null;
  const bytes = Buffer.from(v, "base64url");
  return bytes.toString("base64url") === v ? bytes : null;
}

/** Parse a single-file carrier. Nothing is extracted to disk. */
export function loadCarrier(buf) {
  if (buf.length > LIMITS.maxCarrierBytes) throw new BundleError("BUNDLE_TOO_LARGE", `carrier exceeds ${LIMITS.maxCarrierBytes} bytes`);
  const doc = parseStrictJson(buf, "carrier");
  if (!isObj(doc) || doc.format !== CARRIER_FORMAT) throw new BundleError("NOT_A_BUNDLE", "not a Strix proof-bundle carrier file");
  if (!SUPPORTED_FORMAT_VERSIONS.includes(doc.formatVersion)) {
    throw new BundleError("UNSUPPORTED_VERSION", `unsupported carrier formatVersion ${JSON.stringify(doc.formatVersion)}`);
  }
  for (const k of Object.keys(doc)) {
    if (!["format", "formatVersion", "files"].includes(k)) throw new BundleError("MALFORMED_CARRIER", `unknown carrier field '${k}'`);
  }
  if (!isObj(doc.files)) throw new BundleError("MALFORMED_CARRIER", "carrier 'files' must be an object");
  const names = Object.keys(doc.files);
  if (names.length > LIMITS.maxFiles) throw new BundleError("TOO_MANY_FILES", `more than ${LIMITS.maxFiles} files`);
  const map = new Map();
  for (const p of names) {
    assertSafePath(p);
    const b64 = doc.files[p];
    if (isStr(b64) && b64.length > Math.ceil(LIMITS.maxFileBytes / 3) * 4) throw new BundleError("FILE_TOO_LARGE", `${p} exceeds ${LIMITS.maxFileBytes} bytes`);
    const bytes = decodeCanonicalBase64(b64);
    if (bytes === null) throw new BundleError("MALFORMED_CARRIER", `file '${p}' is not canonical base64`);
    map.set(p, bytes);
  }
  return finishFileMap(map);
}

/** Load a bundle from a directory or a carrier file into Map<path, Buffer>. */
export function loadBundle(bundlePath) {
  let st;
  try {
    st = fs.lstatSync(bundlePath);
  } catch {
    throw new BundleError("NOT_FOUND", `bundle not found: ${bundlePath}`);
  }
  if (st.isSymbolicLink()) throw new BundleError("UNSAFE_PATH", "bundle path is a symbolic link");
  if (st.isDirectory()) return loadDirectory(bundlePath);
  if (!st.isFile()) throw new BundleError("NOT_A_BUNDLE", "bundle path is neither a directory nor a file");
  if (st.size > LIMITS.maxCarrierBytes) throw new BundleError("BUNDLE_TOO_LARGE", `carrier exceeds ${LIMITS.maxCarrierBytes} bytes`);
  return loadCarrier(fs.readFileSync(bundlePath));
}

// ------------------------------------------------------------------- keys

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

export function publicKeyFromJwk(jwk) {
  if (!isObj(jwk) || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || !isStr(jwk.x) || !B64URL.test(jwk.x)) {
    throw new BundleError("UNSUPPORTED_ALGORITHM", "key is not an Ed25519 OKP JWK");
  }
  const raw = decodeCanonicalBase64url(jwk.x);
  if (raw === null || raw.length !== 32) throw new BundleError("MALFORMED_KEY", "Ed25519 public key must be 32 bytes of canonical base64url");
  return crypto.createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: "der", type: "spki" });
}

const KEY_STATUSES = ["active", "retired", "revoked"];
const KEY_ROLES = ["signer", "issuer-root"];

/**
 * Normalize a trust store. Accepts the native trust-store format, a JWKS
 * ({keys:[jwk]}) or a single JWK. Returns Map<keyId, entry>.
 */
export function parseTrustStore(input) {
  const doc = Buffer.isBuffer(input) || isStr(input) ? parseStrictJson(input, "trust store") : input;
  if (!isObj(doc)) throw new BundleError("MALFORMED_TRUST_STORE", "trust store must be a JSON object");
  let entries;
  if (doc.format !== undefined) {
    if (doc.format !== TRUST_STORE_FORMAT) throw new BundleError("MALFORMED_TRUST_STORE", `unknown trust store format ${JSON.stringify(doc.format)}`);
    if (!SUPPORTED_FORMAT_VERSIONS.includes(doc.formatVersion)) throw new BundleError("UNSUPPORTED_VERSION", "unsupported trust store formatVersion");
    if (!Array.isArray(doc.keys)) throw new BundleError("MALFORMED_TRUST_STORE", "'keys' must be an array");
    entries = doc.keys;
  } else if (Array.isArray(doc.keys)) {
    entries = doc.keys.map((jwk) => ({ keyId: jwk?.kid, jwk }));
  } else if (doc.kty !== undefined) {
    entries = [{ keyId: doc.kid, jwk: doc }];
  } else {
    throw new BundleError("MALFORMED_TRUST_STORE", "unrecognized trust store shape");
  }
  const out = new Map();
  for (const e of entries) {
    if (!isObj(e) || !isStr(e.keyId) || !e.keyId) throw new BundleError("MALFORMED_TRUST_STORE", "every key needs a keyId (kid)");
    if (out.has(e.keyId)) throw new BundleError("MALFORMED_TRUST_STORE", `duplicate keyId '${e.keyId}' (ambiguous)`);
    if (!isObj(e.jwk)) throw new BundleError("MALFORMED_TRUST_STORE", `key '${e.keyId}' has no jwk`);
    const status = e.status === undefined ? "active" : e.status;
    if (!KEY_STATUSES.includes(status)) throw new BundleError("MALFORMED_TRUST_STORE", `key '${e.keyId}': unknown status '${status}'`);
    const role = e.role === undefined ? "signer" : e.role;
    if (!KEY_ROLES.includes(role)) throw new BundleError("MALFORMED_TRUST_STORE", `key '${e.keyId}': unknown role '${role}'`);
    for (const f of ["notBefore", "notAfter"]) {
      if (e[f] !== undefined && !Number.isFinite(timeMs(e[f]))) throw new BundleError("MALFORMED_TRUST_STORE", `key '${e.keyId}': bad ${f}`);
    }
    for (const f of ["tenants", "environments"]) {
      if (e[f] !== undefined && !(Array.isArray(e[f]) && e[f].every(isStr))) throw new BundleError("MALFORMED_TRUST_STORE", `key '${e.keyId}': '${f}' must be an array of strings`);
    }
    out.set(e.keyId, {
      keyId: e.keyId,
      publicKey: publicKeyFromJwk(e.jwk),
      x: e.jwk.x,
      owner: isStr(e.owner) ? e.owner : null,
      role,
      status,
      notBefore: e.notBefore ?? null,
      notAfter: e.notAfter ?? null,
      tenants: e.tenants ?? null,
      environments: e.environments ?? null,
    });
  }
  return out;
}

// ------------------------------------------------- native record canonicals

const RECEIPT_ORDER = Object.freeze({
  1: ["schemaVersion", "receiptId", "capabilityId", "action", "decision", "risk", "mode", "invocationHash", "evidenceHash", "proofChainHash", "timestamp"],
  2: ["schemaVersion", "receiptId", "capabilityId", "action", "decision", "risk", "mode", "policyVersion", "tenantId", "environment", "invocationHash", "evidenceHash", "proofChainHash", "timestamp"],
});
const OUTCOME_CORE = Object.freeze(["schemaVersion", "outcomeId", "authorizationReceiptId", "authorizationProofChainHash", "capabilityId", "action", "decision", "executionAttempted", "executionStatus", "invocationHash", "resultHash", "errorCode", "policyVersion", "tenantId", "environment", "completedAt", "signingKeyId", "signatureAlgorithm"]);
const OUTCOME_SIGNED = Object.freeze([...OUTCOME_CORE, "outcomeHash"]);

const ordered = (obj, fields) => `{${fields.map((f) => `${JSON.stringify(f)}:${JSON.stringify(obj[f])}`).join(",")}}`;

/** The exact bytes the gateway signs for an authorization receipt. */
export function receiptSignedBytes(r) {
  const order = isStr(r.schemaVersion) && Object.hasOwn(RECEIPT_ORDER, r.schemaVersion) ? RECEIPT_ORDER[r.schemaVersion] : null;
  if (!order) throw new BundleError("UNSUPPORTED_RECORD_VERSION", `unsupported receipt schemaVersion ${JSON.stringify(r.schemaVersion)}`);
  // Receipt schemas 1 and 2 are Ed25519 by definition and carry no algorithm field. A receipt that
  // declares one anyway must declare exactly that; anything else is refused, never ignored.
  if (r.signatureAlgorithm !== undefined && r.signatureAlgorithm !== "Ed25519") throw new BundleError("UNSUPPORTED_ALGORITHM", `authorization receipt declares unsupported signatureAlgorithm ${JSON.stringify(r.signatureAlgorithm)}`);
  for (const f of order) if (!isStr(r[f]) || r[f] === "") throw new BundleError("MALFORMED_RECORD", `authorization receipt: field '${f}' must be a non-empty string`);
  for (const f of ["invocationHash", "evidenceHash", "proofChainHash"]) if (!HEX64.test(r[f])) throw new BundleError("MALFORMED_RECORD", `authorization receipt: field '${f}' must be 64 lowercase hex characters`);
  // Schema 1 signs no tenant. A tenant written next to it would be outside the gateway's signature
  // yet would steer tenant scoping, so it is refused rather than believed.
  if (r.schemaVersion === "1") for (const f of ["policyVersion", "tenantId", "environment"]) if (Object.hasOwn(r, f)) throw new BundleError("MALFORMED_RECORD", `authorization receipt: schema 1 does not define '${f}'`);
  return Buffer.from(ordered(r, order), "utf8");
}

export function outcomeHashOf(o) {
  return `sha256:${sha256Hex(Buffer.from(ordered(o, OUTCOME_CORE), "utf8"))}`;
}

/** Shape rules of execution-outcome v1; rejects fields the signature does not cover. */
export function outcomeSignedBytes(o) {
  if (o.schemaVersion !== "1") throw new BundleError("UNSUPPORTED_RECORD_VERSION", `unsupported execution outcome schemaVersion ${JSON.stringify(o.schemaVersion)}`);
  if (o.signatureAlgorithm !== "Ed25519") throw new BundleError("UNSUPPORTED_ALGORITHM", `unsupported outcome signatureAlgorithm ${JSON.stringify(o.signatureAlgorithm)}`);
  const allowed = new Set([...OUTCOME_SIGNED, "signature"]);
  for (const k of Object.keys(o)) if (!allowed.has(k)) throw new BundleError("MALFORMED_RECORD", `execution outcome: field '${k}' is not covered by its signature`);
  for (const f of OUTCOME_SIGNED) {
    if (f === "executionAttempted") continue;
    if (!isStr(o[f])) throw new BundleError("MALFORMED_RECORD", `execution outcome: field '${f}' must be a string`);
  }
  if (o.executionAttempted !== true) throw new BundleError("MALFORMED_RECORD", "execution outcome: executionAttempted must be true");
  return Buffer.from(ordered(o, OUTCOME_SIGNED), "utf8");
}

/** DSSE v1 pre-authentication encoding of the manifest bytes. */
export function pae(payloadType, payloadBytes) {
  const t = Buffer.from(payloadType, "utf8");
  return Buffer.concat([Buffer.from(`DSSEv1 ${t.length} `), t, Buffer.from(` ${payloadBytes.length} `), payloadBytes]);
}
export const manifestSignedBytes = (manifestBytes) => pae(MANIFEST_PAYLOAD_TYPE, manifestBytes);

const ID_RE = /^ia_[A-Za-z0-9._-]{1,64}$/;
const exactKeys = (o, keys) => isObj(o) && Object.keys(o).length === keys.length && keys.every((k) => Object.hasOwn(o, k));
const strList = (v) => Array.isArray(v) && v.length > 0 && v.length <= 64 && v.every((x) => isStr(x) && x) && new Set(v).size === v.length;

/** Open a one-signature DSSE envelope: the exact payload bytes, and the signature to check over pae(). */
function openEnvelope(env, payloadType, errCode, label) {
  const bad = (m) => new BundleError(errCode, `${label}: ${m}`);
  if (!exactKeys(env, ["payloadType", "payload", "signatures"])) throw bad("envelope must have exactly payloadType, payload, signatures");
  if (env.payloadType !== payloadType) throw bad("unexpected payloadType");
  if (isStr(env.payload) && env.payload.length > Math.ceil(LIMITS.maxFileBytes / 3) * 4) throw bad("payload is too large");
  const payloadBytes = decodeCanonicalBase64(env.payload);
  if (payloadBytes === null) throw bad("payload is not canonical base64");
  if (!Array.isArray(env.signatures) || env.signatures.length !== 1 || !exactKeys(env.signatures[0], ["keyId", "algorithm", "signature"])) throw bad("exactly one signature {keyId, algorithm, signature} is required");
  const sg = env.signatures[0];
  if (sg.algorithm !== "Ed25519") throw new BundleError("UNSUPPORTED_ALGORITHM", `${label}: unsupported signature algorithm ${JSON.stringify(sg.algorithm)}`);
  if (!isStr(sg.keyId) || !sg.keyId) throw bad("signature keyId must be a non-empty string");
  return { payloadBytes, keyId: sg.keyId, signature: sg.signature, payload: parseStrictJson(payloadBytes, label) };
}

/**
 * Parse an issuer authorization: a statement, signed by an issuer root, that a
 * gateway key may sign the named kinds of record for the named tenants and
 * environments during a validity interval. Parsing establishes nothing; the
 * evaluation is in verifyBundle.
 */
export function parseAuthorization(env, label = "issuer authorization") {
  const a = openEnvelope(env, AUTHORIZATION_PAYLOAD_TYPE, "MALFORMED_AUTHORIZATION", label);
  const p = a.payload;
  const bad = (m) => new BundleError("MALFORMED_AUTHORIZATION", `${label}: ${m}`);
  if (!exactKeys(p, ["type", "version", "authorizationId", "issuer", "issuedAt", "subject", "scope", "notBefore", "notAfter"])) throw bad("payload has missing or unknown fields");
  if (p.type !== "strix-ppb-issuer-authorization") throw bad("wrong type");
  if (p.version !== "1.0") throw new BundleError("UNSUPPORTED_VERSION", `${label}: unsupported authorization version ${JSON.stringify(p.version)}`);
  if (!isStr(p.authorizationId) || !ID_RE.test(p.authorizationId)) throw bad("bad authorizationId");
  if (!isStr(p.issuer) || !p.issuer) throw bad("bad issuer");
  for (const f of ["issuedAt", "notBefore", "notAfter"]) if (!Number.isFinite(timeMs(p[f]))) throw bad(`bad ${f}`);
  if (timeMs(p.notAfter) < timeMs(p.notBefore)) throw bad("notAfter precedes notBefore");
  if (!exactKeys(p.subject, ["gatewayId", "keyId", "jwk"]) || !isStr(p.subject.gatewayId) || !p.subject.gatewayId || !isStr(p.subject.keyId) || !p.subject.keyId) throw bad("bad subject");
  if (!exactKeys(p.scope, ["tenants", "environments", "records"]) || !strList(p.scope.tenants) || !strList(p.scope.environments) || !strList(p.scope.records) || !p.scope.records.every((r) => RECORD_KINDS.includes(r))) throw bad("bad scope");
  return { ...a, publicKey: publicKeyFromJwk(p.subject.jwk), x: p.subject.jwk.x };
}

/** Parse the authorizations container: {format, formatVersion, authorizations: [envelope, ...]}. */
export function parseAuthorizations(input, label = "issuer authorizations") {
  const doc = Buffer.isBuffer(input) || isStr(input) ? parseStrictJson(input, label) : input;
  // A single envelope, as the authority tool prints it, is accepted wherever a container is.
  if (isObj(doc) && Object.hasOwn(doc, "payloadType")) return [parseAuthorization(doc, label)];
  if (!exactKeys(doc, ["format", "formatVersion", "authorizations"]) || doc.format !== AUTHORIZATIONS_FORMAT) throw new BundleError("MALFORMED_AUTHORIZATION", `${label}: not an issuer-authorizations document`);
  if (!SUPPORTED_FORMAT_VERSIONS.includes(doc.formatVersion)) throw new BundleError("UNSUPPORTED_VERSION", `${label}: unsupported formatVersion`);
  if (!Array.isArray(doc.authorizations) || doc.authorizations.length === 0 || doc.authorizations.length > 16) throw new BundleError("MALFORMED_AUTHORIZATION", `${label}: 1 to 16 authorizations are required`);
  return doc.authorizations.map((e, i) => parseAuthorization(e, `${label}[${i}]`));
}

/**
 * Open a revocation list. It has effect only if its signature verifies under
 * an issuer root in the trust store; a list that does not verify is an input
 * error, never read as "nothing is revoked".
 */
export function parseRevocations(input, trustStore) {
  const label = "revocation list";
  const env = Buffer.isBuffer(input) || isStr(input) ? parseStrictJson(input, label) : input;
  const r = openEnvelope(env, REVOCATIONS_PAYLOAD_TYPE, "REVOCATION_LIST_INVALID", label);
  const bad = (m) => new BundleError("REVOCATION_LIST_INVALID", `${label}: ${m}`);
  const p = r.payload;
  if (!exactKeys(p, ["type", "version", "issuer", "issuedAt", "revoked"]) || p.type !== "strix-ppb-authorization-revocations" || p.version !== "1.0") throw bad("payload has missing, unknown or unsupported fields");
  if (!isStr(p.issuer) || !p.issuer || !Number.isFinite(timeMs(p.issuedAt)) || !Array.isArray(p.revoked) || p.revoked.length > 4096) throw bad("bad payload");
  for (const e of p.revoked) if (!exactKeys(e, ["authorizationId", "revokedAt"]) || !isStr(e.authorizationId) || !ID_RE.test(e.authorizationId) || !Number.isFinite(timeMs(e.revokedAt))) throw bad("bad revoked entry");
  const root = trustStore?.get(r.keyId);
  if (!root || root.role !== "issuer-root" || root.status === "revoked") throw bad("not signed by an issuer root in your trust store");
  if (!edVerify(root.publicKey, pae(REVOCATIONS_PAYLOAD_TYPE, r.payloadBytes), r.signature)) throw bad("signature does not verify");
  return { rootKeyId: r.keyId, issuedAt: p.issuedAt, ids: new Set(p.revoked.map((e) => e.authorizationId)) };
}

export function computeBundleId(manifest) {
  const basis = {
    formatVersion: manifest.formatVersion,
    subject: manifest.subject,
    artifacts: manifest.artifacts.map((a) => ({ path: a.path, sha256: a.sha256 })),
  };
  return `ppb_${sha256Hex(Buffer.from(canonicalJSON(basis), "utf8")).slice(0, 32)}`;
}

/** The gateway's policy evaluation order: exact rule, longest prefix, risk override, default, fail closed. */
const RULE_VALUES = ["ALLOW", "DENY", "APPROVAL_REQUIRED"];
/** A disclosed ruleset: exactly {rules, riskOverrides, default}; every rule value from the closed set; default a rule value or null. */
export function isRuleset(v) {
  const rulesOk = (o) => isObj(o) && Object.keys(o).every((k) => RULE_VALUES.includes(o[k]));
  return exactKeys(v, ["rules", "riskOverrides", "default"]) && rulesOk(v.rules) && rulesOk(v.riskOverrides) && (v.default === null || RULE_VALUES.includes(v.default));
}
export function evaluateRuleset(ruleset, capabilityId, risk) {
  const { rules, riskOverrides } = ruleset;
  if (Object.hasOwn(rules, capabilityId)) return { rule: rules[capabilityId], matched: capabilityId };
  let best = "";
  for (const k of Object.keys(rules)) {
    if (!k.endsWith(".*")) continue;
    const p = k.slice(0, -2);
    if (capabilityId.startsWith(p + ".") && p.length > best.length) best = p;
  }
  if (best) return { rule: rules[best + ".*"], matched: best + ".*" };
  if (Object.hasOwn(riskOverrides, risk)) return { rule: riskOverrides[risk], matched: `<risk:${risk}>` };
  if (ruleset.default !== null) return { rule: ruleset.default, matched: "<default>" };
  return { rule: "DENY", matched: "<fail-closed>" };
}

// ------------------------------------------------------------ verification

const MANIFEST_KEYS = ["format", "formatVersion", "critical", "bundleId", "createdAt", "exporter", "subject", "evidence", "digestAlgorithm", "artifacts", "signer", "extensions"];
const SUBJECT_KEYS = ["kind", "receiptId", "tenantId", "environment", "capabilityId", "action", "invocationHash"];
const EVIDENCE_KEYS = ["authorizationDecision", "executionOutcome", "enforcementObservation", "invocationDisclosure", "policyDisclosure"];
const RECEIPT_UNSIGNED_KNOWN = ["signingKeyId", "signature", "tool", "actorId", "actorRole", "approvedBy", "approvalReason", "denialReason"];

function validateManifest(m) {
  const bad = (msg) => {
    throw new BundleError("MALFORMED_MANIFEST", `manifest: ${msg}`);
  };
  if (!isObj(m)) bad("must be a JSON object");
  if (m.format !== FORMAT) throw new BundleError("NOT_A_BUNDLE", `manifest.format is not '${FORMAT}'`);
  if (!SUPPORTED_FORMAT_VERSIONS.includes(m.formatVersion)) {
    throw new BundleError("UNSUPPORTED_VERSION", `bundle formatVersion ${JSON.stringify(m.formatVersion)} is not supported by this verifier (supports ${SUPPORTED_FORMAT_VERSIONS.join(", ")})`);
  }
  if (!Array.isArray(m.critical) || !m.critical.every(isStr)) bad("'critical' must be an array of strings");
  if (m.critical.length) throw new BundleError("UNKNOWN_CRITICAL_EXTENSION", `bundle requires extension(s) this verifier does not implement: ${m.critical.join(", ")}`);
  for (const k of Object.keys(m)) if (!MANIFEST_KEYS.includes(k)) bad(`unknown field '${k}' (extensions belong under 'extensions')`);
  if (m.digestAlgorithm !== "sha-256") throw new BundleError("UNSUPPORTED_ALGORITHM", `unsupported digestAlgorithm ${JSON.stringify(m.digestAlgorithm)}`);
  if (!isStr(m.bundleId) || !/^ppb_[0-9a-f]{32}$/.test(m.bundleId)) bad("bad bundleId");
  if (!Number.isFinite(timeMs(m.createdAt))) bad("bad createdAt");
  if (!isObj(m.exporter) || !isStr(m.exporter.name) || !isStr(m.exporter.version)) bad("bad exporter");
  if (!exactKeys(m.subject, SUBJECT_KEYS)) bad("subject must have exactly: " + SUBJECT_KEYS.join(", "));
  if (m.subject.kind !== "governed-action") bad("subject.kind must be 'governed-action'");
  for (const k of SUBJECT_KEYS) if (!isStr(m.subject[k]) || !m.subject[k]) bad(`subject.${k} must be a non-empty string`);
  if (!exactKeys(m.evidence, EVIDENCE_KEYS)) bad("evidence must have exactly: " + EVIDENCE_KEYS.join(", "));
  for (const k of EVIDENCE_KEYS) if (!isStr(m.evidence[k])) bad(`evidence.${k} must be a string`);
  if (!isObj(m.signer) || !isStr(m.signer.keyId) || !m.signer.keyId) bad("bad signer");
  if (m.signer.algorithm !== "Ed25519") throw new BundleError("UNSUPPORTED_ALGORITHM", `unsupported manifest signature algorithm ${JSON.stringify(m.signer.algorithm)}`);
  if (m.extensions !== undefined && !isObj(m.extensions)) bad("'extensions' must be an object");
  if (!Array.isArray(m.artifacts) || m.artifacts.length === 0 || m.artifacts.length > LIMITS.maxFiles) bad("bad artifacts list");
  const seen = new Set();
  const roles = new Map();
  for (const a of m.artifacts) {
    if (!exactKeys(a, ["path", "role", "sha256", "size"])) bad("each artifact must have exactly: path, role, sha256, size");
    assertSafePath(a.path);
    if (a.path === PATHS.manifest || a.path === PATHS.signature) bad(`'${a.path}' cannot list itself as an artifact`);
    const f = a.path.toLowerCase();
    if (seen.has(f)) throw new BundleError("DUPLICATE_PATH", `artifact listed twice: ${a.path}`);
    seen.add(f);
    if (!isStr(a.sha256) || !HEX64.test(a.sha256)) bad(`artifact ${a.path}: bad sha256`);
    if (!Number.isInteger(a.size) || a.size < 0 || a.size > LIMITS.maxFileBytes) bad(`artifact ${a.path}: bad size`);
    const expected = Object.hasOwn(ROLE_BY_PATH, a.path) ? ROLE_BY_PATH[a.path] : "explanatory";
    if (a.role !== expected) bad(`artifact ${a.path}: role must be '${expected}'`);
    roles.set(a.role, a.path);
  }
  if (!roles.has("authorization-receipt")) bad(`required artifact ${PATHS.receipt} is not listed`);
}

function trustFor(entry, { time, tenantId, environment }) {
  if (entry.status === "revoked") return "REVOKED";
  const t = timeMs(time);
  // An unreadable time cannot be shown to fall inside a declared window: fail closed.
  if ((entry.notBefore || entry.notAfter) && !Number.isFinite(t)) return "OUTSIDE_VALIDITY";
  if (entry.notBefore && t < timeMs(entry.notBefore)) return "OUTSIDE_VALIDITY";
  if (entry.notAfter && t > timeMs(entry.notAfter)) return "OUTSIDE_VALIDITY";
  if (entry.tenants && !entry.tenants.includes(tenantId)) return "TENANT_NOT_AUTHORIZED";
  if (entry.environments && !entry.environments.includes(environment)) return "TENANT_NOT_AUTHORIZED";
  return "TRUSTED";
}

/**
 * Decide whether one issuer authorization gives a gateway key standing for one
 * record. Order is fixed (SPEC §7.4) so independent implementations report the
 * same reason. `rootSigned` says whether the key bytes in the authorization
 * are vouched for by a trusted root, whatever the final verdict.
 */
function judgeAuthorization(a, trustStore, revocations, recordKind, ctx) {
  const p = a.payload;
  const root = trustStore.get(a.keyId);
  if (!root || root.role !== "issuer-root") return { trust: "UNTRUSTED", rootSigned: false, standing: null, rootOwner: null };
  if (!edVerify(root.publicKey, pae(AUTHORIZATION_PAYLOAD_TYPE, a.payloadBytes), a.signature)) return { trust: "AUTHORIZATION_INVALID", rootSigned: false, standing: null, rootOwner: root.owner };
  const listed = revocations && revocations.rootKeyId === a.keyId;
  const standing = listed ? (revocations.ids.has(p.authorizationId) ? "REVOKED" : "NOT_REVOKED") : "NOT_CHECKED";
  const out = (trust) => ({ trust, rootSigned: true, standing, rootOwner: root.owner });
  // The root itself: its status and window apply to the moment it issued the authorization.
  const rootTrust = trustFor(root, { time: p.issuedAt, tenantId: ctx.tenantId, environment: ctx.environment });
  if (rootTrust !== "TRUSTED") return out(rootTrust);
  if (standing === "REVOKED") return out("REVOKED");
  const t = timeMs(ctx.time);
  if (!Number.isFinite(t) || t < timeMs(p.notBefore) || t > timeMs(p.notAfter)) return out("OUTSIDE_VALIDITY");
  if (!p.scope.tenants.includes(ctx.tenantId) || !p.scope.environments.includes(ctx.environment)) return out("TENANT_NOT_AUTHORIZED");
  if (!p.scope.records.includes(recordKind)) return out("RECORD_NOT_AUTHORIZED");
  return out("TRUSTED");
}

function edVerify(publicKey, bytes, sigB64url) {
  const sig = decodeCanonicalBase64url(sigB64url);
  if (sig === null || sig.length !== 64) return false;
  try {
    return crypto.verify(null, bytes, publicKey, sig);
  } catch {
    return false;
  }
}

export const UNSUPPORTED_CONCLUSIONS = Object.freeze([
  "That the action could not have been performed by a path that bypasses the gateway (non-bypassability).",
  "That no other executions of this action occurred outside the recorded one (completeness of the record).",
  "That the policy was correct, adequate, or compliant with any standard.",
  "That the signing key was uncompromised when it signed, or that the signer reported events truthfully.",
  "That the execution environment, the gateway process, or the upstream tool were uncompromised.",
  "That all downstream side effects of the action were observed or recorded.",
  "That any timestamp is correct: all times are asserted by the signer's own clock.",
  "That the actor named in the evidence was authenticated.",
  "That a key marked trusted in your trust store has not been revoked since you last updated it (no online revocation check is made).",
]);

/**
 * Verify a loaded bundle. `files` is Map<path, Buffer>. `opts.trustStore` is
 * the Map from parseTrustStore, or null when the relying party supplied none.
 * Throws BundleError for input that cannot be evaluated; otherwise returns a
 * report whose result.overall is PASSED | FAILED | INCOMPLETE.
 */
export function verifyBundle(files, opts = {}) {
  const trustStore = opts.trustStore ?? null;
  const expect = opts.expect ?? {};
  const failures = [];
  const notes = [];
  const fail = (stage, code, message) => failures.push({ stage, code, message });

  // ---- 1. structure
  const manifestBytes = files.get(PATHS.manifest);
  const sigBytes = files.get(PATHS.signature);
  if (!manifestBytes) throw new BundleError("NOT_A_BUNDLE", "manifest.json is missing");
  const manifest = parseStrictJson(manifestBytes, "manifest.json");
  validateManifest(manifest);

  // ---- 2. integrity: the bundle's file set must equal the signed inventory
  const listed = new Map(manifest.artifacts.map((a) => [a.path, a]));
  for (const a of manifest.artifacts) {
    const buf = files.get(a.path);
    if (!buf) fail("integrity", "MISSING_ARTIFACT", `listed artifact is missing: ${a.path}`);
    else if (buf.length !== a.size || sha256Hex(buf) !== a.sha256) fail("integrity", "DIGEST_MISMATCH", `artifact does not match its signed digest: ${a.path}`);
  }
  for (const p of files.keys()) {
    if (p !== PATHS.manifest && p !== PATHS.signature && !listed.has(p)) fail("integrity", "UNEXPECTED_ARTIFACT", `file is not in the signed inventory: ${p}`);
  }
  if (!sigBytes) fail("integrity", "MISSING_SIGNATURE", "manifest.sig.json is missing");
  const integrityOk = failures.length === 0;

  // ---- 3. parse the signed artifacts (only bytes that matched their digest)
  const artifact = (p) => (integrityOk && listed.has(p) ? parseStrictJson(files.get(p), p) : null);
  let receipt = null;
  let outcome = null;
  let invocation = null;
  let ruleset = null;
  let embedded = new Map();
  const authorizations = new Map();
  const revocations = opts.revocations ?? null;
  let sigDoc = null;
  if (integrityOk) {
    receipt = artifact(PATHS.receipt);
    if (!isObj(receipt)) throw new BundleError("MALFORMED_RECORD", "authorization receipt must be a JSON object");
    outcome = artifact(PATHS.outcome);
    if (outcome !== null && !isObj(outcome)) throw new BundleError("MALFORMED_RECORD", "execution outcome must be a JSON object");
    invocation = artifact(PATHS.invocation);
    ruleset = artifact(PATHS.policy);
    if (invocation !== null && !(exactKeys(invocation, ["capabilityId", "action", "args", "actorId", "actorRole"]) && [invocation.capabilityId, invocation.action, invocation.actorId, invocation.actorRole].every(isStr))) {
      throw new BundleError("MALFORMED_RECORD", "invocation disclosure must have exactly capabilityId, action, args, actorId, actorRole (strings, args any JSON)");
    }
    if (ruleset !== null && !isRuleset(ruleset)) throw new BundleError("MALFORMED_RECORD", "policy disclosure must have exactly rules, riskOverrides, default with values ALLOW, DENY or APPROVAL_REQUIRED");
    if (listed.has(PATHS.embeddedKeys)) {
      // Convenience copy only. Used to report signature *mathematics* when the
      // relying party has no trusted key for a keyId; never a source of trust.
      try {
        embedded = parseTrustStore(files.get(PATHS.embeddedKeys));
      } catch (e) {
        notes.push(`embedded key file ignored: ${e.message}`);
      }
    }
    // Issuer authorizations: from the bundle and/or supplied by the relying party. Being in the
    // bundle gives them no standing; each must be signed by an issuer root in the trust store.
    for (const a of [...(listed.has(PATHS.authorizations) ? parseAuthorizations(files.get(PATHS.authorizations), PATHS.authorizations) : []), ...(opts.authorizations ?? [])]) {
      const id = a.payload.authorizationId;
      const prior = authorizations.get(id);
      if (prior && !prior.payloadBytes.equals(a.payloadBytes)) throw new BundleError("MALFORMED_AUTHORIZATION", `two different authorizations share the id ${id}`);
      authorizations.set(id, a);
    }
    sigDoc = parseStrictJson(sigBytes, PATHS.signature);
    if (!isObj(sigDoc) || sigDoc.format !== SIGNATURE_FORMAT || !SUPPORTED_FORMAT_VERSIONS.includes(sigDoc.formatVersion)) {
      throw new BundleError("MALFORMED_SIGNATURE", "manifest.sig.json is not a supported signature envelope");
    }
    if (sigDoc.payloadType !== MANIFEST_PAYLOAD_TYPE) throw new BundleError("MALFORMED_SIGNATURE", "unexpected payloadType");
    if (!Array.isArray(sigDoc.signatures) || sigDoc.signatures.length !== 1 || !isObj(sigDoc.signatures[0])) {
      throw new BundleError("MALFORMED_SIGNATURE", "v1 requires exactly one manifest signature");
    }
    if (sigDoc.signatures[0].algorithm !== "Ed25519") {
      throw new BundleError("UNSUPPORTED_ALGORITHM", `unsupported manifest signature algorithm ${JSON.stringify(sigDoc.signatures[0].algorithm)}`);
    }
  }

  // ---- 4. signatures and signer trust (kept separate)
  const sigResults = [];
  const checkSig = (label, keyId, bytes, signature, ctx) => {
    const res = { record: label, keyId, mathValid: null, keySource: "none", trust: trustStore ? "UNTRUSTED" : "NOT_ESTABLISHED", owner: null, keyStatus: null, authority: null, authorizationId: null, issuerRootKeyId: null, gatewayId: null, standing: null, scope: null };
    const entry = trustStore?.get(keyId);
    // An issuer root authorizes gateway keys; it is not itself accepted as a record signer.
    const direct = entry && entry.role === "signer" ? entry : null;
    const emb = embedded.get(keyId);
    if (direct) {
      res.keySource = "trust-store";
      res.authority = "DIRECT";
      res.owner = direct.owner;
      res.keyStatus = direct.status;
      res.mathValid = edVerify(direct.publicKey, bytes, signature);
      res.trust = trustFor(direct, ctx);
      if (emb && emb.x !== direct.x) notes.push(`embedded key '${keyId}' differs from the trusted key with the same id; the embedded copy was ignored`);
    } else {
      // Authority chain: issuer root (trust store) -> authorization -> this gateway key.
      const candidates = trustStore ? [...authorizations.values()].filter((a) => a.payload.subject.keyId === keyId).sort((a, b) => (a.payload.authorizationId < b.payload.authorizationId ? -1 : 1)) : [];
      const judged = candidates.map((a) => ({ a, verdict: judgeAuthorization(a, trustStore, revocations, label, ctx) }));
      const pick = judged.find((j) => j.verdict.trust === "TRUSTED") ?? judged[0];
      if (pick) {
        const p = pick.a.payload;
        res.trust = pick.verdict.trust;
        res.authority = "ISSUER_AUTHORIZATION";
        res.authorizationId = p.authorizationId;
        res.issuerRootKeyId = pick.a.keyId;
        res.gatewayId = p.subject.gatewayId;
        res.standing = pick.verdict.standing;
        res.scope = { tenants: p.scope.tenants, environments: p.scope.environments, records: p.scope.records, notBefore: p.notBefore, notAfter: p.notAfter };
        res.owner = `gateway "${p.subject.gatewayId}" authorized by issuer root ${pick.a.keyId}${pick.verdict.rootOwner ? ` ("${pick.verdict.rootOwner}")` : ""}`;
      }
      if (pick && pick.verdict.rootSigned) {
        // The key bytes come from a statement the trusted root signed, not from the bundle's say-so.
        res.keySource = "issuer-authorization";
        res.mathValid = edVerify(pick.a.publicKey, bytes, signature);
      } else if (emb) {
        res.keySource = "embedded-untrusted";
        res.mathValid = edVerify(emb.publicKey, bytes, signature);
      }
    }
    sigResults.push(res);
    return res;
  };
  if (integrityOk) {
    const rBytes = receiptSignedBytes(receipt);
    const ctx = { tenantId: receipt.tenantId ?? "UNSPECIFIED", environment: receipt.environment ?? "UNSPECIFIED" };
    const ms = sigDoc.signatures[0];
    if (ms.keyId !== manifest.signer.keyId) fail("signatures", "SIGNER_MISMATCH", "manifest.sig.json keyId differs from manifest.signer.keyId");
    checkSig("manifest", manifest.signer.keyId, manifestSignedBytes(manifestBytes), ms.signature, { ...ctx, time: manifest.createdAt });
    if (!isStr(receipt.signingKeyId) || !receipt.signingKeyId) throw new BundleError("MALFORMED_RECORD", "authorization receipt has no signingKeyId");
    checkSig("authorization-receipt", receipt.signingKeyId, rBytes, receipt.signature, { ...ctx, time: receipt.timestamp });
    if (outcome) checkSig("execution-outcome", outcome.signingKeyId, outcomeSignedBytes(outcome), outcome.signature, { ...ctx, time: outcome.completedAt });
    for (const s of sigResults) {
      if (s.mathValid === false) fail("signatures", "SIGNATURE_INVALID", `${s.record} signature does not verify under key '${s.keyId}' (${s.keySource})`);
      if (!["TRUSTED", "NOT_ESTABLISHED"].includes(s.trust)) {
        const via = s.authority === "ISSUER_AUTHORIZATION" ? ` (authorization ${s.authorizationId}, issuer root ${s.issuerRootKeyId})` : "";
        const why = {
          UNTRUSTED: via ? "is named by an authorization that no issuer root in your trust store signed" : "is neither in the supplied trust store nor authorized by an issuer root in it",
          AUTHORIZATION_INVALID: "is named by an authorization whose signature does not verify under the issuer root",
          REVOKED: via ? "relies on an authorization or issuer root that is revoked" : "is marked revoked in the supplied trust store",
          OUTSIDE_VALIDITY: "was used outside its validity window",
          TENANT_NOT_AUTHORIZED: "is not authorized for this tenant/environment",
          RECORD_NOT_AUTHORIZED: "is not authorized to sign this kind of record",
        }[s.trust];
        fail("signerTrust", `SIGNER_${s.trust}`, `${s.record}: key '${s.keyId}' ${why}${via}`);
      }
    }
  }
  const mathAll = sigResults.map((s) => s.mathValid);
  const signaturesStatus = !integrityOk ? "NOT_EVALUATED" : mathAll.includes(false) ? "INVALID" : mathAll.includes(null) ? "NOT_EVALUATED" : "VALID";
  const trustAll = sigResults.map((s) => s.trust);
  const trustStatus = !integrityOk
    ? "NOT_EVALUATED"
    : trustAll.every((t) => t === "TRUSTED")
      ? "TRUSTED"
      : trustAll.find((t) => !["TRUSTED", "NOT_ESTABLISHED"].includes(t)) ?? "NOT_ESTABLISHED";

  // ---- 5. consistency of the signed content
  const c = (code, message) => fail("consistency", code, message);
  if (integrityOk) {
    const s = manifest.subject;
    for (const [k, rk] of [["receiptId", "receiptId"], ["capabilityId", "capabilityId"], ["action", "action"], ["invocationHash", "invocationHash"]]) {
      if (s[k] !== receipt[rk]) c("SUBJECT_MISMATCH", `manifest.subject.${k} does not match the authorization receipt`);
    }
    // Schema v1 receipts carry no tenant; the subject must then say so explicitly.
    for (const k of ["tenantId", "environment"]) {
      if (s[k] !== (receipt[k] ?? "UNSPECIFIED")) c("SUBJECT_MISMATCH", `manifest.subject.${k} does not match the authorization receipt`);
    }
    if (computeBundleId(manifest) !== manifest.bundleId) c("BUNDLE_ID_MISMATCH", "bundleId is not the identifier derived from the subject and artifact digests");
    if (sha256Hex(Buffer.from(`${receipt.invocationHash}|${receipt.decision}|${receipt.timestamp}`, "utf8")) !== receipt.evidenceHash) {
      c("RECEIPT_HASH_MISMATCH", "authorization receipt evidenceHash does not match its invocationHash, decision and timestamp");
    }
    if (!["ALLOW", "DENY"].includes(receipt.decision)) c("UNRECOGNIZED_DECISION", `decision ${JSON.stringify(receipt.decision)} is not defined in v1`);
    if (!Number.isFinite(timeMs(receipt.timestamp))) c("BAD_TIMESTAMP", "authorization receipt timestamp is not an RFC 3339 date-time");
    else if (timeMs(manifest.createdAt) < timeMs(receipt.timestamp)) c("TIMESTAMP_ORDER", "bundle claims to have been exported before the decision it describes");

    const ev = manifest.evidence;
    if (ev.authorizationDecision !== "PRESENT") c("EVIDENCE_STATE_MISMATCH", "evidence.authorizationDecision must be PRESENT");
    if (ev.enforcementObservation !== "NOT_CAPTURED") c("EVIDENCE_STATE_MISMATCH", "v1 defines no enforcement-observation artifact; the state must be NOT_CAPTURED");
    const wantOutcome = outcome ? "PRESENT" : receipt.decision === "ALLOW" ? "ABSENT" : "NOT_APPLICABLE";
    if (ev.executionOutcome !== wantOutcome) c("EVIDENCE_STATE_MISMATCH", `evidence.executionOutcome is ${ev.executionOutcome} but the bundle content implies ${wantOutcome}`);
    if (ev.invocationDisclosure !== (invocation ? "PRESENT" : "NOT_DISCLOSED")) c("EVIDENCE_STATE_MISMATCH", "evidence.invocationDisclosure does not match the bundle content");
    if (ev.policyDisclosure !== (ruleset ? "PRESENT" : "NOT_DISCLOSED")) c("EVIDENCE_STATE_MISMATCH", "evidence.policyDisclosure does not match the bundle content");

    if (outcome) {
      if (receipt.decision !== "ALLOW" || outcome.decision !== "ALLOW") c("CONTRADICTORY_RECORDS", "an execution outcome is present for an action whose recorded decision is not ALLOW");
      for (const k of ["capabilityId", "action", "invocationHash", "policyVersion", "tenantId", "environment"]) {
        if (outcome[k] !== receipt[k]) c("OUTCOME_LINK_MISMATCH", `execution outcome ${k} does not match the authorization receipt`);
      }
      if (outcome.authorizationReceiptId !== receipt.receiptId || outcome.authorizationProofChainHash !== receipt.proofChainHash) {
        c("OUTCOME_LINK_MISMATCH", "execution outcome is not linked to this authorization receipt");
      }
      if (outcomeHashOf(outcome) !== outcome.outcomeHash) c("OUTCOME_HASH_MISMATCH", "execution outcome outcomeHash does not match its content");
      const st = outcome.executionStatus;
      const coherent =
        ["SUCCEEDED", "FAILED", "UNKNOWN"].includes(st) &&
        (st === "SUCCEEDED" ? /^sha256:[0-9a-f]{64}$/.test(outcome.resultHash) : outcome.resultHash === "") &&
        (st === "FAILED" ? outcome.errorCode.length > 0 : outcome.errorCode === "");
      if (!coherent) c("CONTRADICTORY_RECORDS", "execution outcome status, resultHash and errorCode contradict each other");
      if (!Number.isFinite(timeMs(outcome.completedAt))) c("BAD_TIMESTAMP", "execution outcome completedAt is not an RFC 3339 date-time");
      else if (timeMs(outcome.completedAt) < timeMs(receipt.timestamp)) c("TIMESTAMP_ORDER", "execution outcome claims completion before the authorization decision");
    }
    if (invocation) {
      if (sha256Hex(Buffer.from(canonicalJSON(invocation), "utf8")) !== receipt.invocationHash) c("DISCLOSURE_MISMATCH", "disclosed invocation does not hash to the signed invocationHash");
      // The hash binds whatever the signer hashed. If that names another capability or action than the
      // receipt's own signed fields, the receipt describes one action and its hash another.
      else if (invocation.capabilityId !== receipt.capabilityId || invocation.action !== receipt.action) c("CONTRADICTORY_RECORDS", "the disclosed invocation names a different capability or action than the receipt it hashes to");
    }
    if (ruleset) {
      const h = `sha256:${sha256Hex(Buffer.from(canonicalJSON(ruleset), "utf8"))}`;
      if (h !== receipt.policyVersion) c("DISCLOSURE_MISMATCH", "disclosed policy ruleset does not hash to the signed policyVersion");
      else if (evaluateRuleset(ruleset, receipt.capabilityId, receipt.risk).rule === "DENY" && receipt.decision === "ALLOW") {
        c("CONTRADICTORY_RECORDS", "the disclosed policy maps this capability to DENY but the recorded decision is ALLOW");
      }
    }
  }
  for (const [k, field] of [["receiptId", "receiptId"], ["tenantId", "tenantId"], ["environment", "environment"]]) {
    if (expect[k] !== undefined && expect[k] !== manifest.subject[field]) fail("expectation", "EXPECTATION_MISMATCH", `expected ${k} ${JSON.stringify(expect[k])} but the bundle is about ${JSON.stringify(manifest.subject[field])}`);
  }
  if (expect.bundleId !== undefined && expect.bundleId !== manifest.bundleId) fail("expectation", "EXPECTATION_MISMATCH", "bundleId differs from the expected one");

  const stageFailed = (s) => failures.some((f) => f.stage === s);
  const consistencyStatus = !integrityOk ? "NOT_EVALUATED" : stageFailed("consistency") ? "INCONSISTENT" : "CONSISTENT";
  const hard = !integrityOk || signaturesStatus === "INVALID" || stageFailed("consistency") || stageFailed("signerTrust") || stageFailed("expectation") || stageFailed("signatures");
  const overall = hard ? "FAILED" : signaturesStatus === "VALID" && trustStatus === "TRUSTED" ? "PASSED" : "INCOMPLETE";

  // ---- 6. claims: derived only from content that passed every check above
  // A FAILED bundle supports no conclusion at all; an INCOMPLETE one yields claims attributed to an unidentified key holder.
  const claimsEvaluated = overall !== "FAILED" && signaturesStatus === "VALID";
  const claims = claimsEvaluated
    ? deriveClaims({ manifest, receipt, outcome, invocation, ruleset, sigResults, trustStatus })
    : [];
  if (integrityOk && signaturesStatus === "NOT_EVALUATED") {
    notes.push("no key was available for at least one signature (not in the trust store, not embedded): its mathematics could not be checked");
  }
  if (trustStore) notes.push("revocation and key status are as recorded in the trust store you supplied; no online check was made");

  return {
    reportFormat: "strix-ppb-verification-report",
    reportVersion: "1.0",
    verifier: { name: VERIFIER_NAME, version: VERIFIER_VERSION },
    bundle: { bundleId: manifest.bundleId, formatVersion: manifest.formatVersion, createdAt: manifest.createdAt, exporter: manifest.exporter, subject: manifest.subject },
    result: {
      overall,
      integrity: { status: integrityOk ? "VERIFIED" : "FAILED", artifactsChecked: manifest.artifacts.length },
      signatures: { status: signaturesStatus, records: sigResults.map(({ record, keyId, mathValid, keySource }) => ({ record, keyId, mathValid, keySource })) },
      signerTrust: { status: trustStatus, trustStoreSupplied: !!trustStore, records: sigResults.map(({ record, keyId, trust, owner, keyStatus, authority, authorizationId, issuerRootKeyId, gatewayId, standing, scope }) => ({ record, keyId, trust, authority, owner, keyStatus, authorizationId, issuerRootKeyId, gatewayId, standing, scope })) },
      consistency: { status: consistencyStatus },
      claims: { status: claimsEvaluated ? "EVALUATED" : "NOT_EVALUATED" },
    },
    evidence: manifest.evidence,
    failures,
    claims,
    unsupportedConclusions: [...UNSUPPORTED_CONCLUSIONS],
    notes,
  };
}

function deriveClaims({ manifest, receipt, outcome, invocation, ruleset, sigResults, trustStatus }) {
  const trusted = trustStatus === "TRUSTED";
  const sigOf = (record) => sigResults.find((s) => s.record === record);
  const whoOf = (record) => {
    const r = sigOf(record);
    return trusted ? `the trusted signer${r.owner ? ` "${r.owner}"` : ""} (key ${r.keyId})` : `the holder of key ${r.keyId}, whose identity is NOT established,`;
  };
  const who = whoOf("authorization-receipt"); // the gateway that signed the decision
  const exporterWho = whoOf("manifest"); // whoever signed the export; the only signature over natively unsigned fields
  const sameSigner = (a, b) => sigOf(a).keyId === sigOf(b).keyId;
  const asserted = trusted ? "ASSERTED" : "ASSERTED_BY_UNTRUSTED_KEY";
  const trustAssumption = trusted
    ? "The trust store you supplied correctly identifies the signer, and the signing key was under the signer's sole control when it signed."
    : "None can be relied on: the signing key is not one you have established trust in.";
  const R = PATHS.receipt;
  const out = [];
  const add = (id, topic, classification, status, statement, supportingArtifacts, trustAssumptions, limitations) =>
    out.push({ id, topic, classification, status, statement, supportingArtifacts, trustAssumptions, limitations });

  add("PPB-C01", "integrity", "CRYPTOGRAPHIC_FINDING", "ESTABLISHED",
    `All ${manifest.artifacts.length} artifacts match the SHA-256 digests in the signed manifest, and the bundle contains no file outside that inventory.`,
    [PATHS.manifest], ["SHA-256 remains collision- and second-preimage-resistant."],
    ["Establishes that the content is unchanged since the manifest was signed; says nothing about whether the content is true."]);

  add("PPB-C02", "signatures", "CRYPTOGRAPHIC_FINDING", "ESTABLISHED",
    `The signature${sigResults.length > 1 ? "s" : ""} on the ${sigResults.map((s) => s.record).join(", ")} ${sigResults.length > 1 ? "are" : "is"} mathematically valid Ed25519 under key${new Set(sigResults.map((s) => s.keyId)).size > 1 ? "s" : ""} ${[...new Set(sigResults.map((s) => s.keyId))].join(", ")}${sigResults.some((s) => s.keySource !== "trust-store") ? " (checked against key material embedded in the bundle, which is not trusted)" : ""}.`,
    [PATHS.signature, R, ...(outcome ? [PATHS.outcome] : [])], ["Ed25519 remains unforgeable."],
    ["A valid signature proves that the holder of the private key signed these exact bytes. It does not prove the statements in them."]);

  add("PPB-C03", "signer-trust", "TRUST_EVALUATION", trusted ? "ESTABLISHED" : "NOT_ESTABLISHED",
    trusted
      ? `Every signing key has standing under the trust store you supplied. ${describeAuthority(sigResults)}`
      : "Authenticated origin is NOT established: no key you have independently chosen to trust was used to check these signatures. Anyone can produce a mathematically valid bundle with a key of their own.",
    sigResults.some((s) => s.authority === "ISSUER_AUTHORIZATION") ? [PATHS.authorizations] : [],
    ["Your trust store was obtained through a channel independent of this bundle."],
    ["Key status is as recorded in your trust store; no online revocation check is made.",
      "Trust in a key today does not prove the key was uncompromised at the time it signed.",
      ...(sigResults.some((s) => s.authority === "ISSUER_AUTHORIZATION")
        ? ["An authorization's validity interval is compared with each record's own time, which the signer asserts.",
          "An issuer authorization shows that the root vouched for this key within the stated scope. It does not show that the gateway behaved correctly."]
        : []),
      ...(sigResults.some((s) => s.standing === "NOT_CHECKED") ? ["No revocation list from the issuer root was supplied: whether the authorization has since been withdrawn was NOT checked."] : [])]);

  add("PPB-C04", "policy-decision", "SOURCE_ASSERTION", asserted,
    `${cap(who)} recorded the decision ${receipt.decision} for action "${receipt.action}" (capability ${receipt.capabilityId}, risk ${receipt.risk}, mode ${receipt.mode}) in tenant "${receipt.tenantId ?? "UNSPECIFIED"}", environment "${receipt.environment ?? "UNSPECIFIED"}", as receipt ${receipt.receiptId}.`,
    [R], [trustAssumption],
    ["This is the signer's record of a decision. A decision record is not an enforcement observation and not an execution result."]);

  if (ruleset) {
    const ev = evaluateRuleset(ruleset, receipt.capabilityId, receipt.risk);
    add("PPB-C05", "policy-identity", "CORROBORATED", "ESTABLISHED",
      `The disclosed policy ruleset hashes to the policy version in the signed receipt (${receipt.policyVersion}). Under that ruleset this capability matches rule ${ev.matched} => ${ev.rule}.`,
      [PATHS.policy, R], ["SHA-256 remains second-preimage-resistant."],
      ["Identifies which ruleset the signer says it evaluated; does not show the evaluation was performed correctly.",
        "Rate limits and identity checks can turn an ALLOW rule into a DENY decision and are not part of the hashed ruleset.",
        "Whether the policy is correct or adequate is not assessed."]);
  } else {
    add("PPB-C05", "policy-identity", "SOURCE_ASSERTION", asserted,
      `${cap(who)} identifies the governing policy only by hash (${receipt.policyVersion ?? "not recorded in this receipt schema"}). The ruleset itself is not disclosed in this bundle.`,
      [R], [trustAssumption], ["The policy's content cannot be inspected from this bundle.", "Whether the policy is correct or adequate is not assessed."]);
  }

  if (invocation) {
    add("PPB-C06", "invocation-binding", "CORROBORATED", "ESTABLISHED",
      "The disclosed invocation (capability, action, arguments, actor fields) hashes to the invocationHash in the signed receipt: the decision was recorded for exactly these arguments.",
      [PATHS.invocation, R], ["SHA-256 remains second-preimage-resistant."],
      ["Shows which request the decision record is about; does not show that this request is what reached the tool."]);
  } else {
    add("PPB-C06", "invocation-binding", "NOT_ESTABLISHED", "NOT_ESTABLISHED",
      "The action's arguments are not disclosed. The receipt binds only their hash, so what was requested cannot be determined from this bundle.",
      [R], [], ["Disclosure is the exporter's choice; a bundle without it supports fewer conclusions."]);
  }

  const actor = invocation ? invocation.actorId : receipt.actorId;
  add("PPB-C07", "actor-identity", "NOT_ESTABLISHED", "NOT_ESTABLISHED",
    `Authentication of the requesting actor is NOT established. ${actor ? `The evidence names actor ${JSON.stringify(actor)}${invocation ? ", a value bound into the signed invocationHash" : ", in a field the native receipt signature does not cover"}` : "No actor identifier was recorded"}; the bundle contains no authentication evidence.`,
    invocation ? [PATHS.invocation, R] : [R], [], ["An actor identifier is a value supplied to the gateway. It is not proof of who made the request."]);

  if (receipt.approvalReason !== undefined || receipt.approvedBy !== undefined) {
    add("PPB-C08", "approval", "SOURCE_ASSERTION", asserted,
      `${cap(exporterWho)}, as signer of this export, reports approval result ${JSON.stringify(receipt.approvalReason ?? null)}${receipt.approvedBy !== undefined ? ` by ${JSON.stringify(receipt.approvedBy)}` : ""}.`,
      [R, PATHS.manifest], [trustAssumption],
      ["These fields are NOT covered by the gateway's own receipt signature. The only signature over them is the manifest's, made at export.",
        ...(sameSigner("manifest", "authorization-receipt") ? [] : ["The export was signed by a different key than the decision record, so this statement is the exporter's, not the deciding gateway's."]),
        "No approver signature or approver identity evidence is included."]);
  } else {
    add("PPB-C08", "approval", "NOT_ESTABLISHED", "NOT_APPLICABLE", "No approval step is recorded for this action.", [R], [], []);
  }

  add("PPB-C09", "enforcement", "NOT_ESTABLISHED", "NOT_ESTABLISHED",
    receipt.decision === "DENY"
      ? "Actual prevention of execution is NOT established. The signer recorded a DENY decision, and by design the gateway issues no execution record for a denied call. The bundle contains no independently evaluable enforcement observation, and cannot show that the action was not performed through a path that does not pass the gateway."
      : "Enforcement is NOT established: the bundle contains no independently evaluable observation that this action could only reach the tool through the recorded decision.",
    [R], [], ["Strix v1 evidence has no enforcement-observation artifact (evidence state NOT_CAPTURED).", "Absence of an execution record is not evidence that nothing executed."]);

  if (outcome) {
    const st = outcome.executionStatus;
    const what = st === "SUCCEEDED" ? `the tool call returned without error (result hash ${outcome.resultHash})` : st === "FAILED" ? `the tool call failed (error code ${JSON.stringify(outcome.errorCode)})` : "the result of the call is unknown";
    add("PPB-C10", "execution-outcome", "SOURCE_ASSERTION", asserted,
      `${cap(whoOf("execution-outcome"))} recorded that execution was attempted after this authorization and that ${what}; status ${st}, outcome ${outcome.outcomeId}.`,
      [PATHS.outcome, R], [trustAssumption],
      [sameSigner("execution-outcome", "authorization-receipt")
        ? "Reported under the same key that signed the decision; it is not an independent observation of the tool."
        : "Signed by a different key than the decision record. That does not make it an independent observation of the tool: both are the signer's own reports.",
        st === "SUCCEEDED" ? "The result itself is not included; only its hash is committed." : "A FAILED or UNKNOWN status does not show that the action had no effect.",
        "Downstream side effects are not recorded."]);
  } else if (receipt.decision === "ALLOW") {
    add("PPB-C10", "execution-outcome", "NOT_ESTABLISHED", "NOT_ESTABLISHED",
      "Execution outcome is NOT established. The exporter states that its store held no execution record for this authorization at export time (evidence state ABSENT). The action may or may not have executed.",
      [PATHS.manifest], [], ["A missing record is not evidence of non-execution."]);
  } else {
    add("PPB-C10", "execution-outcome", "NOT_ESTABLISHED", "NOT_APPLICABLE",
      "No execution outcome applies: the recorded decision is not ALLOW. See PPB-C09 for what that does and does not show.", [R], [], []);
  }

  add("PPB-C11", "time", "SOURCE_ASSERTION", asserted,
    `Times are each signer's own clock readings: decision ${receipt.timestamp} (key ${sigOf("authorization-receipt").keyId})${outcome ? `, completion ${outcome.completedAt} (key ${sigOf("execution-outcome").keyId})` : ""}, export ${manifest.createdAt} (key ${sigOf("manifest").keyId}).`,
    [R, PATHS.manifest], [trustAssumption], ["No independent timestamp authority is involved; these values do not prove when anything happened."]);

  add("PPB-C12", "record-completeness", "NOT_ESTABLISHED", "NOT_ESTABLISHED",
    "Completeness of the signer's log is NOT established. The receipt commits to a position in a hash chain, but the chain is not part of this bundle, so nothing here shows that other records were not omitted, or that this is the only record for this action.",
    [R], [], ["Replay: this bundle can be presented any number of times. Track bundleId / receiptId if uniqueness matters to you."]);

  const extra = Object.keys(receipt).filter((k) => !(RECEIPT_ORDER[receipt.schemaVersion] ?? []).includes(k) && !["signingKeyId", "signature"].includes(k));
  if (extra.length) {
    out.find((x) => x.id === "PPB-C04").limitations.push(`Receipt fields not covered by the gateway's native signature (assertions of the export signer, key ${sigOf("manifest").keyId}, only): ${extra.sort().join(", ")}.`);
  }
  return out;
}

const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);

function describeAuthority(sigResults) {
  const seen = new Map();
  for (const s of sigResults) if (!seen.has(s.keyId)) seen.set(s.keyId, s);
  return [...seen.values()]
    .map((s) =>
      s.authority === "ISSUER_AUTHORIZATION"
        ? `Key ${s.keyId}: authorized by issuer root ${s.issuerRootKeyId} under ${s.authorizationId} for gateway "${s.gatewayId}", tenants ${JSON.stringify(s.scope.tenants)}, environments ${JSON.stringify(s.scope.environments)}, ${s.scope.notBefore} to ${s.scope.notAfter}; revocation ${s.standing === "NOT_REVOKED" ? "checked, not revoked" : "not checked"}.`
        : `Key ${s.keyId}: listed directly in your trust store${s.keyStatus === "retired" ? " (retired)" : ""}.`)
    .join(" ");
}

// -------------------------------------------------------------- rendering

/**
 * Make a line safe to print: control characters, line and paragraph separators and
 * bidirectional controls become \uXXXX. Bundle content is untrusted even when it
 * verifies, and a report is read by people.
 */
export function printable(line) {
  return String(line).replace(/[\u0000-\u001f\u007f-\u009f\u2028\u2029\u200e\u200f\u202a-\u202e\u2066-\u2069\ufeff]/g, (ch) => "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0"));
}

export function renderText(report) {
  const r = report.result;
  const s = report.bundle.subject;
  const L = [];
  const row = (k, v, extra = "") => L.push(`  ${(k + " ").padEnd(24, ".")} ${v.padEnd(14)}${extra}`.trimEnd());
  L.push("Strix Portable Proof Bundle - verification report");
  L.push(`  bundle   ${report.bundle.bundleId} (format ${report.bundle.formatVersion}, exported ${report.bundle.createdAt})`);
  L.push(`  subject  receipt ${s.receiptId}  action ${s.action}  tenant ${s.tenantId}/${s.environment}`);
  L.push("");
  row("Integrity", r.integrity.status, `${r.integrity.artifactsChecked} artifacts in signed inventory`);
  row("Signature mathematics", r.signatures.status, r.signatures.records.map((x) => `${x.record}:${x.mathValid === null ? "no key" : x.mathValid ? "valid" : "INVALID"}`).join(" "));
  row("Signer trust", r.signerTrust.status, r.signerTrust.trustStoreSupplied ? r.signerTrust.records.map((x) => `${x.keyId}:${x.trust}`).filter((v, i, a) => a.indexOf(v) === i).join(" ") : "no trust store supplied");
  row("Evidence consistency", r.consistency.status);
  row("Claims", r.claims.status);
  row("Overall", r.overall);
  L.push("");
  if (r.overall === "PASSED") L.push("  PASSED means the four checks above succeeded. It is not a statement that the", "  action was enforced, executed, safe or compliant. Read the claims below.");
  if (r.overall === "INCOMPLETE") L.push("  INCOMPLETE: nothing failed, but origin is not authenticated. Supply a trust", "  store obtained independently of this bundle (--trust-store).");
  if (report.failures.length) {
    L.push("Failures");
    for (const f of report.failures) L.push(`  [${f.stage}] ${f.code}: ${f.message}`);
    L.push("");
  }
  L.push("Evidence in this bundle");
  for (const [k, v] of Object.entries(report.evidence)) L.push(`  ${k.padEnd(24)} ${v}`);
  L.push("");
  if (r.claims.status === "EVALUATED") {
    L.push("What the evidence supports, and how far");
    for (const cl of report.claims) {
      L.push(`  ${cl.id} [${cl.classification} / ${cl.status}] ${cl.topic}`);
      L.push(`      ${cl.statement}`);
      for (const lim of cl.limitations) L.push(`      limit: ${lim}`);
    }
  } else {
    L.push("Claims were NOT evaluated: no conclusion about the action may be drawn from this bundle.");
  }
  L.push("");
  L.push("Never established by a v1 bundle");
  for (const u of report.unsupportedConclusions) L.push(`  - ${u}`);
  if (report.notes.length) {
    L.push("");
    L.push("Notes");
    for (const n of report.notes) L.push(`  - ${n}`);
  }
  // Every element of L is one line by construction; escaping per line keeps it that way.
  return L.map(printable).join("\n") + "\n";
}

export function exitCodeFor(report) {
  return EXIT[report.result.overall];
}

// --------------------------------------------------------------------- CLI

const USAGE = `strix-proof-verify ${VERIFIER_VERSION} - offline verifier for Strix Portable Proof Bundle v1

Usage:
  strix-proof-verify verify <bundle-dir | bundle.ppb.json> [options]
  strix-proof-verify inspect <bundle-dir | bundle.ppb.json>

Options:
  --trust-store <file>       Keys YOU trust (trust-store JSON, JWKS, or one JWK): gateway keys directly,
                             and/or issuer roots that authorize gateway keys. Without it the result
                             can never be better than INCOMPLETE.
  --issuer-authorizations <file>
                             Issuer authorizations you hold, in addition to any inside the bundle.
  --revocations <file>       Revocation list signed by an issuer root in your trust store.
  --expect-receipt-id <id>   Fail unless the bundle is about this receipt.
  --expect-tenant <id>       Fail unless the bundle is for this tenant.
  --expect-environment <e>   Fail unless the bundle is for this environment.
  --expect-bundle-id <id>    Fail unless the bundle has this identifier.
  --json                     Print the machine-readable report.
  --report <file>            Also write the JSON report to a file.

Exit codes:
  0  PASSED      integrity, signatures, signer trust and consistency all hold
  1  FAILED      tampering, invalid signature, untrusted/revoked signer, or contradictory evidence
  2  ERROR       input could not be evaluated (malformed, unsafe, unsupported version or algorithm)
  3  INCOMPLETE  nothing failed, but signer trust is not established
`;

function parseArgs(argv) {
  const o = { _: [] };
  const flags = { "--trust-store": "trustStore", "--expect-receipt-id": "receiptId", "--expect-tenant": "tenantId", "--expect-environment": "environment", "--expect-bundle-id": "bundleId", "--report": "report", "--issuer-authorizations": "authorizations", "--revocations": "revocations" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") o.json = true;
    else if (a === "--help" || a === "-h") o.help = true;
    else if (Object.hasOwn(flags, a)) {
      if (i + 1 >= argv.length) throw new BundleError("USAGE", `${a} needs a value`);
      o[flags[a]] = argv[++i];
    } else if (a.startsWith("--")) throw new BundleError("USAGE", `unknown option ${a}`);
    else o._.push(a);
  }
  return o;
}

export function main(argv, io = { out: (s) => process.stdout.write(s), err: (s) => process.stderr.write(s) }) {
  let o;
  try {
    o = parseArgs(argv);
    const [cmd, target] = o._;
    if (o.help || !cmd) {
      io.out(USAGE);
      return o.help ? 0 : EXIT.ERROR;
    }
    if (!["verify", "inspect"].includes(cmd) || !target || o._.length !== 2) throw new BundleError("USAGE", "expected: verify|inspect <bundle>");
    const files = loadBundle(target);
    if (cmd === "inspect") {
      const m = parseStrictJson(files.get(PATHS.manifest) ?? Buffer.alloc(0), "manifest.json");
      io.out("UNVERIFIED listing - nothing below has been checked. Run 'verify'.\n");
      io.out(printable(JSON.stringify({ bundleId: m?.bundleId, formatVersion: m?.formatVersion, subject: m?.subject, evidence: m?.evidence, signer: m?.signer, files: [...files.keys()].sort() }, null, 2)).replace(/\\u000a/g, "\n") + "\n");
      return 0;
    }
    const trustStore = o.trustStore ? parseTrustStore(fs.readFileSync(o.trustStore)) : null;
    if ((o.authorizations || o.revocations) && !trustStore) throw new BundleError("USAGE", "--issuer-authorizations and --revocations need --trust-store: they only count when signed by an issuer root you trust");
    const authorizations = o.authorizations ? parseAuthorizations(fs.readFileSync(o.authorizations)) : [];
    const revocations = o.revocations ? parseRevocations(fs.readFileSync(o.revocations), trustStore) : null;
    const report = verifyBundle(files, { trustStore, authorizations, revocations, expect: { receiptId: o.receiptId, tenantId: o.tenantId, environment: o.environment, bundleId: o.bundleId } });
    if (o.report) fs.writeFileSync(o.report, JSON.stringify(report, null, 2) + "\n");
    io.out(o.json ? JSON.stringify(report, null, 2) + "\n" : renderText(report));
    return exitCodeFor(report);
  } catch (e) {
    const code = e instanceof BundleError ? e.code : e?.code === "ENOENT" ? "NOT_FOUND" : "INTERNAL_ERROR";
    const msg = e instanceof Error ? e.message : String(e);
    if (o?.json) io.out(JSON.stringify({ reportFormat: "strix-ppb-verification-report", reportVersion: "1.0", verifier: { name: VERIFIER_NAME, version: VERIFIER_VERSION }, result: { overall: "ERROR" }, error: { code, message: msg } }, null, 2) + "\n");
    else io.err(`ERROR ${code}: ${printable(msg)}\nThe bundle was not evaluated; no conclusion may be drawn from it.\n`);
    return EXIT.ERROR;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href) {
  process.exitCode = main(process.argv.slice(2));
}
