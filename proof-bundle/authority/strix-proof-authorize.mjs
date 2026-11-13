#!/usr/bin/env node
// Strix Portable Proof Bundle v1 — issuer authority tool (offline ceremony).
//
// An ISSUER ROOT key authorizes a gateway's signing key for a bounded scope
// (tenants, environments, kinds of record) and validity interval. Relying
// parties then trust the root, once, instead of every gateway key.
//
// This tool is run by whoever holds the issuer root key, on a machine that is
// not the gateway. The root key never goes into a bundle, a gateway, or the
// verifier. Nothing here contacts a network.
//
// STATUS: the mechanism is implemented and tested. No Strix issuer root exists
// yet; who holds that key and how its public half is published is an open
// decision (see docs/ISSUER-AUTHORIZATION.md).

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  AUTHORIZATION_PAYLOAD_TYPE, BundleError, RECORD_KINDS, REVOCATIONS_PAYLOAD_TYPE, TRUST_STORE_FORMAT,
  pae, parseAuthorization, parseStrictJson, parseTrustStore, publicKeyFromJwk, timeMs,
} from "../verifier/strix-proof-verify.mjs";

export const AUTHORITY_VERSION = "1.0.0";

class AuthorityError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}

const jwkOf = (privateKey, kid) => {
  const der = crypto.createPublicKey(privateKey).export({ format: "der", type: "spki" });
  return { kty: "OKP", crv: "Ed25519", kid, x: der.subarray(der.length - 32).toString("base64url") };
};

function envelope(payloadType, payload, rootKey, rootKid) {
  const payloadBytes = Buffer.from(JSON.stringify(payload, null, 2) + "\n", "utf8");
  const signature = crypto.sign(null, pae(payloadType, payloadBytes), rootKey).toString("base64url");
  return { payloadType, payload: payloadBytes.toString("base64"), signatures: [{ keyId: rootKid, algorithm: "Ed25519", signature }] };
}

/** Sign an issuer authorization. Pure: returns the envelope. */
export function issueAuthorization({ rootKey, rootKid, issuer, gatewayId, gatewayJwk, tenants, environments, records = [...RECORD_KINDS], notBefore, notAfter, issuedAt, authorizationId }) {
  publicKeyFromJwk(gatewayJwk);
  if (typeof gatewayJwk.kid !== "string" || !gatewayJwk.kid) throw new AuthorityError("USAGE", "the gateway JWK needs a kid");
  const payload = {
    type: "strix-ppb-issuer-authorization",
    version: "1.0",
    authorizationId: authorizationId ?? `ia_${crypto.randomBytes(12).toString("hex")}`,
    issuer,
    issuedAt: issuedAt ?? new Date().toISOString(),
    subject: { gatewayId, keyId: gatewayJwk.kid, jwk: { kty: "OKP", crv: "Ed25519", x: gatewayJwk.x } },
    scope: { tenants, environments, records },
    notBefore,
    notAfter,
  };
  const env = envelope(AUTHORIZATION_PAYLOAD_TYPE, payload, rootKey, rootKid);
  parseAuthorization(env); // never emit something the verifier would call malformed
  return env;
}

/** Sign a revocation list. `revoked` is [{authorizationId, revokedAt}]. */
export function issueRevocations({ rootKey, rootKid, issuer, revoked, issuedAt }) {
  const sorted = [...revoked].sort((a, b) => (a.authorizationId < b.authorizationId ? -1 : 1));
  return envelope(REVOCATIONS_PAYLOAD_TYPE, { type: "strix-ppb-authorization-revocations", version: "1.0", issuer, issuedAt: issuedAt ?? new Date().toISOString(), revoked: sorted }, rootKey, rootKid);
}

function loadRoot(dir) {
  let pem, jwk;
  try {
    pem = fs.readFileSync(path.join(dir, "issuer-root-key.pem"), "utf8");
    jwk = parseStrictJson(fs.readFileSync(path.join(dir, "issuer-root-jwk.json")), "issuer-root-jwk.json");
  } catch {
    throw new AuthorityError("ROOT_UNAVAILABLE", "the issuer root key could not be read from --root-dir");
  }
  const rootKey = crypto.createPrivateKey({ key: pem, format: "pem" });
  if (rootKey.asymmetricKeyType !== "ed25519" || jwkOf(rootKey, jwk?.kid).x !== jwk?.x || typeof jwk?.kid !== "string" || !jwk.kid) {
    throw new AuthorityError("ROOT_UNAVAILABLE", "issuer-root-jwk.json does not describe the private key next to it");
  }
  return { rootKey, rootKid: jwk.kid, jwk };
}

const USAGE = `strix-proof-authorize ${AUTHORITY_VERSION} - issuer authority tool for Strix Portable Proof Bundle v1 (offline)

Usage:
  strix-proof-authorize init-root   --root-dir <dir> --key-id <id>
  strix-proof-authorize trust-store --root-dir <dir> --owner <text>
  strix-proof-authorize issue       --root-dir <dir> --issuer <name> --gateway-id <id> --gateway-jwk <public-jwk.json>
                                    --tenant <id>... --environment <e>... --not-before <RFC3339> --not-after <RFC3339>
                                    [--record manifest|authorization-receipt|execution-outcome]... [--authorization-id ia_...]
  strix-proof-authorize revoke      --root-dir <dir> --issuer <name> --authorization-id <ia_...>... [--previous <list.json>]

init-root creates a new Ed25519 issuer root key and refuses to overwrite one. Keep <dir> offline.
issue and revoke print a signed envelope on stdout. revoke with --previous carries earlier entries forward.
Exit codes: 0 ok, 1 refused, 2 usage.
`;

function parseArgs(argv) {
  const o = { _: [], tenant: [], environment: [], record: [], authorizationId: [] };
  const single = { "--root-dir": "rootDir", "--key-id": "keyId", "--owner": "owner", "--issuer": "issuer", "--gateway-id": "gatewayId", "--gateway-jwk": "gatewayJwk", "--not-before": "notBefore", "--not-after": "notAfter", "--previous": "previous" };
  const multi = { "--tenant": "tenant", "--environment": "environment", "--record": "record", "--authorization-id": "authorizationId" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--help" || a === "-h") o.help = true;
    else if (Object.hasOwn(single, a) || Object.hasOwn(multi, a)) {
      if (i + 1 >= argv.length) throw new AuthorityError("USAGE", `${a} needs a value`);
      if (Object.hasOwn(single, a)) o[single[a]] = argv[++i];
      else o[multi[a]].push(argv[++i]);
    } else if (a.startsWith("--")) throw new AuthorityError("USAGE", `unknown option ${a}`);
    else o._.push(a);
  }
  return o;
}

export function main(argv, io = { out: (s) => process.stdout.write(s), err: (s) => process.stderr.write(s) }) {
  try {
    const o = parseArgs(argv);
    const cmd = o._[0];
    if (o.help || !cmd) {
      io.out(USAGE);
      return o.help ? 0 : 2;
    }
    const need = (...names) => {
      for (const n of names) if (o[n] === undefined || (Array.isArray(o[n]) && o[n].length === 0)) throw new AuthorityError("USAGE", `${cmd} needs --${n.replace(/[A-Z]/g, (c) => "-" + c.toLowerCase())}`);
    };
    const json = (v) => io.out(JSON.stringify(v, null, 2) + "\n");
    if (cmd === "init-root") {
      need("rootDir", "keyId");
      const keyFile = path.join(o.rootDir, "issuer-root-key.pem");
      if (fs.existsSync(keyFile)) throw new AuthorityError("ROOT_EXISTS", "an issuer root key already exists in --root-dir; it is never overwritten");
      fs.mkdirSync(o.rootDir, { recursive: true, mode: 0o700 });
      const { privateKey } = crypto.generateKeyPairSync("ed25519");
      fs.writeFileSync(keyFile, privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600, flag: "wx" });
      fs.writeFileSync(path.join(o.rootDir, "issuer-root-jwk.json"), JSON.stringify(jwkOf(privateKey, o.keyId), null, 2) + "\n", { flag: "wx" });
      json({ ok: true, keyId: o.keyId });
      return 0;
    }
    need("rootDir");
    const root = loadRoot(o.rootDir);
    if (cmd === "trust-store") {
      need("owner");
      const doc = { format: TRUST_STORE_FORMAT, formatVersion: "1.0", keys: [{ keyId: root.rootKid, role: "issuer-root", owner: o.owner, status: "active", jwk: { kty: "OKP", crv: "Ed25519", kid: root.rootKid, x: root.jwk.x } }] };
      parseTrustStore(doc);
      json(doc);
      return 0;
    }
    if (cmd === "issue") {
      need("issuer", "gatewayId", "gatewayJwk", "tenant", "environment", "notBefore", "notAfter");
      const gatewayJwk = parseStrictJson(fs.readFileSync(o.gatewayJwk), "gateway JWK");
      json(issueAuthorization({ ...root, issuer: o.issuer, gatewayId: o.gatewayId, gatewayJwk, tenants: o.tenant, environments: o.environment, records: o.record.length ? o.record : [...RECORD_KINDS], notBefore: o.notBefore, notAfter: o.notAfter, authorizationId: o.authorizationId[0] }));
      return 0;
    }
    if (cmd === "revoke") {
      need("issuer", "authorizationId");
      const now = new Date().toISOString();
      const revoked = new Map();
      if (o.previous) {
        // Carry forward only a list this same root signed; a list is append-only.
        const prev = parseStrictJson(fs.readFileSync(o.previous), "previous list");
        const bytes = Buffer.from(String(prev?.payload ?? ""), "base64");
        const sig = prev?.signatures?.[0];
        if (prev?.payloadType !== REVOCATIONS_PAYLOAD_TYPE || sig?.keyId !== root.rootKid || !crypto.verify(null, pae(REVOCATIONS_PAYLOAD_TYPE, bytes), crypto.createPublicKey(root.rootKey), Buffer.from(String(sig?.signature ?? ""), "base64url"))) {
          throw new AuthorityError("PREVIOUS_LIST_INVALID", "--previous is not a revocation list signed by this issuer root");
        }
        for (const e of parseStrictJson(bytes, "previous list payload").revoked) revoked.set(e.authorizationId, e);
      }
      for (const id of o.authorizationId) if (!revoked.has(id)) revoked.set(id, { authorizationId: id, revokedAt: now });
      for (const e of revoked.values()) if (!/^ia_[A-Za-z0-9._-]{1,64}$/.test(e.authorizationId) || !Number.isFinite(timeMs(e.revokedAt))) throw new AuthorityError("USAGE", "bad authorization id");
      json(issueRevocations({ ...root, issuer: o.issuer, revoked: [...revoked.values()], issuedAt: now }));
      return 0;
    }
    throw new AuthorityError("USAGE", `unknown command ${cmd}`);
  } catch (e) {
    const code = e instanceof AuthorityError || e instanceof BundleError ? e.code : "INTERNAL_ERROR";
    io.err(`REFUSED ${code}: ${e instanceof AuthorityError || e instanceof BundleError ? e.message : "unexpected failure; nothing was signed"}\n`);
    return code === "USAGE" ? 2 : 1;
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(fs.realpathSync(process.argv[1])).href) {
  process.exitCode = main(process.argv.slice(2));
}
