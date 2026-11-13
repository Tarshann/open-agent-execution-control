// Verifier behaviour that the carrier-based vectors cannot express: strict
// parsing, directory loading, the CLI contract, the authentic example bundles,
// offline operation, and exhaustive single-byte tampering.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { BundleError, LIMITS, canonicalJSON, loadBundle, loadCarrier, main, parseStrictJson, parseTrustStore, verifyBundle } from "../verifier/strix-proof-verify.mjs";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const verifierPath = path.join(root, "verifier", "strix-proof-verify.mjs");
const examples = path.join(root, "examples");
const demoTrust = path.join(examples, "trust-store.demo.json");
const exampleDirs = fs.readdirSync(examples).filter((n) => /^\d\d-/.test(n) && fs.statSync(path.join(examples, n)).isDirectory());
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "ppb-test-"));
const code = (fn) => {
  try {
    fn();
  } catch (e) {
    if (e instanceof BundleError) return e.code;
    throw e;
  }
  return "NO_ERROR";
};
const cli = (...args) => {
  let out = "";
  let err = "";
  const exit = main(args, { out: (s) => (out += s), err: (s) => (err += s) });
  return { exit, out, err };
};

test("strict JSON: accepts RFC 8259, rejects what would make two parsers disagree", () => {
  assert.deepEqual(parseStrictJson('{"a":[1,-2.5e3,true,null,"x\\u00e9\\n"],"b":{}}'), { a: [1, -2500, true, null, "xé\n"], b: {} });
  for (const bad of ['{"a":1,"a":2}', '{"a":{"b":1,"b":2}}', "﻿{}", "{} x", "{'a':1}", '{"a":01}', '{"a":1,}', "[1,]", '{"__proto__":{}}', '"\u0001"', "NaN", '{"a":1e999}', "", "[" .repeat(40) + "]".repeat(40)]) {
    assert.equal(code(() => parseStrictJson(bad)), "MALFORMED_JSON", JSON.stringify(bad.slice(0, 20)));
  }
  assert.equal(code(() => parseStrictJson(Buffer.from([0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]))), "MALFORMED_JSON");
});

test("canonicalJSON matches ECMAScript ordering and number formatting", () => {
  assert.equal(canonicalJSON({ b: 1, a: [1.5, 1e21, -0, " "], "😀": 1, "￿": 2 }), '{"a":[1.5,1e+21,0," "],"b":1,"😀":1,"￿":2}');
});

test("trust store: three accepted shapes, ambiguous or malformed stores rejected", () => {
  const jwk = { kty: "OKP", crv: "Ed25519", kid: "k", x: Buffer.alloc(32, 1).toString("base64url") };
  assert.equal(parseTrustStore(jwk).size, 1);
  assert.equal(parseTrustStore({ keys: [jwk] }).size, 1);
  assert.equal(parseTrustStore({ format: "strix-ppb-trust-store", formatVersion: "1.0", keys: [{ keyId: "k", jwk }] }).get("k").status, "active");
  assert.equal(code(() => parseTrustStore({ keys: [jwk, jwk] })), "MALFORMED_TRUST_STORE");
  assert.equal(code(() => parseTrustStore({ keys: [{ ...jwk, kty: "RSA" }] })), "UNSUPPORTED_ALGORITHM");
  assert.equal(code(() => parseTrustStore({ keys: [{ ...jwk, x: "AAAA" }] })), "MALFORMED_KEY");
  assert.equal(code(() => parseTrustStore({ format: "strix-ppb-trust-store", formatVersion: "1.0", keys: [{ keyId: "k", jwk, status: "maybe" }] })), "MALFORMED_TRUST_STORE");
  assert.equal(code(() => parseTrustStore({ nothing: true })), "MALFORMED_TRUST_STORE");
});

test("authentic example bundles (real mcp-proxy records) verify PASSED as directories", () => {
  assert.equal(exampleDirs.length, 5);
  const trustStore = parseTrustStore(fs.readFileSync(demoTrust));
  for (const d of exampleDirs) {
    const r = verifyBundle(loadBundle(path.join(examples, d)), { trustStore });
    assert.equal(r.result.overall, "PASSED", d);
    assert.deepEqual(r.failures, []);
  }
});

test("committed sample reports are what the verifier prints today", () => {
  for (const d of exampleDirs) {
    const j = cli("verify", path.join(examples, d), "--trust-store", demoTrust, "--json");
    assert.equal(j.out, fs.readFileSync(path.join(examples, "reports", `${d}.report.json`), "utf8"), d);
    const t = cli("verify", path.join(examples, d), "--trust-store", demoTrust);
    assert.equal(t.out, fs.readFileSync(path.join(examples, "reports", `${d}.report.txt`), "utf8"), d);
  }
});

test("exhaustive tamper: flipping any single byte of any file in a real bundle never yields PASSED", () => {
  const trustStore = parseTrustStore(fs.readFileSync(demoTrust));
  const original = loadBundle(path.join(examples, "01-allow-succeeded"));
  let tried = 0;
  for (const [p, buf] of original) {
    for (let i = 0; i < buf.length; i++) {
      const files = new Map(original);
      const b = Buffer.from(buf);
      b[i] ^= 0x01;
      files.set(p, b);
      let overall;
      try {
        overall = verifyBundle(files, { trustStore }).result.overall;
      } catch (e) {
        assert.ok(e instanceof BundleError, `unexpected crash at ${p}[${i}]: ${e}`);
        overall = "ERROR";
      }
      // Whitespace inside manifest.sig.json is the one place a byte can change
      // without changing meaning: that file is an envelope, not signed content.
      if (overall === "PASSED") assert.equal(p, "manifest.sig.json", `PASSED after flipping ${p}[${i}]`);
      tried++;
    }
  }
  assert.ok(tried > 3000);
});

test("signature envelope whitespace is the only non-signed byte range, and it cannot alter a finding", () => {
  const trustStore = parseTrustStore(fs.readFileSync(demoTrust));
  const files = loadBundle(path.join(examples, "01-allow-succeeded"));
  const sig = JSON.parse(files.get("manifest.sig.json").toString("utf8"));
  const reflowed = new Map(files).set("manifest.sig.json", Buffer.from(JSON.stringify(sig)));
  const a = verifyBundle(files, { trustStore });
  const b = verifyBundle(reflowed, { trustStore });
  assert.deepEqual(b, a);
  sig.signatures[0].keyId = "someone-else";
  assert.equal(verifyBundle(new Map(files).set("manifest.sig.json", Buffer.from(JSON.stringify(sig))), { trustStore }).result.overall, "FAILED");
});

test("directory loading: symlinks, oversized files, too many files, non-canonical names", (t) => {
  const mk = () => {
    const d = tmp();
    fs.cpSync(path.join(examples, "02-deny"), path.join(d, "b"), { recursive: true });
    return path.join(d, "b");
  };
  let d = mk();
  fs.writeFileSync(path.join(d, "big.bin"), Buffer.alloc(LIMITS.maxFileBytes + 1));
  assert.equal(code(() => loadBundle(d)), "FILE_TOO_LARGE");
  d = mk();
  for (let i = 0; i < LIMITS.maxFiles + 1; i++) fs.writeFileSync(path.join(d, `f${i}.txt`), "x");
  assert.equal(code(() => loadBundle(d)), "TOO_MANY_FILES");
  d = mk();
  fs.writeFileSync(path.join(d, "bad name.txt"), "x");
  assert.equal(code(() => loadBundle(d)), "UNSAFE_PATH");
  d = mk();
  fs.writeFileSync(path.join(d, ".hidden"), "x");
  assert.equal(code(() => loadBundle(d)), "UNSAFE_PATH");
  d = mk();
  try {
    fs.symlinkSync(path.join(examples, "trust-store.demo.json"), path.join(d, "link.json"));
  } catch {
    t.diagnostic("symlink creation not permitted on this host; symlink case not exercised");
    return;
  }
  assert.equal(code(() => loadBundle(d)), "UNSAFE_PATH");
});

test("carrier limits: oversized carrier and oversized member are refused before use", () => {
  assert.equal(code(() => loadCarrier(Buffer.alloc(LIMITS.maxCarrierBytes + 1, 0x20))), "BUNDLE_TOO_LARGE");
  const big = Buffer.alloc(LIMITS.maxFileBytes + 3).toString("base64");
  assert.equal(code(() => loadCarrier(Buffer.from(`{"format":"strix-ppb-carrier","formatVersion":"1.0","files":{"a.bin":"${big}"}}`))), "FILE_TOO_LARGE");
  const many = Object.fromEntries(Array.from({ length: LIMITS.maxFiles + 1 }, (_, i) => [`f${i}`, ""]));
  assert.equal(code(() => loadCarrier(Buffer.from(JSON.stringify({ format: "strix-ppb-carrier", formatVersion: "1.0", files: many })))), "TOO_MANY_FILES");
});

test("CLI contract: exit codes 0/1/2/3, JSON on --json, errors never look like results", () => {
  const good = path.join(examples, "01-allow-succeeded");
  assert.equal(cli("verify", good, "--trust-store", demoTrust).exit, 0);
  const noTrust = cli("verify", good, "--json");
  assert.equal(noTrust.exit, 3);
  const rep = JSON.parse(noTrust.out);
  assert.equal(rep.result.overall, "INCOMPLETE");
  assert.equal(rep.result.signatures.status, "VALID");
  assert.equal(rep.result.signerTrust.status, "NOT_ESTABLISHED");
  assert.ok(rep.result.signatures.records.every((r) => r.keySource === "embedded-untrusted"));
  assert.match(cli("verify", good).out, /INCOMPLETE: nothing failed, but origin is not authenticated/);
  assert.equal(cli("verify", good, "--trust-store", demoTrust, "--expect-receipt-id", "rcpt_nope").exit, 1);
  assert.equal(cli("verify", path.join(examples, "does-not-exist")).exit, 2);
  assert.equal(cli("verify", good, "--trust-store", path.join(examples, "nope.json")).exit, 2);
  assert.equal(cli("verify", good, "--bogus").exit, 2);
  assert.equal(cli("verify").exit, 2);
  assert.equal(cli("--help").exit, 0);
  const e = cli("verify", path.join(examples, "does-not-exist"), "--json");
  assert.equal(JSON.parse(e.out).result.overall, "ERROR");
  const insp = cli("inspect", good);
  assert.equal(insp.exit, 0);
  assert.match(insp.out, /^UNVERIFIED listing/);
  const d = tmp();
  const reportFile = path.join(d, "r.json");
  cli("verify", good, "--trust-store", demoTrust, "--report", reportFile);
  assert.equal(JSON.parse(fs.readFileSync(reportFile, "utf8")).result.overall, "PASSED");
});

test("report keeps integrity, signature mathematics, signer trust, consistency and claims as separate fields", () => {
  const r = JSON.parse(cli("verify", path.join(examples, "02-deny"), "--trust-store", demoTrust, "--json").out);
  assert.deepEqual(Object.keys(r.result), ["overall", "integrity", "signatures", "signerTrust", "consistency", "claims"]);
  for (const c of r.claims) {
    assert.deepEqual(Object.keys(c), ["id", "topic", "classification", "status", "statement", "supportingArtifacts", "trustAssumptions", "limitations"]);
  }
  assert.ok(r.unsupportedConclusions.length >= 8);
  const text = cli("verify", path.join(examples, "02-deny"), "--trust-store", demoTrust).out;
  assert.match(text, /Actual prevention of execution is NOT established/);
  assert.match(text, /PASSED means the four checks above succeeded\. It is not a statement/);
  assert.doesNotMatch(text, /prevented|securely executed|tamper-proof|guarantee/i);
});

test("embedded key material never confers trust, even when it is the only key available", () => {
  const files = loadBundle(path.join(examples, "01-allow-succeeded"));
  const r = verifyBundle(files, { trustStore: null });
  assert.equal(r.result.overall, "INCOMPLETE");
  assert.equal(r.claims.find((c) => c.id === "PPB-C03").status, "NOT_ESTABLISHED");
  assert.ok(r.claims.filter((c) => c.classification === "SOURCE_ASSERTION").every((c) => c.status === "ASSERTED_BY_UNTRUSTED_KEY"));
  assert.match(r.claims.find((c) => c.id === "PPB-C04").statement, /identity is NOT established/);
});

test("offline: the verifier runs with every network primitive blocked and attempts none", () => {
  const log = path.join(tmp(), "net.log");
  fs.writeFileSync(log, "");
  const preload = "file://" + path.resolve(root, "..", "validation", "proof-bundle", "block-network.mjs").replace(/\\/g, "/");
  const r = spawnSync(process.execPath, ["--import", preload, verifierPath, "verify", path.join(examples, "04-approved-succeeded"), "--trust-store", demoTrust], { encoding: "utf8", env: { ...process.env, NETWORK_ATTEMPT_LOG: log } });
  assert.equal(r.status, 0, r.stderr);
  assert.equal(fs.readFileSync(log, "utf8"), "");
});

test("the verifier is one file that imports only Node built-ins (no network modules)", () => {
  const src = fs.readFileSync(verifierPath, "utf8");
  const imports = [...src.matchAll(/^import .* from "([^"]+)";$/gm)].map((m) => m[1]).sort();
  assert.deepEqual(imports, ["node:crypto", "node:fs", "node:path", "node:url"]);
  assert.doesNotMatch(src, /\bfetch\(|import\(|require\(|node:(http|https|net|tls|dns|dgram|child_process)/);
});
