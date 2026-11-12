// Exporter against a LIVE real gateway: the keyring key layout, a real key
// rotation, and exports made while the gateway process is appending to the
// store. Needs `npm ci` in validation/proof-bundle; skipped visibly otherwise.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ExportError, buildBundle, loadSigningKey, main } from "../exporter/strix-proof-export.mjs";
import { parseTrustStore, verifyBundle } from "../verifier/strix-proof-verify.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));
const nm = path.resolve(here, "..", "..", "validation", "proof-bundle", "node_modules", "@strixgov");
const skip = fs.existsSync(path.join(nm, "mcp-adapter")) ? false : "@strixgov packages not installed (run npm ci in validation/proof-bundle)";
const COUNT = 300;

test("live gateway: keyring layout, real rotation, and export during concurrent writes", { skip, timeout: 120000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ppb-live-"));
  const store = path.join(dir, "store");
  const keys = path.join(dir, "keys");
  const child = spawn(process.execPath, [path.join(here, "helpers", "gateway-writer.mjs"), nm, store, keys, String(COUNT)], { stdio: ["ignore", "pipe", "pipe"] });
  let out = "";
  let err = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (err += d));
  const exited = new Promise((resolve) => child.on("exit", resolve));
  const id = (tag) => new RegExp(`^${tag} (\\S+)$`, "m").exec(out)?.[1];

  // Export the first action over and over while the gateway keeps writing.
  let done = false;
  exited.then(() => (done = true));
  let exportsDuringWrites = 0;
  let manifestSigners = new Set();
  while (!done) {
    await new Promise((r) => setImmediate(r));
    const first = id("FIRST");
    if (!first) continue;
    let b;
    try {
      b = buildBundle({ storeDir: store, keyDir: keys, receiptId: first, tenantId: "local" });
    } catch (e) {
      // The only acceptable transient: the keyring is mid-rotation. Never a wrong bundle.
      assert.ok(e instanceof ExportError && e.code === "SIGNING_UNAVAILABLE", `unexpected refusal during writes: ${e.code ?? e}`);
      continue;
    }
    let ring;
    try {
      ring = loadSigningKey(keys); // one read: two reads could straddle the rotation
    } catch (e) {
      assert.ok(e instanceof ExportError && e.code === "SIGNING_UNAVAILABLE", String(e));
      continue;
    }
    const trust = parseTrustStore({ keys: [ring.jwk, ...ring.retired] });
    // The export and this read can still straddle the rotation; retry on the next tick rather than misjudge.
    const rep = verifyBundle(b.files, { trustStore: trust });
    if (rep.result.overall !== "PASSED" && rep.failures.every((f) => f.code === "SIGNER_UNTRUSTED")) continue;
    assert.equal(rep.result.overall, "PASSED", JSON.stringify(rep.failures));
    manifestSigners.add(b.manifest.signer.keyId);
    exportsDuringWrites++;
  }
  assert.equal(await exited, 0, err);
  assert.match(out, /^ROTATED$/m);
  assert.ok(exportsDuringWrites >= 5, `only ${exportsDuringWrites} exports overlapped the writer`);

  // Layout really is the gateway's keyring: an active pointer and one directory per key.
  assert.equal(fs.readFileSync(path.join(keys, "active"), "utf8").trim(), "live-key-2");
  assert.ok(fs.existsSync(path.join(keys, "live-key-1", "signing-key.pem")) && !fs.existsSync(path.join(keys, "signing-key.pem")));
  const key = loadSigningKey(keys);
  assert.equal(key.kid, "live-key-2");
  assert.deepEqual(key.retired.map((j) => j.kid), ["live-key-1"]);

  // trust-store output: active + retired, public halves only.
  let ts = "";
  assert.equal(main(["trust-store", "--key-dir", keys, "--owner", "live test"], { out: (s) => (ts += s), err: () => {} }), 0);
  assert.ok(!ts.includes("PRIVATE"));
  const trust = parseTrustStore(ts);
  assert.deepEqual([...trust].map(([k, v]) => `${k}:${v.status}`).sort(), ["live-key-1:retired", "live-key-2:active"]);

  // Pre-rotation record: record signed by the retired key, manifest by the active key.
  const a = buildBundle({ storeDir: store, keyDir: keys, receiptId: id("FIRST"), tenantId: "local" });
  const ra = verifyBundle(a.files, { trustStore: trust });
  assert.equal(ra.result.overall, "PASSED");
  assert.deepEqual(ra.result.signatures.records.map((r) => r.keyId), ["live-key-2", "live-key-1", "live-key-1"]);
  // Without the retired key in the relying party's store, it must not pass.
  assert.equal(verifyBundle(a.files, { trustStore: parseTrustStore({ keys: [key.jwk] }) }).result.overall, "FAILED");
  // Post-rotation record.
  const z = buildBundle({ storeDir: store, keyDir: keys, receiptId: id("LAST"), tenantId: "local" });
  assert.equal(verifyBundle(z.files, { trustStore: trust }).result.overall, "PASSED");
  assert.equal(z.manifest.evidence.executionOutcome, "PRESENT");

  // The exporter created nothing in the key directory and never touched the store's records.
  assert.deepEqual(fs.readdirSync(keys).sort(), ["active", "live-key-1", "live-key-2"]);
  assert.equal(fs.readFileSync(path.join(store, "receipts.jsonl"), "utf8").trim().split("\n").length, COUNT);

  // A keyring whose active pointer tries to escape the directory is refused.
  const evil = path.join(dir, "evil-keys");
  fs.cpSync(keys, evil, { recursive: true });
  fs.writeFileSync(path.join(evil, "active"), "../keys/live-key-2");
  assert.throws(() => loadSigningKey(evil), (e) => e instanceof ExportError && e.code === "SIGNING_UNAVAILABLE");
  fs.writeFileSync(path.join(evil, "active"), "live-key-1"); // pointer names a key whose directory holds another kid's JWK
  fs.copyFileSync(path.join(evil, "live-key-2", "public-jwk.json"), path.join(evil, "live-key-1", "public-jwk.json"));
  assert.throws(() => loadSigningKey(evil), (e) => e instanceof ExportError && e.code === "SIGNING_UNAVAILABLE");
});
