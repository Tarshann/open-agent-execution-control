// Runs the verifier over every public vector and checks the documented result.
import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { BundleError, loadCarrier, parseAuthorizations, parseRevocations, parseTrustStore, verifyBundle, exitCodeFor } from "../verifier/strix-proof-verify.mjs";
import { generate } from "../vectors/generate.mjs";

const dir = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "vectors");
const index = JSON.parse(fs.readFileSync(path.join(dir, "index.json"), "utf8"));

export function runVector(v) {
  try {
    const files = loadCarrier(fs.readFileSync(path.join(dir, v.bundle)));
    const trustStore = v.trustStore ? parseTrustStore(fs.readFileSync(path.join(dir, v.trustStore))) : null;
    const authorizations = v.issuerAuthorizations ? parseAuthorizations(fs.readFileSync(path.join(dir, v.issuerAuthorizations))) : [];
    const revocations = v.revocations ? parseRevocations(fs.readFileSync(path.join(dir, v.revocations)), trustStore) : null;
    const report = verifyBundle(files, { trustStore, authorizations, revocations, expect: v.expectOptions ?? {} });
    return { overall: report.result.overall, exit: exitCodeFor(report), failureCodes: [...new Set(report.failures.map((f) => f.code))].sort(), claims: Object.fromEntries(report.claims.map((c) => [c.id, `${c.classification}/${c.status}`])), report };
  } catch (e) {
    if (!(e instanceof BundleError)) throw e;
    return { overall: "ERROR", exit: 2, errorCode: e.code };
  }
}

test("committed vectors are exactly what the generator produces", () => {
  for (const [p, buf] of generate()) assert.ok(fs.readFileSync(path.join(dir, p)).equals(buf), `${p} is stale; run node vectors/generate.mjs`);
});

for (const v of index.vectors) {
  test(`vector ${v.name}`, () => {
    const got = runVector(v);
    assert.equal(got.overall, v.expect.overall);
    assert.equal(got.exit, v.expect.exit);
    if (v.expect.errorCode) assert.equal(got.errorCode, v.expect.errorCode);
    if (v.expect.failureCodes) assert.deepEqual(got.failureCodes, v.expect.failureCodes);
    for (const [id, want] of Object.entries(v.expect.claims ?? {})) assert.equal(got.claims[id], want, id);
    if (v.expect.noClaims) assert.deepEqual(got.claims, {});
    if (got.overall === "FAILED") assert.equal(got.report.result.claims.status, "NOT_EVALUATED", "a FAILED bundle must yield no claims");
  });
}

test("no vector and no claim ever upgrades enforcement or execution beyond a source assertion", () => {
  for (const v of index.vectors) {
    const got = runVector(v);
    for (const c of got.report?.claims ?? []) {
      if (c.topic === "enforcement") assert.equal(c.status, "NOT_ESTABLISHED");
      if (c.topic === "execution-outcome") assert.ok(["SOURCE_ASSERTION", "NOT_ESTABLISHED"].includes(c.classification));
      if (c.topic === "policy-decision") assert.equal(c.classification, "SOURCE_ASSERTION");
      if (c.topic === "actor-identity") assert.equal(c.status, "NOT_ESTABLISHED");
    }
  }
});
