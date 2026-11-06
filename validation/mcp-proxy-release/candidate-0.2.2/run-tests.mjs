#!/usr/bin/env node
/**
 * `npm test` entry point for @strixgov/mcp-proxy.
 *
 * Works both in a source checkout and in an installed copy of the published
 * tarball (the suite ships in the package; only test/installed-tarball.test.mjs,
 * which needs sibling monorepo packages, is excluded from the tarball).
 *
 * Fails closed: a run that executes ZERO tests, finds no test files, or cannot
 * read a test count exits non-zero. "No tests" must never read as a pass.
 */
import { existsSync, readdirSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const testDir = fileURLToPath(new URL("../test", import.meta.url));
const preflight = fileURLToPath(new URL("./preflight.mjs", import.meta.url));

// Node counts an empty test file as one passing test, so "> 0" is not enough:
// an emptied suite would still pass. Require a floor close to the real size (66 at 0.2.2).
const MIN_TESTS = 60;

const fail = (msg) => {
  process.stderr.write(`\n  @strixgov/mcp-proxy: ${msg}\n\n`);
  process.exit(1);
};

const files = existsSync(testDir) ? readdirSync(testDir).filter((f) => f.endsWith(".test.mjs")) : [];
if (files.length === 0 || !existsSync(preflight)) {
  fail("no tests to run (test/*.test.mjs or scripts/preflight.mjs missing). Exiting non-zero: zero tests run must not read as a pass.");
}

const pre = spawnSync(process.execPath, [preflight], { cwd: root, stdio: "inherit" });
if (pre.status !== 0) process.exit(pre.status ?? 1);

// Run via the node test runner and read its own summary so we can refuse a zero count.
const run = spawnSync(process.execPath, ["--test", ...files.map((f) => `test/${f}`)], {
  cwd: root,
  encoding: "utf8",
  maxBuffer: 64 * 1024 * 1024,
});
process.stdout.write(run.stdout ?? "");
process.stderr.write(run.stderr ?? "");
if (run.status !== 0) process.exit(run.status ?? 1);

const text = `${run.stdout}\n${run.stderr}`;
const count = (label) => {
  const m = text.match(new RegExp(`(?:ℹ|#)\\s+${label}\\s+(\\d+)`));
  return m ? Number(m[1]) : null;
};
const tests = count("tests");
const passed = count("pass");
if (tests === null || passed === null) fail("could not read the test runner's summary; refusing to report success.");
if (tests === 0 || passed === 0) fail(`test runner executed ${tests} tests (${passed} passed). Exiting non-zero: zero tests run must not read as a pass.`);
if (tests < MIN_TESTS) fail(`test runner executed only ${tests} tests; expected at least ${MIN_TESTS}. A truncated or emptied suite must not read as a pass.`);
