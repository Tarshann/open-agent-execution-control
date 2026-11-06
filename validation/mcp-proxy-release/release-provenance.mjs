#!/usr/bin/env node
// Version -> source-commit -> registry-artifact provenance, checkable by anyone with node + npm.
//
//   node release-provenance.mjs generate @strixgov/mcp-proxy@0.2.1 --commit <sha> --repo <git dir> --subdir packages/strixgov-mcp-proxy --out manifests/mcp-proxy-0.2.1.json
//   node release-provenance.mjs verify manifests/mcp-proxy-0.2.1.json [--installed <node_modules/@scope/pkg>] [--repo <git dir>]
//
// verify checks, in order, and exits non-zero on the first class of failure:
//   1. registry dist.integrity == manifest.tarball.integrity
//   2. a freshly fetched tarball hashes to that integrity
//   3. every file in that tarball matches the manifest's per-file sha256 (and no extras / missing)
//   4. (--installed) the files on disk in an installed copy match the manifest
//   5. (--repo)     the files match `git archive <commit>` of the source, except the ones the
//                   manifest declares as expected publish-time rewrites
//
// Claim boundaries (also written into every manifest): this proves "these registry bytes equal
// these source files at this commit (modulo declared rewrites)". It is not an npm provenance
// attestation and does not prove who built or published the tarball.
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync, mkdtempSync, readdirSync, statSync, rmSync, mkdirSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { tmpdir } from "node:os";
import path from "node:path";

const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const integrity = (b) => "sha512-" + createHash("sha512").update(b).digest("base64");
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const sh = (cmd, args, opts = {}) =>
  execFileSync(cmd, args, { encoding: "utf8", shell: process.platform === "win32" && cmd === npm, ...opts }).trim();

function untar(tgzBuf) {
  const buf = gunzipSync(tgzBuf);
  const files = new Map();
  let off = 0;
  while (off + 512 <= buf.length) {
    const h = buf.subarray(off, off + 512);
    if (h.every((b) => b === 0)) break;
    const name = h.subarray(0, 100).toString("utf8").replace(/\0.*$/, "");
    const prefix = h.subarray(345, 500).toString("utf8").replace(/\0.*$/, "");
    const size = parseInt(h.subarray(124, 136).toString("utf8").replace(/\0.*$/, "").trim() || "0", 8);
    const type = String.fromCharCode(h[156] || 48);
    off += 512;
    if (type === "0" || type === "\0") {
      const full = (prefix ? prefix + "/" : "") + name;
      files.set(full.replace(/^package\//, ""), buf.subarray(off, off + size));
    }
    off += Math.ceil(size / 512) * 512;
  }
  return files;
}

function fetchTarball(spec) {
  const dir = mkdtempSync(path.join(tmpdir(), "prov-"));
  try {
    const out = sh(npm, ["pack", spec, "--pack-destination", dir, "--silent"]).split("\n").pop().trim();
    return readFileSync(path.join(dir, out));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function walk(dir, base = dir, acc = new Map()) {
  for (const f of readdirSync(dir)) {
    if (f === "node_modules") continue;
    const p = path.join(dir, f);
    if (statSync(p).isDirectory()) walk(p, base, acc);
    else acc.set(path.relative(base, p).split(path.sep).join("/"), readFileSync(p));
  }
  return acc;
}

function gitArchiveFiles(repo, commit, subdir) {
  const dir = mkdtempSync(path.join(tmpdir(), "prov-src-"));
  try {
    const tar = execFileSync("git", ["-C", repo, "archive", "--format=tar", commit, subdir], { maxBuffer: 512 * 1024 * 1024 });
    const files = new Map();
    // minimal tar reader (git archive emits ustar)
    let off = 0;
    while (off + 512 <= tar.length) {
      const h = tar.subarray(off, off + 512);
      if (h.every((b) => b === 0)) break;
      const name = h.subarray(0, 100).toString("utf8").replace(/\0.*$/, "");
      const prefix = h.subarray(345, 500).toString("utf8").replace(/\0.*$/, "");
      const size = parseInt(h.subarray(124, 136).toString("utf8").replace(/\0.*$/, "").trim() || "0", 8);
      const type = String.fromCharCode(h[156] || 48);
      off += 512;
      if (type === "0") files.set(((prefix ? prefix + "/" : "") + name).replace(subdir + "/", ""), tar.subarray(off, off + size));
      off += Math.ceil(size / 512) * 512;
    }
    return files;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const args = process.argv.slice(2);
const flag = (n) => (args.includes(n) ? args[args.indexOf(n) + 1] : undefined);
const mode = args[0];

if (mode === "generate") {
  const spec = args[1];
  const commit = flag("--commit");
  const repo = flag("--repo");
  const subdir = flag("--subdir");
  const out = flag("--out");
  const rewrites = (flag("--expected-rewrites") ?? "package.json").split(",");
  if (!spec || !commit || !repo || !subdir || !out) throw new Error("usage: generate <pkg@ver> --commit --repo --subdir --out [--expected-rewrites a,b]");
  const tgz = fetchTarball(spec);
  const files = untar(tgz);
  const src = gitArchiveFiles(repo, commit, subdir);
  const [name, version] = [spec.slice(0, spec.lastIndexOf("@")), spec.slice(spec.lastIndexOf("@") + 1)];
  const reg = JSON.parse(sh(npm, ["view", spec, "dist", "--json"]));
  const manifest = {
    schema: "strix-release-provenance/1",
    package: name,
    version,
    registry: { integrity: reg.integrity, shasum: reg.shasum, fileCount: reg.fileCount },
    tarball: { integrity: integrity(tgz), bytes: tgz.length },
    source: {
      commit,
      repository: "Tarshann/strix-platform (private)",
      subdir,
      publicRepositoryResolvable: false,
      note: "This commit is NOT present in the public Strixgov/strix mirror (different history). Verify with a checkout of the private repo, or compare against the per-file hashes below.",
    },
    expectedPublishTimeRewrites: rewrites,
    files: Object.fromEntries(
      [...files].sort(([a], [b]) => a.localeCompare(b)).map(([f, b]) => [
        f,
        { sha256: sha256(b), matchesSourceAtCommit: src.has(f) ? sha256(src.get(f)) === sha256(b) : null },
      ]),
    ),
    claims: {
      proves: "These registry bytes equal the listed source files at the listed commit, except the declared rewrites.",
      doesNotProve: "Who built or published the tarball, that the build environment was clean, or that the source commit is the reviewed/released state. Not an npm provenance attestation.",
    },
  };
  mkdirSync(path.dirname(out), { recursive: true });
  writeFileSync(out, JSON.stringify(manifest, null, 2) + "\n");
  const bad = Object.entries(manifest.files).filter(([f, v]) => v.matchesSourceAtCommit !== true && !rewrites.includes(f));
  console.log(`wrote ${out}: ${files.size} files, ${bad.length} unexplained source mismatches`);
  process.exit(bad.length ? 1 : 0);
}

if (mode === "verify") {
  const manifest = JSON.parse(readFileSync(args[1], "utf8"));
  const spec = `${manifest.package}@${manifest.version}`;
  const results = [];
  const rec = (name, ok, detail = "") => results.push({ name, ok, detail });

  const reg = JSON.parse(sh(npm, ["view", spec, "dist", "--json"]));
  rec("registry integrity == manifest", reg.integrity === manifest.registry.integrity, reg.integrity);
  const tgz = fetchTarball(spec);
  rec("fetched tarball integrity == manifest", integrity(tgz) === manifest.tarball.integrity, integrity(tgz));
  const files = untar(tgz);
  const diff = (got, want) => {
    const gk = new Set(got.keys()), wk = new Set(Object.keys(want));
    const bad = [];
    for (const f of wk) if (!gk.has(f)) bad.push(`missing ${f}`);
    for (const f of gk) if (!wk.has(f)) bad.push(`extra ${f}`);
    for (const f of wk) if (gk.has(f) && sha256(got.get(f)) !== want[f].sha256) bad.push(`changed ${f}`);
    return bad;
  };
  const b1 = diff(files, manifest.files);
  rec("tarball files == manifest per-file sha256", b1.length === 0, b1.join("; "));
  if (flag("--installed")) {
    const b2 = diff(walk(flag("--installed")), manifest.files);
    rec(`installed copy (${flag("--installed")}) == manifest`, b2.length === 0, b2.join("; "));
  }
  if (flag("--repo")) {
    const src = gitArchiveFiles(flag("--repo"), manifest.source.commit, manifest.source.subdir);
    const b3 = [];
    for (const [f, b] of files) {
      const same = src.has(f) && sha256(src.get(f)) === sha256(b);
      if (!same && !manifest.expectedPublishTimeRewrites.includes(f)) b3.push(`${f} differs from source @ ${manifest.source.commit.slice(0, 9)}`);
    }
    rec("tarball == source at commit (modulo declared rewrites)", b3.length === 0, b3.join("; "));
  }
  for (const r of results) console.log(`${r.ok ? "PASS" : "FAIL"}  ${r.name}${r.ok ? "" : "  -> " + r.detail}`);
  console.log(`\n${spec}: source commit ${manifest.source.commit}`);
  console.log(`Scope: ${manifest.claims.proves}`);
  process.exit(results.every((r) => r.ok) ? 0 : 1);
}

console.error("usage: release-provenance.mjs generate|verify ...");
process.exit(2);
