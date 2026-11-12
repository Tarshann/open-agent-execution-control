#!/usr/bin/env node
// Writes release/SHA256SUMS and release/release-manifest.json for the files a
// customer or operator actually runs or relies on. `--check` fails if either
// is stale. The checksums are unsigned: they let a recipient confirm they hold
// the same bytes as this repository commit, not who built them.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
const FILES = [
  "verifier/strix-proof-verify.mjs",
  "exporter/strix-proof-export.mjs",
  "authority/strix-proof-authorize.mjs",
  "python/ppb_verify.py",
  "docs/SPEC.md",
  "vectors/index.json",
];
const sha = (p) => crypto.createHash("sha256").update(fs.readFileSync(path.join(root, p))).digest("hex");
const sums = FILES.map((p) => `${sha(p)}  ${p}\n`).join("");
const src = (p) => fs.readFileSync(path.join(root, p), "utf8");
const manifest = JSON.stringify({
  product: "Strix Portable Proof Bundle",
  version: pkg.version,
  status: "release candidate - not published, not deployed",
  formatVersion: "1.0",
  components: {
    "strix-proof-verify": /VERIFIER_VERSION = "([^"]+)"/.exec(src(FILES[0]))[1],
    "strix-proof-export": /EXPORTER_VERSION = "([^"]+)"/.exec(src(FILES[1]))[1],
    "strix-proof-authorize": /AUTHORITY_VERSION = "([^"]+)"/.exec(src(FILES[2]))[1],
    "ppb_verify.py": /ppb_verify\.py\/([0-9.]+)/.exec(src(FILES[3]))[1],
  },
  requires: { node: pkg.engines.node, python: ">=3.11 (second implementation only), cryptography" },
  files: Object.fromEntries(FILES.map((p) => [p, { sha256: sha(p), bytes: fs.statSync(path.join(root, p)).size }])),
  checksumsSigned: false,
}, null, 2) + "\n";

const out = { "release/SHA256SUMS": sums, "release/release-manifest.json": manifest };
if (process.argv.includes("--check")) {
  const stale = Object.entries(out).filter(([p, c]) => !fs.existsSync(path.join(root, p)) || fs.readFileSync(path.join(root, p), "utf8") !== c).map(([p]) => p);
  console.log(stale.length ? `STALE: ${stale.join(", ")} (run node scripts/build-release.mjs)` : "release checksums are current");
  process.exit(stale.length ? 1 : 0);
}
fs.mkdirSync(path.join(root, "release"), { recursive: true });
for (const [p, c] of Object.entries(out)) fs.writeFileSync(path.join(root, p), c);
process.stdout.write(sums);
