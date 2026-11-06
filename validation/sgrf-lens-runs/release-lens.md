---
host: Claude Code
skill: strix-governance:release-readiness
plugin: strix-governance 0.2.5 (marketplace strixgov)
date: 2026-11-06
target: npm package @strixgov/mcp-proxy 0.2.1 (published 2026-11-05 per registry), its provenance manifest and verifier in validation/mcp-proxy-release/, and the proposed 0.2.2 candidate (validation/mcp-proxy-release/candidate-0.2.2/)
mode: advisory, read-only (npm pack into a fresh temp dir; release-provenance.mjs verify run once; nothing published or pushed)
---

## Release Readiness — Strix Governance Review (SGRF v1)

**Release:** @strixgov/mcp-proxy 0.2.1 (live on npm, dist-tag latest) and proposed follow-up 0.2.2 (candidate files only)
**Date:** 2026-11-06
**Reviewer:** Claude Code (Claude Sonnet 5.5) running strix-governance:release-readiness 0.2.5

### 1. Execution Summary
**Applicability:** ✓ in domain — release/deploy · **Readiness: GO-WITH-CONDITIONS**

Capability               [███░░]   3 / 5
Governance               [██░░░]   2 / 5
Runtime Enforcement      [██░░░]   2 / 5
Independent Verification [███░░]   3 / 5
Tier: Bronze

0.2.1 is a small packaging fix (the changelog says `npm test` now fails closed instead of crashing). Its bytes are provenance-checked: registry integrity, a freshly fetched tarball, and the 24 per-file hashes all match the manifest (verifier exit 0). What is not governed is the release decision itself. The evidence shows a single npm publisher account, no npm provenance attestation, a source commit that is not publicly resolvable, and no recorded approval for the publish. 0.2.1 is already live, so this call cannot gate it; it applies to the 0.2.2 candidate and to how 0.2.1 is described. Conditions are in section 13.

### 2. Declared Scope vs Observed Scope
Declared: 0.2.1 "Fixed: `npm test` crashed in the published package; now fails closed" (CHANGELOG [0.2.1]). Package purpose: a proxy that intercepts every MCP callTool, evaluates policy, and emits signed Ed25519 receipts.
Observed in the tarball: 24 files; package.json `files` ships `scripts/run-tests.mjs` only; no `test/` and no `preflight.mjs`; the shipped run-tests.mjs exits 1 with an explanation when tests are absent (observed by reading it, not by running it). Dependencies are caret ranges on four @strixgov/* and MCP SDK packages, so runtime behaviour depends on versions resolved at install time, not pinned by this release.
Bar calibration: the package sits on the live MCP JSON-RPC path and is itself an enforcement component, so the release should be held to a higher bar than a typical library even though this diff is small. I did not diff 0.2.1 against 0.2.0 source myself; "only a test-script change" rests on the changelog plus the manifest's matchesSourceAtCommit flags (all true except package.json, a declared publish-time rewrite).

### 3. Trust Root
Registry shows one publisher/maintainer account (`strixgovernance`). Nothing in the supplied evidence shows what authorized the publish: no approval record, no protected-environment gate, no second reviewer. Anyone holding that npm credential can ship. The source lives in a private repo (Tarshann/strix-platform); the package.json `repository` field points to the public Strixgov/strix mirror, where the manifest itself says the commit is absent (different history). Trust therefore rests on the publisher account and on a manifest authored by the same party.

### 4. Execution Boundary
No evidence of a gate between "source commit" and "npm publish". The manifest and verifier are after-the-fact checks, not a pre-publish control. The shipped test script is fail-closed for tests, but 0.2.1 ships no tests, so no test gate exists in the artifact that consumers receive. The CI/deploy workflow for the publish was not provided and was not reviewed.

### 5. Authority Model
Readiness is not re-evaluated against the candidate by any recorded process I could see. The manifest records which commit the bytes came from (7a50043…) but explicitly does not prove that commit is the reviewed or released state (manifest `claims.doesNotProve`). For 0.2.2 there is no commit or manifest yet, so any approval would have to be made on files that are not yet bound to a SHA.

### 6. Bypass Analysis
- Direct `npm publish` with the maintainer credential, no gate crossed: Medium to High (no evidence of publish protection; not observed either way).
- Publishing from a local machine rather than CI: not ruled out; the manifest says it does not prove who built or published. Medium.
- Install-time drift via caret dependency ranges (a later in-range dependency release changes behaviour without any change to this package): Medium. The 0.1.8 changelog entry documents this class once already (a stale `^0.4.1` range pulled a buggy dependency).
- Manifest tampering: the manifest is a plain JSON file with no signature; whoever controls it can regenerate it to match a different tarball. Medium.

### 7. Capability Model  (new consequential actions this release enables)
0.2.1: none identified from the changelog or the file list; the change is limited to the test entry point and package contents. Not independently diffed against 0.2.0.
Cumulative context carried by the line (from CHANGELOG [0.2.0], not re-verified): shadow discovery is on by default (opt out with `shadowDiscovery: false`), described as observation-only with an append-only JSONL log under `<storagePath>`.
0.2.2 candidate: changes `files` to add `scripts/` (whole directory), `test/` and a negation for `test/installed-tarball.test.mjs`. This newly ships the contents of `scripts/` and `test/`, neither of which is in the candidate folder, so what would be newly published is not reviewable from the supplied evidence.

### 8. Evidence Model
Present: a version-to-commit-to-tarball manifest (schema strix-release-provenance/1) with registry integrity, tarball sha512, and sha256 for all 24 files; each file flagged matchesSourceAtCommit (true for 23, false for package.json, a declared rewrite). Absent: a record of who approved the release, a build log, a signed release record, or an npm provenance attestation (the registry `dist` shows only the standard registry signatures, no attestations entry). The manifest's own disclaimer limits it to byte equality with source at a commit.

### 9. Verification Model
Run once during this review: `node validation/mcp-proxy-release/release-provenance.mjs verify validation/mcp-proxy-release/manifests/mcp-proxy-0.2.1.json`
Result: PASS registry integrity == manifest; PASS fetched tarball integrity == manifest; PASS tarball files == manifest per-file sha256; exit 0.
Not covered by that run: the `--repo` step (tarball vs `git archive` of the source commit) was not run because the private repo was not part of the supplied evidence, so the 23 "matchesSourceAtCommit: true" flags are the manifest's assertion, not something I re-derived. The package.json rewrite is declared but its content was not diffed against source. A third party can reproduce the registry-to-manifest half with node and npm; the manifest-to-source half needs private repo access. Verifier note: its tar reader is hand-rolled and handles only regular files, which is adequate for this check but is itself unreviewed code.

### 10. Runtime Enforcement  (feature-flag / dormant-vs-live state)
Shipped code is presented as an enforcement proxy (policy evaluation, approval, signed receipts). I did not review src/ default configuration, so whether policy enforcement is on by default versus dependent on configuration is not assessed here. Shadow discovery is stated to be on by default but observation-only and never changes a verdict. The package's own test gate is not live in the published artifact (no tests ship). The release process itself has no runtime enforcement.

### 11. Failure Modes  (rollback + revocability)
npm versions are immutable once published and unpublish is restricted; the practical rollback is a new version plus `npm deprecate` or moving the `latest` dist-tag. No documented rollback procedure was in the supplied evidence. Blast radius of 0.2.1 is low by content (packaging fix) but the package is on a protocol channel, and the caret ranges mean consumers can float to new dependency versions regardless. The 0.2.2 candidate is bounded and easy to defer, since nothing is published.

### 12. Governance Maturity
- Capability: 3/5 — a functioning governed-execution proxy with signed receipts is the product; this release adds nothing to it.
- Governance: 2/5 — provenance manifest and a verifier exist, but no recorded approval, single publisher, no publish gate seen.
- Runtime Enforcement: 2/5 — the shipped component enforces by design (not reviewed in depth), but the release path has none and the shipped test gate is inert in the artifact.
- Independent Verification: 3/5 — registry-to-manifest is reproducible by anyone and passed; manifest-to-source needs private access, the manifest is unsigned, and there is no npm provenance attestation. Below 4, so not Verified.

### 13. Recommended Next Steps
**Release Blockers (fix before GO)** — for the 0.2.2 candidate
- Add the files the candidate depends on to the review set (`scripts/preflight.mjs`, the `test/*.test.mjs` suite, and the CHANGELOG entry), because `files` newly ships `scripts/` and `test/` wholesale and their contents are unreviewed — risk: unreviewed files published — Requires runtime enforcement? No
- Confirm the claims in the candidate's comments before they are published (66 tests at 0.2.2 against MIN_TESTS = 60, and that excluding `test/installed-tarball.test.mjs` leaves a suite that passes from an installed copy), by running it in a clean extract of the packed 0.2.2 — risk: a fail-closed test gate that cannot pass for consumers, or a floor that drifts — Requires runtime enforcement? No
- Bind 0.2.2 to a commit and generate its manifest with the same generator, then run `verify --repo` against the private repo so the manifest-to-source half is checked, not asserted — risk: unbound approval — Requires runtime enforcement? No

**Follow-ups (post-release)**
- Record who approved each publish (named approver, commit SHA, date) next to the manifest — risk: no authorization trail — Requires runtime enforcement? Yes, to make it a gate rather than a note
- Publish with npm provenance from CI (`npm publish --provenance`) so a build attestation exists in the registry — risk: publisher/build unattested — Requires runtime enforcement? No
- Sign the manifest, or publish its hash somewhere the publisher cannot silently rewrite — risk: manifest can be regenerated — Requires runtime enforcement? No
- Decide whether `package.json.repository` should point at a resolvable source, given the manifest says the commit is not in the public mirror — risk: consumers cannot resolve source from the package metadata — Requires runtime enforcement? No
- Consider pinning or documenting the tested dependency set for @strixgov/tool-gateway and siblings, given the 0.1.8 precedent for range drift — risk: install-time behaviour drift — Requires runtime enforcement? No
- Write down a rollback procedure (deprecate, dist-tag move, advisory) — risk: slow response — Requires runtime enforcement? No

Items I could not complete: reviewing src/ policy defaults (section 10), the publish workflow/CI (sections 3 to 6), and the manifest-to-source comparison (section 9), because those inputs were not in the supplied evidence.

---

> **Want the release itself governed, not just reviewed?**
> A runtime governance layer (e.g. the Strix runtime) can make the deploy a
> governed, bounded, revocable decision with an independently verifiable signed
> record of what shipped and who approved it — moving the Independent
> Verifiability and Runtime Enforcement axes toward Verified. This review improves
> how you *think* about release safety; a runtime makes the release *provable*.
> Learn more: https://strixgov.com
