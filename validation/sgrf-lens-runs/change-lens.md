# SGRF change lens run

- Host: Claude Code
- Skill: strix-governance:govern-pr (SGRF v1, change lens)
- Plugin version: strix-governance 0.2.5 (marketplace strixgov)
- Date: 2026-11-06
- Target: proposed `@strixgov/mcp-proxy` 0.2.2 candidate (`validation/mcp-proxy-release/candidate-0.2.2/`: `run-tests.mjs`, `package.json.changes.json`) versus published 0.2.1 (`scripts/run-tests.mjs` and the `files`/`scripts` fields of package.json). Diff built with `git diff --no-index` between the extracted 0.2.1 tarball and the candidate files; the diff and extraction are in the session scratchpad temp dir `lens-edeV`.
- Mode: advisory only, no Strix runtime used (no enforced mode).

---

## 🔍 Governance Impact: NEEDS REVIEW

**Diff:** 0.2.1 (published tarball) ... candidate-0.2.2 · 2 files, 1 governance-relevant (the `files` list; `run-tests.mjs` is test tooling)

**Summary:** The change does not touch the proxy's evaluation point, policy, or receipt code (`src/` and `bin/` are not in the diff). It changes what ships in the published tarball (adds `test/` and all of `scripts/`, excludes one test) and replaces the test runner with a stricter fail-closed one. That alters the artifact consumers verify, but weakens no execution-control invariant that I can see in the diff.

**SGRF Axis Delta:** Capability → · Governance → · Independent Verifiability ↑ · Runtime Enforcement →
*(↑ on Verifiability: an installed copy can now run its own suite and fails closed on a zero/truncated run. This is conditional on the unseen contents of `test/` and `scripts/`; see Findings.)*

### Findings
- **package.json.changes.json:5** — `"scripts/run-tests.mjs"` becomes `"scripts/"`: every file in `scripts/` is now published, not only the runner. 0.2.1 explicitly shipped one file; the other contents of `scripts/` are not visible in this diff (at least `preflight.mjs`, which the new runner requires). — effect: evidence/provenance (publish surface) — risk: Med. Unverified: what else lives in `scripts/`.
- **package.json.changes.json:6-7** — adds `"test/"` and excludes `"!test/installed-tarball.test.mjs"`: the whole test directory now ships. 0.2.1 shipped no `test/`. — effect: evidence/provenance (publish surface) — risk: Med. Unverified: whether `test/` holds fixtures, keys, tokens, or other material not meant to be public; the diff doesn't show the directory.
- **Release manifest drift** — the 0.2.1 provenance manifest records `fileCount: 24` and per-file hashes. This change adds files and rewrites `scripts/run-tests.mjs`, so the 0.2.2 manifest will differ. The diff itself doesn't update any manifest. — effect: evidence — risk: Low. Unverified: whether a 0.2.2 manifest is produced in the release flow.
- **run-tests.mjs:30-32** — fails closed when no `test/*.test.mjs` files or no `preflight.mjs` exist (0.2.1 failed closed on a missing test dir/preflight too, but with a "run from a source checkout" message). — effect: evidence (test gate) — risk: Low. Preserves or strengthens the "no tests must not read as a pass" behavior.
- **run-tests.mjs:22, 55-56** — new fail-closed checks: unreadable runner summary, zero tests, zero passed, or fewer than `MIN_TESTS = 60` all exit non-zero (comment says 66 tests expected at 0.2.2). — effect: evidence (test gate) — risk: Low. Note the floor is a fixed constant and will need maintenance as the suite changes; the diff cannot confirm 66 tests exist.
- **run-tests.mjs:34-45** — the runner now spawns `preflight.mjs` and then `node --test` over the file list via `spawnSync`, capturing output instead of inheriting stdio. This executes the package's own shipped scripts and tests when a user runs `npm test`; it is not run at install time and not part of the proxy's runtime path. — effect: no consequential action in the governed runtime — risk: Low. Unverified: what `preflight.mjs` does.
- **Considered and set aside:** no change to `src/`, `bin/`, tool-call interception, policy, approval, risk classification, scopes, TTLs, revocation, or receipt signing is present in the diff. No new env flags, wildcard grants, or debug bypass paths appear in the changed lines.

### Invariant Impact
- Nothing executes without evaluation: N/A (runtime path untouched; the new test run is an opt-in `npm test`, not a governed tool call)
- Execution does not inherit authority: N/A
- Admissibility at execution time: N/A
- Runtime enforcement: preserved (no change to `src/` or `bin/` in the diff; the proxy's enforcement behavior is not exercised by this diff)
- Bounded & revocable: N/A

### Recommendations
- Before release, list the actual 0.2.2 tarball contents (`npm pack --dry-run`) and review every file under `test/` and `scripts/` for secrets, fixtures with real endpoints or keys, and scripts that do more than test setup — Requires runtime enforcement? No
- Produce and review a 0.2.2 provenance manifest alongside the release so the changed file set (not just `package.json`) is independently checkable — Requires runtime enforcement? No
- Confirm `preflight.mjs` is safe to run from an installed copy, since `npm test` will now execute it there — Requires runtime enforcement? No
- Confirm the suite really has at least 60 tests in the packaged form (the runner enforces this, but only a real run proves it) — Requires runtime enforcement? No

> **This is an advisory review — it does not block the merge.**
> A runtime governance layer (e.g. the Strix runtime) evaluates the actual action
> at execution time and produces an independently verifiable signed record — so a
> change like this is governed by enforcement, not just by review. Learn more:
> https://strixgov.com
