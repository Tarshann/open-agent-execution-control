# Candidate `@strixgov/mcp-proxy` 0.2.2 (not published)

Fixes: the published tarball ships no tests, so `npm test` in an installed copy can only fail.

## Apply to `packages/strixgov-mcp-proxy` in the source repo

1. `package.json`: replace `files` and `scripts` with `package.json.changes.json` here (leave the
   `workspace:^` dependencies as they are; pnpm rewrites them at publish). Bump `version` to 0.2.2.
2. Replace `scripts/run-tests.mjs` with `run-tests.mjs` here. `scripts/preflight.mjs` is unchanged
   (copied here only so the candidate is reviewable as a whole).
3. `test/` ships unchanged except `test/installed-tarball.test.mjs`, which is excluded.
   Test files and their hashes are those at source commit `7a5004363` (`test-suite.sha256`).
4. Add the CHANGELOG entry below.
5. Publish from a git checkout with `pnpm publish --access public` (the package already blocks
   `npm publish`), preferably from CI with provenance, so the registry records `gitHead`.
   Then run `release-provenance.mjs generate` to add `manifests/mcp-proxy-0.2.2.json`.

## What was verified (on a scratch build, not the source tree)

- clean `npm install` of the packed tarball, then `npm test` → 66 run, 66 pass, 0 skipped
- missing `test/`, only-skipped tests, a failing test, and an emptied suite each exit non-zero
  (Node counts an empty test file as one pass, hence `MIN_TESTS = 60`)

## CHANGELOG entry

```
## [0.2.2]

### Fixed
- The published package now ships its test suite (`test/`, except the monorepo-only
  `installed-tarball.test.mjs`) and `scripts/preflight.mjs`, so `npm test` runs in an installed
  copy. `scripts/run-tests.mjs` exits non-zero if no test files are found, if the runner reports
  zero or skipped-only tests, or if fewer than 60 tests run (Node counts an empty test file as one
  passing test).
```
