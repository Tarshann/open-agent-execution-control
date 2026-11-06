# Build summary: MCP Proxy release validation, 2026-11-06

What was built, what shipped, what was found, and what is still open. Detail and re-run
commands: [`validation/README.md`](../validation/README.md).

## Shipped

| What | Where | State |
|------|-------|-------|
| `@strixgov/mcp-proxy` 0.2.2 (ships tests; fails on empty or truncated suites) | npm; source `d9a8d8b14` in Tarshann/strix-platform (#2733) | **Published**; clean install runs 66/66 tests |
| Register and mirror reconciliation | strix-platform #2734 | Merged |
| Registers BEHIND → LIVE, CLAUDE.md release notes | strix-platform #2737 | Open, awaiting CI |
| Validation harnesses, corrected docs and sales copy, pilot protocol | this repo, PR #20 | Open |

## Built

- **`validation/mcp-proxy-boundary/`**: real `strix-mcp-proxy` CLI over stdio in front of a disposable
  fixture with a handler log. Seven hard checks.
- **`validation/mcp-proxy-release/`**: `release-provenance.mjs` (registry integrity, per-file hashes,
  installed-copy and source-commit checks) and manifests for proxy 0.2.1, 0.2.2 and Guard 0.1.1.
- **`validation/wire-hosted/`, `wire-offline/`**: hosted accountless Sandbox Mode vs Offline Mode, with
  a traffic log of what leaves the machine.
- **`validation/solo-govern/`**: labelled fixture and scorer for `solo govern` 0.4.1.
- **`validation/sgrf-lens-runs/`**: verbatim output of the three published SGRF lenses (advisory).
- **`docs/pilot/CUSTOMER-SAFE-PILOT.md`**: one codebase, one action, one route; covered, uncovered and
  unknown paths reported separately.
- **Copy**: setup guide, strix-wire README, three one-pagers (md + html) and the claims cheat sheet.

## Findings

1. 0.2.1's tarball shipped no tests; `npm test` failed closed (exit 1). Fixed in 0.2.2.
2. Node counts an empty test file as one passing test, so "> 0 tests" is not a guard; 0.2.2 enforces a floor of 60.
3. The registry had no `gitHead` for 0.2.1 (packed from a temp directory). Rebuilt: 0.2.1 and Guard 0.1.1 →
   `7a5004363`; 0.2.2 → `d9a8d8b14`. Only the pnpm `package.json` rewrite differs.
4. The public `Strixgov/strix` mirror does not contain those commits, so the `repository` link can't be
   resolved by outsiders.
5. Routed allow, deny, approval timeout and approved execution behave as configured. **A direct call to the
   upstream outside the proxy runs with no receipt.**
6. A timeout and a policy deny look the same to the client; only the receipt (`approvalReason: TIMEOUT`) differs.
7. `@strixgov/verifier` `chainValid` stayed true for a chain containing a TAMPERED receipt; gate on per-receipt status.
8. Hosted Wire Sandbox: provisioning works; `/api/v1/evaluate` returned HTTP 400 for all 10 capabilities. Offline Mode passes.
9. `solo govern` 0.4.1: 9 of 13 supported-language actions and 0 of 10 in other languages or indirect calls in the fixture.
10. Hosted mode sends the action's parameters in plain text; the old "non-secret parameters only" wording was inaccurate.

## Open

- Hosted Sandbox `/api/v1/evaluate` fix, then re-run `validation/wire-hosted/run.py`. Landing page still carries old claims.
- Publish future releases from CI with `npm publish --provenance`; mirror the release commit to the public repo.
- `scripts/` is not copied by `sync-packages-to-public-release.mjs`.
- strix-platform #2733 checks `guard-commercial-contract` and `capabilities (no DB)` failed and were not investigated.
- `solo govern`: `--root` inside a git checkout resolves to the enclosing repo; `solo --help` crashes on cp1252 consoles; `compare` prints an unmeasured matrix.
- Pilot protocol not yet exercised on a real customer-style copy.

## Claims boundary

Evidence here supports statements about specific versions on a synthetic fixture, on Windows. It does not
support whole-agent coverage, PHI or egress control, compliance, or production-readiness claims.
