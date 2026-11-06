# Release validation, 2026-11-06

What was run, what it showed, and what it does **not** show. Every result below
comes from a command in this directory that you can re-run; evidence files are
committed next to each harness. Nothing was published, pushed or sent to
customers. Versions: `@strixgov/mcp-proxy` 0.2.1, `@strixgov/guard` 0.1.1,
`@strixgov/verifier` 1.24.1, `solo-builder-core` 0.4.1, `strix-governance`
(SGRF) plugin 0.2.5. Host: Windows 11, Node 24.21, Python 3.12.

| # | Item | Result | Evidence |
|---|------|--------|----------|
| 1 | Proxy tarball tests | 0.2.1 confirmed broken as reported (see below). Fix built and tested as a **candidate 0.2.2**; **not published** | `mcp-proxy-release/candidate-0.2.2/` |
| 2 | Version to commit | Done retroactively for proxy 0.2.1 and Guard 0.1.1 with a verifier | `mcp-proxy-release/manifests/`, `release-provenance.mjs` |
| 3 | Wire setup claims | Offline Mode passes. Hosted Sandbox Mode **fails** at the evaluate step. Docs and copy corrected | `wire-offline/`, `wire-hosted/` |
| 4 | `solo govern` | Works as a static inventory with large known blind spots. Documented as such | `solo-govern/` |
| 5 | Controls at the boundary | Allow, deny, approval timeout, approved execution recorded; out-of-proxy path runs with no receipt | `mcp-proxy-boundary/` |
| 6 | SGRF plugin | Three published lenses run in Claude Code; reports retained. Advisory only | `sgrf-lens-runs/` |
| 7 | Sales copy | Overclaims removed or qualified; claims sheet extended | `docs/sales/`, `skills/strix-wire/` |

## 1. Proxy packaging

- **0.2.1 as published:** `npm install` of the exact registry tarball, then
  `npm test` → exit 1 with "no tests to run here". The tarball ships `scripts/run-tests.mjs`
  but no `test/` and no `scripts/preflight.mjs` (24 files). So the report is right that the
  tests are missing; the "zero tests must not pass" part was already in 0.2.1 (it fails closed).
- **Candidate 0.2.2** (built from the published 0.2.1 tree plus the source commit's tests, packed
  with `npm pack`, installed clean): `npm test` → 66 tests, 66 pass, 0 skipped. The suite runs
  against the installed package, not a checkout.
- **Zero-test guard, with negative controls on the installed copy:** missing `test/` → exit 1;
  only skipped tests → exit 1; a failing test → exit 1. **Finding:** Node counts an *empty* test
  file as one passing test, so "> 0 tests" is not a real guard (an emptied suite exited 0). The
  candidate runner therefore also enforces a floor (`MIN_TESTS = 60`); the empty-file case now
  exits 1. Re-set the floor when the suite grows.
- `test/installed-tarball.test.mjs` needs sibling monorepo packages, so the candidate excludes it
  from the tarball (`!test/installed-tarball.test.mjs`).
- **Guard 0.1.1:** clean install of the tarball ships `test/` and `npm test` → 12/12 pass,
  matching the reported "12 tests".
- **Not done:** the change is not applied to `packages/strixgov-mcp-proxy` in the source repo
  and nothing was published. The candidate's tarball integrity
  (`sha512-Eu+ddcMTfqp7QsiB19Exm4b2dTER/Dt2h0nbIvbBOWrPgYPOkjTzuk2hFan+9c0RFSw01UAmG6P2um249OQPTg==`)
  was produced on this machine and will change when it is rebuilt by `pnpm publish`.
  The SGRF change lens flagged that `scripts/` and `test/` contents were unreviewed; the
  candidate directory now includes `preflight.mjs`, and the tests are the source commit's own.

## 2. Release traceability

`node release-provenance.mjs verify manifests/mcp-proxy-0.2.1.json --installed <path> --repo <checkout>`
checks: registry integrity equals the manifest; a freshly fetched tarball hashes to it; every
file's sha256 matches; an installed copy matches; and (with a checkout of the private repo) the
files equal `git archive <commit>` except declared rewrites. All five pass for proxy 0.2.1; a
one-line edit to an installed file makes the installed-copy check fail (negative control).

- proxy **0.2.1 → `7a5004363`**: 23 of 24 files byte-identical; only `package.json` differs, and
  the diff is exactly pnpm's publish rewrite (`workspace:^` → `^`, script order, a unicode
  escape, `prepublishOnly` removed).
- guard **0.1.1 → `7a5004363`**: 10 of 11 files identical; same `package.json` rewrite.
- **Why this was needed:** registry metadata has **no `gitHead`**; it records `_from file:…\strix-pub`,
  i.e. the tarball was packed and published from a temporary directory, not a git checkout.
- **Gap that remains:** commit `7a5004363` lives in the **private** `Tarshann/strix-platform`
  repo. The `repository` field points to the public `Strixgov/strix` mirror, which has different
  history, does not contain that commit, and (at `ef14f31`) has no `scripts/run-tests.mjs`.
  So an outside party cannot resolve the link today. Ship a public mirror commit that contains
  the release, or publish via CI with `npm publish --provenance` so the registry carries a signed
  attestation. A manifest in this repo is a stopgap, unsigned, and proves "these bytes equal this
  source", not who built them.

## 3. Wire: hosted Sandbox Mode vs Offline Mode

- **Hosted (accountless):** `python wire-hosted/run.py payment.charge` with every `STRIX_*`
  variable removed. `POST /api/public/sandbox/provision` succeeded (shared tenant `strix-sandbox`,
  ~1 hour credential, 10 capabilities). `POST /api/v1/evaluate` then returned **HTTP 400
  `Unknown action type`** for `payment.charge`; a probe of all 10 provisioned capabilities (with
  and without parameters) failed the same way. The inert operation never ran and no hosted receipt
  exists. The helper reports that 400 as `StrixDenied`, which reads as a policy denial.
  The docs also list `payment.refund`, which the provision response did not include.
  The request shape matches the server's required fields, so this looks like a server-side
  capability registry gap for the sandbox tenant, but that is a hypothesis, not a diagnosis.
  **Re-run before any promise.** Hosted data flow, from the recorded traffic and the helper source:
  your IP, capability name, actor id, parameter hash, timestamps, and (success path) the
  parameters in plain text.
- **Offline:** `python wire-offline/run.py <solo>` with socket connections blocked: an unapproved
  HIGH-risk call is refused and the operation does not run; an approved call runs once and writes a
  signed receipt; `solo strix-wire verify` verifies it; a tampered copy is rejected; 0 connection
  attempts. Caveat: `approval_granted=True` is the caller's attestation that a human approved, and
  the receipt is a `LOCAL_MACHINE_ASSERTION` (a local key signed it), not third-party custody.
- Doc changes: the setup guide, README and one-pagers now separate the two modes, say plainly that
  hosted mode uses the network and what leaves the machine, and carry the 2026-11-06 status. The
  strix-wire test suite passes after the edits (see "Test runs" below).
- **Landing page:** it is not in this repository, so it was not changed. It needs the same edits.

## 4. `solo govern` (0.4.1)

`python solo-govern/run.py <solo>` scores `solo govern scan --include-ai` against a hand-labelled
fixture. Result: **9 of 13** supported-language actions detected; **0 of 10** in Go, Java, Ruby,
shell, SQL, or reached via an alias or `getattr`; **0** false positives in the negative files
(docstrings, strings, test names, `dict.pop`); 2 extra hits that are AI SDK *imports*, not calls.
Missed even in Python/TS: `subprocess.run`, `smtplib sendmail`, `requests.post`, `fetch(POST)`.
Scan exits 0 and reports `ok: true` regardless of what it cannot see.

Other findings: `suppress` works only with `# strix: allow capability=<id> reason="…"` (reason
required); a hand-rolled `governed_action(...)` wrapper is **not** counted as governed (only the
approved `strix_wire` wrapper is, which is deliberate anti-spoofing, but the positive path was not
exercised here); `--root DIR` inside a git checkout resolved to the enclosing repo root, so scan
a copy outside any repo; `solo --help` crashes on a cp1252 Windows console (set `PYTHONUTF8=1`);
`solo govern compare` prints "only Strix catches this" from a built-in matrix and was not measured
against the named tools. **Document it as a static, pattern-based inventory, not coverage.**
Commands exercised: `scan`, `coverage`, `trend`, `suppressions`, `wrap-help`, `compare`, `policy`,
`profile`, `slsa`, `apply-policy` (help/exit only for the last four).

## 5. Controls at the boundary

`npm ci && node run.mjs` in `mcp-proxy-boundary/` drives the real `strix-mcp-proxy` CLI over stdio
in front of a stdio fixture whose handler log records every execution. Seven hard checks, all pass:

| Step | What happened | Handler ran? | Receipt | Outcome record |
|------|---------------|--------------|---------|----------------|
| A `read_note`, policy ALLOW | returned | yes | ALLOW | SUCCEEDED |
| B `delete_note`, policy DENY | MCP error | **no** | DENY | none |
| C `write_note`, nobody approves (3 s timeout) | MCP error after the wait | **no** | DENY, `approvalReason: TIMEOUT` | none |
| D `write_note`, out-of-band approver | returned | yes (sandbox file has only the approved note) | ALLOW, `USER_APPROVED` | SUCCEEDED |
| E `delete_note` **directly on the upstream** | returned | **yes** | **none** | **none** |

- E is the boundary result that matters: the control applies only to the routed path. Anything that
  can reach the upstream another way is unaffected.
- Receipts are *authorization/interception* records (ALLOW or DENY). Only the execution-outcome
  records say an operation completed; both ALLOW cases have one, the DENY cases have none. A client
  can't tell a timeout from a policy deny by the error text; the receipt's `approvalReason` can.
- Independent verification used `@strixgov/verifier` 1.24.1 (a separate package, same vendor):
  4 receipts and 2 outcomes VERIFIED; a tampered receipt is reported TAMPERED. **Finding:**
  `chainValid` stayed `true` for the chain that contained the tampered receipt, so gate on each
  receipt's `verificationStatus`, not on `chainValid` alone.
- Outcome records are signed by the proxy, i.e. they attest what the proxy observed from the
  upstream; the handler log is the independent ground truth for what ran.
- Not tested: signer or store failure, approval reuse, upstream crash, unclassified tool names,
  HTTP-transport MCP servers (the README says the proxy does not intercept those), multi-process
  access to the same upstream.

## 6. SGRF plugin

Run in Claude Code with `strix-governance` 0.2.5 (installed from marketplace `strixgov`), each
lens by a fresh subagent that was given the target and no conclusions: system lens →
`sgrf-lens-runs/system-lens.md`, change lens → `change-lens.md`, release lens → `release-lens.md`.
The reports are retained verbatim. They are advisory model-generated reviews, not a merge gate,
runtime control or certification, and their scores are not evidence about the product. Several
sections were marked Unverified by the lenses themselves; read those.

## 7. Sales copy

See `git diff docs/sales skills/strix-wire`. Removed or qualified: "nothing executes until
evaluated", "non-bypassable", "tamper-proof", "no data leaves the machine" / "only non-secret
parameters travel", "running in production today", "about 2 minutes", "no data shared", and the
compliance framing. New "never say" rows: whole-agent coverage, healthcare/PHI/egress, compliance
or certification, accountless-hosted-works, `solo govern` completeness, SGRF-as-gate. Nothing in
the repo claimed healthcare egress; the row is a guard for sales conversations.

## Test runs after the edits

`python -m pytest skills plugins` → 279 passed, 3 skipped (Windows). The "271 tests" figure in the
docs is for commit `3d1e4db` on Linux and Windows; the current tree is 282, measured on Windows
only.

## Re-running

```bash
cd validation/mcp-proxy-boundary && npm ci && node run.mjs
node validation/mcp-proxy-release/release-provenance.mjs verify validation/mcp-proxy-release/manifests/mcp-proxy-0.2.1.json
python validation/solo-govern/run.py <path-to-solo>      # PYTHONUTF8=1 on Windows
python validation/wire-offline/run.py <path-to-solo>
python validation/wire-hosted/run.py payment.charge      # real network call to the hosted service
```
