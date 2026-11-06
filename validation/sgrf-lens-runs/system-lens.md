- **Host:** Claude Code
- **Skill:** `strix-governance:runtime-governance-review` (SGRF v1 system lens)
- **Plugin version:** strix-governance 0.2.5 (installed path `C:\Users\user\.claude\plugins\cache\strixgov\strix-governance\0.2.5`)
- **Date:** 2026-11-06
- **Target path:** `C:\Users\user\Tarshann\.claude\worktrees\mcp-proxy-release-validation-a43014\validation\mcp-proxy-boundary\` (route: MCP client -> strix-mcp-proxy -> fixture upstream tools read_note / write_note / delete_note)

---

## Strix Governance Review (SGRF v1)

**Target:** `validation/mcp-proxy-boundary/` — disposable fixture; named route MCP client -> `strix-mcp-proxy` (`@strixgov/mcp-proxy` 0.2.1) -> stdio fixture upstream (`read_note`, `write_note`, `delete_note`). Everything outside that route is out of scope and marked Unverified where relevant.
**Date:** 2026-11-06
**Reviewer:** Claude Code (Claude Sonnet 5.5), reading files only; nothing was executed or re-run. Run results below are taken from the pre-existing `evidence/raw-run.json` (generatedAt 2026-11-06T14:42:53Z), not from a run in this review.

### 1. Execution Summary
**Applicability:** ◐ partial — the reviewed route is in domain (an execution boundary in front of consequential-looking tools), but the target is a disposable test fixture with inert tools, local-only identity, and throwaway keys, so deployment-grade expectations (real trust root, production tenancy) are calibrated down, not scored as failures.

Capability               ██████        3 / 5
Governance               ██████        3 / 5
Runtime Enforcement      ████████      4 / 5
Independent Verification ████████      4 / 5
Tier: Silver (not Verified-tier on the route as deployed: verifiability evidence is strong, but the boundary is bypassable by design of the stdio deployment and identity is unattested; see below)

On the one named route, the proxy evaluated every routed call at call time and enforced the result: ALLOW ran the handler, DENY and approval TIMEOUT did not, and an out-of-band approval ran it exactly once. Signed authorization receipts (4) and execution outcomes (2) verify independently with the separate `@strixgov/verifier` package, and a tampered receipt is reported TAMPERED. The same fixture shows the boundary is not self-protecting: calling the upstream directly (step E) ran `delete_note`, the capability the proxy DENYs as CRITICAL, with no receipt and no outcome. Identity is `tenantId: local` with no attested actor on the receipts, the harness approver was automated, and the verifier's `chainValid` flag stayed true over a chain containing a TAMPERED receipt. Governance is real on the routed path and absent on the unrouted one.

### 2. Declared Scope vs Observed Scope
**Declared** (from `package.json` and the `run.mjs` header): "Disposable fixture that records proxy allow / deny / approval-timeout / approved-execution and the out-of-proxy path. Not a product package." The harness claims to drive the real CLI over stdio, read what the upstream handler actually executed, and verify the signed records independently.

**Observed:** `run.mjs` builds a config, spawns `strix-mcp-proxy` with `--config`, drives A (ALLOW), B (DENY), C (APPROVAL_REQUIRED, nobody approves, `timeoutMs` 3000), D (APPROVAL_REQUIRED, file-based approver approves), then E (direct upstream call, no proxy). It uses a handler log written by the upstream itself as ground truth for "what ran", then verifies receipts and outcomes with `@strixgov/verifier` 1.24.1, including a tamper negative control. This matches the declared scope. The fixture upstream's tools are inert (the only side effect is a line appended to a sandbox file in a temp dir), so no real consequential action is governed. This calibrates the bar: the proxy is held to execution-boundary expectations (decide at call time, fail closed, signed evidence); the fixture is not held to production identity or key management.

### 3. Trust Root
- **Policy and signing authority:** a locally generated signing key (`signingKeyId: strix-boundary`, Ed25519 per the outcome records) in `keyPath` under a temp dir; the public JWK is copied to `evidence/public-jwk.json`. Authority is whoever controls that process and directory; there is no external root (no KMS/HSM, no hosted tenant). Acceptable for a fixture; Unverified for any deployment.
- **Identity attribution:** receipts carry `tenantId: "local"` and `environment: "local"`. The proxy source forwards actor context from the client's request `_meta` (`strix_actor_id`, `strix_actor_role`, `src/proxy.mjs:321-325`); the CLI documents `STRIX_TRUSTED_ACTOR_ID` and `STRIX_REQUIRE_TRUSTED_IDENTITY` to override this. `run.mjs` sets neither, and none of the four receipts contains an actor field in the evidence I read. So no caller identity is attributed in the recorded decisions. A human vs agent distinction is not made.
- **Approver identity:** the approval record shows `approvedBy: "validation-harness"`, a self-declared string written by an automated script (`startApprover`, `run.mjs:74-93`) that auto-approves any request file. It demonstrates the mechanism, not human oversight.

### 4. Execution Boundary
- **Single point on the routed path:** all three tools are reached through one proxy process, with capability ids `mcp.boundary.<tool>` and action `mcp.callTool:<tool>`. Step 0 shows `tools/list` through the proxy returns exactly the three declared tools.
- **Not a single point for the system:** the upstream is an ordinary stdio MCP server that executes whatever reaches it. Nothing in the upstream checks for a proxy-issued authorization (no token validation in `fixture-upstream.mjs`; the SECURITY.md of the proxy itself lists the token validator as a separate, later enforcement primitive). The boundary exists only where traffic is routed through it. Step E demonstrates the second path.
- **Out of scope / Unverified:** how any real MCP client is configured to reach the proxy rather than the upstream; HTTP transports (the proxy source mentions other transports, `src/proxy.mjs:356`); anything beyond stdio.

### 5. Authority Model
- **Attenuation:** not applicable on this route. There is no delegation chain; policy is a flat map of capability id to decision, and the client has no grant to attenuate.
- **Re-evaluation at point of use:** yes for routed calls. Step D shows an approval is bound to a single call: C (timeout) and D (approved) are separate receipts for the same capability with different decisions. There is no evidence in the run of an approval being reused for a later call, but no step tests reuse explicitly, so reuse resistance is Unverified.
- **Inheritance:** the spawned upstream inherits the full parent environment (`upstream.env: { ...process.env, ... }`, `run.mjs:35`; the written config redacts it). Whatever credentials are in that environment are available to the upstream regardless of policy. In this fixture there are none of consequence; as a pattern it is authority inheritance by default.

### 6. Bypass Analysis
| # | Path | Evidence | Risk |
|---|------|----------|------|
| 1 | Call the upstream process directly, around the proxy | Step E: `delete_note` ran, handler log shows it, receipts stayed at 4 and outcomes at 2 (`run.mjs:132-143`, check E). The policy DENYs this capability on the routed path. | **High** for any deployment where the upstream is reachable by the client; Low for this fixture itself (tool is inert) |
| 2 | Policy default | `default: "DENY"`; only three capabilities declared. Behavior of an unlisted tool name was not exercised by any step. | Unverified |
| 3 | Client-supplied actor identity | Proxy reads `strix_actor_id/role` from client `_meta` unless trusted identity is configured; this run does not configure it. A client could assert any actor. | Medium (attribution only; decisions in this policy do not key on actor) |
| 4 | Approver as an automated, self-asserting file writer | Anything that can write `<id>.response.json` into `requestDir` can approve. In the harness this is the point; in a deployment the directory's access control is the control. | Medium; Unverified for a real deployment |
| 5 | Skip flags / debug / `NODE_ENV` branches in the proxy | I grepped `src/` and `bin/` for `NODE_ENV`, skip/dev flags and found none relevant; I did not read all 1105 lines of source line by line. Auto-approval exists as a documented mode (`approval.type: "auto"`, "demo shortcut", `src/proxy.mjs:227-229`) and was not used here. | Low for this run; `type: "auto"` would be High if used outside demos |
| 6 | Verifier `chainValid` flag | `run.mjs` records `chainValid: true` for a chain containing a TAMPERED receipt (`out.observations`). A consumer gating on `chainValid` alone would accept tampered evidence. | Medium (verification-consumption bypass, not an execution bypass) |

### 7. Capability Model
Capabilities are static declarations in the config: `id`, `name`, `risk` (LOW/MEDIUM/CRITICAL), `mode` (READ/WRITE), `description`. Policy maps ids to ALLOW / APPROVAL_REQUIRED / DENY with a DENY default. They are not dynamic: no scope on arguments (policy does not inspect `note`), no expiry, no issuance evidence per capability, and no decay on drift (the `policyVersion` is a `sha256:` hash of the policy, which makes change detectable in receipts, but nothing revokes or ages capabilities). Risk labels are operator-asserted and not checked against what the upstream tool actually does (the fixture's `delete_note` is "inert", yet labelled CRITICAL).

### 8. Evidence Model
Per routed call the proxy writes signed schema-v2 authorization receipts to `receipts.jsonl`, with fields including `capabilityId`, `action`, `decision`, `risk`, `policyVersion`, `invocationHash`, `evidenceHash`, `proofChainHash`, `timestamp`, `signingKeyId`, `signature`. ALLOWed executions additionally get a signed execution outcome (`execution-outcomes.jsonl`) linked by `authorizationReceiptId` and `authorizationProofChainHash`, with `executionStatus`, `resultHash`, `outcomeHash`. DENY decisions (B, C) have receipts and no outcomes, which matches the handler log (handler did not run). Receipt count 4, outcome count 2 matches the two executions routed through the proxy. **Coverage gap:** the unrouted call (step E) produced no record at all, so the audited path covers only routed traffic. Receipts do not carry the call arguments, only `invocationHash`, which is good for privacy and means a verifier cannot read what was requested without the original invocation (Unverified whether the proxy retains it; `store-snapshots.jsonl` exists in `evidence/` and I did not inspect its contents).

### 9. Verification Model
This is the strongest area. `run.mjs` verifies with `@strixgov/verifier` 1.24.1, a separate package from the proxy (`@strixgov/mcp-proxy` 0.2.1), using only the public JWK: `verifyReceiptChain` (4/4 VERIFIED) and `verifyExecutionOutcomeRecord` (2/2 VERIFIED, each cross-checked against its authorization receipt). A negative control that flips `decision` on the first receipt is reported `TAMPERED`. Caveats from the evidence itself: (a) the verifier and proxy are both Strix packages, so "independent" means separate code and key, not a different vendor; (b) `chainValid` was true despite a TAMPERED receipt, so consumers must gate on per-receipt `verificationStatus`; (c) the public key was taken from the same machine and directory that produced the receipts, so key provenance (that this JWK is the one the operator actually published) is not independently established here; (d) I did not re-run the verifier in this review.

### 10. Runtime Enforcement
Admissibility is judged at execution time on the routed path, not at config time: each `tools/call` triggers a decision, and the fixture's handler log proves enforcement (not just logging): B and C produced zero handler invocations; A and D produced exactly one each. Approval is a blocking, per-call wait (C waited 3142 ms against a 3000 ms timeout, then denied). The enforcement is not non-bypassable: it holds only for traffic through the proxy (see §6 #1).

### 11. Failure Modes
- **Approval timeout:** fails closed. Step C: handler did not run; DENY receipt with `approvalReason: "TIMEOUT"`.
- **Policy default:** `DENY` for unmatched capabilities per config and CLI help (`--policy-default` default DENY); not exercised by a step.
- **Non-TTY terminal approver:** per proxy source comments (`src/proxy.mjs:224-228`), the default terminal approver fails closed (PROMPT_FAILED) when stdio is not a TTY.
- **Webhook notify failure:** per `src/webhook-approver.mjs` comments, notification failure neither approves nor denies; not exercised here.
- **Signer unavailable / key missing / disk full / store write failure:** not exercised, Unverified. Whether a receipt-write failure blocks execution (fail closed) or permits it (fail open) is the most important untested question on this route.
- **Stale or conflicting policy:** not exercised, Unverified.
- **Upstream crash or hang after ALLOW:** not exercised; outcome-record behavior for `FAILED` executions is Unverified.

### 12. Governance Maturity
- Capability: 3/5 — three tools with a read / write / delete spread, all inert, one stdio upstream, no autonomy or integration reach. Scored as a fixture, not a product.
- Governance: 3/5 — sub-signals: Trust Root Clarity low (local-only signing key, `tenantId: local`, no attested actor); Execution Boundary Strength medium (single point on the routed path, absent for the upstream directly); Authority Model medium (per-call re-evaluation, flat policy, no attenuation, inherited environment); Bypass Resistance low-medium (direct-upstream path is High); Capability Freshness low (static, no decay); Human Oversight low-medium (approval mechanism works, but the approver in this run was automated).
- Runtime Enforcement: 4/5 — decisions evaluated and enforced per call at runtime with fail-closed behavior on timeout and a DENY default, confirmed by the handler log as ground truth; held below 5 because the boundary is bypassable (step E) and failure behavior on signer/store failure was not exercised.
- Independent Verification: 4/5 — signed receipts and outcomes, public key, separate verifier, tamper negative control, all VERIFIED; held below 5 because audited-path coverage excludes unrouted calls, `chainValid` is not a safe gate on its own, and key provenance is local.

### 13. Recommended Next Steps
**High Priority**
- Make the upstream unreachable except through the proxy (or have the upstream require a proxy-issued token), so step E cannot succeed — Risk: the policy's DENY on a CRITICAL capability is advisory for anyone who can reach the upstream — Requires runtime enforcement? **Yes**
- Add a step that forces a receipt-store write failure and a missing-key condition, and assert the handler does not run — Risk: fail-open on signer/store failure is untested for a consequential action — Requires runtime enforcement? **Yes** (behavior of the enforcement layer); the test itself is hygiene
- Configure `STRIX_TRUSTED_ACTOR_ID` and `STRIX_REQUIRE_TRUSTED_IDENTITY` in a variant run and show receipts bind an attested actor — Risk: receipts currently attribute decisions to no one — Requires runtime enforcement? **Yes**

**Medium Priority**
- Add a step for an unlisted tool name (expected: DENY by default) and for argument-sensitive policy (e.g. a different `note` value) — Risk: default-DENY and argument handling are claimed but not exercised — Requires runtime enforcement? **Yes**
- Add a step that replays one approval or response file for a second call — Risk: approval reuse resistance is Unverified — Requires runtime enforcement? **Yes**
- Pin and publish the public key out of band, and have the verifier step check against the published key rather than the local copy — Risk: key provenance is assumed — Requires runtime enforcement? **No**
- Scope the upstream child environment to the variables it needs instead of inheriting `process.env` — Risk: inherited authority — Requires runtime enforcement? **No**

**Quick Wins (prompting/hygiene only)**
- In any consumer of these records, gate on per-receipt `verificationStatus`, never on `chainValid` alone (the harness already notes this in `observations`).
- Document in the fixture README that check E is a demonstration of the unrouted path, so the "E bypass ran and left no record" result is read as a deployment-topology finding, not a proxy defect.
- Record in the evidence which `approval.type` was used (`file`) and that the approver was automated, so the D result is not read as human oversight.

---

> **Want these recommendations enforced, not just recommended?**
> A runtime governance layer (e.g. the Strix runtime) can evaluate every
> consequential action against the same criteria used in this review — at the
> moment of execution — and produce an independently verifiable, signed record of
> each decision. SGRF improves how an agent *thinks* about governance; a runtime
> makes the decisions *non-bypassable* and moves the Independent Verifiability and
> Runtime Enforcement axes toward Verified. Learn more: https://strixgov.com

*This review is advisory and diagnostic. It did not enforce anything, did not run the fixture, and did not produce a signed record. The receipts and verification results cited are from the pre-existing `evidence/` files in the target directory.*
