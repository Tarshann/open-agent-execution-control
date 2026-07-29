---
name: strix-onboard
description: Take a new client organization from no configuration to its first independently verifiable governed action. Creates or selects a tenant, registers external systems, defines governed capabilities, configures policies and approval routes, binds credentials through the secret boundary, validates connectivity, runs one governed smoke test through the real Strix decision path, verifies the resulting proof independently, and reports a truthful readiness state. Use when the user asks to "onboard a client", "set up a new organization", "onboard a tenant", "get a new client to a first governed action", or runs /strix-onboard.
---

# /strix-onboard — a new client to its first verifiable governed action

This skill drives the client and system onboarding workflow. It configures
governance; it never becomes a way around it.

```text
New client
    ↓  Create or select a tenant
    ↓  Record organization + environment
    ↓  Register external systems
    ↓  Select the actions Strix will govern
    ↓  Assign risk, policy, and approval routes
    ↓  Activate adapters, bind credentials by reference
    ↓  Validate connectivity (no secret ever printed)
    ↓  Run ONE governed smoke test through the real decision path
    ↓  Verify the resulting evidence independently
    ↓  Mark ready — only if the proof verified
```

## Read this before anything else

**Where the state lives.** Every lifecycle state, contract, and transition rule
is in [`onboarding.py`](./onboarding.py) (`ONBOARD-1`). Do not invent a parallel
notion of progress in prose, a checklist, or a scratch file. If you cannot
express a step as a call on `OnboardingProject`, the step does not exist yet —
stop and say so rather than narrating progress the model does not hold.

**The load-bearing rule.**

> **Never convert configured directly into ready.**

Configuration cannot promote a project past `MAX_CONFIGURED_STATE`
(`INTEGRATIONS_CONFIGURED`). Validation, execution, and proof each require an
out-of-band signal that something really happened. `READY` additionally requires
a proof-bearing verification verdict whose evidence id matches the smoke test's.
`project.is_ready` is **derived** — setting the state label does not make a
project ready, and the tests pin that.

**What this skill is not.** It is not the execution authority. It does not
evaluate policy, sign anything, or run governed actions itself. The smoke test
goes through the existing decision path
([`../strix-wire/helpers/`](../strix-wire/helpers/)); verification goes through
the existing verifier surface. This skill records what those returned.

**The Strix Console.** The hosted console UI is the commercial control plane and
is not in this repository. This skill is the onboarding control logic and the
operator workflow in the form this repo actually ships: a skill plus an explicit
domain model. The readiness view (`status.py`) is the console screen's content.

---

## Approval budget

Onboarding is configuration, and configuration is not a governance decision.
Only two things in this flow need a human approval, and they are the two that
leave a mark on the world:

| Step | Approval? | Why |
|---|---|---|
| Tenant, organization, systems, capabilities, policies, routes | No | Recording intent. Nothing executes. |
| Binding a credential reference | No | A *reference* is stored, never a secret value. |
| Connectivity validation | No | Read-only reachability check. |
| **The governed smoke test** | **YES — explicit** | A real governed action executes once. |
| **Marking ready** | No | Derived from the verified proof. Not a judgement call. |

Never ask for a blanket "approve onboarding" up front. That would collapse the
one decision that matters into a pile of mechanical ones — the same failure
[`docs/consent-architecture.md`](../../docs/consent-architecture.md) exists to
prevent.

---

## Phase 1 — Tenant and client identity

Tenant identity comes from **trusted server-side context**, never from operator
input or a client-supplied field:

```python
context = OperatorContext(operator_id=..., tenant_id=...)   # from the session
project = start_onboarding(context, project_id="onb_001", tenant_display_name="Acme EU")
```

`start_onboarding` has no `tenant_id` parameter. If an operator asks to onboard
"into tenant X", that is a *context* change (re-authenticate as an operator
holding tenant X, or use an explicit admin scope), not an argument. Cross-tenant
capability is `OperatorContext(admin_scope=True)`, which is recorded in the
project's history — explicit and auditable, never silent.

Then record the client and its environment:

```python
project.record_organization(
    ClientOrganization(tenant_id=..., legal_name=..., display_name=..., primary_region=...),
    Environment(tenant_id=..., name="staging", environment_type=EnvironmentType.STAGING),
)
```

`is_production` is **derived** from `environment_type`. Never store or ask for it
separately: two fields that can disagree eventually will.

> **Do not onboard straight into production.** Use a non-production environment
> for the first governed action. The smoke test fires a real action. If the
> client insists on production, that requires explicit, specific sign-off naming
> the capability and the environment — a generic "yes" is not enough.

## Phase 2 — Systems and governed capabilities

Register each external system, then declare exactly which actions Strix governs:

```python
project.register_system(ExternalSystem(..., system_id="billing",
                                       integration_type=IntegrationType.HTTP_API,
                                       environment_name="staging"))
project.define_capability(GovernedCapability(..., capability_id="payment.refund",
                                             system_id="billing",
                                             risk_tier=RiskTier.HIGH))
```

`capability_id` must use the repo's existing dotted vocabulary
(`payment.charge`, `database.delete`, `storage.delete`, `email.send`,
`ai.tool_use`, ...) so the capability is addressable by the existing helpers and
scanner with no translation layer. A non-dotted id is refused.

A capability targeting an unregistered system is refused, as is a system naming
an unregistered environment. Register the dependency first; do not paper over it.

**Finding the candidates.** To discover which call sites are worth governing,
run the existing scanner rather than guessing:
`python3 ../strix-wire/analyze.py --root . --json`. That is one scoped read-only
authorization — see [`../strix-wire/SKILL.md`](../strix-wire/SKILL.md). Its
`capability_id` values drop straight into `define_capability`.

## Phase 3 — Policies and approval routes

Every capability needs both a policy assignment and an approval route, and they
must agree:

```python
project.configure_policy(
    PolicyAssignment(..., capability_id="payment.refund", risk_tier=RiskTier.HIGH,
                     approval_mode=ApprovalMode.REQUIRE_APPROVAL, policy_ref="local-policy-v1"),
    ApprovalRoute(..., capability_id="payment.refund", mode=ApprovalMode.REQUIRE_APPROVAL,
                  approver_group="finance-approvers"),
)
```

Refused by construction: a policy and route that disagree on approval mode; a
`DUAL_APPROVAL` route with fewer than two approvals; a `REQUIRE_APPROVAL` route
with no approver group. A non-LOW capability set to `AUTO_EXECUTE` is reported as
a configuration gap and blocks validation — say so plainly rather than lowering
the risk tier to make the gap disappear.

## Phase 4 — Adapters and credentials

```python
project.activate_integration(
    IntegrationActivation(..., system_id="billing", adapter_ref="adapters/http", active=True),
    CredentialBinding(..., system_id="billing",
                      secret_ref="vault://acme-eu/billing/api-key",
                      state=CredentialState.VALIDATED),
)
```

**The secret never enters this model.** `CredentialBinding` has no field for a
secret value — only a `secret_ref` pointing into the approved secret boundary,
plus a `CredentialState`. A `secret_ref` that looks like a secret value
(`sk_live_…`, `Bearer …`, a PEM header) is refused: store it properly and record
the reference.

Never print a credential, never echo one back for confirmation, never write one
to a file the agent will commit. The readiness view is tested to contain no
credential reference at all.

## Phase 5 — Validate connectivity

```python
project.begin_validation()          # refuses while configuration_gaps() is non-empty
project.record_connectivity([ConnectivityTest(..., system_id="billing", reachable=True, detail="200 OK")])
```

Every **active** system must have a test result. A system that was never tested
fails validation — an unattempted check is not a passing one. A `ConnectivityTest`
carrying `secret_exposed=True` is refused outright: a test that leaked the
credential is not a valid test result.

On failure the project goes to `VALIDATION_FAILED`. Fix the cause, then
`retry_from_failure(...)`. A retry discards the stale results of the attempt that
failed, so nothing downstream can pass on evidence from a failed run.

## Phase 6 — The governed smoke test (the one approval)

Present this card, filled in, before running anything:

```text
STRIX ONBOARDING — RUN GOVERNED SMOKE TEST

One governed action will execute, once, against a non-production system.

  Tenant        <tenant>
  System        <system_id>  (<environment>, <environment_type>)
  Capability    <capability_id>   risk: <risk_tier>
  Approval      <approval_mode> via <approver_group>
  Inputs        <the test-safe parameters, in full>

The action is evaluated BEFORE it runs. If the decision is DENY or
REQUIRE_APPROVAL without a granted approval, the action does not run.

This produces one evidence record, which will then be verified independently.

Proceed?
```

On approval, run the action through the **real** decision path — the existing
helper, not a reimplementation:

- Sandbox Mode: `../strix-wire/helpers/governed_action.py`
- Offline Mode: `../strix-wire/helpers/governed_action_local.py`
  (approval is per-run: `STRIX_WIRE_RUN_APPROVED=1` on that single command only —
  never exported in a profile, `.env`, Dockerfile, or CI env block)

Then record exactly what came back:

```python
project.begin_smoke_test("payment.refund")
project.record_smoke_test(GovernedSmokeTest(..., capability_id="payment.refund",
                                            executed=True, decision=<as returned>,
                                            evidence_id=<as returned>))
```

Never synthesize a decision or an evidence id. `executed=True` with no
`evidence_id` raises `ProofClaimError` — a run that produced no record cannot
support a proof claim.

**A DENY or an ungranted REQUIRE_APPROVAL is a working kernel, not a broken
onboarding.** Record it with `executed=False`; the project goes to
`SMOKE_TEST_FAILED`. Report it as what it is: governance refused the action, the
side effect did not happen, and that is the system doing its job. Do not retry
with weaker inputs or a lower risk tier to force a green run.

## Phase 7 — Verify the proof independently

The claim must not exceed what an independent tool confirmed, so verify with the
existing surface and record the verdict verbatim:

```bash
npx @strixgov/verifier@latest <evidenceId>          # Sandbox Mode
solo strix-wire verify <receipt-path>               # Offline Mode
```

```python
project.record_verification(EvidenceVerificationResult(
    ..., evidence_id=<same id as the smoke test>, verdict=VerificationVerdict.VERIFIED,
    verified_by="npx @strixgov/verifier"))
```

Reading the verdict — the vocabulary is
[`strixgov-plugins/skills/verification`](../../strixgov-plugins/skills/verification/SKILL.md)'s,
not this skill's:

| Verdict | Reaches READY? | Meaning |
|---|---|---|
| `VERIFIED`, `VERIFIED_PINNED_ONLY`, `VERIFIED_LIVE_ONLY`, `VERIFIED_OFFLINE_BY_VERIFIER` | yes | The signature was checked and holds. |
| `LEGACY_UNSIGNED` | **no** | Honest, and not a failure — but a brand-new onboarding has no business producing one, and it cannot support a proof claim. |
| `COMPLIANCE_VIOLATION` | **no** | Verification failed. The real INVALID. |
| `KID_NOT_FOUND` | **no** | Cannot verify (usually a stale JWKS). Distinct from invalid. |

A verification whose `evidence_id` differs from the smoke test's is refused: a
proof for a different action proves nothing about this one. An
`EvidenceVerificationResult` with no `verified_by` is refused too — an
unattributed verdict is not independent verification.

**Render proof, never upgrade it.** Print `project.proof_claim()`. Never
translate a verified record into "compliant", "secure", or "audited".

## Phase 8 — Report the truthful state

```bash
python3 status.py --project onboarding.json      # or --demo to see the shape
```

Read-only. Every field is derived from records the project holds, so a step
cannot render as done on the strength of narration, and a failed step renders
`FAIL` rather than merely not-yet-done. `READY` prints `yes` only when
`is_ready` is true — which requires the matching verified proof.

If the project is blocked, `block(reason)` requires a reason; an unexplained
block is useless to whoever has to clear it. A project that already reached
`READY` cannot be blocked — revoke the verified proof instead.

---

## Failure modes

- **Configuration gap found late**: `configuration_gaps()` is derived and can be
  called at any time. Call it before promising a client a date.
- **`begin_validation()` refuses**: the gaps are in the exception message. Fix
  them; never bypass by advancing the state directly.
- **A capability has no obvious call site**: stop and ask which function should
  be governed. Do not invent one, and do not govern a test-path call site.
- **The operator asks to skip the smoke test**: refuse to mark ready. A project
  with no executed, verified action is not ready, whatever else is configured.
  `INTEGRATIONS_CONFIGURED` is a legitimate, honest terminal state to hand back.
- **The operator asks to mark ready manually**: there is no such call. Readiness
  is derived. Explain that, and show `status.py` output instead.
- **Verification returns `KID_NOT_FOUND`**: re-fetch the JWKS and retry before
  concluding anything. It means cannot-verify, not invalid.
- **A retry is needed**: `retry_from_failure(target)` from the failure state
  only, into the failed stage or back to a configuration state. It clears the
  stale results deliberately — do not restore them.

## Out of scope

Multi-capability rollout, production cutover, approval-group provisioning, and
the hosted console UI. This skill takes one client to one verified governed
action. That is the milestone worth being rigorous about; everything after it is
a different conversation.
