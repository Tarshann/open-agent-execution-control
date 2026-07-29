# strix-onboard — a new client to its first verifiable governed action

`ONBOARD-1`. A **reference implementation** of the onboarding path: the domain
contracts, the state machine, and the operator workflow that carry one client
organization from no configuration to a governed action whose receipt has been
checked by an external verifier — and that refuse to report ready until an
accepted verdict is on file.

> **Scope.** This is the open skills-layer reference model, not the hosted Strix
> Console and not a production provisioning system. It holds state, derives
> readiness, and records what the decision path and the verifier returned. It
> does not persist to a database, authenticate an operator, call a hosted tenant
> API, integrate a credential vault, or run adapter connectivity jobs — those
> surfaces are not in this repository. Validation is repository-layer only; see
> [`docs/VALIDATION.md`](../../docs/VALIDATION.md), including its known gaps.

```text
New client → tenant → systems → governed actions → policies + approvals
          → adapters + credentials → connectivity → governed smoke test
          → independent proof verification → READY
```

## What's here

| File | What it is |
|---|---|
| [`SKILL.md`](./SKILL.md) | The operator workflow — the guided flow, the one approval gate, and the failure modes. |
| [`onboarding.py`](./onboarding.py) | The domain contracts, the state machine, and the tenancy boundary. All lifecycle truth lives here. |
| [`status.py`](./status.py) | The readiness view (the console screen's content). Read-only. |
| [`tests/`](./tests/) | 56 behavioral tests on the state machine, 15 on the readiness view, 18 pinning SKILL.md to the code. |

## The load-bearing rule

> **Never convert configured directly into ready.**

This is the onboarding form of the discipline in
[`plugins/strix-personal/scripts/_vendor/lifecycle.py`](../../plugins/strix-personal/scripts/_vendor/lifecycle.py)
("never convert detected directly into governed"), and it is enforced the same
way rather than reimplemented differently:

- configuration data cannot promote a project past `MAX_CONFIGURED_STATE`
  (`INTEGRATIONS_CONFIGURED`);
- `READY_FOR_SMOKE_TEST`, `PROOF_PENDING` and `READY` each require a matching,
  passing `OnboardingSignal` — an out-of-band fact that something really
  happened;
- `READY` additionally requires a proof-bearing verification verdict whose
  evidence id matches the smoke test's;
- `is_ready` is **derived**. Forcing the state label does not make a project
  ready, and a test pins that.

## The states

```text
DRAFT → TENANT_CREATED → SYSTEMS_REGISTERED → CAPABILITIES_DEFINED
      → POLICIES_CONFIGURED → INTEGRATIONS_CONFIGURED   ← MAX_CONFIGURED_STATE
      → VALIDATION_PENDING → READY_FOR_SMOKE_TEST
      → SMOKE_TEST_RUNNING → PROOF_PENDING → READY

diversions:  VALIDATION_FAILED   (from VALIDATION_PENDING)
             SMOKE_TEST_FAILED   (from SMOKE_TEST_RUNNING)
             PROOF_FAILED        (from PROOF_PENDING)
             BLOCKED             (terminal, requires a reason)
```

Forward-only along the progression. A failure state is reachable only from the
stage it is the failure *of*. `retry_from_failure()` is the one backward move,
valid only from a failure state, and it discards the stale results of the
attempt that failed so nothing downstream can pass on them.

## Tenant binding

Tenant identity comes from the operator context, not from a caller-supplied
field:

```python
project = start_onboarding(context, project_id="onb_001")   # no tenant_id parameter
```

There is no parameter for a client to populate with someone else's tenant. Every
record attached to a project is checked against the project's tenant and refused
on mismatch (`TenantIsolationError`), so a mis-scoped record cannot be attached
even if a query layer returns one. Cross-tenant capability is
`OperatorContext(admin_scope=True)` — explicit, and recorded in the project's
history.

**Called binding rather than isolation, deliberately.** This is an in-process
attachment check. Production tenant isolation additionally requires
authenticated tenant context, server-side authorization, query scoping or
row-level security, and service boundaries — none of which are in this
repository. The check is defence in depth for a layer that has the rest; it is
not a substitute for it.

## Proof discipline

No proof claim may exceed what can be independently verified, so:

- the verdict vocabulary is borrowed verbatim from the existing verifier surface
  ([`strixgov-plugins/skills/verification`](../../strixgov-plugins/skills/verification/SKILL.md)),
  so onboarding cannot invent a friendlier result than the tool returns;
- `LEGACY_UNSIGNED`, `COMPLIANCE_VIOLATION` and `KID_NOT_FOUND` do not reach
  `READY`;
- a verification for a different evidence id is refused — a proof for another
  action proves nothing about this one;
- an unattributed verdict is refused — a verdict naming no verifier cannot be
  audited back to anything;
- `proof_claim()` states what was checked and explicitly disclaims the rest:
  a verified record attests that the record is signed and unmodified, **not**
  that the governed system is secure or compliant.

**The limit of that last point.** `verified_by` is attribution, not proof of
independence. Requiring it non-empty stops an anonymous verdict, but nothing
here checks that the named tool is independent of Strix or was executed at all —
a caller could pass any string. Independence comes from an operator running the
public verifier out-of-band against a publicly resolvable record. This repo
ships no such record, so nothing in it demonstrates end-to-end independent
verifiability; `docs/VALIDATION.md` lists what a real proof bundle would need.

## Not the execution authority

This skill configures governance; it never executes a governed action. The smoke
test runs through the existing decision path
([`../strix-wire/helpers/`](../strix-wire/helpers/)) and verification runs through
the existing verifier. This model records what they returned.

The hosted Strix Console UI is the commercial control plane and is not in this
repository — this is the onboarding control logic and operator workflow in the
form this repo ships.

## Secrets

`CredentialBinding` has no field for a secret value: only a `secret_ref` into the
approved secret boundary, plus a `CredentialState`. A `secret_ref` that looks
like a secret value (`sk_live_…`, `Bearer …`, a PEM header) is refused. A
connectivity test that reports `secret_exposed=True` is refused. The readiness
view is tested to contain no credential reference at all.

## Run it

```bash
python3 status.py --demo                      # see the shape of the view
python3 status.py --project onboarding.json   # render a stored project
python3 -m pytest tests -q                    # 89 tests
```
