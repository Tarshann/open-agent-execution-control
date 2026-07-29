"""Behavioral proof of the ONBOARD-1 onboarding state machine.

The invariants under test are the ones the architecture rests on:

  - configuration alone can never produce a READY project
    ("never convert configured directly into ready");
  - a project cannot reference another tenant's records, and the tenant cannot
    be supplied by the caller;
  - no proof claim exceeds what was independently verified;
  - failure states are reachable only from the stage that failed, and a retry
    discards the stale results of the attempt that failed;
  - an onboarding record can never be mistaken for an evidence row.
"""

from __future__ import annotations

import dataclasses
import importlib.util
import sys
from pathlib import Path

import pytest

MODULE_PATH = Path(__file__).resolve().parents[1] / "onboarding.py"


def _load():
    spec = importlib.util.spec_from_file_location("strix_onboarding_under_test", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ob = _load()


TENANT = "acme-eu"
OTHER_TENANT = "globex-us"


@pytest.fixture
def context():
    return ob.OperatorContext(operator_id="op_1", tenant_id=TENANT)


@pytest.fixture
def project(context):
    return ob.start_onboarding(context, "onb_001", "Acme EU")


def _configure(project, tenant: str = TENANT, *, risk=None, approval=None):
    """Walk a project through every configuration step, to INTEGRATIONS_CONFIGURED."""
    risk = risk or ob.RiskTier.HIGH
    approval = approval or ob.ApprovalMode.REQUIRE_APPROVAL
    project.record_organization(
        ob.ClientOrganization(
            tenant_id=tenant, legal_name="Acme GmbH", display_name="Acme", primary_region="eu-west-1"
        ),
        ob.Environment(tenant_id=tenant, name="staging", environment_type=ob.EnvironmentType.STAGING),
    )
    project.register_system(
        ob.ExternalSystem(
            tenant_id=tenant,
            system_id="billing",
            display_name="Billing API",
            integration_type=ob.IntegrationType.HTTP_API,
            environment_name="staging",
        )
    )
    project.define_capability(
        ob.GovernedCapability(
            tenant_id=tenant, capability_id="payment.refund", system_id="billing", risk_tier=risk
        )
    )
    project.configure_policy(
        ob.PolicyAssignment(
            tenant_id=tenant,
            capability_id="payment.refund",
            risk_tier=risk,
            approval_mode=approval,
            policy_ref="local-policy-v1",
        ),
        ob.ApprovalRoute(
            tenant_id=tenant,
            capability_id="payment.refund",
            mode=approval,
            approver_group="finance-approvers",
        ),
    )
    project.activate_integration(
        ob.IntegrationActivation(
            tenant_id=tenant,
            system_id="billing",
            integration_type=ob.IntegrationType.HTTP_API,
            adapter_ref="adapters/http",
            active=True,
        ),
        ob.CredentialBinding(
            tenant_id=tenant,
            system_id="billing",
            secret_ref="vault://acme-eu/billing/api-key",
            state=ob.CredentialState.VALIDATED,
        ),
    )
    return project


def _reach_proof_pending(project, tenant: str = TENANT):
    _configure(project, tenant)
    project.begin_validation()
    project.record_connectivity(
        [ob.ConnectivityTest(tenant_id=tenant, system_id="billing", reachable=True, detail="200 OK")]
    )
    project.begin_smoke_test("payment.refund")
    project.record_smoke_test(
        ob.GovernedSmokeTest(
            tenant_id=tenant,
            capability_id="payment.refund",
            executed=True,
            decision="REQUIRE_APPROVAL_GRANTED",
            evidence_id="dec_abc123",
        )
    )
    return project


# ---------------------------------------------------------------------------
# Never convert configured directly into ready.
# ---------------------------------------------------------------------------


def test_full_configuration_stops_at_integrations_configured(project):
    _configure(project)
    assert project.state is ob.OnboardingState.INTEGRATIONS_CONFIGURED
    assert project.state is ob.MAX_CONFIGURED_STATE
    assert project.is_ready is False
    assert project.configuration_gaps() == []


def test_configuration_cannot_leap_to_ready(project):
    _configure(project)
    with pytest.raises(ob.OnboardingTransitionError, match="no leaping the lifecycle"):
        project._advance(ob.OnboardingState.READY, "forced")


def test_every_gated_state_refuses_without_its_signal(project):
    _configure(project)
    project.begin_validation()
    for target, kind in (
        (ob.OnboardingState.READY_FOR_SMOKE_TEST, "connectivity"),
        (ob.OnboardingState.PROOF_PENDING, "execution"),
        (ob.OnboardingState.READY, "verification"),
    ):
        with pytest.raises(ob.OnboardingError) as exc:
            project._advance(target, "forced", signal=None)
        assert kind in str(exc.value) or "leaping" in str(exc.value)


def test_a_wrong_or_failing_signal_does_not_promote(project):
    _configure(project)
    project.begin_validation()
    with pytest.raises(ob.OnboardingTransitionError):
        project._advance(
            ob.OnboardingState.READY_FOR_SMOKE_TEST,
            "forced",
            signal=ob.OnboardingSignal(kind="execution"),  # wrong kind
        )
    with pytest.raises(ob.OnboardingTransitionError):
        project._advance(
            ob.OnboardingState.READY_FOR_SMOKE_TEST,
            "forced",
            signal=ob.OnboardingSignal(kind="connectivity", passed=False),
        )


def test_validation_refuses_to_begin_with_gaps(project):
    project.record_organization(
        ob.ClientOrganization(tenant_id=TENANT, legal_name="Acme GmbH", display_name="Acme"),
        ob.Environment(tenant_id=TENANT, name="staging", environment_type=ob.EnvironmentType.STAGING),
    )
    with pytest.raises(ob.OnboardingError, match="incomplete configuration"):
        project.begin_validation()


def test_the_happy_path_reaches_ready(project):
    _reach_proof_pending(project)
    assert project.state is ob.OnboardingState.PROOF_PENDING
    assert project.is_ready is False, "an unverified proof is not readiness"
    project.record_verification(
        ob.EvidenceVerificationResult(
            tenant_id=TENANT,
            evidence_id="dec_abc123",
            verdict=ob.VerificationVerdict.VERIFIED,
            verified_by="npx @strixgov/verifier",
        )
    )
    assert project.state is ob.OnboardingState.READY
    assert project.is_ready is True


# ---------------------------------------------------------------------------
# Tenant isolation.
# ---------------------------------------------------------------------------


def test_start_onboarding_takes_no_tenant_argument():
    # The defence is structural: there is no parameter for a caller to populate
    # with someone else's tenant.
    params = set(inspect_signature_params(ob.start_onboarding))
    assert "tenant_id" not in params
    assert "tenant" not in params


def inspect_signature_params(fn):
    import inspect

    return inspect.signature(fn).parameters.keys()


def test_tenant_comes_from_trusted_context(context):
    project = ob.start_onboarding(context, "onb_x")
    assert project.tenant_id == TENANT


@pytest.mark.parametrize(
    "record_factory,label",
    [
        (
            lambda t: ("record_organization", (
                ob.ClientOrganization(tenant_id=t, legal_name="Evil Corp"),
                ob.Environment(tenant_id=t, name="staging"),
            )),
            "organization",
        ),
    ],
)
def test_foreign_tenant_records_are_refused_at_the_boundary(project, record_factory, label):
    method, args = record_factory(OTHER_TENANT)
    with pytest.raises(ob.TenantIsolationError, match="never reference"):
        getattr(project, method)(*args)


def test_no_step_accepts_a_foreign_tenant_record(project):
    # Walk the whole flow, offering a foreign-tenant record at every step.
    _configure(project)
    foreign_checks = [
        (
            "register_system",
            (ob.ExternalSystem(
                tenant_id=OTHER_TENANT, system_id="x", environment_name="staging"
            ),),
        ),
        (
            "define_capability",
            (ob.GovernedCapability(
                tenant_id=OTHER_TENANT, capability_id="payment.charge", system_id="billing"
            ),),
        ),
        (
            "record_connectivity",
            ([ob.ConnectivityTest(tenant_id=OTHER_TENANT, system_id="billing", reachable=True)],),
        ),
        (
            "record_smoke_test",
            (ob.GovernedSmokeTest(
                tenant_id=OTHER_TENANT,
                capability_id="payment.refund",
                executed=True,
                evidence_id="dec_1",
            ),),
        ),
        (
            "record_verification",
            (ob.EvidenceVerificationResult(
                tenant_id=OTHER_TENANT,
                evidence_id="dec_1",
                verdict=ob.VerificationVerdict.VERIFIED,
                verified_by="verifier",
            ),),
        ),
    ]
    for method, args in foreign_checks:
        with pytest.raises(ob.TenantIsolationError):
            getattr(project, method)(*args)


def test_an_invalid_tenant_slug_is_refused():
    for bad in ("", "UPPER", "has space", "a", "x" * 100, "../etc", "acme_eu"):
        with pytest.raises(ob.TenantIsolationError):
            ob.OperatorContext(operator_id="op", tenant_id=bad)


def test_admin_scope_is_explicit_and_recorded():
    admin = ob.OperatorContext(operator_id="root", tenant_id=TENANT, admin_scope=True)
    project = ob.start_onboarding(admin, "onb_admin")
    assert any("admin scope" in event for _state, event in project.history)
    # …and a normal operator's project says nothing about admin scope.
    plain = ob.start_onboarding(
        ob.OperatorContext(operator_id="op", tenant_id=TENANT), "onb_plain"
    )
    assert not any("admin scope" in event for _state, event in plain.history)


# ---------------------------------------------------------------------------
# No proof claim may exceed what can be independently verified.
# ---------------------------------------------------------------------------


def test_an_executed_smoke_test_without_evidence_is_rejected():
    with pytest.raises(ob.ProofClaimError, match="no record cannot be claimed"):
        ob.GovernedSmokeTest(
            tenant_id=TENANT, capability_id="payment.refund", executed=True, evidence_id=None
        )


def test_verification_for_a_different_action_is_refused(project):
    _reach_proof_pending(project)
    with pytest.raises(ob.ProofClaimError, match="proves nothing about this one"):
        project.record_verification(
            ob.EvidenceVerificationResult(
                tenant_id=TENANT,
                evidence_id="dec_SOMEONE_ELSE",
                verdict=ob.VerificationVerdict.VERIFIED,
                verified_by="npx @strixgov/verifier",
            )
        )


@pytest.mark.parametrize(
    "verdict",
    [
        ob.VerificationVerdict.LEGACY_UNSIGNED,
        ob.VerificationVerdict.COMPLIANCE_VIOLATION,
        ob.VerificationVerdict.KID_NOT_FOUND,
        ob.VerificationVerdict.ERROR,
    ],
)
def test_a_non_proof_bearing_verdict_fails_the_proof_stage(project, verdict):
    _reach_proof_pending(project)
    project.record_verification(
        ob.EvidenceVerificationResult(
            tenant_id=TENANT,
            evidence_id="dec_abc123",
            verdict=verdict,
            verified_by="npx @strixgov/verifier",
        )
    )
    assert project.state is ob.OnboardingState.PROOF_FAILED
    assert project.is_ready is False
    assert "Not proven" in project.proof_claim()


def test_error_is_distinct_from_every_other_refusal(project):
    """`ERROR` exists because the real verifier returns it.

    Handed this repository's `local-receipt-v1`, `npx @strixgov/verifier
    receipt` prints `Status: ERROR` / `unknown schemaVersion` and exits 2 — it
    supports tool-gateway schemaVersion "1" and "2" only. Recorded in
    docs/PROOF-ATTEMPT.md.

    Without this term an operator meeting that outcome had to pick a verdict
    that says something false: KID_NOT_FOUND (the key resolved fine),
    LEGACY_UNSIGNED (the record is signed), or COMPLIANCE_VIOLATION (nothing
    was found non-compliant). Collapsing "could not check" into "checked and
    failed" is the same class of error as collapsing "we did not finish
    looking" into "we looked and it is clean".
    """
    assert ob.VerificationVerdict.ERROR.value == "ERROR"
    assert ob.VerificationVerdict.ERROR not in ob._PROOF_BEARING_VERDICTS
    # Not silently equal to any other refusal, so a report cannot blur them.
    others = {
        ob.VerificationVerdict.KID_NOT_FOUND,
        ob.VerificationVerdict.LEGACY_UNSIGNED,
        ob.VerificationVerdict.COMPLIANCE_VIOLATION,
    }
    assert ob.VerificationVerdict.ERROR not in others


@pytest.mark.parametrize(
    "verdict",
    [
        ob.VerificationVerdict.VERIFIED,
        ob.VerificationVerdict.VERIFIED_PINNED_ONLY,
        ob.VerificationVerdict.VERIFIED_LIVE_ONLY,
        ob.VerificationVerdict.VERIFIED_OFFLINE_BY_VERIFIER,
    ],
)
def test_proof_bearing_verdicts_reach_ready(project, verdict):
    _reach_proof_pending(project)
    project.record_verification(
        ob.EvidenceVerificationResult(
            tenant_id=TENANT,
            evidence_id="dec_abc123",
            verdict=verdict,
            verified_by="npx @strixgov/verifier",
        )
    )
    assert project.is_ready is True


def test_an_unattributed_verdict_is_not_independent_verification():
    with pytest.raises(ob.ProofClaimError, match="not independent verification"):
        ob.EvidenceVerificationResult(
            tenant_id=TENANT,
            evidence_id="dec_1",
            verdict=ob.VerificationVerdict.VERIFIED,
            verified_by="",
        )


def test_forcing_the_state_label_does_not_make_a_project_ready(project):
    _configure(project)
    project.state = ob.OnboardingState.READY  # tamper with the label directly
    assert project.is_ready is False, "readiness must be derived, not asserted"
    assert "No proof claimed" in project.proof_claim()


def test_the_proof_claim_never_upgrades_to_compliant(project):
    _reach_proof_pending(project)
    project.record_verification(
        ob.EvidenceVerificationResult(
            tenant_id=TENANT,
            evidence_id="dec_abc123",
            verdict=ob.VerificationVerdict.VERIFIED,
            verified_by="npx @strixgov/verifier",
        )
    )
    claim = project.proof_claim()
    # The verifier's discipline: render proof, never upgrade it. "secure" and
    # "compliant" may appear ONLY inside the explicit disclaimer, so remove the
    # disclaimer and assert the remaining claim makes no such assertion.
    disclaimer = (
        "This attests that the record is signed and unmodified — not that the "
        "governed system is secure or compliant."
    )
    assert disclaimer in claim
    remainder = claim.replace(disclaimer, "")
    for upgrade in ("secure", "compliant", "safe", "approved by policy"):
        assert upgrade not in remainder, f"proof claim upgraded to {upgrade!r}"
    assert claim.startswith("VERIFIED:")
    # The claim must name the evidence and the tool, so the reader can redo it.
    assert "dec_abc123" in claim and "@strixgov/verifier" in claim


def test_cannot_verify_before_a_smoke_test_produced_a_proof(project):
    _configure(project)
    with pytest.raises(ob.ProofClaimError, match="before a smoke test"):
        project.record_verification(
            ob.EvidenceVerificationResult(
                tenant_id=TENANT,
                evidence_id="dec_1",
                verdict=ob.VerificationVerdict.VERIFIED,
                verified_by="verifier",
            )
        )


# ---------------------------------------------------------------------------
# Failure states and retries.
# ---------------------------------------------------------------------------


def test_unreachable_system_fails_validation(project):
    _configure(project)
    project.begin_validation()
    project.record_connectivity(
        [ob.ConnectivityTest(tenant_id=TENANT, system_id="billing", reachable=False, detail="timeout")]
    )
    assert project.state is ob.OnboardingState.VALIDATION_FAILED
    assert any("unreachable: billing" in event for _s, event in project.history)


def test_an_untested_active_system_fails_validation_rather_than_passing(project):
    # A check that was never attempted is not a check that passed.
    _configure(project)
    project.begin_validation()
    project.record_connectivity([])
    assert project.state is ob.OnboardingState.VALIDATION_FAILED
    assert any("never tested: billing" in event for _s, event in project.history)


def test_a_denied_smoke_test_is_a_working_kernel_but_not_a_proof(project):
    _configure(project)
    project.begin_validation()
    project.record_connectivity(
        [ob.ConnectivityTest(tenant_id=TENANT, system_id="billing", reachable=True)]
    )
    project.begin_smoke_test("payment.refund")
    project.record_smoke_test(
        ob.GovernedSmokeTest(
            tenant_id=TENANT,
            capability_id="payment.refund",
            executed=False,
            decision="REQUIRE_APPROVAL",
            detail="approval not granted",
        )
    )
    assert project.state is ob.OnboardingState.SMOKE_TEST_FAILED
    assert project.is_ready is False


def test_a_failure_state_is_only_reachable_from_its_own_stage(project):
    _configure(project)
    with pytest.raises(ob.OnboardingTransitionError, match="only reachable from"):
        project._fail(ob.OnboardingState.PROOF_FAILED, "forced")


def test_a_failed_project_cannot_advance_without_a_retry(project):
    _configure(project)
    project.begin_validation()
    project.record_connectivity(
        [ob.ConnectivityTest(tenant_id=TENANT, system_id="billing", reachable=False)]
    )
    with pytest.raises(ob.OnboardingTransitionError, match="retry_from_failure"):
        project.begin_smoke_test("payment.refund")


def test_retry_discards_the_stale_results_of_the_failed_attempt(project):
    _reach_proof_pending(project)
    project.record_verification(
        ob.EvidenceVerificationResult(
            tenant_id=TENANT,
            evidence_id="dec_abc123",
            verdict=ob.VerificationVerdict.COMPLIANCE_VIOLATION,
            verified_by="npx @strixgov/verifier",
        )
    )
    assert project.state is ob.OnboardingState.PROOF_FAILED
    project.retry_from_failure(ob.OnboardingState.PROOF_PENDING)
    # The failed verdict must not linger where a later check could read it.
    assert project.verification is None
    assert project.is_ready is False


def test_retry_from_validation_failure_clears_downstream_results(project):
    _reach_proof_pending(project)
    project.state = ob.OnboardingState.VALIDATION_PENDING
    project.record_connectivity(
        [ob.ConnectivityTest(tenant_id=TENANT, system_id="billing", reachable=False)]
    )
    project.retry_from_failure(ob.OnboardingState.INTEGRATIONS_CONFIGURED)
    assert project.connectivity_tests == []
    assert project.smoke_test is None and project.verification is None


def test_retry_is_only_valid_from_a_failure_state(project):
    _configure(project)
    with pytest.raises(ob.OnboardingTransitionError, match="only valid from a failure state"):
        project.retry_from_failure(ob.OnboardingState.DRAFT)


def test_retry_cannot_jump_forward_past_the_failed_stage(project):
    _configure(project)
    project.begin_validation()
    project.record_connectivity(
        [ob.ConnectivityTest(tenant_id=TENANT, system_id="billing", reachable=False)]
    )
    with pytest.raises(ob.OnboardingTransitionError, match="cannot retry into"):
        project.retry_from_failure(ob.OnboardingState.READY)


def test_blocking_requires_a_reason_and_stops_progress(project):
    _configure(project)
    with pytest.raises(ob.OnboardingError, match="requires a reason"):
        project.block("")
    project.block("client withdrew consent for the staging refund path")
    assert project.state is ob.OnboardingState.BLOCKED
    with pytest.raises(ob.OnboardingTransitionError, match="blocked project cannot advance"):
        project.begin_validation()


def test_a_ready_project_cannot_be_blocked(project):
    _reach_proof_pending(project)
    project.record_verification(
        ob.EvidenceVerificationResult(
            tenant_id=TENANT,
            evidence_id="dec_abc123",
            verdict=ob.VerificationVerdict.VERIFIED,
            verified_by="verifier",
        )
    )
    with pytest.raises(ob.OnboardingTransitionError, match="already reached READY"):
        project.block("too late")


# ---------------------------------------------------------------------------
# Configuration coherence.
# ---------------------------------------------------------------------------


def test_a_high_risk_capability_may_not_be_set_to_auto_execute(project):
    _configure(project, risk=ob.RiskTier.CRITICAL, approval=ob.ApprovalMode.AUTO_EXECUTE)
    gaps = project.configuration_gaps()
    assert any("auto-execute" in g for g in gaps), gaps
    with pytest.raises(ob.OnboardingError, match="incomplete configuration"):
        project.begin_validation()


def test_a_policy_and_route_that_disagree_are_refused(project):
    project.record_organization(
        ob.ClientOrganization(tenant_id=TENANT, legal_name="Acme"),
        ob.Environment(tenant_id=TENANT, name="staging"),
    )
    project.register_system(
        ob.ExternalSystem(tenant_id=TENANT, system_id="billing", environment_name="staging")
    )
    project.define_capability(
        ob.GovernedCapability(
            tenant_id=TENANT, capability_id="payment.refund", system_id="billing"
        )
    )
    with pytest.raises(ob.OnboardingError, match="two disagreeing approval rules"):
        project.configure_policy(
            ob.PolicyAssignment(
                tenant_id=TENANT,
                capability_id="payment.refund",
                approval_mode=ob.ApprovalMode.AUTO_EXECUTE,
            ),
            ob.ApprovalRoute(
                tenant_id=TENANT,
                capability_id="payment.refund",
                mode=ob.ApprovalMode.REQUIRE_APPROVAL,
                approver_group="finance",
            ),
        )


def test_a_capability_on_an_unregistered_system_is_refused(project):
    project.record_organization(
        ob.ClientOrganization(tenant_id=TENANT, legal_name="Acme"),
        ob.Environment(tenant_id=TENANT, name="staging"),
    )
    project.register_system(
        ob.ExternalSystem(tenant_id=TENANT, system_id="billing", environment_name="staging")
    )
    with pytest.raises(ob.OnboardingError, match="unregistered system"):
        project.define_capability(
            ob.GovernedCapability(
                tenant_id=TENANT, capability_id="payment.refund", system_id="ghost"
            )
        )


def test_a_system_in_an_unregistered_environment_is_refused(project):
    project.record_organization(
        ob.ClientOrganization(tenant_id=TENANT, legal_name="Acme"),
        ob.Environment(tenant_id=TENANT, name="staging"),
    )
    with pytest.raises(ob.OnboardingError, match="not registered on this project"):
        project.register_system(
            ob.ExternalSystem(tenant_id=TENANT, system_id="x", environment_name="production")
        )


def test_capability_ids_must_match_the_existing_dotted_vocabulary():
    with pytest.raises(ob.OnboardingError, match="must be dotted"):
        ob.GovernedCapability(tenant_id=TENANT, capability_id="refund", system_id="billing")


def test_dual_approval_needs_two_approvers():
    with pytest.raises(ob.OnboardingError, match="minimum_approvals >= 2"):
        ob.ApprovalRoute(
            tenant_id=TENANT,
            capability_id="payment.refund",
            mode=ob.ApprovalMode.DUAL_APPROVAL,
            approver_group="finance",
            minimum_approvals=1,
        )


def test_production_is_derived_from_the_environment_type_not_stored_twice():
    prod = ob.Environment(tenant_id=TENANT, name="prod", environment_type=ob.EnvironmentType.PRODUCTION)
    staging = ob.Environment(tenant_id=TENANT, name="stg", environment_type=ob.EnvironmentType.STAGING)
    assert prod.is_production is True and staging.is_production is False
    assert "is_production" not in {f.name for f in dataclasses.fields(ob.Environment)}


# ---------------------------------------------------------------------------
# The secret-handling boundary.
# ---------------------------------------------------------------------------


def test_credential_binding_holds_no_secret_field():
    names = {f.name for f in dataclasses.fields(ob.CredentialBinding)}
    for forbidden in ("secret", "value", "api_key", "token", "password"):
        assert forbidden not in names


@pytest.mark.parametrize(
    "leaky",
    ["sk_live_ABC123", "sk_test_XYZ", "-----BEGIN PRIVATE KEY-----", "Bearer abc.def"],
)
def test_a_secret_value_pasted_as_a_reference_is_refused(leaky):
    with pytest.raises(ob.OnboardingError, match="looks like a secret VALUE"):
        ob.CredentialBinding(
            tenant_id=TENANT,
            system_id="billing",
            secret_ref=leaky,
            state=ob.CredentialState.REFERENCED,
        )


def test_a_bound_credential_needs_a_reference():
    with pytest.raises(ob.OnboardingError, match="needs a secret_ref"):
        ob.CredentialBinding(
            tenant_id=TENANT, system_id="billing", secret_ref="", state=ob.CredentialState.VALIDATED
        )


def test_a_connectivity_test_that_exposed_a_secret_is_not_a_valid_result():
    with pytest.raises(ob.OnboardingError, match="exposes a secret"):
        ob.ConnectivityTest(
            tenant_id=TENANT, system_id="billing", reachable=True, secret_exposed=True
        )


def test_no_secret_reference_appears_in_the_readiness_view(project):
    _reach_proof_pending(project)
    rendered = repr(project.readiness())
    assert "vault://" not in rendered, "the readiness view leaked a credential reference"


# ---------------------------------------------------------------------------
# Type-disjointness from evidence.
# ---------------------------------------------------------------------------


def test_an_onboarding_project_cannot_impersonate_an_evidence_row():
    assert ob._project_has_no_evidence_fields()
    names = {f.name for f in dataclasses.fields(ob.OnboardingProject)}
    assert not (names & {"record_hash", "chain_seq", "prev_hash"})


def test_no_onboarding_contract_declares_evidence_fields():
    # Every dataclass in the module, not just the project.
    for name in dir(ob):
        obj = getattr(ob, name)
        if not dataclasses.is_dataclass(obj) or not isinstance(obj, type):
            continue
        field_names = {f.name for f in dataclasses.fields(obj)}
        assert not (field_names & {"record_hash", "chain_seq", "prev_hash"}), name


# ---------------------------------------------------------------------------
# The console view.
# ---------------------------------------------------------------------------


def test_readiness_reports_gaps_rather_than_a_green_step(project):
    project.record_organization(
        ob.ClientOrganization(tenant_id=TENANT, legal_name="Acme"),
        ob.Environment(tenant_id=TENANT, name="staging"),
    )
    view = project.readiness()
    assert view["is_ready"] is False
    assert view["configuration_gaps"], "an unconfigured project must not look complete"
    assert view["verification_verdict"] is None
    assert "No proof claimed" in view["proof_claim"]


def test_readiness_is_tenant_scoped_and_states_the_contract(project):
    view = project.readiness()
    assert view["tenant_id"] == TENANT
    assert view["contract"] == "ONBOARD-1"


def test_history_records_every_transition(project):
    _reach_proof_pending(project)
    states = [state for state, _event in project.history]
    assert states[0] == ob.OnboardingState.DRAFT.value
    assert ob.OnboardingState.PROOF_PENDING.value in states
