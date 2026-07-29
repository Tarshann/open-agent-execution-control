#!/usr/bin/env python3
"""Strix client and system onboarding — the control-plane state machine.

Takes one organization from no configuration to its first **independently
verifiable** governed action, and refuses to describe it as ready until that
proof exists and has been checked by something other than this module.

WHERE THIS SITS
---------------
This repository is the open methodology + skills layer; the Strix Console is
the hosted commercial control plane and is not in this tree. So the onboarding
"screens" live where every other operator workflow in this repo lives — a
Claude Code skill (``SKILL.md``) driving an explicit domain model. This module
is that model: the contracts, the state machine, and the tenancy boundary.
Rendering is the skill's job; deciding is this module's.

The console is a control plane, not the execution authority. Nothing here
executes a governed action. Onboarding delegates the smoke test to the
existing decision path (``skills/strix-wire/helpers/governed_action*.py``) and
delegates verification to the existing verifier surface
(``@strixgov/verifier`` / ``strixgov-plugins/skills/verification``). This
module records *that those happened* and what they returned.

THE LOAD-BEARING RULE
---------------------
Mirrors the discipline in ``plugins/strix-personal/scripts/_vendor/lifecycle.py``
("never convert detected directly into governed"). Its onboarding form:

    **Never convert configured directly into ready.**

Configuration data — tenants, systems, capabilities, policies, activations —
cannot promote a project past ``MAX_CONFIGURED_STATE``. Every state beyond it
requires a matching out-of-band :class:`OnboardingSignal`, and ``READY``
additionally requires an independent verification verdict that actually
attests a signature. An onboarding project therefore cannot talk its way to
READY; something outside it has to have really happened.

Type-disjointness, same as ``lifecycle.py``: nothing here declares
``record_hash`` / ``chain_seq`` / ``prev_hash``, so
``dataclasses.asdict()`` on an onboarding record can never be mistaken for an
evidence row. Pinned by ``tests/test_onboarding_state.py``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, fields
from enum import Enum

CONTRACT = "ONBOARD-1"
MODEL_VERSION = "0.1.0"


# ---------------------------------------------------------------------------
# Errors — each names a distinct refusal, so callers cannot collapse them.
# ---------------------------------------------------------------------------


class OnboardingError(RuntimeError):
    """Base class for every onboarding refusal."""


class OnboardingTransitionError(OnboardingError):
    """An illegal state transition (e.g. DRAFT straight to READY)."""


class TenantIsolationError(OnboardingError):
    """An attempt to bind a record from one tenant into another's project."""


class ProofClaimError(OnboardingError):
    """A readiness or proof claim that exceeds what was actually verified."""


# ---------------------------------------------------------------------------
# States
# ---------------------------------------------------------------------------


class OnboardingState(str, Enum):
    """Where one onboarding project sits on the road to a governed action."""

    DRAFT = "draft"
    TENANT_CREATED = "tenant_created"
    SYSTEMS_REGISTERED = "systems_registered"
    CAPABILITIES_DEFINED = "capabilities_defined"
    POLICIES_CONFIGURED = "policies_configured"
    INTEGRATIONS_CONFIGURED = "integrations_configured"
    VALIDATION_PENDING = "validation_pending"
    VALIDATION_FAILED = "validation_failed"
    READY_FOR_SMOKE_TEST = "ready_for_smoke_test"
    SMOKE_TEST_RUNNING = "smoke_test_running"
    SMOKE_TEST_FAILED = "smoke_test_failed"
    PROOF_PENDING = "proof_pending"
    PROOF_FAILED = "proof_failed"
    READY = "ready"
    BLOCKED = "blocked"


#: The main progression. Failure states and BLOCKED are diversions off this
#: line, never steps along it.
_PROGRESSION: list[OnboardingState] = [
    OnboardingState.DRAFT,
    OnboardingState.TENANT_CREATED,
    OnboardingState.SYSTEMS_REGISTERED,
    OnboardingState.CAPABILITIES_DEFINED,
    OnboardingState.POLICIES_CONFIGURED,
    OnboardingState.INTEGRATIONS_CONFIGURED,
    OnboardingState.VALIDATION_PENDING,
    OnboardingState.READY_FOR_SMOKE_TEST,
    OnboardingState.SMOKE_TEST_RUNNING,
    OnboardingState.PROOF_PENDING,
    OnboardingState.READY,
]
_RANK: dict[OnboardingState, int] = {s: i for i, s in enumerate(_PROGRESSION)}

#: The furthest a project can be placed from configuration data alone. This is
#: the structural form of "never convert configured directly into ready":
#: everything past this point needs a real out-of-band signal.
MAX_CONFIGURED_STATE = OnboardingState.INTEGRATIONS_CONFIGURED

#: Which stage each failure state is the failure *of*. A failure is reached
#: only from its own stage — a validation failure cannot appear before
#: validation was attempted.
_FAILURE_OF: dict[OnboardingState, OnboardingState] = {
    OnboardingState.VALIDATION_FAILED: OnboardingState.VALIDATION_PENDING,
    OnboardingState.SMOKE_TEST_FAILED: OnboardingState.SMOKE_TEST_RUNNING,
    OnboardingState.PROOF_FAILED: OnboardingState.PROOF_PENDING,
}

#: States that may ONLY be entered with a matching, passing signal. This is
#: the barrier that stops configuration from manufacturing a "ready" verdict.
_SIGNAL_KIND_FOR: dict[OnboardingState, str] = {
    OnboardingState.READY_FOR_SMOKE_TEST: "connectivity",
    OnboardingState.PROOF_PENDING: "execution",
    OnboardingState.READY: "verification",
}

#: Minimum state a project must already hold before entering a given state, so
#: no signal lets a project leap the chain.
_MIN_PRECURSOR: dict[OnboardingState, OnboardingState] = {
    OnboardingState.READY_FOR_SMOKE_TEST: OnboardingState.VALIDATION_PENDING,
    OnboardingState.SMOKE_TEST_RUNNING: OnboardingState.READY_FOR_SMOKE_TEST,
    OnboardingState.PROOF_PENDING: OnboardingState.SMOKE_TEST_RUNNING,
    OnboardingState.READY: OnboardingState.PROOF_PENDING,
}


# ---------------------------------------------------------------------------
# Verification vocabulary — borrowed verbatim from the verifier surface
# (strixgov-plugins/skills/verification/SKILL.md), so onboarding cannot
# invent a friendlier verdict than the tool actually returns.
# ---------------------------------------------------------------------------


class VerificationVerdict(str, Enum):
    VERIFIED = "VERIFIED"
    VERIFIED_PINNED_ONLY = "VERIFIED_PINNED_ONLY"
    VERIFIED_LIVE_ONLY = "VERIFIED_LIVE_ONLY"
    VERIFIED_OFFLINE_BY_VERIFIER = "VERIFIED_OFFLINE_BY_VERIFIER"
    LEGACY_UNSIGNED = "LEGACY_UNSIGNED"
    COMPLIANCE_VIOLATION = "COMPLIANCE_VIOLATION"
    KID_NOT_FOUND = "KID_NOT_FOUND"


#: Verdicts that actually attest an Ed25519 signature over the record.
#: LEGACY_UNSIGNED is deliberately absent: it is honest about predating
#: signing, and it is NOT a failure — but a brand-new onboarding has no
#: business producing one, and it cannot support a "verifiable proof" claim.
_PROOF_BEARING_VERDICTS = frozenset(
    {
        VerificationVerdict.VERIFIED,
        VerificationVerdict.VERIFIED_PINNED_ONLY,
        VerificationVerdict.VERIFIED_LIVE_ONLY,
        VerificationVerdict.VERIFIED_OFFLINE_BY_VERIFIER,
    }
)


class EnvironmentType(str, Enum):
    """Deployment environment. ``is_production`` is derived from this, never
    supplied alongside it — two fields that can disagree will."""

    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    SANDBOX = "sandbox"

    @property
    def is_production(self) -> bool:
        return self is EnvironmentType.PRODUCTION


class CredentialState(str, Enum):
    """Where a credential is, never what it is. No field in this module ever
    holds a secret value — see :class:`CredentialBinding`."""

    ABSENT = "absent"
    REFERENCED = "referenced"
    VALIDATED = "validated"
    REJECTED = "rejected"
    REVOKED = "revoked"


class RiskTier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ApprovalMode(str, Enum):
    """How a governed capability is authorized."""

    AUTO_EXECUTE = "auto_execute"
    REQUIRE_APPROVAL = "require_approval"
    DUAL_APPROVAL = "dual_approval"
    DENY = "deny"


class IntegrationType(str, Enum):
    HTTP_API = "http_api"
    DATABASE = "database"
    MESSAGE_QUEUE = "message_queue"
    OBJECT_STORAGE = "object_storage"
    MCP_SERVER = "mcp_server"
    CUSTOM_ADAPTER = "custom_adapter"


# ---------------------------------------------------------------------------
# Tenancy — the boundary every other record hangs off.
# ---------------------------------------------------------------------------

_SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")


@dataclass(frozen=True)
class OperatorContext:
    """Trusted, server-side-derived request context.

    The tenant a project belongs to is read from HERE and nowhere else. A
    client-supplied tenant id is never honoured: :func:`start_onboarding`
    takes no tenant argument, so there is no parameter for an attacker to
    populate. Cross-tenant access, where an operator legitimately holds it, is
    explicit (:attr:`admin_scope`) and always recorded in the project's
    history — never silent.
    """

    operator_id: str
    tenant_id: str
    admin_scope: bool = False

    def __post_init__(self) -> None:
        if not self.operator_id:
            raise TenantIsolationError("operator context requires an operator_id")
        if not _SLUG.match(self.tenant_id or ""):
            raise TenantIsolationError(
                f"tenant_id {self.tenant_id!r} is not a valid tenant slug; the "
                "tenant must come from trusted server-side context"
            )


@dataclass(frozen=True)
class Tenant:
    """An existing Strix tenancy boundary. Onboarding selects or creates one;
    it does not define a second tenant model."""

    tenant_id: str
    display_name: str

    def __post_init__(self) -> None:
        if not _SLUG.match(self.tenant_id or ""):
            raise TenantIsolationError(f"invalid tenant_id: {self.tenant_id!r}")


@dataclass(frozen=True)
class TenantScoped:
    """Base for every record that must not cross a tenant boundary."""

    tenant_id: str

    def __post_init__(self) -> None:
        if not _SLUG.match(self.tenant_id or ""):
            raise TenantIsolationError(f"invalid tenant_id: {self.tenant_id!r}")


# ---------------------------------------------------------------------------
# Domain contracts
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ClientOrganization(TenantScoped):
    legal_name: str = ""
    display_name: str = ""
    primary_region: str = ""

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.legal_name:
            raise OnboardingError("client organization requires a legal_name")


@dataclass(frozen=True)
class Environment(TenantScoped):
    name: str = ""
    environment_type: EnvironmentType = EnvironmentType.SANDBOX

    @property
    def is_production(self) -> bool:
        return self.environment_type.is_production


@dataclass(frozen=True)
class ExternalSystem(TenantScoped):
    """A system Strix will govern actions against."""

    system_id: str = ""
    display_name: str = ""
    integration_type: IntegrationType = IntegrationType.HTTP_API
    environment_name: str = ""


@dataclass(frozen=True)
class GovernedCapability(TenantScoped):
    """One action Strix will govern, on one system.

    ``capability_id`` uses the same dotted vocabulary as the rest of the repo
    (``payment.charge``, ``database.delete``, ``ai.tool_use``, ...), so a
    capability defined here is addressable by the existing helpers and scanner
    without translation.
    """

    capability_id: str = ""
    system_id: str = ""
    risk_tier: RiskTier = RiskTier.HIGH
    reversible: bool = False

    def __post_init__(self) -> None:
        super().__post_init__()
        if "." not in (self.capability_id or ""):
            raise OnboardingError(
                f"capability_id {self.capability_id!r} must be dotted "
                "(e.g. 'payment.charge') to match the existing capability "
                "vocabulary"
            )


@dataclass(frozen=True)
class ApprovalRoute(TenantScoped):
    """Who must approve, and how many of them."""

    capability_id: str = ""
    mode: ApprovalMode = ApprovalMode.REQUIRE_APPROVAL
    approver_group: str = ""
    minimum_approvals: int = 1

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.mode in (ApprovalMode.REQUIRE_APPROVAL, ApprovalMode.DUAL_APPROVAL):
            if not self.approver_group:
                raise OnboardingError(
                    f"{self.capability_id}: {self.mode.value} needs an approver_group"
                )
        if self.mode is ApprovalMode.DUAL_APPROVAL and self.minimum_approvals < 2:
            raise OnboardingError(
                f"{self.capability_id}: dual approval needs minimum_approvals >= 2"
            )


@dataclass(frozen=True)
class PolicyAssignment(TenantScoped):
    """Binds a capability to a risk tier and an approval route."""

    capability_id: str = ""
    risk_tier: RiskTier = RiskTier.HIGH
    approval_mode: ApprovalMode = ApprovalMode.REQUIRE_APPROVAL
    policy_ref: str = ""


@dataclass(frozen=True)
class CredentialBinding(TenantScoped):
    """A *reference* to a secret held by the approved secret-handling boundary.

    There is deliberately no field for the secret itself. Onboarding records
    where a credential lives and whether it validated; the value never enters
    this model, is never logged, and never reaches an onboarding report.
    """

    system_id: str = ""
    secret_ref: str = ""
    state: CredentialState = CredentialState.ABSENT

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.state is not CredentialState.ABSENT and not self.secret_ref:
            raise OnboardingError(
                f"{self.system_id}: a credential past ABSENT needs a secret_ref "
                "pointing at the secret store"
            )
        looks_like_secret = any(
            marker in (self.secret_ref or "")
            for marker in ("sk_live_", "sk_test_", "-----BEGIN", "Bearer ")
        )
        if looks_like_secret:
            raise OnboardingError(
                f"{self.system_id}: secret_ref looks like a secret VALUE, not a "
                "reference. Store the secret in the secret boundary and record "
                "its reference here."
            )


@dataclass(frozen=True)
class IntegrationActivation(TenantScoped):
    """An adapter turned on for one system, with its credential binding."""

    system_id: str = ""
    integration_type: IntegrationType = IntegrationType.HTTP_API
    adapter_ref: str = ""
    active: bool = False


@dataclass(frozen=True)
class ConnectivityTest(TenantScoped):
    """The result of reaching a system without exposing its secret."""

    system_id: str = ""
    reachable: bool = False
    detail: str = ""
    secret_exposed: bool = False

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.secret_exposed:
            raise OnboardingError(
                f"{self.system_id}: a connectivity test that exposes a secret is "
                "not a valid test result"
            )


@dataclass(frozen=True)
class GovernedSmokeTest(TenantScoped):
    """One governed action run through the REAL decision path.

    ``decision`` and ``evidence_id`` are whatever the existing helper returned.
    Onboarding never synthesizes either: an ``executed`` smoke test with no
    ``evidence_id`` is rejected, because a run that produced no record cannot
    support a proof claim.
    """

    capability_id: str = ""
    executed: bool = False
    decision: str = ""
    evidence_id: str | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.executed and not self.evidence_id:
            raise ProofClaimError(
                f"{self.capability_id}: smoke test reports executed=True with no "
                "evidence_id — a run with no record cannot be claimed as proof"
            )


@dataclass(frozen=True)
class EvidenceVerificationResult(TenantScoped):
    """An INDEPENDENT check of the smoke test's record.

    ``verified_by`` names the tool that produced the verdict (e.g.
    ``npx @strixgov/verifier``). ``is_proof_bearing`` is derived from the
    verdict vocabulary, so onboarding cannot upgrade LEGACY_UNSIGNED or a
    COMPLIANCE_VIOLATION into a passing proof.
    """

    evidence_id: str = ""
    verdict: VerificationVerdict = VerificationVerdict.KID_NOT_FOUND
    verified_by: str = ""

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.evidence_id:
            raise ProofClaimError("a verification result needs an evidence_id")
        if not self.verified_by:
            raise ProofClaimError(
                "a verification result must name the tool that produced it; an "
                "unattributed verdict is not independent verification"
            )

    @property
    def is_proof_bearing(self) -> bool:
        return self.verdict in _PROOF_BEARING_VERDICTS


# ---------------------------------------------------------------------------
# Signals — the out-of-band facts that justify leaving the configured states.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OnboardingSignal:
    """A fact from outside this module that justifies a promotion.

    ``kind`` is one of ``"connectivity"`` (every activated system was reached),
    ``"execution"`` (the governed smoke test actually ran through the decision
    path), or ``"verification"`` (an independent verifier checked the record).
    """

    kind: str
    passed: bool = True
    evidence_id: str | None = None
    detail: str = ""


# ---------------------------------------------------------------------------
# The project
# ---------------------------------------------------------------------------


@dataclass
class OnboardingProject:
    """One client's journey from no configuration to a verified governed action.

    Deliberately NOT evidence-shaped: no ``record_hash`` / ``chain_seq`` /
    ``prev_hash`` field, so this can never be mistaken for an authoritative
    evidence row. Pinned by ``tests/test_onboarding_state.py``.
    """

    project_id: str
    tenant: Tenant
    operator_id: str
    state: OnboardingState = OnboardingState.DRAFT
    organization: ClientOrganization | None = None
    environments: list[Environment] = field(default_factory=list)
    systems: list[ExternalSystem] = field(default_factory=list)
    capabilities: list[GovernedCapability] = field(default_factory=list)
    policies: list[PolicyAssignment] = field(default_factory=list)
    approval_routes: list[ApprovalRoute] = field(default_factory=list)
    credentials: list[CredentialBinding] = field(default_factory=list)
    activations: list[IntegrationActivation] = field(default_factory=list)
    connectivity_tests: list[ConnectivityTest] = field(default_factory=list)
    smoke_test: GovernedSmokeTest | None = None
    verification: EvidenceVerificationResult | None = None
    history: list[tuple[str, str]] = field(default_factory=list)
    blocked_reason: str = ""

    # -- tenancy ----------------------------------------------------------

    @property
    def tenant_id(self) -> str:
        return self.tenant.tenant_id

    def _guard_tenant(self, record: TenantScoped, label: str) -> None:
        """Refuse any record from another tenant.

        This is the isolation boundary in code. A query layer must enforce the
        same rule; this check means a mis-scoped record cannot be attached even
        if a query returns it.
        """
        if record.tenant_id != self.tenant_id:
            raise TenantIsolationError(
                f"{label} belongs to tenant {record.tenant_id!r}, not "
                f"{self.tenant_id!r}; onboarding state may never reference "
                "another tenant's records"
            )

    def _note(self, event: str) -> None:
        self.history.append((self.state.value, event))

    # -- configuration (never advances past MAX_CONFIGURED_STATE) ---------

    def record_organization(self, org: ClientOrganization, env: Environment) -> None:
        self._guard_tenant(org, "client organization")
        self._guard_tenant(env, "environment")
        self.organization = org
        if env not in self.environments:
            self.environments.append(env)
        self._advance(OnboardingState.TENANT_CREATED, f"organization {org.display_name or org.legal_name}")

    def register_system(self, system: ExternalSystem) -> None:
        self._guard_tenant(system, f"system {system.system_id!r}")
        if not any(e.name == system.environment_name for e in self.environments):
            raise OnboardingError(
                f"system {system.system_id!r} names environment "
                f"{system.environment_name!r}, which is not registered on this project"
            )
        self.systems.append(system)
        self._advance(OnboardingState.SYSTEMS_REGISTERED, f"system {system.system_id}")

    def define_capability(self, capability: GovernedCapability) -> None:
        self._guard_tenant(capability, f"capability {capability.capability_id!r}")
        if not any(s.system_id == capability.system_id for s in self.systems):
            raise OnboardingError(
                f"capability {capability.capability_id!r} targets unregistered "
                f"system {capability.system_id!r}"
            )
        self.capabilities.append(capability)
        self._advance(OnboardingState.CAPABILITIES_DEFINED, f"capability {capability.capability_id}")

    def configure_policy(self, policy: PolicyAssignment, route: ApprovalRoute) -> None:
        self._guard_tenant(policy, f"policy for {policy.capability_id!r}")
        self._guard_tenant(route, f"approval route for {route.capability_id!r}")
        known = {c.capability_id for c in self.capabilities}
        for item, label in ((policy, "policy"), (route, "approval route")):
            if item.capability_id not in known:
                raise OnboardingError(
                    f"{label} references undefined capability {item.capability_id!r}"
                )
        if policy.capability_id != route.capability_id:
            raise OnboardingError(
                "a policy assignment and its approval route must cover the same "
                f"capability ({policy.capability_id!r} vs {route.capability_id!r})"
            )
        if policy.approval_mode != route.mode:
            raise OnboardingError(
                f"{policy.capability_id}: policy says {policy.approval_mode.value} "
                f"but the approval route says {route.mode.value}; a governed "
                "capability must not carry two disagreeing approval rules"
            )
        self.policies.append(policy)
        self.approval_routes.append(route)
        self._advance(OnboardingState.POLICIES_CONFIGURED, f"policy {policy.capability_id}")

    def activate_integration(
        self, activation: IntegrationActivation, credential: CredentialBinding
    ) -> None:
        self._guard_tenant(activation, f"activation for {activation.system_id!r}")
        self._guard_tenant(credential, f"credential for {credential.system_id!r}")
        if activation.system_id != credential.system_id:
            raise OnboardingError(
                "an activation and its credential binding must cover the same system"
            )
        if not any(s.system_id == activation.system_id for s in self.systems):
            raise OnboardingError(
                f"activation targets unregistered system {activation.system_id!r}"
            )
        self.activations.append(activation)
        self.credentials.append(credential)
        self._advance(
            OnboardingState.INTEGRATIONS_CONFIGURED, f"activation {activation.system_id}"
        )

    # -- validation and beyond (signal-gated) -----------------------------

    def begin_validation(self) -> None:
        """Move to VALIDATION_PENDING once configuration is complete."""
        gaps = self.configuration_gaps()
        if gaps:
            raise OnboardingError(
                "cannot begin validation with incomplete configuration: "
                + "; ".join(gaps)
            )
        self._advance(OnboardingState.VALIDATION_PENDING, "validation started")

    def record_connectivity(self, tests: list[ConnectivityTest]) -> None:
        """Attach connectivity results and resolve VALIDATION_PENDING.

        Every activated system must have been reached. A missing test is a
        failure, not a pass — an unattempted check is not a successful one.
        """
        for test in tests:
            self._guard_tenant(test, f"connectivity test for {test.system_id!r}")
        self.connectivity_tests = list(tests)

        activated = {a.system_id for a in self.activations if a.active}
        tested = {t.system_id for t in tests}
        untested = sorted(activated - tested)
        unreachable = sorted(t.system_id for t in tests if not t.reachable)

        if untested or unreachable:
            problems = []
            if unreachable:
                problems.append(f"unreachable: {', '.join(unreachable)}")
            if untested:
                problems.append(f"never tested: {', '.join(untested)}")
            self._fail(OnboardingState.VALIDATION_FAILED, "; ".join(problems))
            return

        self._advance(
            OnboardingState.READY_FOR_SMOKE_TEST,
            f"{len(tested)} system(s) reachable",
            signal=OnboardingSignal(
                kind="connectivity", passed=True, detail=f"{len(tested)} reachable"
            ),
        )

    def begin_smoke_test(self, capability_id: str) -> None:
        if not any(c.capability_id == capability_id for c in self.capabilities):
            raise OnboardingError(f"unknown capability {capability_id!r}")
        self._advance(OnboardingState.SMOKE_TEST_RUNNING, f"smoke test {capability_id}")

    def record_smoke_test(self, result: GovernedSmokeTest) -> None:
        """Attach the governed smoke test's outcome.

        A DENY or REQUIRE_APPROVAL verdict that stopped the action is a
        *working* kernel, but it is not a completed proof loop: there is no
        executed action to verify, so onboarding cannot proceed to PROOF.
        """
        self._guard_tenant(result, f"smoke test for {result.capability_id!r}")
        self.smoke_test = result
        if not result.executed:
            self._fail(
                OnboardingState.SMOKE_TEST_FAILED,
                f"decision {result.decision or 'unknown'}: {result.detail or 'action did not execute'}",
            )
            return
        self._advance(
            OnboardingState.PROOF_PENDING,
            f"executed with evidence {result.evidence_id}",
            signal=OnboardingSignal(
                kind="execution", passed=True, evidence_id=result.evidence_id
            ),
        )

    def record_verification(self, result: EvidenceVerificationResult) -> None:
        """Attach an independent verification verdict and settle readiness."""
        self._guard_tenant(result, "verification result")
        if self.smoke_test is None or not self.smoke_test.evidence_id:
            raise ProofClaimError(
                "cannot verify a proof before a smoke test produced one"
            )
        if result.evidence_id != self.smoke_test.evidence_id:
            raise ProofClaimError(
                f"verification is for evidence {result.evidence_id!r} but this "
                f"project's smoke test produced {self.smoke_test.evidence_id!r}; "
                "a proof for a different action proves nothing about this one"
            )
        self.verification = result
        if not result.is_proof_bearing:
            self._fail(
                OnboardingState.PROOF_FAILED,
                f"verdict {result.verdict.value} does not attest a signature",
            )
            return
        self._advance(
            OnboardingState.READY,
            f"{result.verdict.value} via {result.verified_by}",
            signal=OnboardingSignal(
                kind="verification", passed=True, evidence_id=result.evidence_id
            ),
        )

    # -- off-ramps --------------------------------------------------------

    def block(self, reason: str) -> None:
        """Terminal stop. Requires a reason — an unexplained block is useless
        to the operator who has to clear it."""
        if not reason:
            raise OnboardingError("blocking an onboarding project requires a reason")
        if self.state is OnboardingState.READY:
            raise OnboardingTransitionError(
                "cannot block a project that already reached READY; revoke the "
                "verified proof instead"
            )
        self.state = OnboardingState.BLOCKED
        self.blocked_reason = reason
        self._note(f"blocked: {reason}")

    def retry_from_failure(self, target: OnboardingState) -> None:
        """Re-enter the failed stage, or step back to fix configuration.

        This is the one backward move the machine allows, and only from a
        failure state: a failed validation must be able to become a passing
        one after the operator fixes the cause.
        """
        if self.state not in _FAILURE_OF:
            raise OnboardingTransitionError(
                f"retry_from_failure is only valid from a failure state, not "
                f"{self.state.value}"
            )
        failed_stage = _FAILURE_OF[self.state]
        allowed = {failed_stage} | {
            s for s in _PROGRESSION if _RANK[s] <= _RANK[MAX_CONFIGURED_STATE]
        }
        if target not in allowed:
            raise OnboardingTransitionError(
                f"cannot retry into {target.value} from {self.state.value}; "
                f"retry the failed stage ({failed_stage.value}) or step back to a "
                "configuration state to fix the cause"
            )
        previous = self.state
        self.state = target
        # Stale results must not survive a retry, or a later readiness check
        # could pass on evidence from the attempt that already failed.
        if previous is OnboardingState.PROOF_FAILED:
            self.verification = None
        if previous is OnboardingState.SMOKE_TEST_FAILED:
            self.smoke_test = None
            self.verification = None
        if previous is OnboardingState.VALIDATION_FAILED:
            self.connectivity_tests = []
            self.smoke_test = None
            self.verification = None
        self._note(f"retry from {previous.value}")

    # -- the transition rules --------------------------------------------

    def _fail(self, failure_state: OnboardingState, detail: str) -> None:
        expected_stage = _FAILURE_OF[failure_state]
        if self.state is not expected_stage:
            raise OnboardingTransitionError(
                f"{failure_state.value} is only reachable from "
                f"{expected_stage.value}, not {self.state.value}"
            )
        self.state = failure_state
        self._note(f"{failure_state.value}: {detail}")

    def _advance(
        self,
        target: OnboardingState,
        detail: str,
        *,
        signal: OnboardingSignal | None = None,
    ) -> None:
        """Advance to ``target``, enforcing every transition rule.

        Rules:
          * forward-only along the progression (no silent downgrade);
          * a state may not be re-entered as a no-op advance past its stage;
          * gated states need a matching, passing signal;
          * READY additionally needs a proof-bearing verification on file.
        """
        current = self.state
        if current is OnboardingState.BLOCKED:
            raise OnboardingTransitionError(
                "a blocked project cannot advance; clear the block first"
            )
        if current in _FAILURE_OF:
            raise OnboardingTransitionError(
                f"cannot advance from {current.value}; call retry_from_failure() "
                "after fixing the cause"
            )
        if target not in _RANK:
            raise OnboardingTransitionError(f"{target.value} is not a progression state")

        # Configuration steps are repeatable: registering a second system while
        # already at SYSTEMS_REGISTERED is normal, not a downgrade.
        if _RANK[target] == _RANK[current]:
            self._note(detail)
            return
        if _RANK[target] < _RANK[current]:
            raise OnboardingTransitionError(
                f"illegal transition {current.value} -> {target.value} "
                "(onboarding is forward-only)"
            )

        precursor = _MIN_PRECURSOR.get(target)
        if precursor is not None and _RANK[current] < _RANK[precursor]:
            raise OnboardingTransitionError(
                f"cannot reach {target.value} from {current.value}: must be at "
                f"least {precursor.value} first (no leaping the lifecycle)"
            )

        required = _SIGNAL_KIND_FOR.get(target)
        if required is not None:
            if signal is None or signal.kind != required or not signal.passed:
                raise OnboardingTransitionError(
                    f"{target.value} requires a passing {required!r} signal — "
                    "refusing to promote on configuration data alone"
                )
            if target is OnboardingState.READY:
                if self.verification is None or not self.verification.is_proof_bearing:
                    raise ProofClaimError(
                        "READY requires a proof-bearing verification verdict on file"
                    )
        self.state = target
        self._note(detail)

    # -- derived views ----------------------------------------------------

    def configuration_gaps(self) -> list[str]:
        """What is still missing before validation may begin. Derived, so the
        console cannot show a green step that no data supports."""
        gaps: list[str] = []
        if self.organization is None:
            gaps.append("no client organization recorded")
        if not self.environments:
            gaps.append("no environment recorded")
        if not self.systems:
            gaps.append("no external system registered")
        if not self.capabilities:
            gaps.append("no governed capability defined")

        covered = {p.capability_id for p in self.policies}
        for capability in self.capabilities:
            if capability.capability_id not in covered:
                gaps.append(f"capability {capability.capability_id} has no policy assignment")
            if capability.risk_tier is not RiskTier.LOW:
                route = next(
                    (r for r in self.approval_routes if r.capability_id == capability.capability_id),
                    None,
                )
                if route is not None and route.mode is ApprovalMode.AUTO_EXECUTE:
                    gaps.append(
                        f"capability {capability.capability_id} is "
                        f"{capability.risk_tier.value} risk but set to auto-execute"
                    )
        active = {a.system_id for a in self.activations if a.active}
        for system in self.systems:
            if system.system_id not in active:
                gaps.append(f"system {system.system_id} has no active integration")
        for credential in self.credentials:
            if credential.state is CredentialState.ABSENT:
                gaps.append(f"system {credential.system_id} has no credential bound")
        return gaps

    @property
    def is_ready(self) -> bool:
        """READY is derived from evidence, never asserted.

        Even if ``state`` were forced to READY, this returns False without a
        proof-bearing verification whose evidence id matches the smoke test.
        """
        if self.state is not OnboardingState.READY:
            return False
        if self.smoke_test is None or not self.smoke_test.executed:
            return False
        if self.verification is None or not self.verification.is_proof_bearing:
            return False
        return self.verification.evidence_id == self.smoke_test.evidence_id

    def proof_claim(self) -> str:
        """The only sentence the console may print about this project's proof.

        No proof claim may exceed what can be independently verified, so this
        is derived from the verification result rather than from the state
        label.
        """
        if self.verification is None:
            return "No proof claimed: no evidence has been independently verified."
        verdict = self.verification.verdict
        if not self.verification.is_proof_bearing:
            return (
                f"Not proven: {self.verification.verified_by} returned "
                f"{verdict.value} for evidence {self.verification.evidence_id}."
            )
        return (
            f"{verdict.value}: evidence {self.verification.evidence_id} was "
            f"independently checked by {self.verification.verified_by}. This "
            "attests that the record is signed and unmodified — not that the "
            "governed system is secure or compliant."
        )

    def readiness(self) -> dict:
        """A truthful console view. Every field is derived from records held."""
        return {
            "contract": CONTRACT,
            "model_version": MODEL_VERSION,
            "project_id": self.project_id,
            "tenant_id": self.tenant_id,
            "state": self.state.value,
            "is_ready": self.is_ready,
            "configuration_gaps": self.configuration_gaps(),
            "systems": len(self.systems),
            "capabilities": len(self.capabilities),
            "active_integrations": sum(1 for a in self.activations if a.active),
            "smoke_test_evidence_id": (
                self.smoke_test.evidence_id if self.smoke_test else None
            ),
            "verification_verdict": (
                self.verification.verdict.value if self.verification else None
            ),
            "proof_claim": self.proof_claim(),
            "blocked_reason": self.blocked_reason or None,
        }


def start_onboarding(
    context: OperatorContext, project_id: str, tenant_display_name: str = ""
) -> OnboardingProject:
    """Open a project for the tenant in the operator's trusted context.

    Note the signature: there is no ``tenant_id`` parameter. The tenant is
    taken from ``context``, so a client cannot submit an arbitrary tenant id to
    reach another tenant's data — the parameter simply does not exist.
    """
    if not project_id:
        raise OnboardingError("an onboarding project requires a project_id")
    tenant = Tenant(
        tenant_id=context.tenant_id,
        display_name=tenant_display_name or context.tenant_id,
    )
    project = OnboardingProject(
        project_id=project_id, tenant=tenant, operator_id=context.operator_id
    )
    opened = f"opened by {context.operator_id}"
    if context.admin_scope:
        # Cross-tenant capability is explicit and auditable, never silent.
        opened += " (admin scope)"
    project.history.append((OnboardingState.DRAFT.value, opened))
    return project


def _project_has_no_evidence_fields() -> bool:
    """True if OnboardingProject cannot impersonate an evidence row."""
    names = {f.name for f in fields(OnboardingProject)}
    return not (names & {"record_hash", "chain_seq", "prev_hash"})


__all__ = [
    "CONTRACT",
    "MODEL_VERSION",
    "MAX_CONFIGURED_STATE",
    "ApprovalMode",
    "ApprovalRoute",
    "ClientOrganization",
    "ConnectivityTest",
    "CredentialBinding",
    "CredentialState",
    "Environment",
    "EnvironmentType",
    "EvidenceVerificationResult",
    "ExternalSystem",
    "GovernedCapability",
    "GovernedSmokeTest",
    "IntegrationActivation",
    "IntegrationType",
    "OnboardingError",
    "OnboardingProject",
    "OnboardingSignal",
    "OnboardingState",
    "OnboardingTransitionError",
    "OperatorContext",
    "PolicyAssignment",
    "ProofClaimError",
    "RiskTier",
    "Tenant",
    "TenantIsolationError",
    "TenantScoped",
    "VerificationVerdict",
    "start_onboarding",
]
