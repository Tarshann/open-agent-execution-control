"""The console view must be truthful, inert, and leak nothing.

An operator reads this to decide whether a client is live. Three ways it could
lie, each tested here:

  - a step that failed rendering as done (or merely as not-yet-started);
  - a project rendering as READY without a verified proof behind it;
  - a credential reference or a control sequence reaching the operator's screen.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

_SKILL_DIR = Path(__file__).resolve().parents[1]


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, _SKILL_DIR / filename)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ob = _load("strix_onboarding_model_view_test", "onboarding.py")
st = _load("strix_onboarding_status_test", "status.py")

T = "acme-eu"


def _project(project_id: str = "onb_1"):
    return ob.start_onboarding(
        ob.OperatorContext(operator_id="op", tenant_id=T), project_id, "Acme EU"
    )


def _configure(project):
    project.record_organization(
        ob.ClientOrganization(tenant_id=T, legal_name="Acme GmbH", display_name="Acme"),
        ob.Environment(tenant_id=T, name="staging", environment_type=ob.EnvironmentType.STAGING),
    )
    project.register_system(
        ob.ExternalSystem(tenant_id=T, system_id="billing", environment_name="staging")
    )
    project.define_capability(
        ob.GovernedCapability(tenant_id=T, capability_id="payment.refund", system_id="billing")
    )
    project.configure_policy(
        ob.PolicyAssignment(tenant_id=T, capability_id="payment.refund"),
        ob.ApprovalRoute(tenant_id=T, capability_id="payment.refund", approver_group="finance"),
    )
    project.activate_integration(
        ob.IntegrationActivation(tenant_id=T, system_id="billing", active=True),
        ob.CredentialBinding(
            tenant_id=T,
            system_id="billing",
            secret_ref="vault://acme-eu/billing/api-key",
            state=ob.CredentialState.VALIDATED,
        ),
    )
    return project


def _validated(project):
    _configure(project)
    project.begin_validation()
    project.record_connectivity(
        [ob.ConnectivityTest(tenant_id=T, system_id="billing", reachable=True)]
    )
    return project


def _executed(project):
    _validated(project)
    project.begin_smoke_test("payment.refund")
    project.record_smoke_test(
        ob.GovernedSmokeTest(
            tenant_id=T,
            capability_id="payment.refund",
            executed=True,
            decision="REQUIRE_APPROVAL_GRANTED",
            evidence_id="dec_abc123",
        )
    )
    return project


def _step_marks(rendered: str) -> dict[str, str]:
    marks = {}
    for line in rendered.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            mark, _, label = stripped[1:].partition("]")
            marks[label.strip()] = mark.strip()
    return marks


# ---------------------------------------------------------------------------
# A failed step must read as failed.
# ---------------------------------------------------------------------------


def test_a_failed_validation_marks_the_validation_step_failed():
    project = _configure(_project())
    project.begin_validation()
    project.record_connectivity(
        [ob.ConnectivityTest(tenant_id=T, system_id="billing", reachable=False, detail="timeout")]
    )
    marks = _step_marks(st.render(project.readiness(), ob))
    assert marks["Validate integration"] == "FAIL", marks
    assert marks["Connect credentials and adapters"] == "done"
    assert marks["Run governed smoke test"] == "--"
    assert marks["Verify evidence independently"] == "--"


def test_a_failed_smoke_test_marks_the_smoke_test_step_failed():
    project = _validated(_project())
    project.begin_smoke_test("payment.refund")
    project.record_smoke_test(
        ob.GovernedSmokeTest(
            tenant_id=T,
            capability_id="payment.refund",
            executed=False,
            decision="DENY",
            detail="policy denied",
        )
    )
    marks = _step_marks(st.render(project.readiness(), ob))
    assert marks["Run governed smoke test"] == "FAIL", marks
    assert marks["Validate integration"] == "done"
    assert marks["Verify evidence independently"] == "--"


def test_a_failed_proof_marks_the_verification_step_failed():
    project = _executed(_project())
    project.record_verification(
        ob.EvidenceVerificationResult(
            tenant_id=T,
            evidence_id="dec_abc123",
            verdict=ob.VerificationVerdict.COMPLIANCE_VIOLATION,
            verified_by="npx @strixgov/verifier",
        )
    )
    marks = _step_marks(st.render(project.readiness(), ob))
    assert marks["Verify evidence independently"] == "FAIL", marks
    assert marks["Run governed smoke test"] == "done"
    assert "READY       no" in st.render(project.readiness(), ob)


def test_no_step_reads_done_beyond_the_projects_actual_state():
    project = _configure(_project())
    marks = _step_marks(st.render(project.readiness(), ob))
    assert marks["Connect credentials and adapters"] == "done"
    for later in ("Validate integration", "Run governed smoke test", "Verify evidence independently"):
        assert marks[later] == "--", f"{later} claimed progress the project has not made"


def test_the_happy_path_renders_every_step_done_and_ready_yes():
    project = _executed(_project())
    project.record_verification(
        ob.EvidenceVerificationResult(
            tenant_id=T,
            evidence_id="dec_abc123",
            verdict=ob.VerificationVerdict.VERIFIED,
            verified_by="npx @strixgov/verifier",
        )
    )
    rendered = st.render(project.readiness(), ob)
    assert all(mark == "done" for mark in _step_marks(rendered).values())
    assert "READY       yes" in rendered
    assert "dec_abc123" in rendered and "VERIFIED" in rendered


# ---------------------------------------------------------------------------
# Readiness cannot be faked in the view.
# ---------------------------------------------------------------------------


def test_a_forced_ready_state_still_renders_ready_no():
    project = _configure(_project())
    project.state = ob.OnboardingState.READY  # tampered label, no proof on file
    rendered = st.render(project.readiness(), ob)
    assert "READY       no" in rendered, rendered
    assert "No proof claimed" in rendered


def test_gaps_and_block_reasons_are_surfaced():
    project = _project()
    project.record_organization(
        ob.ClientOrganization(tenant_id=T, legal_name="Acme"),
        ob.Environment(tenant_id=T, name="staging"),
    )
    rendered = st.render(project.readiness(), ob)
    assert "GAP" in rendered
    project.block("client withdrew consent")
    assert "BLOCKED     client withdrew consent" in st.render(project.readiness(), ob)


# ---------------------------------------------------------------------------
# The view is inert and leaks nothing.
# ---------------------------------------------------------------------------


def test_the_view_never_prints_a_credential_reference():
    project = _executed(_project())
    rendered = st.render(project.readiness(), ob)
    assert "vault://" not in rendered
    assert "api-key" not in rendered


def test_operator_supplied_text_cannot_forge_the_view():
    esc = "\x1b"
    project = _project()
    project.record_organization(
        ob.ClientOrganization(
            tenant_id=T,
            legal_name=f"Acme{esc}[2K\r  [done]  Verify evidence independently",
            display_name="Acme",
        ),
        ob.Environment(tenant_id=T, name="staging"),
    )
    project.block(f"reason{esc}[2K\r  READY       yes")
    rendered = st.render(project.readiness(), ob)
    assert esc not in rendered and "\r" not in rendered
    # The forged lines must not have materialized: the real READY field still
    # reads "no", and the column mimicry is collapsed so injected text cannot
    # pass for a status line.
    ready_lines = [ln for ln in rendered.splitlines() if ln.strip().startswith("READY")]
    assert ready_lines == ["  READY       no"], ready_lines
    assert "READY       yes" not in rendered
    assert _step_marks(rendered)["Verify evidence independently"] == "--"


def test_safe_reduces_to_printable_ascii():
    assert st._safe("a\tb\nc") == "a b c"
    assert st._safe("café") == "caf?"
    assert st._safe("x" * 200).endswith("...")


# ---------------------------------------------------------------------------
# CLI behaviour.
# ---------------------------------------------------------------------------


def test_cli_demo_renders_and_exits_zero(capsys):
    assert st.main(["--demo"]) == 0
    out = capsys.readouterr().out
    assert "STRIX ONBOARDING -- READINESS" in out
    assert "READY       no" in out


def test_cli_json_emits_the_raw_view(capsys):
    assert st.main(["--demo", "--json"]) == 0
    view = json.loads(capsys.readouterr().out)
    assert view["contract"] == "ONBOARD-1"
    assert view["is_ready"] is False


def test_cli_rejects_a_missing_record(tmp_path, capsys):
    assert st.main(["--project", str(tmp_path / "nope.json")]) == 2
    assert "no project record" in capsys.readouterr().err


def test_cli_rejects_a_file_that_is_not_a_readiness_record(tmp_path, capsys):
    path = tmp_path / "other.json"
    path.write_text(json.dumps({"hello": "world"}))
    assert st.main(["--project", str(path)]) == 2
    assert "not an onboarding readiness record" in capsys.readouterr().err


def test_cli_round_trips_a_stored_record(tmp_path, capsys):
    project = _executed(_project())
    project.record_verification(
        ob.EvidenceVerificationResult(
            tenant_id=T,
            evidence_id="dec_abc123",
            verdict=ob.VerificationVerdict.VERIFIED,
            verified_by="npx @strixgov/verifier",
        )
    )
    path = tmp_path / "onboarding.json"
    path.write_text(json.dumps(project.readiness()))
    assert st.main(["--project", str(path)]) == 0
    out = capsys.readouterr().out
    assert "READY       yes" in out
    assert "acme-eu" in out
