"""SKILL.md must stay honest about what the code actually does.

The strix-wire suite learned this the hard way: prose drifts from behaviour, and
a skill document that overstates its guarantees is worse than one that says
nothing. These tests couple the document to the model.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parents[1]
SKILL_MD = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
ONBOARDING_SRC = (SKILL_DIR / "onboarding.py").read_text(encoding="utf-8")
STATUS_SRC = (SKILL_DIR / "status.py").read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"^\s*>\s?", "", text, flags=re.M))


FLAT = _flat(SKILL_MD)


def _load():
    spec = importlib.util.spec_from_file_location(
        "strix_onboarding_contract_test", SKILL_DIR / "onboarding.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ob = _load()


# ---------------------------------------------------------------------------
# The document's claims match the model.
# ---------------------------------------------------------------------------


def test_every_state_in_the_model_is_a_real_enum_member():
    # The brief's state list, verbatim. Drift here means the console and the
    # model disagree about what states exist.
    expected = {
        "DRAFT",
        "TENANT_CREATED",
        "SYSTEMS_REGISTERED",
        "CAPABILITIES_DEFINED",
        "POLICIES_CONFIGURED",
        "INTEGRATIONS_CONFIGURED",
        "VALIDATION_PENDING",
        "VALIDATION_FAILED",
        "READY_FOR_SMOKE_TEST",
        "SMOKE_TEST_RUNNING",
        "SMOKE_TEST_FAILED",
        "PROOF_PENDING",
        "PROOF_FAILED",
        "READY",
        "BLOCKED",
    }
    assert {s.name for s in ob.OnboardingState} == expected


def test_the_documented_load_bearing_rule_is_the_implemented_one():
    assert "Never convert configured directly into ready" in SKILL_MD
    assert ob.MAX_CONFIGURED_STATE is ob.OnboardingState.INTEGRATIONS_CONFIGURED
    assert "MAX_CONFIGURED_STATE" in SKILL_MD


def test_the_documented_gated_states_are_the_gated_states():
    # SKILL.md promises validation, execution and proof each need a real signal.
    assert set(ob._SIGNAL_KIND_FOR) == {
        ob.OnboardingState.READY_FOR_SMOKE_TEST,
        ob.OnboardingState.PROOF_PENDING,
        ob.OnboardingState.READY,
    }
    assert set(ob._SIGNAL_KIND_FOR.values()) == {"connectivity", "execution", "verification"}


def test_the_verdict_table_matches_the_verification_vocabulary():
    # Every verdict the document tabulates must exist in the enum, and every
    # enum member must appear in the document — no silent third category.
    for verdict in ob.VerificationVerdict:
        assert verdict.value in SKILL_MD, f"{verdict.value} is undocumented"
    documented = set(re.findall(r"`(VERIFIED[A-Z_]*|LEGACY_UNSIGNED|COMPLIANCE_VIOLATION|KID_NOT_FOUND)`", SKILL_MD))
    known = {v.value for v in ob.VerificationVerdict}
    assert documented <= known, f"documented verdicts not in the model: {documented - known}"


def test_the_documented_proof_bearing_set_matches_the_model():
    proof_bearing = {v.value for v in ob._PROOF_BEARING_VERDICTS}
    assert proof_bearing == {
        "VERIFIED",
        "VERIFIED_PINNED_ONLY",
        "VERIFIED_LIVE_ONLY",
        "VERIFIED_OFFLINE_BY_VERIFIER",
    }
    # LEGACY_UNSIGNED must be documented as NOT reaching READY.
    assert ob.VerificationVerdict.LEGACY_UNSIGNED not in ob._PROOF_BEARING_VERDICTS
    assert "has no business producing one" in FLAT


def test_start_onboarding_is_documented_as_taking_no_tenant_argument():
    import inspect

    assert "tenant_id" not in inspect.signature(ob.start_onboarding).parameters
    assert "no `tenant_id` parameter" in SKILL_MD


def test_readiness_is_documented_as_derived():
    assert "derived" in FLAT
    assert "there is no such call" in FLAT.lower()
    # And there really is no setter.
    assert not hasattr(ob.OnboardingProject, "mark_ready")
    assert not hasattr(ob.OnboardingProject, "set_ready")


# ---------------------------------------------------------------------------
# The document does not authorize a bypass.
# ---------------------------------------------------------------------------


def test_the_smoke_test_is_the_only_approval_gate_documented():
    assert "RUN GOVERNED SMOKE TEST" in SKILL_MD
    assert "Never ask for a blanket" in SKILL_MD
    # A refused action must be reported, never worked around.
    assert "Do not retry with weaker inputs" in FLAT
    assert "working kernel, not a broken onboarding" in FLAT


def test_the_document_forbids_synthesizing_a_decision_or_evidence_id():
    assert "Never synthesize a decision or an evidence id" in SKILL_MD


def test_the_document_forbids_marking_ready_without_a_verified_proof():
    assert "refuse to mark ready" in FLAT
    assert "legitimate, honest terminal state" in FLAT


def test_the_document_delegates_execution_and_verification():
    # Onboarding is a control plane, not the execution authority.
    assert "not the execution authority" in FLAT
    for delegate in ("governed_action.py", "governed_action_local.py", "@strixgov/verifier"):
        assert delegate in SKILL_MD
    assert "Render proof, never upgrade it" in SKILL_MD


def test_the_per_run_approval_caveat_travels_with_the_offline_helper():
    # The same limitation strix-wire documents must not be dropped here.
    assert "STRIX_WIRE_RUN_APPROVED=1" in SKILL_MD
    assert "never exported in a profile" in FLAT


# ---------------------------------------------------------------------------
# The model and the read-only surface have no execution capability.
# ---------------------------------------------------------------------------

FORBIDDEN = [
    "subprocess",
    "os.system",
    "os.popen",
    "socket",
    "urllib",
    "requests",
    "httpx",
    "eval(",
    "write_text",
    "write_bytes",
    ".unlink(",
    ".mkdir(",
    ".chmod(",
]


def test_the_onboarding_model_has_no_execution_or_network_primitive():
    import io
    import tokenize

    for name, src in (("onboarding.py", ONBOARDING_SRC), ("status.py", STATUS_SRC)):
        kept = []
        for tok in tokenize.generate_tokens(io.StringIO(src).readline):
            if tok.type in (tokenize.COMMENT, tokenize.STRING):
                continue
            if tok.string.strip():
                kept.append(tok.string)
        code = " ".join(kept).replace(" . ", ".").replace(" (", "(")
        for token in FORBIDDEN:
            assert token not in code, f"{name} contains {token!r}"


def test_the_readiness_surface_only_ever_opens_files_read_only():
    import ast

    tree = ast.parse(STATUS_SRC)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        is_open = (isinstance(func, ast.Name) and func.id == "open") or (
            isinstance(func, ast.Attribute) and func.attr in ("open", "write_text")
        )
        if is_open:
            assert func.attr != "write_text" if isinstance(func, ast.Attribute) else True
            modes = list(node.args[1:2]) + [k.value for k in node.keywords if k.arg == "mode"]
            for mode in modes:
                assert isinstance(mode, ast.Constant)
                assert not set(mode.value) & set("wax+")
