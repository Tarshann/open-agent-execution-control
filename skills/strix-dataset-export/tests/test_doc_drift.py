"""Doc-drift checks: the non-claims and field names documented in
SKILL.md/README.md/ARCHITECTURE.md must stay literally true of the code, not
just true when they were written. Pattern borrowed from
skills/strix-onboard/tests/test_skill_contract.py.
"""

from __future__ import annotations

import inspect
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parents[1]


def _read(name: str) -> str:
    return (SKILL_DIR / name).read_text(encoding="utf-8")


def test_completeness_claim_constant_matches_the_literal_documented_everywhere(core_mod):
    assert core_mod.COMPLETENESS_CLAIM == "NOT_PROVEN"
    skill_md = _read("SKILL.md")
    architecture_md = _read("ARCHITECTURE.md")
    assert 'completeness: "NOT_PROVEN"' in skill_md
    assert 'completeness: "NOT_PROVEN"' in architecture_md


def test_the_safe_harbor_non_claim_is_pinned_in_code_and_in_docs(core_mod):
    source = inspect.getsource(core_mod._apply_safe_harbor_v1)
    non_claim = "does NOT implement, certify, or claim conformance with the HIPAA"
    assert non_claim in source

    skill_md = _read("SKILL.md")
    readme = _read("README.md")
    architecture_md = _read("ARCHITECTURE.md")
    assert "not a certification" in skill_md.lower()
    assert "de-identification" in readme.lower()
    assert "does not implement, certify, or claim conformance" in architecture_md.lower()


def test_the_headline_claim_is_identical_in_skill_and_readme():
    claim = (
        "> Strix can refuse a protected-content transfer to an external destination\n"
        "> before it executes, and leave a verifiable record of exactly what was\n"
        "> barred and why."
    )
    skill_md = _read("SKILL.md")
    readme = _read("README.md")
    assert claim in skill_md
    assert claim in readme


def test_every_exception_class_documented_in_skill_md_is_a_real_exception(core_mod):
    skill_md = _read("SKILL.md")
    documented = [
        "StrixDatasetExportPolicyDenied",
        "StrixDatasetExportApprovalRequired",
        "StrixDatasetExportSelfApprovalDenied",
        "StrixDatasetExportTokenMissing",
        "StrixDatasetExportTokenExpired",
        "StrixDatasetExportTokenAlreadyRedeemed",
        "StrixDatasetExportTokenBindingMismatch",
        "StrixDatasetExportKeyError",
        "StrixDatasetExportReceiptPersistenceError",
    ]
    for name in documented:
        assert f"`{name}`" in skill_md, f"{name} is documented in SKILL.md's failure-modes list"
        cls = getattr(core_mod, name)
        assert issubclass(cls, core_mod.StrixDatasetExportError)

    # And the reverse: every concrete error subclass the module defines is
    # documented somewhere in SKILL.md's failure-modes list, so a new
    # exception class can't be added without a matching doc update.
    for name, obj in vars(core_mod).items():
        if (
            isinstance(obj, type)
            and issubclass(obj, core_mod.StrixDatasetExportError)
            and obj is not core_mod.StrixDatasetExportError
        ):
            assert f"`{name}`" in skill_md, f"{name} is a real exception class missing from SKILL.md"


def test_the_not_protected_classification_allowlist_matches_the_architecture_note(core_mod):
    assert core_mod.NOT_PROTECTED_CLASSIFICATIONS == frozenset({"INTERNAL_AGGREGATE"})
    architecture_md = _read("ARCHITECTURE.md")
    assert "INTERNAL_AGGREGATE" in architecture_md


def test_the_gate_report_honestly_disclaims_a_canonical_local_template(core_mod):
    gate_report = _read("GATE-REPORT.md")
    normalized = " ".join(gate_report.lower().replace("**", "").split())
    assert "no canonical local template" in normalized
    assert "not a citation of" in normalized
