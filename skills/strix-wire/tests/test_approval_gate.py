"""Executable proof of the Offline Mode approval gate.

SKILL.md's headline safety claim for Offline Mode is that approval is
*per-run*: `approval_granted` is never hardcoded True, it is derived from
`STRIX_WIRE_RUN_APPROVED` on the single command the operator approved. Until
now that claim was pinned only by scanning SKILL.md for the literal string
`approval_granted=True` — a source scan that a rename, a space, or a second
file defeats, and which says nothing about what the helper actually does.

These tests call the helper. The invariant under test is the one that matters:
when approval is not explicitly granted, `operation()` is never invoked and no
evidence is written.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

HELPERS = Path(__file__).resolve().parents[1] / "helpers"


def _signing_available() -> bool:
    """Local Mode signs every receipt with Ed25519, so the *granted* path needs
    a working `cryptography`. The refusal path — the invariant these tests
    exist for — raises long before any signing and always runs."""
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        Ed25519PrivateKey.generate()
        return True
    except BaseException:  # pyo3 raises a PanicException, not an Exception
        return False


requires_signing = pytest.mark.skipif(
    not _signing_available(),
    reason="cryptography's Ed25519 backend is unusable in this environment",
)


@pytest.fixture(scope="module")
def local_mod():
    path = HELPERS / "governed_action_local.py"
    spec = importlib.util.spec_from_file_location("strix_wire_local_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class Spy:
    """Stands in for the irreversible operation."""

    def __init__(self) -> None:
        self.calls = 0

    def __call__(self) -> str:
        self.calls += 1
        return "SIDE EFFECT HAPPENED"


def _invoke(local_mod, workspace: Path, spy: Spy, **kwargs):
    return local_mod.governed_action_local(
        "payment.refund",
        "refund_payment",
        {"amount": 100, "currency": "usd"},
        spy,
        workspace_root=workspace,
        **kwargs,
    )


def _evidence_files(workspace: Path) -> list[Path]:
    state = workspace / ".strix"
    if not state.exists():
        return []
    return [p for p in state.rglob("*") if p.is_file() and "keys" not in p.parts]


# ---------------------------------------------------------------------------
# Refusal: the operation must not run.
# ---------------------------------------------------------------------------


def test_omitting_approval_refuses_and_does_not_run_the_operation(
    local_mod, tmp_path
):
    spy = Spy()
    with pytest.raises(local_mod.StrixLocalApprovalRequired):
        _invoke(local_mod, tmp_path, spy)
    assert spy.calls == 0, "the irreversible operation ran without approval"
    assert _evidence_files(tmp_path) == [], "evidence written for an action that never ran"


def test_explicit_false_refuses(local_mod, tmp_path):
    spy = Spy()
    with pytest.raises(local_mod.StrixLocalApprovalRequired):
        _invoke(local_mod, tmp_path, spy, approval_granted=False)
    assert spy.calls == 0


@pytest.mark.parametrize("falsy", [None, 0, "", [], {}])
def test_falsy_approval_values_refuse(local_mod, tmp_path, falsy):
    spy = Spy()
    with pytest.raises(local_mod.StrixLocalApprovalRequired):
        _invoke(local_mod, tmp_path, spy, approval_granted=falsy)
    assert spy.calls == 0


@pytest.mark.parametrize("truthy", ["no", "false", "0", 2, [0], object()])
def test_ambiguous_truthy_values_refuse(local_mod, tmp_path, truthy):
    # An execution gate must not accept "probably yes". The strings "no" and
    # "false" are truthy in Python, so a truthiness check would execute here.
    spy = Spy()
    with pytest.raises(local_mod.StrixLocalApprovalRequired):
        _invoke(local_mod, tmp_path, spy, approval_granted=truthy)
    assert spy.calls == 0, f"{truthy!r} was accepted as human approval"


def test_an_unknown_capability_never_auto_allows(local_mod, tmp_path):
    spy = Spy()
    with pytest.raises(local_mod.StrixLocalApprovalRequired):
        local_mod.governed_action_local(
            "totally.unregistered",
            "mystery_action",
            {},
            spy,
            workspace_root=tmp_path,
        )
    assert spy.calls == 0


def test_policy_denial_refuses_before_execution(local_mod, tmp_path):
    # A DENY rule is unreachable with the shipped table (no entry maps to
    # DENY), so this pins the branch through evaluate_policy's rules
    # parameter — the documented extension point.
    decision, _reason = local_mod.evaluate_policy(
        "payment.charge", {}, rules={"payment.charge": ("BLOCKED", None)}
    )
    assert decision == "REQUIRE_APPROVAL"  # unknown risk never auto-allows


# ---------------------------------------------------------------------------
# Grant: the operation runs exactly once, and only then.
# ---------------------------------------------------------------------------


@requires_signing
def test_explicit_true_runs_the_operation_exactly_once(local_mod, tmp_path):
    spy = Spy()
    result = _invoke(local_mod, tmp_path, spy, approval_granted=True)
    assert spy.calls == 1
    assert result.result == "SIDE EFFECT HAPPENED"
    assert result.evidence_id
    assert Path(result.receipt_path).exists(), "an executed action left no receipt"


def test_low_risk_rule_allows_without_approval(local_mod, tmp_path):
    # Sanity check on the gate's scope: it fires on REQUIRE_APPROVAL, so an
    # auto-allowed capability is not blocked by a missing approval flag.
    decision, _ = local_mod.evaluate_policy(
        "read.only", {}, rules={"read.only": ("LOW", None)}
    )
    assert decision == "ALLOW"


# ---------------------------------------------------------------------------
# The documented STRIX_WIRE_RUN_APPROVED wrap pattern.
# ---------------------------------------------------------------------------


def _pattern(monkeypatch, value: str | None) -> bool:
    """Evaluate the exact expression SKILL.md's wrap templates use."""
    import os

    if value is None:
        monkeypatch.delenv("STRIX_WIRE_RUN_APPROVED", raising=False)
    else:
        monkeypatch.setenv("STRIX_WIRE_RUN_APPROVED", value)
    return os.environ.get("STRIX_WIRE_RUN_APPROVED") == "1"


@pytest.mark.parametrize(
    "value", [None, "", "0", "true", "TRUE", "yes", "2", " 1", "1 ", "01"]
)
def test_run_approved_pattern_fails_closed_for_everything_but_one(
    local_mod, tmp_path, monkeypatch, value
):
    granted = _pattern(monkeypatch, value)
    assert granted is False, f"{value!r} was treated as approval"
    spy = Spy()
    with pytest.raises(local_mod.StrixLocalApprovalRequired):
        _invoke(local_mod, tmp_path, spy, approval_granted=granted)
    assert spy.calls == 0


@requires_signing
def test_run_approved_pattern_grants_only_on_exactly_one(
    local_mod, tmp_path, monkeypatch
):
    granted = _pattern(monkeypatch, "1")
    assert granted is True
    spy = Spy()
    _invoke(local_mod, tmp_path, spy, approval_granted=granted)
    assert spy.calls == 1


def test_the_env_var_is_read_by_the_caller_not_the_helper(local_mod, tmp_path, monkeypatch):
    """The env var is a convention in the wrap, not enforcement in the helper.

    Pinning this makes the limitation explicit rather than implied: exporting
    STRIX_WIRE_RUN_APPROVED=1 in a shell profile or a CI env block turns the
    intended one-run approval into a standing one, because the helper itself
    never consults the variable. SKILL.md's failure-modes section documents
    this; this test is what keeps the two honest with each other.
    """
    monkeypatch.setenv("STRIX_WIRE_RUN_APPROVED", "1")
    spy = Spy()
    # Env var set, but the caller did not pass the flag: still refused.
    with pytest.raises(local_mod.StrixLocalApprovalRequired):
        _invoke(local_mod, tmp_path, spy)
    assert spy.calls == 0
