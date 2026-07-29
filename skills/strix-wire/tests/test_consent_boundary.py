"""Behavioral proof of WIRE-CONSENT-1: the single analysis authorization
covers every read-only phase and cannot be upgraded into mutation or
execution authority.

Section-F coverage (docs/consent-architecture.md):
  - one authorization covers all read-only analysis commands
  - analysis cannot write to the repository
  - analysis cannot inspect parent or sibling directories
  - temporary-directory exclusions are applied automatically
  - helper integrity validation runs inside analysis scope
  - missing toolchain produces one clear remediation, not repeated prompts
  - skipping the wrap changes zero files
  - applying the wrap executes zero consequential actions
  - declining execution creates no execution evidence
  - changed repository scope requires fresh consent (scope is pinned per run)
"""

from __future__ import annotations

import importlib
import importlib.util
import os
import sys
from pathlib import Path

import pytest

from conftest import (
    SKILL_DIR,
    make_python_repo,
    make_ts_repo,
    tree_snapshot,
)

ALL_PHASES = [
    "scope",
    "repository",
    "preflight",
    "runtime",
    "scan",
    "candidate-analysis",
    "helper-integrity",
]


def _norm(p: str) -> str:
    return p.replace("\\", "/")


# ---------------------------------------------------------------------------
# One authorization covers all read-only analysis phases.
# ---------------------------------------------------------------------------


def test_one_authorization_covers_every_analysis_phase(analyze_mod, workspace):
    report, code = analyze_mod.run_analysis(workspace["child"])
    assert code == 0
    assert report["verdict"] == "OK"
    assert report["phases_completed"] == ALL_PHASES
    # Every phase's evidence is present in the single report.
    for section in ("preflight", "runtime", "repository", "scan", "helper_integrity"):
        assert section in report, f"missing analysis section: {section}"
    assert report["read_only"] is True
    assert report["consent"]["contract"] == "WIRE-CONSENT-1"


# ---------------------------------------------------------------------------
# Analysis cannot write to the repository (or anywhere near it).
# ---------------------------------------------------------------------------


def test_analysis_writes_nothing(analyze_mod, workspace):
    before = tree_snapshot(workspace["parent"])
    report, code = analyze_mod.run_analysis(workspace["child"])
    assert code == 0 and report["verdict"] == "OK"
    after = tree_snapshot(workspace["parent"])
    assert before == after, "analysis modified, created, or deleted files"


def test_analysis_creates_no_execution_evidence(analyze_mod, workspace):
    analyze_mod.run_analysis(workspace["child"])
    analyze_mod.run_analysis(workspace["child"])  # even repeated runs
    for dirpath, dirnames, filenames in os.walk(workspace["parent"]):
        assert ".strix" not in dirnames, "analysis created an evidence directory"
        assert "receipts.jsonl" not in filenames
        assert not any("evidence" in f.lower() for f in filenames)


# ---------------------------------------------------------------------------
# Analysis cannot inspect parent or sibling directories.
# ---------------------------------------------------------------------------


def test_analysis_reads_nothing_outside_root(analyze_mod, workspace, open_recorder):
    sibling = str(workspace["sibling"].resolve())
    marker = str(workspace["marker"].resolve())
    with open_recorder() as rec:
        report, code = analyze_mod.run_analysis(workspace["child"])
    assert code == 0 and report["verdict"] == "OK"
    for opened in rec.paths:
        assert not opened.startswith(sibling), f"opened sibling file: {opened}"
        assert opened != marker, "opened a parent-directory file"


def test_report_references_no_path_outside_root(analyze_mod, workspace):
    report, _ = analyze_mod.run_analysis(workspace["child"])
    everything = [c["file"] for c in report["scan"]["candidates"]]
    everything += [e["file"] for e in report["scan"]["excluded_temporary"]]
    everything += [c["path"] for c in report["helper_integrity"]["copies_in_repo"]]
    for rel in everything:
        assert ".." not in _norm(rel).split("/"), f"path escapes root: {rel}"
        assert "sibling" not in _norm(rel), f"sibling content surfaced: {rel}"
        assert "PARENT_MARKER" not in rel


# ---------------------------------------------------------------------------
# Temporary-directory exclusions are applied automatically.
# ---------------------------------------------------------------------------


def test_temp_path_exclusions_are_automatic(analyze_mod, workspace):
    report, _ = analyze_mod.run_analysis(workspace["child"])
    excluded = {_norm(e["file"]) for e in report["scan"]["excluded_temporary"]}
    assert "tmp/decoy.py" in excluded
    assert "temp/decoy2.py" in excluded
    kept = {_norm(c["file"]) for c in report["scan"]["candidates"]}
    assert "src/billing/charge.py" in kept
    assert not kept & excluded
    # Test paths never even reach the exclusion list — the scanner drops them.
    assert not any("tests/" in f for f in kept | excluded)


# ---------------------------------------------------------------------------
# Helper integrity validation runs inside the analysis scope.
# ---------------------------------------------------------------------------


def test_helper_integrity_runs_inside_analysis(analyze_mod, workspace):
    # A divergent stub (name matches a governed-action helper, content does
    # not) must be flagged by the same single-authorization run.
    stub = workspace["child"] / "src" / "strix_wire.py"
    stub.write_text("# placeholder helper, not the canonical client\n")
    report, code = analyze_mod.run_analysis(workspace["child"])
    assert code == 0
    assert "helper-integrity" in report["phases_completed"]
    copies = report["helper_integrity"]["copies_in_repo"]
    assert [c for c in copies if _norm(c["path"]) == "src/strix_wire.py"]
    assert all(c["identical"] is False for c in copies)
    # Every bundled helper is hashed so the report can attest the canon.
    bundled = report["helper_integrity"]["bundled"]
    assert len(bundled) == 4 and all(b["sha256"] for b in bundled)


def test_helper_integrity_detects_identical_copy(analyze_mod, tmp_path):
    # Unit-level: a byte-identical copy reports identical=True. (A full run
    # on such a repo STOPs at preflight by design — the repo is already
    # governed — so the identical case is pinned at the function level.)
    copy = tmp_path / "strix_wire.py"
    copy.write_bytes((SKILL_DIR / "helpers" / "governed_action.py").read_bytes())
    result = analyze_mod.helper_integrity(tmp_path, [copy])
    assert result["copies_in_repo"] == [
        {
            "path": "strix_wire.py",
            "bundled_name": "helpers/governed_action.py",
            "identical": True,
        }
    ]


# ---------------------------------------------------------------------------
# Preflight STOP halts analysis before scanning (fail closed).
# ---------------------------------------------------------------------------


def test_preflight_stop_halts_before_scanning(analyze_mod, tmp_path):
    root = make_python_repo(tmp_path / "prod")
    (root / "deploy.md").write_text("uses sk_live_ABC123 in production\n")
    report, code = analyze_mod.run_analysis(root)
    assert code == 3
    assert report["verdict"] == "STOP"
    assert report["phases_completed"] == ["scope", "repository", "preflight"]
    assert "scan" not in report and "helper_integrity" not in report


def test_truncated_preflight_fails_closed(analyze_mod, workspace, monkeypatch):
    # "We didn't finish looking" must never render as PREFLIGHT OK.
    preflight = analyze_mod._load_bundled_module("preflight")
    monkeypatch.setattr(
        preflight,
        "scan",
        lambda root: {
            "verdict": "OK",
            "governed": False,
            "production": False,
            "markers": [],
            "reason": "no markers (but the walk hit its file bound)",
            "filesScanned": 6000,
            "truncated": True,
        },
    )
    report, code = analyze_mod.run_analysis(workspace["child"])
    assert code == 3
    assert report["verdict"] == "STOP"
    assert "truncated" in report["reason"]
    assert "scan" not in report
    # The human render must not say OK either.
    rendered = analyze_mod._format_human(report)
    assert "PREFLIGHT   STOP" in rendered and "PREFLIGHT   OK" not in rendered


def test_unreadable_subtree_fails_closed(analyze_mod, workspace, monkeypatch):
    monkeypatch.setattr(
        analyze_mod, "_unreadable_subtrees", lambda root, skip: ["child/locked"]
    )
    report, code = analyze_mod.run_analysis(workspace["child"])
    assert code == 3
    assert report["verdict"] == "STOP"
    assert "could not be read" in report["reason"]


def test_non_repository_refused_before_any_content_read(
    analyze_mod, tmp_path, open_recorder
):
    # A directory with no repo markers must be refused with NOTHING read —
    # the analysis grant is not a generic directory reader.
    loose = tmp_path / "not-a-repo"
    loose.mkdir()
    secret = loose / "diary.py"
    secret.write_text("stripe.Charge.create(amount=1)\n")
    with open_recorder() as rec:
        report, code = analyze_mod.run_analysis(loose)
    assert code == 4
    assert report["verdict"] == "REMEDIATION_REQUIRED"
    assert len(report["remediation"]) == 1
    assert str(secret.resolve()) not in rec.paths


def test_cli_refuses_root_outside_cwd(analyze_mod, tmp_path, monkeypatch, capsys):
    # The executed scope is bound to the disclosed scope (the opened
    # project): an approved command shape cannot quietly point elsewhere.
    inside = make_python_repo(tmp_path / "opened")
    elsewhere = make_python_repo(tmp_path / "elsewhere")
    monkeypatch.chdir(inside)
    assert analyze_mod.main(["--root", str(elsewhere), "--json"]) == 2
    assert "outside the current working directory" in capsys.readouterr().err
    # Same root with the explicit re-disclosure flag is allowed…
    assert analyze_mod.main(
        ["--root", str(elsewhere), "--json", "--allow-external-root"]
    ) == 0
    # …and the normal onboarding shape (--root .) always works.
    assert analyze_mod.main(["--root", ".", "--json"]) == 0


# ---------------------------------------------------------------------------
# Missing toolchain: one clear remediation, not repeated prompts.
# ---------------------------------------------------------------------------


def test_missing_node_is_one_remediation_not_a_stop(analyze_mod, tmp_path, monkeypatch):
    root = make_ts_repo(tmp_path / "tsrepo")
    monkeypatch.setenv("PATH", "")  # no node anywhere
    report, code = analyze_mod.run_analysis(root)
    assert code == 0, "analysis must still complete — Node matters only at run time"
    assert report["runtime"]["node_found"] is False
    node_items = [r for r in report["remediation"] if "Node" in r["issue"]]
    assert len(node_items) == 1, "exactly one remediation entry, never a prompt loop"
    assert "nodejs.org" in node_items[0]["fix"]


# ---------------------------------------------------------------------------
# Skipping the wrap changes zero files; applying the wrap executes nothing;
# declining execution creates no execution evidence.
# ---------------------------------------------------------------------------



def test_skipping_the_wrap_changes_zero_files(analyze_mod, workspace):
    # The terminal state after Approval 1 + a declined Approval 2 is exactly
    # the post-analysis tree: analysis ran, nothing else did.
    before = tree_snapshot(workspace["child"])
    report, _ = analyze_mod.run_analysis(workspace["child"])
    assert report["scan"]["recommended"] is not None  # there WAS something to wrap
    assert tree_snapshot(workspace["child"]) == before


WRAPPED_CHARGE_LOCAL = '''\
import os
import pathlib

from strix_wire_local import governed_action_local

SENTINEL = pathlib.Path({sentinel})
WORKSPACE = pathlib.Path({workspace})


def charge(amount):
    action = governed_action_local(
        "payment.charge",
        "charge_card",
        {{"amount": amount, "currency": "usd"}},
        lambda: SENTINEL.write_text("the consequential action ran"),
        # The wrap SKILL.md prescribes: run-scoped, never hardcoded.
        approval_granted=os.environ.get("STRIX_WIRE_RUN_APPROVED") == "1",
        workspace_root=WORKSPACE,
    )
    return action.result
'''


def _apply_the_wrap(tmp_path: Path) -> tuple[Path, Path]:
    """Do exactly what an approved Phase 3 does: copy the helper into the repo
    (3b) and rewrite the call site (3c). Returns (repo root, sentinel path)."""
    root = make_python_repo(tmp_path / "wrapme")
    sentinel = root / "SIDE_EFFECT_FIRED"
    (root / "strix_wire_local.py").write_bytes(
        (SKILL_DIR / "helpers" / "governed_action_local.py").read_bytes()
    )
    (root / "src" / "billing" / "charge.py").write_text(
        WRAPPED_CHARGE_LOCAL.format(
            sentinel=repr(str(sentinel)), workspace=repr(str(root))
        )
    )
    return root, sentinel


def _import_wrapped(root: Path):
    """Import the rewritten call site as the customer's code would."""
    sys.path.insert(0, str(root))
    try:
        spec = importlib.util.spec_from_file_location(
            "wrapped_charge_under_test", root / "src" / "billing" / "charge.py"
        )
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(root))


def test_applying_the_wrap_executes_no_consequential_action(tmp_path):
    # Editing files is not executing them: after the wrap is applied, nothing
    # has run and no evidence exists.
    root, sentinel = _apply_the_wrap(tmp_path)
    assert not sentinel.exists(), "applying the wrap must not execute the action"
    assert not (root / ".strix").exists()


def test_the_wrapped_call_site_refuses_to_run_without_the_run_approval(
    tmp_path, monkeypatch
):
    # The real invariant: the wrap is not merely inert on disk — when the
    # customer's code CALLS it without the run-scoped approval, the governed
    # operation is refused and the side effect never happens.
    root, sentinel = _apply_the_wrap(tmp_path)
    monkeypatch.delenv("STRIX_WIRE_RUN_APPROVED", raising=False)
    module = _import_wrapped(root)
    local = importlib.import_module("strix_wire_local")

    with pytest.raises(local.StrixLocalApprovalRequired):
        module.charge(2500)

    assert not sentinel.exists(), "the wrapped operation ran without approval"
    receipts = list((root / ".strix").rglob("*.json")) if (root / ".strix").exists() else []
    assert not [p for p in receipts if "keys" not in p.parts], (
        "evidence was recorded for an action that never ran"
    )


def test_declined_execution_leaves_no_evidence(analyze_mod, workspace):
    # Approval 3 declined == nothing ran == no evidence artifact of any kind.
    analyze_mod.run_analysis(workspace["child"])
    child = workspace["child"]
    assert not (child / ".strix").exists()
    names = {f for _, _, fs in os.walk(child) for f in fs}
    assert not any(n.endswith(".evidence.json") or n == "receipts.jsonl" for n in names)


# ---------------------------------------------------------------------------
# Consent is single-run and single-root.
# ---------------------------------------------------------------------------


def test_consent_pins_scope_and_expiry(analyze_mod, workspace):
    report, _ = analyze_mod.run_analysis(workspace["child"])
    consent = report["consent"]
    assert Path(consent["scope_root"]) == workspace["child"].resolve()
    assert consent["expires"] == "end-of-run"
    assert "fresh ANALYSIS REQUEST" in consent["rescope"]
    assert "separate" in consent["not_upgradeable"]


def test_changed_scope_produces_distinct_consent(analyze_mod, tmp_path):
    a = make_python_repo(tmp_path / "repo_a")
    b = make_python_repo(tmp_path / "repo_b")
    report_a, _ = analyze_mod.run_analysis(a)
    report_b, _ = analyze_mod.run_analysis(b)
    assert report_a["consent"]["scope_root"] != report_b["consent"]["scope_root"]
    # Neither report grants anything about the other root: every path each
    # one mentions stays inside its own scope.
    for rep, own in ((report_a, "repo_a"), (report_b, "repo_b")):
        for c in rep["scan"]["candidates"]:
            assert own in rep["consent"]["scope_root"]
            assert ".." not in _norm(c["file"]).split("/")
