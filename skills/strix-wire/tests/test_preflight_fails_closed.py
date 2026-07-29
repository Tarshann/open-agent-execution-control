"""The preflight guard must never report an incomplete scan as a clean one.

The guard's whole job is to refuse repos that are already governed or look
like production. Every path where it gives up on a file is therefore a path
where it might have skipped the one marker that mattered: "we didn't finish
looking" must resolve to STOP, not OK.

Directory-level failures were already covered (analyze.py sweeps for
unreadable subtrees). These tests cover the file-level ones.

Note on technique: the suite runs as root in CI, where permission bits do not
make a file unreadable, so the I/O failure is injected at the read call for
one specific path. That is the exact failure the handler under test claims to
absorb — a real EACCES/EIO on one file mid-walk.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from conftest import load_skill_module, make_python_repo


@pytest.fixture
def preflight_mod():
    return load_skill_module("preflight")


def _break_reads_of(monkeypatch, target: Path, exc: Exception) -> None:
    """Make exactly one file raise on read; every other read is untouched."""
    real_read_text = Path.read_text

    def guarded(self, *args, **kwargs):
        if self == target:
            raise exc
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded)


def _break_stat_of(monkeypatch, target: Path, exc: Exception) -> None:
    real_stat = Path.stat

    def guarded(self, *args, **kwargs):
        if self == target:
            raise exc
        return real_stat(self, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", guarded)


def test_an_unreadable_file_stops_instead_of_reporting_clean(
    preflight_mod, tmp_path, monkeypatch
):
    root = make_python_repo(tmp_path / "repo")
    blocked = root / "src" / "billing" / "charge.py"
    _break_reads_of(monkeypatch, blocked, PermissionError(13, "Permission denied"))

    result = preflight_mod.scan(root)

    assert result["verdict"] == "STOP", "an unread file was reported as a clean scan"
    assert result["unreadableFiles"] == ["src/billing/charge.py"]
    assert "could not be read" in result["reason"]
    # The verdict must not masquerade as a governance/production finding.
    assert result["governed"] is False and result["production"] is False


def test_an_unstattable_file_stops_too(preflight_mod, tmp_path, monkeypatch):
    root = make_python_repo(tmp_path / "repo")
    blocked = root / "src" / "billing" / "charge.py"
    _break_stat_of(monkeypatch, blocked, OSError(5, "I/O error"))

    result = preflight_mod.scan(root)

    assert result["verdict"] == "STOP"
    assert result["unreadableFiles"] == ["src/billing/charge.py"]


def test_a_readable_repo_reports_no_unreadable_files(preflight_mod, tmp_path):
    # The guard must not cry wolf: a fully readable repo still passes cleanly.
    result = preflight_mod.scan(make_python_repo(tmp_path / "repo"))
    assert result["verdict"] == "OK"
    assert result["unreadableFiles"] == []
    assert "could not be read" not in result["reason"]


def test_a_real_marker_still_wins_the_reason_line(
    preflight_mod, tmp_path, monkeypatch
):
    # When the repo is genuinely production AND a file was unreadable, the
    # operator-facing reason should name the marker, not the I/O problem.
    root = make_python_repo(tmp_path / "repo")
    (root / "deploy.md").write_text("uses sk_live_ABC123 in production\n")
    _break_reads_of(
        monkeypatch,
        root / "src" / "billing" / "charge.py",
        PermissionError(13, "Permission denied"),
    )

    result = preflight_mod.scan(root)

    assert result["verdict"] == "STOP"
    assert result["production"] is True
    assert "live-production markers" in result["reason"]
    assert result["unreadableFiles"] == ["src/billing/charge.py"]


def test_analysis_halts_before_scanning_when_a_file_is_unreadable(
    analyze_mod, tmp_path, monkeypatch
):
    # End-to-end: the fail-closed preflight verdict must stop the single
    # authorized analysis run before it scans or reports candidates.
    root = make_python_repo(tmp_path / "repo")
    _break_reads_of(
        monkeypatch,
        root / "src" / "billing" / "charge.py",
        PermissionError(13, "Permission denied"),
    )

    report, code = analyze_mod.run_analysis(root)

    assert code == 3
    assert report["verdict"] == "STOP"
    assert report["phases_completed"] == ["scope", "repository", "preflight"]
    assert "scan" not in report and "helper_integrity" not in report
    rendered = analyze_mod._format_human(report)
    assert "PREFLIGHT   STOP" in rendered and "PREFLIGHT   OK" not in rendered
