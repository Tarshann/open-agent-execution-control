"""Behavioral proof that the analysis scope survives a hostile repository.

The ANALYSIS REQUEST card promises "Read source files in this repository" and
explicitly refuses "Access files outside this repository". A symlink is the
cheapest way to break that promise while every reported path still looks
local: the walk lists an in-root name, and the read follows the link out.

These tests craft the escape and assert the analyzer refuses it. They are
behavioral — each one builds a real link to real out-of-scope content and
checks what was actually opened, via the interpreter's audit hook.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from conftest import DECOY_PY, load_skill_module, make_python_repo

pytestmark = pytest.mark.skipif(
    not hasattr(os, "symlink") or sys.platform == "win32",
    reason="symlink creation needs POSIX-style symlink support",
)

SECRET = "SUPER_SECRET_OUT_OF_SCOPE_VALUE"


@pytest.fixture
def preflight_mod():
    return load_skill_module("preflight")


@pytest.fixture
def scanner_mod():
    return load_skill_module("scanner")


def _outside_tree(tmp_path: Path) -> tuple[Path, Path]:
    """Out-of-scope content carrying a production marker, so a successful escape
    shows up in the verdict as well as in the recorded reads."""
    outside = tmp_path / "outside"
    (outside / "nested").mkdir(parents=True)
    secret = outside / "secrets.py"
    secret.write_text(f"# {SECRET}\nSTRIPE_KEY = 'sk_live_ABCDEF123456'\n")
    (outside / "nested" / "more.py").write_text(f"# {SECRET}\n{DECOY_PY}")
    return outside, secret


@pytest.fixture
def hostile(tmp_path: Path) -> dict:
    """Escapes via FILE symlinks and an in-root cycle only.

    Deliberately no directory symlink out of root: that makes the scan
    *incomplete*, which is a separate verdict (see ``escaping_dir``). Here the
    scan can still see the whole repo, so the correct outcome is a clean OK
    with the escapes refused.
    """
    outside, secret = _outside_tree(tmp_path)
    root = make_python_repo(tmp_path / "repo")
    os.symlink(secret, root / "src" / "config.py")          # file link out
    os.symlink(root / "src", root / "src" / "loop")         # dir link, in-root
    return {"root": root, "outside": outside, "secret": secret}


@pytest.fixture
def escaping_dir(tmp_path: Path) -> dict:
    """A repo whose source lives behind a directory symlink out of root.

    A legitimate shared-package layout, and the case that regressed: refusing
    to follow the link keeps the scan in scope but means it never read the
    repo's code, so it must not certify it.
    """
    outside, secret = _outside_tree(tmp_path)
    root = make_python_repo(tmp_path / "repo")
    os.symlink(outside, root / "src" / "linked_dir")
    return {"root": root, "outside": outside, "secret": secret}


def _opened_outside(paths: list[str], outside: Path) -> list[str]:
    prefix = str(outside.resolve())
    return [p for p in paths if p.startswith(prefix)]


# ---------------------------------------------------------------------------
# H1 — reading through a file symlink must not leave the analysis root.
# ---------------------------------------------------------------------------


def test_preflight_never_reads_through_an_escaping_file_symlink(
    preflight_mod, hostile, open_recorder
):
    with open_recorder() as rec:
        result = preflight_mod.scan(hostile["root"])
    assert not _opened_outside(rec.paths, hostile["outside"]), (
        "preflight read content from outside the analysis root through a symlink"
    )
    # The out-of-scope live key must not be reported as this repo's marker.
    assert result["verdict"] == "OK", result
    assert result["production"] is False
    assert not any("Stripe" in m["marker"] for m in result["markers"])
    # And the refusal is disclosed, not silent.
    reasons = {link["reason"] for link in result["symlinksSkipped"]}
    assert "file symlink resolves outside the analysis root" in reasons


def test_scanner_drops_escaping_file_symlinks(scanner_mod, hostile, open_recorder):
    with open_recorder() as rec:
        files = scanner_mod._iter_source_files(hostile["root"])
        candidates = scanner_mod.scan(hostile["root"], limit=100)
    assert not _opened_outside(rec.paths, hostile["outside"])
    assert not [f for f in files if f.name == "config.py"], (
        "an escaping symlink survived source enumeration"
    )
    for c in candidates:
        assert "linked_dir" not in c.file.replace("\\", "/")
        assert "config.py" not in c.file


def test_helper_integrity_skips_an_escaping_helper_symlink(
    analyze_mod, tmp_path, open_recorder
):
    # A link named like a governed-action helper, pointing outside the repo.
    outside = tmp_path / "outside"
    outside.mkdir()
    target = outside / "real.py"
    target.write_text(f"# {SECRET}\n")
    root = make_python_repo(tmp_path / "repo")
    link = root / "governed_action.py"
    os.symlink(target, link)

    with open_recorder() as rec:
        result = analyze_mod.helper_integrity(root, [link])
    assert not _opened_outside(rec.paths, outside), "hashed a file outside the root"
    assert result["copies_in_repo"] == []


# ---------------------------------------------------------------------------
# H2 — directory symlinks are never descended, and cycles terminate.
# ---------------------------------------------------------------------------


def test_preflight_does_not_descend_directory_symlinks(preflight_mod, hostile):
    result = preflight_mod.scan(hostile["root"])
    reasons = " ".join(link["reason"] for link in result["symlinksSkipped"])
    assert "directory symlink not followed" in reasons, result["symlinksSkipped"]
    # An in-root link loses nothing, so it must not make the scan incomplete.
    assert result["unscannedSubtrees"] == []
    assert result["verdict"] == "OK"


def test_a_directory_symlink_out_of_root_stops_instead_of_certifying(
    preflight_mod, escaping_dir, open_recorder
):
    """The regression this guards: refusing to read outside the root keeps the
    scan in scope, but a repo whose content sits behind that link was never
    examined — and an unexamined repo cannot be reported clean.
    """
    with open_recorder() as rec:
        result = preflight_mod.scan(escaping_dir["root"])

    # Still in scope: nothing outside the root was read.
    assert not _opened_outside(rec.paths, escaping_dir["outside"])
    # But the scan is incomplete, so it must fail closed rather than say OK.
    assert result["verdict"] == "STOP", result
    assert result["unscannedSubtrees"] == ["src/linked_dir"] or result[
        "unscannedSubtrees"
    ] == [os.path.join("src", "linked_dir")]
    assert "never examined" in result["reason"]
    # And it must not masquerade as a governance/production finding.
    assert result["governed"] is False and result["production"] is False


def test_the_escaping_directory_halts_analysis_before_scanning(
    analyze_mod, escaping_dir
):
    report, code = analyze_mod.run_analysis(escaping_dir["root"])
    assert code == 3
    assert report["verdict"] == "STOP"
    assert report["phases_completed"] == ["scope", "repository", "preflight"]
    assert "scan" not in report


def _plain_repo(root: Path) -> Path:
    root.mkdir(parents=True)
    (root / "src").mkdir()
    (root / "pyproject.toml").write_text("[project]\nname = 'x'\n")
    (root / "src" / "charge.py").write_text("import stripe\nstripe.Charge.create(amount=1)\n")
    return root


def test_a_symlink_cycle_costs_the_scan_nothing(preflight_mod, tmp_path):
    """A directory link back to an ancestor must not be re-walked.

    Note the cycle terminates either way: the kernel refuses a path after
    ~40 symlink resolutions (ELOOP) and the walk treats that as an
    unreadable directory. What a following walk *does* pay is repeated
    scanning of the same files down every level of the loop — before this
    guard, this repo's 2 readable files were read 42 times.
    """
    plain = preflight_mod.scan(_plain_repo(tmp_path / "plain"))

    cyclic = _plain_repo(tmp_path / "cyclic")
    deep = cyclic / "src" / "a" / "b"
    deep.mkdir(parents=True)
    os.symlink(cyclic / "src", deep / "back")
    looped = preflight_mod.scan(cyclic)

    assert looped["verdict"] == "OK"
    assert looped["truncated"] is False
    assert looped["filesScanned"] == plain["filesScanned"], (
        "the cycle was walked: it inflated the scan beyond the real file count"
    )
    assert len(looped["symlinksSkipped"]) == 1
    skipped = looped["symlinksSkipped"][0]
    assert skipped["path"] == os.path.join("src", "a", "b", "back")
    assert "not followed" in skipped["reason"]
    # The link points back inside the root, so nothing went unexamined.
    assert looped["unscannedSubtrees"] == []


def test_full_analysis_of_a_hostile_repo_stays_in_scope(
    analyze_mod, hostile, open_recorder
):
    # End-to-end: the single authorized command, against a repo built to escape.
    with open_recorder() as rec:
        report, code = analyze_mod.run_analysis(hostile["root"])
    assert not _opened_outside(rec.paths, hostile["outside"]), (
        "the analysis read outside its authorized scope"
    )
    assert code == 0 and report["verdict"] in ("OK", "NO_CANDIDATES"), report
    # No reported path may name the linked-in tree.
    reported = [c["file"] for c in report["scan"]["candidates"]]
    reported += [e["file"] for e in report["scan"]["excluded_temporary"]]
    reported += [c["path"] for c in report["helper_integrity"]["copies_in_repo"]]
    for rel in reported:
        normalized = rel.replace("\\", "/")
        assert "linked_dir" not in normalized and "loop/" not in normalized
    # The human render discloses the refusal rather than implying full coverage.
    assert "LINKS" in analyze_mod._format_human(report)
