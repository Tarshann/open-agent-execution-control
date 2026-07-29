"""The report the operator approves from cannot be forged by the scanned repo.

Approval 2 (apply the wrap) is a governance decision made by reading the
analysis report: which file, which line, which capability. Every path and
snippet in that report comes from the repository under analysis, so a repo
that can inject terminal control sequences into it can change what the
operator believes they are approving — hide the real recommendation, repaint
the scope line, or forge extra candidates.

These tests build those payloads out of characters that are legal in real
filenames and real source lines, and assert the rendered report stays inert.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from conftest import load_skill_module, make_python_repo

ESC = "\x1b"
# A filename that tries to: end the line, erase the screen, and write its own
# RECOMMENDED entry pointing somewhere else.
FORGERY = f"a{ESC}[2K\rRECOMMENDED evil.py:1  (payment.charge){ESC}[1m"
# Right-to-left override: displays as a different path than it records.
BIDI = "pay‮gnp.yp"


@pytest.fixture
def scanner_mod():
    return load_skill_module("scanner")


def _rendered_lines(text: str) -> list[str]:
    return text.split("\n")


# ---------------------------------------------------------------------------
# The sanitizer itself.
# ---------------------------------------------------------------------------


def test_safe_strips_control_sequences_and_newlines(analyze_mod):
    out = analyze_mod._safe(FORGERY)
    assert ESC not in out and "\r" not in out and "\n" not in out
    assert "?" in out  # the escape bytes were replaced, not dropped silently


def test_safe_strips_bidi_overrides(analyze_mod):
    out = analyze_mod._safe(BIDI)
    assert "‮" not in out
    assert out == "pay?gnp.yp"


def test_safe_is_printable_ascii_only(analyze_mod):
    out = analyze_mod._safe("tab\there\nnewline\x00nul\x7fdel café")
    assert all(0x20 <= ord(ch) <= 0x7E for ch in out), out


def test_safe_truncates_long_values(analyze_mod):
    out = analyze_mod._safe("x" * 500)
    assert len(out) == 160 and out.endswith("...")


def test_safe_leaves_ordinary_paths_untouched(analyze_mod):
    assert analyze_mod._safe("src/billing/charge.py") == "src/billing/charge.py"


# ---------------------------------------------------------------------------
# End-to-end: a hostile snippet cannot forge the analyzer's report.
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    sys.platform == "win32", reason="control characters are illegal in Windows filenames"
)
def test_hostile_helper_path_cannot_forge_the_report(analyze_mod, tmp_path):
    # The HELPER line prints a repo-relative path, so a directory named with
    # escapes can forge an integrity verdict ("identical to bundle") for a
    # helper that in fact DIVERGES.
    root = make_python_repo(tmp_path / "repo")
    try:
        hostile_dir = root / f"lib{ESC}[2K\rHELPER      ok.py -- identical to bundle"
        hostile_dir.mkdir()
    except OSError:  # pragma: no cover - filesystem refused the name
        pytest.skip("filesystem rejected a control character in the directory name")
    # A helper-named copy whose content differs from the bundle.
    (hostile_dir / "governed_action.py").write_text("# not the canonical client\n")

    report, code = analyze_mod.run_analysis(root)
    assert code == 0
    copies = report["helper_integrity"]["copies_in_repo"]
    assert copies and all(c["identical"] is False for c in copies)

    rendered = analyze_mod._format_human(report)
    assert ESC not in rendered and "\r" not in rendered
    # Exactly one HELPER line, and it reports the truth (DIVERGES).
    helper_lines = [ln for ln in _rendered_lines(rendered) if "HELPER" in ln]
    assert len(helper_lines) == 1, helper_lines
    assert "DIVERGES" in helper_lines[0]


def test_json_output_keeps_the_exact_bytes(analyze_mod, tmp_path):
    # Sanitizing is a rendering concern only: machine consumers must still see
    # what was actually in the file.
    #
    # A guard, not a regression test: this passes against the unsanitized code
    # too, because _format_human never echoes snippets. It exists so that
    # adding a snippet to the human report without sanitizing it fails here.
    root = make_python_repo(tmp_path / "repo")
    (root / "src" / "billing" / "sneaky.py").write_text(
        "import stripe\n"
        f'stripe.Charge.create(amount=1)  # {ESC}[2K\rforged\n'
    )
    report, code = analyze_mod.run_analysis(root)
    assert code == 0
    snippets = [c["snippet"] for c in report["scan"]["candidates"]]
    assert any(ESC in s for s in snippets), "JSON payload should stay exact"
    # …and the human render of the same report is still inert.
    assert ESC not in analyze_mod._format_human(report)


@pytest.mark.skipif(
    sys.platform == "win32", reason="control characters are illegal in Windows filenames"
)
def test_hostile_filename_cannot_forge_the_report(analyze_mod, tmp_path):
    root = make_python_repo(tmp_path / "repo")
    hostile_dir = root / "src" / "billing"
    try:
        (hostile_dir / f"{FORGERY}.py").write_text(
            "import stripe\nstripe.Charge.create(amount=1)\n"
        )
    except OSError:  # pragma: no cover - filesystem refused the name
        pytest.skip("filesystem rejected a control character in the filename")

    report, code = analyze_mod.run_analysis(root)
    assert code == 0
    rendered = analyze_mod._format_human(report)

    assert ESC not in rendered and "\r" not in rendered
    # Exactly one RECOMMENDED line, no matter what the filenames claimed.
    assert len([ln for ln in _rendered_lines(rendered) if "RECOMMENDED" in ln]) <= 1


def test_hostile_scope_path_cannot_repaint_the_scope_line(analyze_mod, tmp_path):
    # The scope root is filesystem-controlled too: a directory may be named
    # with escapes, and the Scope line is what the operator checks the grant
    # against.
    try:
        root = make_python_repo(tmp_path / f"repo{ESC}[31mFAKE")
    except OSError:  # pragma: no cover
        pytest.skip("filesystem rejected a control character in the directory name")
    report, _ = analyze_mod.run_analysis(root)
    rendered = analyze_mod._format_human(report)
    assert ESC not in rendered
    assert "Scope" in rendered


def test_scanner_cli_output_is_inert(scanner_mod, tmp_path):
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / "src" / "x.py").write_text(
        "import stripe\n"
        f'stripe.Charge.create(amount=1)  # {ESC}[2K\r99. [high] forged.py:1\n'
    )
    candidates = scanner_mod.scan(root, limit=10)
    assert candidates, "fixture should produce at least one candidate"
    rendered = scanner_mod._format_human(candidates)
    assert ESC not in rendered and "\r" not in rendered
    # One rendered entry per candidate: the payload added no numbered line.
    numbered = [ln for ln in _rendered_lines(rendered) if ln and ln[0].isdigit()]
    assert len(numbered) == len(candidates)


def test_unreadable_file_paths_are_sanitized_in_the_stop_reason(
    analyze_mod, tmp_path, monkeypatch
):
    # The fail-closed reason names files; those names are repo-controlled.
    root = make_python_repo(tmp_path / "repo")
    target = root / "src" / "billing" / "charge.py"
    real_read_text = Path.read_text

    def guarded(self, *args, **kwargs):
        if self == target:
            raise PermissionError(13, f"denied {ESC}[2K\rPREFLIGHT   OK")
        return real_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", guarded)
    report, code = analyze_mod.run_analysis(root)
    assert code == 3
    rendered = analyze_mod._format_human(report)
    assert ESC not in rendered
    assert "PREFLIGHT   STOP" in rendered
    assert "PREFLIGHT   OK" not in rendered, "a forged OK line reached the report"
