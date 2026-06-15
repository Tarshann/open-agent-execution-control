#!/usr/bin/env python3
"""strix-personal: lifecycle rollup for the repo (the /strix-status surface).

Shows where every action point sits on DETECTED → … → VERIFIED, plus coverage.
Read-only. Zero-install (vendored core).

    python3 scripts/strix_status.py --root . [--include-ai] [--json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "_vendor"))

import action_scanner  # noqa: E402  (vendored)
from lifecycle import _PROGRESSION, ActionState, ScanReport  # noqa: E402  (vendored)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Lifecycle status for the repository.")
    p.add_argument("--root", default=".", help="Repository root (default: cwd).")
    p.add_argument("--include-ai", action="store_true", help="Include AI surfaces.")
    p.add_argument("--json", action="store_true", help="Emit JSON.")
    args = p.parse_args(argv)

    root = Path(args.root).resolve()
    candidates = action_scanner.scan(root, include_ai=args.include_ai)
    report = ScanReport.from_candidates(candidates)
    states = report.by_state()

    if args.json:
        print(json.dumps({
            "schema": "strix_personal.status/v1",
            "total": report.total,
            "coverage": report.coverage(),
            "governed": report.governed_count(),
            "by_state": states,
        }, indent=2))
        return 0

    print("\U0001f512 Strix Personal — lifecycle status")
    print(report.headline())
    print("")
    ordered = [*_PROGRESSION, ActionState.SUPPRESSED]
    width = max((len(s.value) for s in ordered), default=10)
    for s in ordered:
        n = states.get(s.value, 0)
        bar = "█" * n
        print(f"  {s.value.ljust(width)}  {str(n).rjust(3)}  {bar}")
    print("")
    if report.coverage() >= 0.999 and report.total:
        print("All detected actions are governed locally.")
        print("Upgrade to hosted approvals + public proof links: strixgov.com (Connected Mode).")
    else:
        print("Next: /strix-apply to wrap the open action points.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
