#!/usr/bin/env python3
"""strix-onboard: the onboarding readiness surface (read-only).

Renders one onboarding project's truthful state — the console view. Read-only
by construction: it loads a project record, derives every field, and prints.
It cannot advance a project, execute anything, or reach the network.

    python3 status.py --project onboarding.json [--json]

The input is a project record as written by the onboarding flow (see SKILL.md).
Absent a record, `--demo` renders the shape of the view so an operator can see
what the flow produces before running it.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _load_model():
    spec = importlib.util.spec_from_file_location(
        "strix_onboarding_model", _HERE / "onboarding.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


_UNSAFE_FOR_DISPLAY = re.compile(r"[^\x20-\x7e]")


def _safe(value: object, limit: int = 120) -> str:
    """Render operator-supplied text as one inert, single-line token.

    Organization names, system ids and verifier output are all externally
    supplied, and this view is what an operator reads to decide whether a
    client is ready. Same discipline as the strix-wire analyzer's report.
    """
    text = str(value)
    for ch in ("\t", "\n", "\r"):
        text = text.replace(ch, " ")
    text = _UNSAFE_FOR_DISPLAY.sub("?", text)
    # Collapse runs of spaces. This report aligns its own labels on fixed
    # columns ("READY       yes"), so a value allowed to keep long space runs
    # could mimic a status line convincingly enough to fool a reader skimming
    # for one — or a script grepping for it.
    text = " ".join(text.split(" "))
    text = re.sub(r" {2,}", " ", text)
    if len(text) > limit:
        text = text[: limit - 3] + "..."
    return text


#: The operator-visible journey. Each step maps to the state that COMPLETES it,
#: so a step is only ever shown done when the project actually holds that state.
_STEPS: list[tuple[str, str]] = [
    ("Create tenant", "tenant_created"),
    ("Identify systems", "systems_registered"),
    ("Select governed actions", "capabilities_defined"),
    ("Configure approvals and policies", "policies_configured"),
    ("Connect credentials and adapters", "integrations_configured"),
    ("Validate integration", "ready_for_smoke_test"),
    ("Run governed smoke test", "proof_pending"),
    ("Verify evidence independently", "ready"),
]


def render(view: dict, model) -> str:
    progression = [s.value for s in model._PROGRESSION]
    state = view["state"]
    # A failure state is NOT a point on the progression: rank from the stage it
    # diverged from, and mark the step that was in flight as FAILED rather than
    # letting it read as merely not-yet-done.
    failure_of = {k.value: v.value for k, v in model._FAILURE_OF.items()}
    diverged = failure_of.get(state)
    effective = diverged or state
    rank = progression.index(effective) if effective in progression else -1
    # The step in flight at `diverged` is the first one that completes after it.
    failed_step_rank = None
    if diverged is not None:
        for _label, completing in _STEPS:
            if progression.index(completing) > rank:
                failed_step_rank = progression.index(completing)
                break

    lines = [
        "STRIX ONBOARDING -- READINESS",
        "",
        f"  Project     {_safe(view['project_id'])}",
        f"  Tenant      {_safe(view['tenant_id'])}",
        f"  State       {_safe(state)}",
        "",
    ]
    for label, completing_state in _STEPS:
        step_rank = progression.index(completing_state)
        if step_rank == failed_step_rank:
            mark = "FAIL"
        elif rank >= step_rank:
            mark = "done"
        else:
            mark = "  --"
        lines.append(f"  [{mark}]  {label}")

    lines += [
        "",
        f"  Systems     {view['systems']}"
        f"  |  Capabilities {view['capabilities']}"
        f"  |  Active integrations {view['active_integrations']}",
    ]
    if view["smoke_test_evidence_id"]:
        lines.append(f"  Evidence    {_safe(view['smoke_test_evidence_id'])}")
    if view["verification_verdict"]:
        lines.append(f"  Verdict     {_safe(view['verification_verdict'])}")
    lines += ["", f"  READY       {'yes' if view['is_ready'] else 'no'}"]
    if view["blocked_reason"]:
        lines.append(f"  BLOCKED     {_safe(view['blocked_reason'], limit=300)}")
    for gap in view["configuration_gaps"]:
        lines.append(f"  GAP         {_safe(gap)}")
    lines += ["", "  " + _safe(view["proof_claim"], limit=400)]
    return "\n".join(lines)


def _demo_view(model) -> dict:
    """A project mid-flow, so the shape of the view is inspectable offline."""
    context = model.OperatorContext(operator_id="operator@example", tenant_id="acme-eu")
    project = model.start_onboarding(context, "onb_demo", "Acme EU")
    project.record_organization(
        model.ClientOrganization(
            tenant_id="acme-eu",
            legal_name="Acme GmbH",
            display_name="Acme",
            primary_region="eu-west-1",
        ),
        model.Environment(
            tenant_id="acme-eu",
            name="staging",
            environment_type=model.EnvironmentType.STAGING,
        ),
    )
    project.register_system(
        model.ExternalSystem(
            tenant_id="acme-eu",
            system_id="billing",
            display_name="Billing API",
            integration_type=model.IntegrationType.HTTP_API,
            environment_name="staging",
        )
    )
    project.define_capability(
        model.GovernedCapability(
            tenant_id="acme-eu",
            capability_id="payment.refund",
            system_id="billing",
            risk_tier=model.RiskTier.HIGH,
        )
    )
    return project.readiness()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Render one onboarding project's readiness (read-only)."
    )
    parser.add_argument("--project", help="Path to the project record (JSON).")
    parser.add_argument("--json", action="store_true", help="Emit the raw view.")
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Render a mid-flow example instead of a stored record.",
    )
    args = parser.parse_args(argv)

    model = _load_model()

    if args.demo:
        view = _demo_view(model)
    elif args.project:
        path = Path(args.project)
        if not path.is_file():
            print(f"error: no project record at {path}", file=sys.stderr)
            return 2
        view = json.loads(path.read_text(encoding="utf-8"))
        missing = {"project_id", "tenant_id", "state", "is_ready"} - set(view)
        if missing:
            print(
                f"error: {path} is not an onboarding readiness record "
                f"(missing {', '.join(sorted(missing))})",
                file=sys.stderr,
            )
            return 2
    else:
        parser.error("pass --project <file> or --demo")
        return 2

    view.setdefault("configuration_gaps", [])
    view.setdefault("blocked_reason", None)
    for key in ("systems", "capabilities", "active_integrations"):
        view.setdefault(key, 0)
    for key in ("smoke_test_evidence_id", "verification_verdict"):
        view.setdefault(key, None)
    view.setdefault("proof_claim", "No proof claimed.")

    print(json.dumps(view, indent=2) if args.json else render(view, model))
    return 0


if __name__ == "__main__":
    sys.exit(main())
