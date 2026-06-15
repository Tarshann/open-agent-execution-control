---
description: Show where every action point sits on DETECTED → … → VERIFIED, plus coverage.
argument-hint: "[--include-ai]"
---

# /strix-status — the governance lifecycle of this repo

Render the lifecycle rollup so the user sees progress from detection to
verified governance at a glance.

## What to do

1. Run:

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/strix_status.py" --root . --include-ai $ARGUMENTS
   ```

2. Present the lifecycle histogram and coverage. Explain the states honestly:
   - **DETECTED / WRAPPABLE** — found, not yet governed.
   - **WRAPPED** — a `governed_action()` wrap is present at the call site.
   - **TESTED / ENFORCED** — verified to route through the boundary (no bypass).
   - **VERIFIED** — a real signed evidence record exists and checks out.
   - **SUPPRESSED** — explicitly opted out with a stated reason.

3. If everything detected is governed, surface the upgrade moment: hosted
   approvals, receipt history, and public proof links come with Connected Mode
   (set `STRIX_API_KEY` + `STRIX_TENANT_ID`). Otherwise point at `/strix-apply`.

## Guardrails

- Coverage counts WRAPPED-or-better plus SUPPRESSED. Never count DETECTED as
  governed.
