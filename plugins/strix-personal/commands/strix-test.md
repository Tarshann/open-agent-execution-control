---
description: Exercise a wrapped capability — allowed, approval-required, and tamper/bypass scenarios.
argument-hint: "--file <path>"
---

# /strix-test — prove the wrap actually governs

Run three controlled checks against a wrapped call site so the user sees
governance behave before trusting it in production.

## What to do

1. **Bypass check (static, always run).** Confirm every call to the wrapped
   capability routes through the boundary — no ungoverned sibling remains:

   ```bash
   python3 "${CLAUDE_PLUGIN_ROOT}/scripts/strix_apply.py" --root . $ARGUMENTS
   ```

   Read the "bypass check" line. PASS means ENFORCED is reachable; OPEN means a
   bypass still exists and must be wrapped first.

2. **Allowed + approval-required scenarios (runtime).** If the user has
   `STRIX_API_KEY` + `STRIX_TENANT_ID` set (Connected Mode) or a local kernel,
   run the smallest entry point that hits the wrapped call with **test-safe**
   arguments (Stripe test card, tiny amounts, sandbox targets). Expect:
   - a low-risk capability → `ALLOW` → a real `evidenceId` is printed;
   - a HIGH/CRITICAL capability → `APPROVAL_REQUIRED` → the action does **not**
     run until approved.

   If neither connected mode nor a local kernel is available, say so — do not
   fabricate an evidenceId or a verdict.

3. **Tamper is detectable.** Remind the user they can verify any produced
   record independently, and that a tampered payload or flipped signature byte
   is REJECTED by the verifier:

   ```bash
   npx @strixgov/verifier@latest <evidenceId>
   ```

4. Summarize as a table: `ALLOW` · `APPROVAL_REQUIRED` · `BYPASS` · `RECEIPT`.

## Guardrails

- Never run a real-money or production mutation to "complete the test." Use
  staging / test credentials, or stop and tell the user.
- Report what actually happened. If a step was skipped, say it was skipped.
