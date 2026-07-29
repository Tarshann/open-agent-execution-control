# WIRE-CONSENT-1 — the Strix Wire consolidated consent architecture

Status: adopted (v0.3.0). Applies to `/strix-wire` (`skills/strix-wire/`).
Contract pinned by `skills/strix-wire/tests/`.

## The problem this fixes

The original onboarding flow raised a permission prompt for every internal
tool invocation — inspect folder, run `preflight.py`, locate Python, run
preflight with Python, check the repository, run the mutation scanner,
analyze candidates, re-run with temporary paths excluded, read the existing
governed-action helper, verify the bundled helper is identical — **eight to
ten mechanical prompts before the user ever saw the proposed wrap** (ten in
the worst case, which is the count enumerated above), and eleven clicks to a
finished proof.

That is not just friction. It is a safety regression: after six or seven
routine confirmations, users approve the consequential one without examining
it. A permission UX that treats "read a folder" and "execute an irreversible
mutation" as equally prompt-worthy trains exactly the reflex — click Allow,
don't read — that governance tooling exists to prevent.

## The rule

> **Collapse mechanical permissions, not governance decisions.**

Two kinds of consent were being presented as equals. They are not:

| | Analysis consent | Action authorization |
|---|---|---|
| Covers | Read-only inspection: folder walk, repo check, preflight, runtime detection, scanning, candidate analysis, temp-path exclusion, helper reading, helper-integrity comparison | Anything that can modify code or cause an action: applying the wrap; executing the governed call |
| Risk if granted wrongly | Someone read files they could already read | Code changed; an irreversible action fired |
| Granularity | ONE scoped grant per run | One explicit approval PER decision |
| Reusable? | No — expires at end of run; new run or new root = fresh grant | No — capability- and target-specific |
| Presented as | One ANALYSIS REQUEST card + one command | PROPOSED CHANGE card; RUN SANDBOX PROOF card |

## The mechanism

The prompt count was a direct function of the command count: the harness
prompts per tool invocation, and the skill used to make ~10 of them before
the proposal. The consolidation is therefore mechanical, not cosmetic:

**`analyze.py` runs every read-only phase in a single process.** One
command, one permission prompt, one disclosed card. In order: scope guard →
repository check (stat-only) → preflight (fail-closed, vendored, in-process)
→ runtime detection → consequential-action scan → candidate analysis with
automatic temporary-path exclusion → helper-integrity comparison (SHA-256 of
every bundled helper vs. any copy already in the repo). The repository check
precedes every content read on purpose: a directory with no repository
markers is refused before the analysis has read a single file, so the grant
cannot be turned into a generic directory reader. The old flow's
manual "exclude temporary paths and refine" re-run is now automatic; the old
flow's separate helper read + byte-compare is now a report section.

The three journeys and their approval budgets:

```text
analysis only                      1 approval
analysis + wrap                    2 approvals
analysis + wrap + sandbox proof    3 approvals
(+1 only when environment setup is genuinely required, e.g. installing
 Node before a TypeScript run-proof)
```

## Why the broad grant cannot be upgraded (Gate J)

A single broad "allow analysis" is only safe if it is incapable of becoming
authority for anything else. Three independent layers enforce that:

1. **By absence of capability.** `analyze.py` contains no write, subprocess,
   socket, or network capability at all — its only output is stdout. It cannot
   apply the wrap it recommends, it cannot execute a candidate, it cannot
   install or fetch anything, and it reads file content only under the
   disclosed `--root` (plus its own bundle). There is no code path from
   "analysis approved" to "file modified" inside the authorized command.

   Be precise about the strength of this layer: there is **no runtime sandbox**
   confining the process. The guarantee is that the shipped code has no such
   primitive, and that layer 3 fails if one appears. It is a defence against
   the analysis grant quietly growing new capability over time — not against
   someone shipping a modified analyzer.

   Four further hardenings: the CLI refuses a `--root` outside the current
   working directory (so the approved command shape cannot quietly point at
   an arbitrary directory; `--allow-external-root` exists only for a
   deliberately re-disclosed scope); a non-repository directory is refused
   before any file content is read; **scope containment survives symlinks** —
   no directory symlink is followed and no file symlink leaving the root is
   read, so a crafted repo cannot make an in-root path yield out-of-root
   content, and skipped links are disclosed in `symlinksSkipped`; and the
   embedded preflight fails closed on truncation, unreadable subtrees **and
   unreadable individual files** — a file that could not be read was never
   checked for markers, so "we didn't finish looking" is never rendered as
   "PREFLIGHT OK".

   One more, on the way out: every repository-controlled value (paths,
   snippets, I/O error text) is sanitized before it reaches the human report,
   because that report is what the operator reads to make approval 2. A
   filename carrying ANSI escapes or a bidi override could otherwise forge or
   repaint the lines that decision rests on.
2. **By expiry.** The grant is single-run and single-root. The report pins
   `consent.scope_root` and `consent.expires = "end-of-run"`; the skill
   instructions require a fresh ANALYSIS REQUEST card for any re-run or any
   root change, and forbid treating an earlier approval as standing
   permission. The one authorized command pattern
   (`python … analyze.py --root …`) grants nothing if reused: rerunning it
   yields another read-only analysis, never a mutation.
3. **By test.** `skills/strix-wire/tests/` pins both layers:
   source-scanned tests fail if a write/subprocess/network primitive ever
   appears in the analyzer (or its vendored preflight/scanner) — including the
   `pathlib` spellings that reach the same syscalls as the `os.*` ones — and
   every `open()` is AST-checked for a read-only literal mode. Behavioral tests
   run the analyzer against fixture repos and assert zero filesystem deltas,
   zero reads outside the root (via a Python audit hook on `open`), automatic
   temp-path exclusion, and no evidence artifacts. A hostile-repository suite
   builds real escapes — a file link out, a directory link out, a link back to
   an ancestor — and asserts, from the audit hook, what was actually opened.
   Contract tests fail if SKILL.md's consent card ever drifts from the
   analyzer's actual grant list, or if the wrap/run checkpoints lose their
   "separate, explicit approval" language.

   The execution gate is pinned behaviorally, not by prose: the offline helper
   is called with the approval flag absent, false, falsy, and ambiguously
   truthy, and each case must refuse with the operation spy never invoked and
   no evidence written. A hardcoded-approval scan covers all four shipped
   helpers in any spelling, since a single space defeated the original
   substring check.

The mutation and execution capabilities live on the other side of the
governance checkpoints: the wrap is applied by the agent's ordinary
file-edit tooling only after the PROPOSED CHANGE approval, and execution
happens only after the RUN SANDBOX PROOF approval — where the governed
helper itself evaluates the action against the kernel (Sandbox Mode) or the
local policy gate (Offline Mode) before letting it fire.

## The invariants

1. Repository access is limited to the disclosed root.
2. Analysis authorization does not authorize source modification.
3. Source-modification approval does not authorize execution.
4. Execution approval is capability- and target-specific.
5. Skipped execution is a valid terminal state.
6. No signed evidence is claimed before an evaluated run occurs (PROOF-1).
7. Broad analysis permission cannot become a reusable bypass for later
   commands.

## What the consolidation deliberately did NOT touch

The two governance checkpoints are unchanged in number and strengthened in
content:

- **Approval 2 — source modification** (`PROPOSED CHANGE`): shows the exact
  target, the exact diff, "Files that will change: N", and — load-bearing —
  "Actions that will execute: 0". Skipping changes zero files.
- **Approval 3 — sandbox execution** (`RUN SANDBOX PROOF`): shows exactly
  what will run, once, with test-safe inputs, and what it will not touch.
  Declining creates no execution evidence and is rendered as a completed,
  honest terminal state.

One confirmation is never enough to both wrap and run.

Two subtleties the checkpoints encode:

- **Harness prompts are echoes, not approvals.** Depending on the user's
  permission mode, the harness may additionally confirm the file edits or
  the run command that follow an approval — showing the same diff or
  command the user just reviewed. The governance question is asked exactly
  once per decision regardless; a harness echo neither substitutes for it
  nor duplicates it. (Phase 1 is the inverse case: there the harness prompt
  for the single analysis command IS the click, so the skill deliberately
  does not add a redundant question.)
- **Offline Mode approvals live in the run command, not the source.** The
  offline wrap derives its `approval_granted` from a per-invocation
  environment variable (`STRIX_WIRE_RUN_APPROVED=1`) set only on the single
  command the user approved. Committed source at rest grants nothing; an
  unattended CI import sees the variable unset and the policy gate denies.
  A hardcoded `approval_granted=True` would have turned the one-run
  execution approval into a permanent code-resident authorization — the
  exact "reusable bypass" invariant 7 forbids.

## How to talk about this (trust-claim discipline)

Do not market this as "fewer security prompts." The accurate claim:

> **Strix Wire asks once for read-only analysis, then pauses only at
> decisions that can change code or cause an action.**

Reducing low-value prompts is what makes the important approvals
meaningful; the count went down precisely so that attention at the two real
checkpoints could go up.
