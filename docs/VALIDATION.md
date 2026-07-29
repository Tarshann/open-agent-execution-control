# Validation manifest

What was actually run, on what, with what result. Written so a third party can
reproduce it and so the pass count cannot be quoted without its conditions.

Produced for pull request #2, extended by #4 (claim scoping) and the
marketplace re-point that followed.

## Scope of this manifest

This records **repository-layer validation only**: the onboarding domain model,
the strix-wire analyzer, and the approval helpers, exercised in-process against
fixture repositories.

It does **not** record an end-to-end hosted run. No part of this manifest
demonstrates a real client onboarded through a hosted console, a hosted policy
service, a production credential vault, a live adapter, a production evidence
service, or a publicly resolvable proof. Those surfaces do not exist in this
repository. See [Known gaps](#known-gaps).

## Commit under test

| | |
|---|---|
| Base (public `main`) | `f1469b1` — merge of pull request #4 |
| Measured at | this branch, at or above that base |
| Branch | `claude/strix-console-onboarding-bcbe3a-vg8w4i` |
| Working tree | clean at time of run |

The base SHA is cited rather than the tip because a manifest cannot cite its own
hash, and a rebase changes the tip while leaving the tested content identical.
The suite is unchanged from `main` at that base; later commits on this branch
touch only manifests and documentation. To confirm at any tip:

```bash
git rev-parse HEAD && python3 -m pytest skills -q -rs
```

## Environment

| | |
|---|---|
| OS | Ubuntu 24.04.4 LTS |
| Platform | `Linux-6.18.5-x86_64-with-glibc2.39` |
| Python | 3.11.15 (GCC 13.3.0) |
| pytest | 9.1.1 |
| cryptography | 41.0.7 (system, `/usr/lib/python3/dist-packages`) |
| cffi | 2.1.0 (**installed during the session**, `/usr/local/lib/python3.11/dist-packages`) |
| Node | v22.22.2 (not exercised by these tests) |

## Command

```bash
python3 -m pytest skills -q -rs
```

Use `-rs`. Without it, skips are counted but not named, and the skips here are
load-bearing.

## Result — and the condition attached to it

Two different totals are correct depending on whether `cffi` is present. Both are
reported because quoting the first without the second would overstate what ran.

| Environment | Result |
|---|---|
| **As run here** (cffi installed) | `180 passed` · 0 skipped |
| **Fresh clone of this image** (no cffi) | `178 passed, 2 skipped` |

The second was verified, not assumed, by shadowing `_cffi_backend` with a module
that raises on import and re-running the suite.

### The two conditional tests

Both are in `skills/strix-wire/tests/test_approval_gate.py`:

| Test | Line | Skips when |
|---|---|---|
| `test_explicit_true_runs_the_operation_exactly_once` | 154 | Ed25519 backend unusable |
| `test_run_approved_pattern_grants_only_on_exactly_one` | 203 | Ed25519 backend unusable |

These are the **granted** branch of the approval gate — the path that signs a
receipt. When they skip, the suite still proves that approval is *refused*
without an explicit boolean (the invariant that prevents an unapproved
irreversible action), but it does **not** prove the signing path works.

`cryptography` does not fail cleanly here: a missing `_cffi_backend` makes the
Rust binding panic rather than raise `ImportError`, which is why the skip guard
catches `BaseException`. `requirements-test.txt` now declares the
dependency so this degradation is deliberate rather than accidental.

### Other conditional skips

Platform-gated, and **not** triggered on Linux — all ran here:

| File | Condition |
|---|---|
| `test_scope_containment.py` | whole module skips without POSIX symlink support |
| `test_report_integrity.py` (3 sites) | skips on Windows, or if the filesystem rejects a control character in a filename |

## Per-file breakdown (as run, cffi present)

| Suite | Tests | What it pins |
|---|---|---|
| `strix-wire/tests/test_approval_gate.py` | 29 | Approval refused unless an explicit boolean; env-var pattern semantics |
| `strix-wire/tests/test_consent_boundary.py` | 20 | Analysis authorization cannot become mutation or execution authority |
| `strix-wire/tests/test_consent_contract.py` | 20 | Source scans: no write/subprocess/network primitive; AST-checked `open()` modes |
| `strix-wire/tests/test_scope_containment.py` | 6 | Symlink escapes (file, directory, ancestor cycle) |
| `strix-wire/tests/test_report_integrity.py` | 11 | Repo-controlled text cannot forge the approval report |
| `strix-wire/tests/test_preflight_fails_closed.py` | 5 | An unreadable file makes the scan incomplete, not clean |
| `strix-onboard/tests/test_onboarding_state.py` | 56 | State machine, tenant binding, proof discipline |
| `strix-onboard/tests/test_readiness_view.py` | 15 | The readiness view cannot flatter or be forged |
| `strix-onboard/tests/test_skill_contract.py` | 18 | SKILL.md pinned to the model, incl. the non-claims table |
| **Total** | **180** | |

## Discrimination evidence

A passing suite proves nothing unless the tests would fail on the defect. Each
fix on this branch was checked against the prior commit:

| Fix | Method | Result |
|---|---|---|
| Symlink containment | Copied the 6 new tests into a worktree at the pre-fix commit | 6 failed |
| Preflight fail-closed | Same, 5 tests | 5 failed |
| Report sanitization | Same, 11 tests | 10 failed; 1 labelled in-file as a forward guard, not a regression test |
| Approval truthiness | Same, 29 tests | 6 failed (the ambiguous-truthy cases) |
| Wrap-execution test | Mutated the gate to always allow | New test failed; the replaced tautological test passed |
| Hardened source scans | Injected a spaced `approval_granted = True` into a SKILL.md code block, and a nested write-mode `open()` | Both caught; the previous regex/substring versions missed both |

Reproducing the worktree method:

```bash
git worktree add /tmp/prefix <pre-fix-sha>
cp skills/strix-wire/tests/test_scope_containment.py /tmp/prefix/skills/strix-wire/tests/
cd /tmp/prefix && python3 -m pytest skills/strix-wire/tests/test_scope_containment.py -q
```

## Known gaps

Required before the hosted Console onboarding objective could be considered
validated. None are addressed by this manifest.

1. No hosted tenant onboarding run (no hosted API exists in this repository).
2. No credential-vault binding test — the model accepts references only.
3. No adapter connectivity test against a real non-production integration.
4. No policy-denial or approval-required test through a hosted decision service.
5. **No real governed action executed, and therefore no evidence id.**
6. **No public verifier output.** No `npx @strixgov/verifier <id>` run against a
   publicly resolvable record is included, so "anyone can check it" is
   unproven here.
7. No cross-tenant isolation test at the persistence or API layer — the tests
   cover in-process attachment refusal only.
8. No key-rotation-during-onboarding or JWKS-outage behaviour.
9. No browser readiness view.
10. Verifier **independence is not established by this code.**
    `EvidenceVerificationResult.verified_by` is an *attribution* field: it
    requires a non-empty name, which prevents an anonymous verdict, but nothing
    checks that the named tool is independent or was actually executed. A caller
    could pass any string. Independence comes from an operator running the public
    verifier out-of-band — not from this field.

## A proof bundle would need

Not produced here. For a future release to claim independent verifiability, it
should ship:

- commit SHA;
- evidence id and the receipt itself;
- signing key id (`kid`) and the public JWKS location;
- the exact verifier command and its version or checksum;
- the expected verdict;
- the trust-scope statement (what the verdict does and does not establish).
