# Validation manifest

What was actually run, on what, with what result. Written so a third party can
reproduce it and so the pass count cannot be quoted without its conditions.

Produced for pull request #2, extended by #4 (claim scoping), #5 (marketplace
re-point), #6 (a fail-open found in one of the fixes), #9 (licence), #10 (the
review of #8 — `strix-dataset-export`, contributed from another branch — and the
four fixes it produced), #12 (merged-state accounting), and #13 (a second platform,
and the three defects it exposed).

Every fix recorded here is **merged into public `main`** and measured on **both**
platforms. This revision of the manifest is itself the only thing outstanding.

## Scope of this manifest

This records **repository-layer validation only**: the onboarding domain model,
the strix-wire analyzer, the approval helpers, and the dataset-export governance
helper, exercised in-process against fixture repositories and synthetic rows, on
Linux and Windows.

It does **not** record an end-to-end hosted run. No part of this manifest
demonstrates a real client onboarded through a hosted console, a hosted policy
service, a production credential vault, a live adapter, a production evidence
service, or a publicly resolvable proof. Those surfaces do not exist in this
repository. See [Known gaps](#known-gaps).

## Commit under test

| | |
|---|---|
| Measured at | `3d1e4db`, merged into `main` as `c36f420` (pull request #13) |
| Which is | the head of public `main`, and the parent of this manifest revision |
| Windows run | `3d1e4db` on Windows; the earlier failing run on `8f45610` |
| Working tree | clean at time of every run |

Both platforms measured the same commit, `3d1e4db`. A manifest cannot contain its
own hash, so the only thing not covered by that SHA is this file's own revision,
which adds no code.

`main` also contains `99ac613` (merge `e4ab265`, pull request #11) — a README
scope callout contributed from another branch. It is documentation-only, changes
no skill code or test, and every total below was measured with it present.

To confirm:

```bash
git rev-parse HEAD && python3 -m pytest skills -q -rs
```

The commits behind the review of #8, so a reader can review them without going
through the pull request:

| Commit | Contents |
|---|---|
| `8f244d6` | the review of #8 itself, and this manifest brought current |
| `1601e4f` | Finding 1 — token record signing |
| `9f138f9` | Findings 2, 3 and 4 — Merkle construction, redemption atomicity, corrupt-token typing |
| `458b822` | merge of #10 into `main` |
| `8f45610` | merged-state accounting (#12); the tree the **failing** Windows run was made against |
| `3d1e4db` | the three Windows fixes (W1/W2/W3); the tree both platforms now measure |
| `c36f420` | merge of #13 into `main` |

## Environments

Two platforms, both measured. The second was added after the Linux-only runs were
found to be hiding two defects — see [Windows](#windows--the-second-platform).

| | Linux (primary) | Windows (second) |
|---|---|---|
| OS | Ubuntu 24.04.4 LTS | Windows, `win32` |
| Platform | `Linux-6.18.5-x86_64-with-glibc2.39` | — |
| Python | 3.11.15 (GCC 13.3.0) | 3.11.2544.0, **Windows Store build** (`WindowsApps`) |
| pytest | 9.1.1 | 9.1.1 |
| cryptography | 41.0.7 (system, `/usr/lib/python3/dist-packages`) | 45.0.7 (wheel) |
| cffi | 2.1.0 (**installed during the session**) | 2.0.0 |
| Node | v22.22.2 (not exercised by these tests) | — |

The Windows Python being the Store build matters and is recorded deliberately: it
sandboxes handle duplication, which is what exposed the harness defect below.

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
| **Linux, cffi installed** | `282 passed` · 0 skipped |
| **Linux, fresh clone of this image** (no cffi) | `233 passed, 49 skipped` · 0 failed |
| **Windows** | `260 passed, 11 skipped` · 0 failed — measured at `3d1e4db` (271-test suite); the 11 later tests (2 verdict, 9 tool-gateway export) have not yet run there |

At `3d1e4db`, 260 + 11 = 271 matched Linux exactly, so the two platforms ran the
same suite and differed only in filesystem gates. The suite has since grown to
282: +2 for the `ERROR` verification verdict, +9 for the tool-gateway export
(signing-gated, hence the clean-checkout skips rising 40 → 49).

The second was verified, not assumed, by shadowing `_cffi_backend` with a module
that raises on import and re-running the suite.

The Linux totals were re-measured on the merge commit after each merge, not
carried forward from the pre-merge branch run. They are unchanged by the merges
themselves — expected, since a merge commit of an already-tested branch alters no
file, but a manifest that reports a merged commit without having run it is
reporting an inference. The count rose from 270 to 271 with the Windows fixes,
which replaced one contended round with three new lock tests.

### The signing-dependent tests

40 tests need a working Ed25519 backend and skip without one — 15% of the suite:

| Suite | Skipped | What stops being proven |
|---|---|---|
| `strix-wire` | 2 | The **granted** branch of the approval gate — the path that signs a receipt. Refusal without an explicit boolean is still proven. |
| `strix-dataset-export` | 38 | Receipt tampering detection, offline chain verification, self-approval refusal, the adapter-never-invoked denial paths, the whole token lifecycle, and every redemption-lock test — i.e. most of the evidence and verifiability claims. |

Worth stating plainly: 38 of `strix-dataset-export`'s 89 tests (43%) do not run in
a clean checkout, and they include the ones that substantiate its
independent-verifiability claims. **Install `requirements-test.txt` before treating
that suite's green result as meaningful.**

Counted from `-v` output, not `-rs`: `-rs` groups skips by source line, so
parametrized cases collapse and its list totals 37 where the real figure is 40.

That fraction rose from 31% when the token record became signed: minting now needs
the key, so the token-lifecycle tests are signing-gated too. The alternative was
to let minting fall back to an unsigned record, which would have preserved the
hole the signature exists to close. Failing closed and skipping loudly is the
better trade, but it is a real cost and worth seeing stated.

`cryptography` does not fail cleanly here: a missing `_cffi_backend` makes the
Rust binding panic rather than raise `ImportError`, which is why the skip guard
catches `BaseException`. `requirements-test.txt` now declares the
dependency so this degradation is deliberate rather than accidental.

### Other conditional skips

Platform-gated. All ran on Linux; these 11 are exactly what Windows skips:

| File | Tests | Condition |
|---|---|---|
| `test_scope_containment.py` | 8 | whole module skips without POSIX symlink support |
| `test_report_integrity.py` | 3 | skips on Windows, or if the filesystem rejects a control character in a filename |

## Windows — the second platform

Every number above this section was once Linux-only, and this manifest said so and
claimed nothing about Windows. That was honest but not sufficient: two defects were
sitting in code the Linux suite structurally could not reach. A Windows run found
both, and a third was found beside them.

**First Windows run** (before the fixes below):

```
6 failed, 252 passed, 12 skipped in 8.36s
```

**Second Windows run** (`3d1e4db`, after the fixes):

```
260 passed, 11 skipped in 7.97s
```

Zero failures, and the skip count fell by one because the deterministic exclusion
probe now covers Windows instead of skipping. The remaining 11 are all in
`strix-wire` — 8 symlink-scope, 3 control-character — so **every signing-gated
test ran on Windows**, including the 38 that a clean Linux checkout skips. The two
platforms have complementary blind spots rather than nested ones.

The first run's 12 skips were the expected platform gates — 8 in
`test_scope_containment.py` (POSIX symlinks), 3 in `test_report_integrity.py`
(control characters are illegal in Windows filenames), 1 for the `fcntl`-only lock
probe. Its 6 failures were two distinct causes, and **neither was a flaky test**.

### W1 — reports used platform-native path separators (product defect)

Three failures in `test_preflight_fails_closed.py`, all of this shape:

```
AssertionError: assert ['src\\billing\\charge.py'] == ['src/billing/charge.py']
```

`preflight.py`, `scanner.py` and `analyze.py` each built report paths with
`str(path.relative_to(root))`, which yields `os.sep`. So the same repository
produced `src/billing/charge.py` on Linux and `src\billing\charge.py` on Windows,
in `unreadableFiles`, `unscannedSubtrees`, `symlinksSkipped`, scanner findings and
the helper-copy list. These strings are operator-facing and meant to be diffed and
quoted as evidence, so platform-dependent output is a defect in the report, not a
detail of the host.

Fixed by emitting `.as_posix()` at all three sites. `scanner._is_test_path()`
already normalized separators internally, so test-path exclusion was behaving
correctly on Windows — only the emitted string was wrong.

**Discrimination.** The three tests were already correct and already
discriminating; they asserted the POSIX form and failed on the native one. What
was missing was not test quality but platform coverage — and note that on Linux
`str()` and `as_posix()` are identical, so **no Linux run can ever catch a
regression here.** The guard for W1 is Windows-only, by nature: the first Windows
run is its discrimination evidence, and the second (all three tests passing) is its
fix evidence. Neither could have come from this image.

### W2 — the contended redemption probe could not start on Windows (harness defect)

Three failures, one per round of
`test_concurrent_redemption_spends_the_token_exactly_once`:

```
PermissionError: [WinError 5] Access is denied
  ... multiprocessing/reduction.py, in duplicate: _winapi.DuplicateHandle(
```

`ProcessPoolExecutor` startup duplicates a pipe handle, and the Windows Store
build of Python sandboxes that call. The probe never reached a redemption, so the
"6 failed" said nothing about whether the lock holds — and it failed on precisely
the one platform whose lock implementation nothing else covered.

Rewritten to launch N independent `subprocess.Popen` children (the outer
`subprocess` call already worked on that Python) released together through a
barrier file: each child signals readiness, then spins until a `go` file appears.
A harness failure now `pytest.fail`s with an explicit "this is a harness failure,
not a lock result" message, so the two can never again be confused.

**This made the test stronger, not merely portable.** With the lock disabled:

| Probe | Redemptions that succeeded |
|---|---|
| Old, `ProcessPoolExecutor` (16 workers) | 2 of 16 |
| New, `Popen` + barrier (10 racers) | **10 of 10** |

The pool's own scheduling was serialising the racers; an explicit barrier makes
the race deterministic instead of incidental. Rounds dropped from 3 to 2 and
racers from 16 to 10, which is affordable precisely because the signal is no
longer probabilistic.

### W3 — the Windows lock branch silently degraded to no lock (product defect)

Found by reading `_token_lock` in light of W2 — not by a failing test, because no
test could reach it:

```python
msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
except (ImportError, OSError):
    pass
```

`LK_LOCK` retries ten times at one-second intervals and then raises, and that
raise was **caught and ignored**. On Windows, a redemption contended for more than
ten seconds would proceed with no mutual exclusion at all — the fix for Finding 3
becoming a fix-shaped no-op under exactly the load it exists for. The `# pragma: no
cover - non-POSIX` on that branch was the visible tell that nothing exercised it.

Now two cases, deliberately not alike:

| Situation | Behaviour |
|---|---|
| No locking module on the platform at all | proceeds — documented best effort, unchanged |
| A locking module exists and the lock cannot be taken | raises `StrixDatasetExportTokenLockUnavailable` |

The second is the fail-closed choice: a refused redemption is retryable, a
double-spend is not. Windows now polls `LK_NBLCK` against an explicit
`_TOKEN_LOCK_TIMEOUT_SECONDS = 30` deadline rather than relying on `LK_LOCK`'s
undocumented-in-practice ten-second give-up.

Both cases are tested on Linux by injecting a failing and an absent locking
module, so the distinction is pinned on any platform — and the deterministic
exclusion probe gained an `msvcrt` branch, so it runs on Windows instead of
skipping.

**`msvcrt.locking` cross-process exclusion is now measured, not inferred.** In the
second Windows run, `test_the_token_lock_excludes_a_second_holder` passed: while
`_token_lock` held the sidecar file, a separate process attempting
`msvcrt.locking(fd, LK_NBLCK, 1)` was refused, and acquired it once the holder
released. That is the assertion the Windows branch previously had no test for at
all, and it is the load-bearing one — a contended probe passing could in principle
reflect racers that happened to serialise, whereas a non-blocking acquire being
refused cannot.

### What Windows measured, and what it still does not

Measured on Windows by the second run: W1's three report-path assertions, the
barrier-released contended probe (2 rounds), `msvcrt` cross-process exclusion, the
lock-unavailable fail-closed path, the no-locking-module best-effort path, and all
38 signing-gated tests that a clean Linux checkout skips.

Still **not** measured on Windows, and not claimed:

- **Symlink scope containment.** All 8 `test_scope_containment.py` tests skip
  there. Windows does have directory symlinks and junctions (`mklink /D`, `/J`),
  and `preflight.py`'s containment logic is what stops a link out of the root
  being followed or silently dropped — so the platform where that logic is least
  tested is one where the feature genuinely exists. The module skips on
  `sys.platform == "win32"` rather than probing whether this particular Windows
  can create a symlink, which is the narrower gate it should be.
- **Control-character report forgery.** 3 of the 11 skips; the filesystem refuses
  the filenames the test needs, which is itself a mitigation, not a verification.
- **The `LK_LOCK` ten-second give-up under real sustained contention.** W3's fix
  is verified by construction and by the exclusion probe; nobody has held a
  Windows token lock for over thirty seconds to watch the new deadline fire.

## Per-file breakdown (as run, cffi present)

| Suite | Tests | What it pins |
|---|---|---|
| `strix-wire/tests/test_approval_gate.py` | 29 | Approval refused unless an explicit boolean; env-var pattern semantics |
| `strix-wire/tests/test_consent_boundary.py` | 20 | Analysis authorization cannot become mutation or execution authority |
| `strix-wire/tests/test_consent_contract.py` | 20 | Source scans: no write/subprocess/network primitive; AST-checked `open()` modes |
| `strix-wire/tests/test_scope_containment.py` | 8 | Symlink escapes (file, directory, ancestor cycle) and the out-of-root completeness STOP |
| `strix-wire/tests/test_report_integrity.py` | 11 | Repo-controlled text cannot forge the approval report |
| `strix-wire/tests/test_preflight_fails_closed.py` | 5 | An unreadable file makes the scan incomplete, not clean |
| `strix-onboard/tests/test_onboarding_state.py` | 56 | State machine, tenant binding, proof discipline |
| `strix-onboard/tests/test_readiness_view.py` | 15 | The readiness view cannot flatter or be forged |
| `strix-onboard/tests/test_skill_contract.py` | 18 | SKILL.md pinned to the model, incl. the non-claims table |
| `strix-dataset-export/tests/` (19 files) | 89 | Policy-before-execution, token binding/replay/expiry, token record signing, **concurrent-redemption atomicity** (deterministic exclusion on both POSIX and Windows, plus a barrier-released contended probe), **lock-unavailable fail-closed vs no-module best-effort**, **Merkle construction**, receipt tampering, offline chain verification, doc drift |
| **Total** | **271** | |

## Discrimination evidence

A passing suite proves nothing unless the tests would fail on the defect. Every
fix recorded in this manifest was checked against the pre-fix commit — by
worktree for the strix-wire work, by mutation for the dataset-export work:

| Fix | Method | Result |
|---|---|---|
| Symlink containment | Copied the 6 new tests into a worktree at the pre-fix commit | 6 failed |
| Preflight fail-closed | Same, 5 tests | 5 failed |
| Report sanitization | Same, 11 tests | 10 failed; 1 labelled in-file as a forward guard, not a regression test |
| Approval truthiness | Same, 29 tests | 6 failed (the ambiguous-truthy cases) |
| Wrap-execution test | Mutated the gate to always allow | New test failed; the replaced tautological test passed |
| Hardened source scans | Injected a spaced `approval_granted = True` into a SKILL.md code block, and a nested write-mode `open()` | Both caught; the previous regex/substring versions missed both |
| Directory-symlink completeness | Reverted the `unscanned_subtrees` STOP clause | 2 failed |
| `strix-dataset-export` (#8), 8 guards | Mutated each guard in turn — see the review section below | 8/8 caught |
| Token record signing (Finding 1 fix) | Removed the verification call; removed the re-sign after status flip | 6 failed; 4 failed |
| Merkle: duplicate-id refusal (Finding 2) | Disabled the duplicate check | 3 failed |
| Merkle: odd-node promotion (Finding 2) | Reverted to hashing the odd node with itself | 5 failed |
| Merkle: leaf count bound (Finding 2) | Returned the bare pairwise root | 3 failed |
| Merkle: strict proof positions (Finding 2) | Reinstated the silent fall-through to "right" | 1 failed |
| Redemption atomicity (Finding 3) | Disabled the token lock | 4 failed |
| Report path separators (W1) | Windows run, before and after | **Not discriminable on Linux** — `str()` and `as_posix()` are identical here. 3 failed before the fix, 3 passed after, both on Windows. That platform is the guard. |
| Lock failure is fail-closed (W3) | Restored the swallow (`except OSError: pass`) | 1 failed |
| The lock itself, after the probe rewrite (W2) | Took no lock at all | 3 failed — the deterministic probe plus both contended rounds, each reporting 10 of 10 redemptions |

Reproducing the worktree method:

```bash
git worktree add /tmp/prefix <pre-fix-sha>
cp skills/strix-wire/tests/test_scope_containment.py /tmp/prefix/skills/strix-wire/tests/
cd /tmp/prefix && python3 -m pytest skills/strix-wire/tests/test_scope_containment.py -q
```

## A defect found in one of the fixes

Recorded here because a manifest that lists only successful fixes is not a
validation record.

The symlink containment fix stopped following directory symlinks — correct for
scope — and thereby stopped scanning any subtree behind a link pointing out of
the root, with nothing recording that the scan had covered less than the
repository. A repo laid out that way (shared-package or monorepo) was certified
"No governance or production markers found; safe to proceed" on a scan that never
read its source. Same fail-open as an unreadable file, through a different door,
and inconsistent with the unreadable-file fix shipped one commit later.

Repaired by separating scope from completeness: a link whose target is inside the
root is skipped harmlessly (the walk reaches the target directly); a link whose
target is outside is recorded in `unscannedSubtrees` and forces `verdict: STOP`.
The visited set also now ignores a zero inode, which some Windows and network
filesystems report and which would collide across directories.

Mirror commit `b004731`, merged via #6.

## Review of #8 (`strix-dataset-export`)

Contributed from another branch and merged before review. Assessed here against
the same standard as the rest: do the tests discriminate, and do the claims match
the code.

### What holds up

- **42 tests pass, and 8 of 8 security guards are caught by mutation.** Each
  guard was disabled in turn and the suite re-run: self-approval (3 failed),
  approval gate (23), token replay (1), token expiry (1), token binding (6),
  receipt hash recompute (1), Ed25519 verification (1), Merkle inclusion (2).
  Nothing survived.
- **`verify_receipt` does not trust its input.** It resolves the public key from
  the local registry by the receipt's `kid`, recomputes `evidenceHash` and
  `proofChainHash`, and verifies the signature over the canonicalized payload.
  Verification failure of any kind resolves to `INVALID` rather than crashing.
- **Merkle leaf and internal nodes are domain-separated** by distinct key names
  (`rowId`/`classification`/`fieldsHash` vs `left`/`right`), which blocks the
  usual node-confusion second-preimage attack.
- **No row content reaches the evidence.** Exporting rows carrying canary values
  produced a receipt, an evidence record and a chain entry containing neither
  canary — only hashes. Verified by grep against everything persisted under the
  state directory.
- **`test_doc_drift.py` is a genuine contract test**, not string-matching for its
  own sake: it pins the `COMPLETENESS_CLAIM` constant against the literal in two
  documents, and checks the exception list bidirectionally — every documented
  exception is a real class, and every real class is documented.
- **`GATE-REPORT.md` is honest about its own standing.** It states that no
  canonical local Gate D/F/G/H template exists in this repository, labels its
  gate lettering best-effort rather than SGRF-conformant, and carries a real
  non-claims section.

### Finding 1 — the execution token is unauthenticated (medium) — **RESOLVED**

> Fixed, and merged to `main` in #10. The token record now carries its own Ed25519 signature
> over every field, verified before any field is trusted and re-signed when
> redemption flips `status`. Both demonstrated attacks are refused, and 11
> regression tests pin it. Original finding and evidence retained below.


`_binding_hash` covers the payload hash, destination, transform and
classification digest. It does **not** cover `status`, `expiresAt` or `tokenId`,
and the token record is plain JSON on disk. Two of the three claimed enforcement
properties are therefore not tamper-evident. Confirmed by experiment:

| Edit to the token file | Result |
|---|---|
| `status: REDEEMED` -> `MINTED` | **replay succeeded** — single-use defeated |
| `expiresAt` -> far future | **expired token accepted** — time limit defeated |
| a bound field (destination) | correctly refused (`TokenBindingMismatch`) |

`GATE-REPORT.md` §4 reads "Tampering with any bound field after minting —
including hand-editing the token file — produces a
`StrixDatasetExportTokenBindingMismatch` on redemption ... Replay is refused ...
and expiry is enforced." That is literally true of *bound* fields, but the
parenthetical invites the reading that file tampering is caught generally. It is
not, for precisely the two fields carrying the replay and expiry properties, and
`test_negative_token_replay.py` / `test_negative_expired_token.py` prove those
only against a non-tampering caller.

**Resolution.** `mint_execution_token` now signs the whole record — deliberately
the whole record rather than a chosen subset, so a field added later cannot
silently sit outside the protected set. `redeem_execution_token` verifies that
signature *before* reading `status` or `expiresAt`, and re-signs after the status
flip, so resetting `status` to `MINTED` cannot restore a valid signature.
Unsigned records, unknown signing keys and malformed signatures are all refused
with `StrixDatasetExportTokenSignatureInvalid`.

Re-run of the original experiment after the fix:

| Edit to the token file | Result |
|---|---|
| `status: REDEEMED` -> `MINTED` | refused (`TokenSignatureInvalid`) |
| `expiresAt` -> far future | refused (`TokenSignatureInvalid`) |
| `tokenId` swapped | refused (`TokenSignatureInvalid`) |
| signature stripped | refused (`TokenSignatureInvalid`) |
| signed by an unregistered key | refused (`TokenSignatureInvalid`) |
| a bound field (destination) | refused (`TokenBindingMismatch`) — the two failures stay distinguishable |
| untouched token | redeems exactly once, then `TokenAlreadyRedeemed` |

**Trust scope, stated precisely.** This makes the record tamper-*evident* against
anything that cannot sign with this project's local key. It is not a defence
against someone holding that key, which lives under `<state_dir>/keys/` on the
same machine — the same `LOCAL_MACHINE_ASSERTION` boundary the rest of Local Mode
declares, not a stronger one. `SKILL.md` says this in the same words.

### Finding 2 — Merkle odd-leaf duplication collides (low) — **RESOLVED**

> Fixed, and merged to `main` in #10. The investigation found two further defects
> in the same primitive. Original finding retained below, followed by what was
> actually wrong and what was done.


`build_merkle_tree` duplicates the final node on an odd count, so `[a,b,c]` and
`[a,b,c,c]` produce an identical root — confirmed by experiment. This does **not**
violate any current claim: the skill disclaims completeness everywhere and every
receipt carries `completeness: "NOT_PROVEN"`, and membership proofs remain sound.
It matters as a constraint on the future: the root is not a reliable commitment to
the multiset of rows, so no completeness or row-count claim may ever be built on
it without changing the construction.

**What was actually wrong.** Investigating it turned up two more defects, and
reordered which one mattered most:

1. **Duplicate `row_id`s were accepted** — and this is the load-bearing defect.
   `merkle_inclusion_proof()` resolves a `row_id` to a single index, so a proof
   for a duplicated id attested only the first copy and read as *false* for the
   second. It is also what made the collision reachable: `[a,b,c,c]` requires a
   duplicate id. Refusing duplicates fixes the proof ambiguity and makes the
   demonstrated collision unconstructible.
2. **The odd node was hashed with itself** rather than promoted. With duplicates
   refused this is no longer exploitable, so promotion is defence in depth — the
   root no longer depends on the duplicate check staying in place. It remains
   directly observable: a duplicating build emits a proof step whose sibling is
   the node's own leaf hash; a promoting build emits no step for that level. That
   signature is what the regression test pins, because the collision itself can
   no longer be built.
3. **The leaf count was not bound into the root**, so `totalRowCountCommitted` in
   a disclosure was pure assertion. It is now folded into the published root with
   a versioned domain tag, and `verify_merkle_inclusion()` requires the count —
   verification cannot be done without committing to a row number.

Plus a hardening found while testing: `_apply_proof` treated any unrecognised
`position` as `"right"`, silently reinterpreting a hostile proof; and a non-mapping
proof step raised `AttributeError` out of `verify_merkle_inclusion` instead of
returning `False`. Both are now refusals.

**Not claimed.** Membership proofs were sound before and remain sound. None of
this makes the root a completeness proof — completeness is still `NOT_PROVEN`, and
that disclaimer survives a failed verification (tested).

### Finding 3 — token redemption is not atomic (low) — **RESOLVED**

> Fixed, and merged to `main` in #10. Original finding and the measurement that
> established it are retained below.

`redeem_execution_token` read the file, checked `status`, then wrote — three steps
with no mutual exclusion, so two concurrent redemptions could both read `MINTED`,
both pass the check, and both proceed. Signing the record does not help: both
readers see a legitimately signed token.

**Measured, not theorised.** Sixteen concurrent processes against one token:

| Build | Successful redemptions |
|---|---|
| Before | **2** — the token was spent twice |
| After | 1, with 15 clean `TokenAlreadyRedeemed` |

**Resolution.** The whole read-check-write runs under an exclusive OS-level lock
(`fcntl.flock`, `msvcrt.locking` on Windows) taken on a sidecar `.lock` file — not
on the record, so the record can be rewritten while the lock is held. OS locks
release when the descriptor closes or the process dies, so an interrupted
redemption cannot wedge a token, which a marker-file mutex would. If neither
locking module is available the body still runs: serialising is an improvement
where the platform supports it, and refusing to redeem at all on an exotic
platform would be the worse failure.

Two tests, because a concurrency test alone is a weak guard: one deterministic
(holding the lock excludes a second process, probed non-blocking), one under real
contention across three rounds. Disabling the lock fails four of them.

### Finding 4 — corrupt-token handling is uneven (nit) — **RESOLVED**

> Fixed, and merged to `main` in #10.

A token file that parses but lacks `expiresAt` raised `KeyError` rather than a
`StrixDatasetExport*` exception. Malformed JSON was handled; a missing key was not.

**Resolution.** Presence is checked before the field is read, so a structurally
valid record missing `expiresAt` raises `StrixDatasetExportTokenMissing` — the
same type as a corrupt file, since both mean "this is not a usable token" — and
`status` is read with `.get()` rather than indexed. Pinned by
`test_a_token_missing_expiry_is_a_token_error_not_a_keyerror`, which re-signs the
truncated record with the real key first — otherwise the signature check would
reject it before the missing field was ever reached, and the test would pass
without exercising the fix.

### Not assessed

The 1,204-line helper was reviewed at its security-critical surfaces — policy
ordering, token lifecycle, receipt verification, Merkle construction, selective
disclosure, evidence persistence. The `safe-harbor-v1` transform's
de-identification *correctness* was not assessed, and the skill does not claim it:
it is documented as a declared test transform that certifies nothing.

## Known gaps

Required before the hosted Console onboarding objective could be considered
validated. Item 5 is closed by [`PROOF-ATTEMPT.md`](./PROOF-ATTEMPT.md); item 6 is
narrowed by it from "not attempted" to a named blocker. The rest are not addressed
by this manifest.

1. No hosted tenant onboarding run (no hosted API exists in this repository).
2. No credential-vault binding test — the model accepts references only.
3. No adapter connectivity test against a real non-production integration.
4. No policy-denial or approval-required test through a hosted decision service.
5. ~~No real governed action executed, and therefore no evidence id.~~
   **Closed.** One executed, mutating a file on disk, decision
   `REQUIRE_APPROVAL_GRANTED`, evidence id `local_ev_19280411de58494ebd98ef099e9d8fee`,
   signature valid under this repository's own offline check. See
   [`PROOF-ATTEMPT.md`](./PROOF-ATTEMPT.md).
6. ~~No public verifier output.~~ **Closed for Local Mode's trust scope.** The
   raw `local-receipt-v1` is still refused (`unknown schemaVersion`,
   `@strixgov/verifier@1.20.0`) — but `export_tool_gateway_receipt()` projects a
   verified local receipt into the tool-gateway `schemaVersion: "1"` shape
   (which, unlike v2, needs no `tenantId`/`environment` — nothing is invented),
   and the published verifier returned **`Status: VERIFIED`, exit 0** on the real
   receipt, and `TAMPERED`, exit 1, on a one-field forgery of it. What remains
   open is narrower and stated precisely in
   [`PROOF-ATTEMPT.md`](./PROOF-ATTEMPT.md): the trust anchor is the local key,
   so the record is reproducible by anyone holding the receipt + JWKS files but
   not publicly *resolvable* — a hosted evidence record under Strix-custody keys
   is still the hosted platform's to produce.
7. No cross-tenant isolation test at the persistence or API layer — the tests
   cover in-process attachment refusal only.
8. No key-rotation-during-onboarding or JWKS-outage behaviour.
9. No browser readiness view.
10. **Symlink scope containment is unverified on Windows.** All 8
    `test_scope_containment.py` tests skip there, on a platform that does have
    directory symlinks and junctions. The module gates on `sys.platform ==
    "win32"` rather than on whether this host can actually create a symlink,
    which is the narrower gate it should use.
11. **W1 has no automated guard on Linux.** Report paths are asserted in POSIX
    form, which `str()` also produces on POSIX, so a regression to native
    separators would pass every Linux run. Only a Windows run can catch it —
    meaning CI on Linux alone would let it back in.
12. **No CI.** Both platforms are run by hand. Everything in this manifest is a
    point-in-time measurement by a named human on a named machine, not a gate
    that blocks a regression from merging.
13. Verifier **independence is not established by this code.**
    `EvidenceVerificationResult.verified_by` is an *attribution* field: it
    requires a non-empty name, which prevents an anonymous verdict, but nothing
    checks that the named tool is independent or was actually executed. A caller
    could pass any string. Independence comes from an operator running the public
    verifier out-of-band — not from this field.

## A proof bundle would need

[`PROOF-ATTEMPT.md`](./PROOF-ATTEMPT.md) now assembles every item on this list,
including the verdict:

| Element | Status in `PROOF-ATTEMPT.md` |
|---|---|
| commit SHA | ✅ `f46cee5` (action executed there; export added after) |
| evidence id and the receipt itself | ✅ real, executed, quoted in full |
| signing key id (`kid`) and public key | ✅ `local-744c02d8284506d0`, exported as JWKS |
| the exact verifier command and its version | ✅ `npx @strixgov/verifier@1.20.0 receipt … --jwks …` |
| the expected verdict | ✅ **obtained**: `VERIFIED`, exit 0 — with the discrimination check (`TAMPERED`, exit 1, on a one-field forgery) |
| the trust-scope statement | ✅ independent *code*, local *trust anchor* — a `LOCAL_MACHINE_ASSERTION` checkable by an external tool, not a hosted-custody claim |

The earlier revision of this section noted that a bundle with every row populated
except an honestly-obtained verdict proves nothing. The verdict row is now real —
and the trust-scope row is what keeps it from being quoted as more than it is:
reproducible by anyone holding the two files, publicly resolvable by no one,
because no hosted record exists.
