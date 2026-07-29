# Validation manifest

What was actually run, on what, with what result. Written so a third party can
reproduce it and so the pass count cannot be quoted without its conditions.

Produced for pull request #2, extended by #4 (claim scoping), #5 (marketplace
re-point), #6 (a fail-open found in one of the fixes), #9 (licence), and #10 (the
review of #8 — `strix-dataset-export`, contributed from another branch — and the
four fixes it produced). Every fix recorded here is **merged into public `main`**
— nothing below describes a pending proposal. This revision of the manifest is
itself the only thing outstanding.

## Scope of this manifest

This records **repository-layer validation only**: the onboarding domain model,
the strix-wire analyzer, the approval helpers, and the dataset-export governance
helper, exercised in-process against fixture repositories and synthetic rows.

It does **not** record an end-to-end hosted run. No part of this manifest
demonstrates a real client onboarded through a hosted console, a hosted policy
service, a production credential vault, a live adapter, a production evidence
service, or a publicly resolvable proof. Those surfaces do not exist in this
repository. See [Known gaps](#known-gaps).

## Commit under test

| | |
|---|---|
| Measured at | `458b822` — merge of pull request #10 into `main` |
| Which is | the head of public `main`, and the parent of this manifest revision |
| Working tree | clean at time of run |

Earlier revisions of this manifest cited a base SHA rather than a tip, because a
manifest cannot contain its own hash. That caveat no longer applies to the
numbers below: they were re-run **on the merge commit itself**, after #10 landed,
so the commit named above is exactly the tree that produced them. The only commit
after it is the one carrying this paragraph, which touches this file alone.

`main` also contains `99ac613` (merge `e4ab265`, pull request #11) — a README
scope callout contributed from another branch. It is documentation-only, changes
no skill code or test, and both totals below were measured with it present.

To confirm:

```bash
git rev-parse HEAD && python3 -m pytest skills -q -rs
```

The commits carrying the four fixes, so a reader can review them without going
through the pull request:

| Commit | Contents |
|---|---|
| `8f244d6` | the review of #8 itself, and this manifest brought current |
| `1601e4f` | Finding 1 — token record signing |
| `9f138f9` | Findings 2, 3 and 4 — Merkle construction, redemption atomicity, corrupt-token typing |
| `458b822` | merge of #10 into `main` |

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
| **As run here** (cffi installed) | `270 passed` · 0 skipped |
| **Fresh clone of this image** (no cffi) | `231 passed, 39 skipped` · 0 failed |

The second was verified, not assumed, by shadowing `_cffi_backend` with a module
that raises on import and re-running the suite.

Both were re-measured on `458b822` after the merge, not carried forward from the
pre-merge branch run. They are unchanged from it — expected, since a merge commit
of an already-tested branch alters no file, but a manifest that reports a merged
commit without having run it is reporting an inference.

### The signing-dependent tests

39 tests need a working Ed25519 backend and skip without one — 14% of the suite:

| Suite | Skipped | What stops being proven |
|---|---|---|
| `strix-wire` | 2 | The **granted** branch of the approval gate — the path that signs a receipt. Refusal without an explicit boolean is still proven. |
| `strix-dataset-export` | 37 | Receipt tampering detection, offline chain verification, self-approval refusal, the adapter-never-invoked denial paths, and the whole token lifecycle — i.e. most of the evidence and verifiability claims. |

Worth stating plainly: 37 of `strix-dataset-export`'s 88 tests (42%) do not run in
a clean checkout, and they include the ones that substantiate its
independent-verifiability claims. **Install `requirements-test.txt` before treating
that suite's green result as meaningful.**

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
| `strix-wire/tests/test_scope_containment.py` | 8 | Symlink escapes (file, directory, ancestor cycle) and the out-of-root completeness STOP |
| `strix-wire/tests/test_report_integrity.py` | 11 | Repo-controlled text cannot forge the approval report |
| `strix-wire/tests/test_preflight_fails_closed.py` | 5 | An unreadable file makes the scan incomplete, not clean |
| `strix-onboard/tests/test_onboarding_state.py` | 56 | State machine, tenant binding, proof discipline |
| `strix-onboard/tests/test_readiness_view.py` | 15 | The readiness view cannot flatter or be forged |
| `strix-onboard/tests/test_skill_contract.py` | 18 | SKILL.md pinned to the model, incl. the non-claims table |
| `strix-dataset-export/tests/` (19 files) | 88 | Policy-before-execution, token binding/replay/expiry, token record signing, **concurrent-redemption atomicity**, **Merkle construction**, receipt tampering, offline chain verification, doc drift |
| **Total** | **270** | |

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
