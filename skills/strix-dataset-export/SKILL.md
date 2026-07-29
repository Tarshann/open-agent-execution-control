---
name: strix-dataset-export
description: Govern a research.dataset.export call site so that protected or unlabelled rows cannot leave via a cross-party export without a declared, versioned de-identify transform, a named approver distinct from the requester, and a payload-bound single-use execution token — leaving a signed, hash-chained, independently verifiable receipt of exactly what was admitted, what was barred, and why. Use when the user asks to "govern a dataset export", "wire dataset export policy", "gate a research data transfer", or runs /strix-dataset-export.
---

# /strix-dataset-export — refuse a protected-content transfer before it executes

This skill demonstrates one governed capability end to end:
`research.dataset.export`. It answers exactly one claim —

> Strix can refuse a protected-content transfer to an external destination
> before it executes, and leave a verifiable record of exactly what was
> barred and why.

— and nothing more. It does **not** claim to have caught a real breach, to
prevent breaches generally, to make a transfer lawful by virtue of a signed
receipt, or to have verified that any de-identification was performed
correctly. See "Out of scope" below and `ARCHITECTURE.md` §10 for the full
list of non-claims.

## Read this before anything else

1. **The export adapter is unreachable until every gate has passed.**
   `governed_export()` in `helpers/dataset_export_local.py` evaluates policy,
   then (for a cross-party destination) requires approval, then mints and
   redeems an execution token, and only then calls the caller-supplied
   `export_fn`. Every failure mode along the way raises before `export_fn`
   is ever called — this is proven behaviorally, not just claimed, by
   `tests/test_negative_policy_denial_never_invokes_adapter.py` (a Spy stands
   in for the adapter and its call count is asserted `== 0` on every denial
   path).
2. **Unlabelled and unrecognized classifications fail closed as protected.**
   There is exactly one allow-listed "not protected" classification
   (`INTERNAL_AGGREGATE`, see `Classification` in the core module). A row
   with no classification tag, or a tag nobody registered, is barred the
   same as PHI when the destination is cross-party and no transform was
   declared.
3. **A cross-party export requires a named approver distinct from the
   requester.** `evaluate_approval()` refuses self-approval before it even
   checks whether approval was granted — a coincidentally-true grant never
   masks `approver_id == requester_id`.
4. **The execution token is bound to the exact request it was minted
   against.** Payload hash, destination, declared transform, and a separate
   classification digest are all hashed together into `bindingHash`.
   Changing any of them after minting — including editing the token file by
   hand — makes redemption fail with `StrixDatasetExportTokenBindingMismatch`.
   Tokens are single-use (`redeem_execution_token` marks the file
   `REDEEMED`) and time-limited (default 300s TTL).
5. **`safe-harbor-v1` is a declared TEST transform, not a certification.**
   It masks this fixture's two direct identifiers (`mrn`, `dob`) on PHI rows.
   It does not implement, certify, or claim conformance with the HIPAA Safe
   Harbor method, and it does not prove de-identification correctness.
6. **Every receipt carries `completeness: "NOT_PROVEN"`, literally.** This
   is not boilerplate — the selective-disclosure fixture
   (`build_selective_disclosure`) proves that specific disclosed rows are
   members of the receipted set (via a Merkle inclusion proof against the
   receipt's committed root), and explicitly does not, and cannot, prove
   that the disclosed rows are the complete row set.

## The seven-stage flow

```text
rows, destination, requester
        |
        v
1. evaluate_export_policy()   -- admit/bar per row; zero admitted -> STOP
        |
        v
2. evaluate_approval()        -- CROSS_PARTY only; distinct named approver -> STOP if absent/self
        |
        v
3. mint_execution_token()     -- bound to payload+destination+transform+classification, TTL
        |
        v
4. redeem_execution_token()   -- binding must still match; single-use -> STOP if missing/expired/replayed/tampered
        |
        v
5. apply declared transform   -- only if policy marked the export deidentified
        |
        v
6. export_fn(request)         -- the governed side effect, called at most once
        |
        v
7. build + sign + chain receipt
```

## Failure modes (one exception class per gate)

- `StrixDatasetExportPolicyDenied` — every row barred, zero admitted.
- `StrixDatasetExportApprovalRequired` — cross-party, no valid distinct-approver grant.
- `StrixDatasetExportSelfApprovalDenied` — `approver_id == requester_id`.
- `StrixDatasetExportTokenMissing` — redeeming a token_id that doesn't exist.
- `StrixDatasetExportTokenExpired` — redeeming past the token's TTL.
- `StrixDatasetExportTokenAlreadyRedeemed` — replaying a spent token.
- `StrixDatasetExportTokenBindingMismatch` — payload, destination, transform, or classification changed since minting.
- `StrixDatasetExportKeyError` — the local Ed25519 signing key is missing, corrupt, or `cryptography` isn't installed.
- `StrixDatasetExportReceiptPersistenceError` — the export ran but the receipt couldn't be written durably.

## Out of scope

- **No multi-party quorum.** Only a single named approver distinct from the
  requester is required. Multi-approver vote-collection is not implemented
  here or anywhere else in this repository (see `ARCHITECTURE.md` §11).
- **No real HIPAA Safe Harbor certification.** `safe-harbor-v1` is a
  deterministic demo transform for the synthetic fixture only.
- **No integration with the hosted, closed-source `@strixgov/verifier`
  CLI.** Offline verification here (`verify_receipt`/`verify_chain`) is a
  self-contained recompute-and-compare check reusing strix-wire Local
  Mode's algorithm — it is not the same tool `strixgov-plugins` shells out
  to, and this repository has no in-repo implementation of that tool to
  integrate with.
- **No claim that a signed receipt makes the underlying transfer lawful,**
  or that the row classifications supplied to the policy were themselves
  correct.

## Contract tests

```bash
python -m pytest skills/strix-dataset-export/tests -q
```

Covers: the three required scenarios (A/B/C), every negative path listed
above, Merkle inclusion proof correctness, end-to-end offline verification
across a two-record chain, and a doc-drift check pinning the non-claims in
this file and in the module docstrings against the actual code.
