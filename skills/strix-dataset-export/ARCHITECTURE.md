# Architecture — `research.dataset.export`

## 1. Scope and status

This is a new, self-contained skill demonstrating one governed capability
end to end, offline and local-only. It is a demo-grade vertical slice, not
the hosted Strix runtime — there is no network call anywhere in this skill,
no Strix account, and no dependency on the closed-source
`@strixgov/verifier` CLI. Everything it proves, it proves by recomputation
against files on local disk.

It is genuinely new within this repository: no existing file implements
data classification, execution tokens, a requester/approver distinction, or
Merkle-based selective disclosure. What it reuses — not by import, but by
copying the same algorithm, per this repo's house style of self-contained,
copyable helper files — is the canonical-JSON hashing, Ed25519 signing, and
hash-chained receipt ledger already proven out in
`skills/strix-wire/helpers/governed_action_local.py`.

## 2. The seven-stage flow

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

`governed_export()` (in `helpers/dataset_export_local.py`) is the single
entry point that sequences all seven stages. Every stage before (6) can
raise; `export_fn` is called at most once, and only after (1)-(4) have all
succeeded.

## 3. Data classification model and the fail-closed allow-list

`NOT_PROTECTED_CLASSIFICATIONS` is an allow-list of exactly one entry,
`INTERNAL_AGGREGATE`. Every other value — `PHI`, `None` (no tag at all), or
any string nobody has registered — is protected by construction. Adding a
new "safe" classification requires a conscious, reviewed edit to this
constant; it can never become safe merely because nothing barred it.

For a `CROSS_PARTY` destination with no registered transform, each barred
row gets one of three reason codes:

- `PHI_PROTECTED_NO_DEIDENTIFY_TRANSFORM`
- `UNLABELLED_FAILS_CLOSED_AS_PROTECTED`
- `UNKNOWN_CLASSIFICATION_FAILS_CLOSED_AS_PROTECTED`

If a transform name+version *was* declared but isn't in the registry, every
protected row instead gets `UNREGISTERED_DEIDENTIFY_TRANSFORM` — the same
fail-closed outcome as declaring nothing, but with a reason that tells the
operator their declaration didn't match anything real, rather than silently
behaving as if they'd declared nothing.

An `INTERNAL` destination admits every row regardless of classification —
internal distribution is not the transfer this policy exists to gate.

## 4. The `safe-harbor-v1` transform contract (and its non-claim)

`_apply_safe_harbor_v1` is deterministic: the same row always produces the
same masked row. For a `PHI`-classified row it replaces the fixture's two
direct-identifier fields (`mrn`, `dob`) with a fixed placeholder; every
other classification passes through unchanged, since this fixture places no
direct identifiers on them.

**This is a declared TEST transform for the synthetic fixture only.** It
does not implement, certify, or claim conformance with the HIPAA Safe
Harbor method (which requires removing eighteen specific identifier
categories and a documented re-identification risk assessment — neither of
which this function does), and it does not prove that de-identification was
performed correctly for any real dataset. `deidentified=True` on a receipt
means "the declared transform ran," not "this export is legally
de-identified."

## 5. The approval gate

`evaluate_approval()` is a no-op for `INTERNAL`. For `CROSS_PARTY`:

1. If `approver_id == requester_id`, raise `StrixDatasetExportSelfApprovalDenied`
   — checked *before* the granted flag, so a coincidentally-true grant can
   never mask self-approval.
2. Otherwise require `approval_granted is True` (a strict identity check,
   not truthiness — mirrors strix-wire's `approval_granted is not True`
   gate) and a non-empty, distinct `approver_id`, else raise
   `StrixDatasetExportApprovalRequired`.

There is no persistent, pre-granted approval record independent of the
call — approval is supplied by the caller at call time, the same shape as
strix-wire's Offline Mode gate. What's new here is the identity
distinction; strix-wire's gate has no approver-identity concept at all.

## 6. The execution token

Net-new primitive; no other file in this repository mints, binds, expires,
or redeems a token before an action's side effect. Structure:

- `classification_digest(rows)` — a canonical hash of the `{row_id,
  classification}` snapshot actually evaluated, independent of the payload
  hash, so a classification swap alone still invalidates a token.
- `mint_execution_token(...)` — writes
  `<state_dir>/dataset-export/tokens/<token_id>.json` with `status=MINTED`,
  a `bindingHash` over `{payloadHash, destinationVisibility, destinationId,
  transformName, transformVersion, classificationDigest}`, and an
  `expiresAt` (default 300s TTL).
- `redeem_execution_token(...)` — the single dispatch point for every
  failure mode: missing token, already-redeemed (replay), expired, or a
  binding mismatch (payload, destination, transform, or classification
  changed since minting — "editing the file voids it," literally, since the
  binding hash is recomputed from the redemption-time arguments, not read
  back from the file). On success the token file becomes `status=REDEEMED`
  and can never be redeemed again.

`governed_export()` is the only caller that reaches the export adapter, and
it always calls `redeem_execution_token` immediately before invoking it —
there is no lower-level path that skips this.

## 7. The evidence receipt

Reuses strix-wire Local Mode's exact canonicalization (`json.dumps(...,
sort_keys=True, separators=(",",":"), ensure_ascii=False, allow_nan=False)`
→ SHA-256), Ed25519 signing, local key registry
(`<state_dir>/keys/registry.json`), and hash-chain shape (`evidenceHash` /
`prevHash` / `chainSeq` / `proofChainHash`), targeting the **same**
`<state_dir>/evidence/receipts.jsonl` file strix-wire itself writes to — one
workspace, one signing key, one evidence chain, shared across capabilities.
Full field list is documented in the `_build_receipt_payload` docstring in
`helpers/dataset_export_local.py`; the two fields most specific to this
capability are `decisionOutcome` (the policy verdict: `ADMIT_ALL` /
`ADMIT_PARTIAL` / `ADMIT_NONE`) and `executionOutcome` (the adapter run:
`SUCCEEDED` / `FAILED`) — deliberately distinct fields, so a policy that
admitted rows but whose adapter then failed is visible as such, not
conflated with a policy denial.

## 8. Selective disclosure via Merkle inclusion proofs

`build_merkle_tree()` builds a standard binary hash tree (leaves sorted by
`row_id` for determinism; an unpaired last node is duplicated as its own
sibling) over the full row set evaluated by policy — including barred rows,
so their membership can later be proven without disclosing admitted rows'
content, or vice versa. `build_selective_disclosure(rows, row_ids)` reveals
only the requested rows plus their inclusion proofs and the committed root;
`verify_selective_disclosure()` confirms each disclosed row is genuinely a
member of the set committed to that root.

**What this proves:** the disclosed rows are members of the exact row set
this receipt's Merkle root commits to. **What this does not prove:** that
the disclosed rows are the complete barred set, the complete admitted set,
or the complete original dataset — every disclosure and every verification
result carries this disclaimer verbatim (`_COMPLETENESS_DISCLAIMER`), and
every receipt separately carries `completeness: "NOT_PROVEN"`.

## 9. Independent offline verification (and why it is not the hosted verifier)

`verify_receipt()` and `verify_chain()` recompute `evidenceHash` and
`proofChainHash` from the stored payload, resolve the signing key from the
local registry, and Ed25519-verify the signature — trusting nothing that
was merely stored on the record itself. This mirrors
`governed_action_local.py`'s `_verify_local_record_for_reliance` philosophy
exactly: recompute and compare.

This is **not** an integration with `@strixgov/verifier`, the closed-source
npm tool `strixgov-plugins`' `/strix-verify` and `/strix-verify-offline`
commands shell out to. That tool has no vendored implementation anywhere in
this repository — no algorithm detail, no JWKS schema, nothing to integrate
against. The verifier here is a local, self-contained recompute-and-compare
check over this skill's own local key registry, following the one
verification pattern that *does* have a real, working, in-repo
implementation (strix-wire Local Mode).

## 10. Threat model / non-claims

A receipt from this helper is a `LOCAL_MACHINE_ASSERTION`: it proves the
holder of a specific local Ed25519 key produced a hash-chained,
tamper-evident record of one policy evaluation and (if it proceeded) one
executed export. It does **not** prove:

- that the `safe-harbor-v1` transform meets any legal or regulatory
  de-identification standard, or that de-identification was performed
  correctly for any real dataset (§4);
- that a signed receipt makes the underlying transfer lawful;
- that the row classifications supplied to the policy were themselves
  correct — this policy trusts its `classification` input, it does not
  independently re-derive it from row content;
- that a disclosed subset of rows is the complete row set (§8);
- that this mechanism would have caught any particular real-world
  export — detecting the call site in the first place is a different
  concern (`skills/strix-wire`'s scanner), out of scope here;
- that this prevents data breaches generally.

## 11. Out of scope

- **Multi-party (quorum) approval.** Only a single named approver distinct
  from the requester is required. Nothing in this repository — including
  `skills/strix-onboard`'s `ApprovalRoute.minimum_approvals` — implements
  runtime vote-collection; quorum elsewhere in this repo is only a
  verification-record-type *name* for the hosted, closed-source verifier.
- **Real HIPAA Safe Harbor certification** (§4).
- **Integration with the hosted `@strixgov/verifier` CLI** (§9).
- **Detecting the export call site in a real codebase** — that's
  `skills/strix-wire`'s job, not this skill's.
