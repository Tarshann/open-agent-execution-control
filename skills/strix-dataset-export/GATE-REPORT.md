# Gate Report — `research.dataset.export`

## 1. Applicability declaration

**This repository has no canonical local template for Gates D, F, G, or
H.** A repo-wide search turns up exactly two locally-defined gate
references: **Gate J** (`docs/consent-architecture.md` — the analysis
read-only consent boundary, i.e. why a broad scoped-read grant can't be
upgraded into execution authority) and one throwaway **Gate E** comment
(`plugins/strix-personal/scripts/_vendor/patcher.py`, about rollback-safe
wrapping and bypass detection). The full Strix Governance Review Framework
(SGRF v1), its 13-section report structure, and its 4-axis profile are
stated in `README.md` to live **upstream**, not vendored in this repository.

Everything below is therefore a **best-effort structured account** against
the axis language this repo's own skill descriptions actually use
(decision-before-execution, enforcement/bypass-resistance, forensics/
evidence completeness, independent verifiability) — **not** a citation of an
authoritative local Gate D/F/G/H specification, because none exists here to
cite. Treat the letter labels below as organizing headings borrowed from
context, not as claims that this report conforms to the upstream SGRF spec
byte-for-byte.

## 2. Gate D (inferred meaning: decision evaluated before execution)

Every export runs `evaluate_export_policy()` before anything else, and the
export adapter (`export_fn`) is unreachable until that decision, an
approval gate (when applicable), and execution-token redemption have all
already succeeded — see `governed_export()`'s ordering in
`helpers/dataset_export_local.py`. This is not merely claimed: it is proven
behaviorally by `tests/test_negative_policy_denial_never_invokes_adapter.py`,
where a `Spy` stands in for the adapter and its call count is asserted `==
0` across every denial path (zero-admitted, missing approval,
self-approval).

## 3. Gate E (inferred meaning, per the one local precedent: bypass/rollback-safety)

There is no lower-level entry point to the export side effect than
`governed_export()` — `export_fn` is a plain parameter the orchestrator
calls exactly once, at the end of its sequence, never independently. A
caller who bypasses `governed_export()` entirely and calls their own export
function directly gets no receipt, no chain entry, and no token — the
"bypass" in that case is visible as an absence of governance evidence, not
as a governance failure this code can detect from the inside. This is the
same limitation strix-wire's own bypass-detection has (it checks for
ungoverned sibling call sites via static analysis, which is out of scope
for this skill).

## 4. Gate F (inferred meaning: enforcement / bypass-resistance of the token)

The execution token is the concrete enforcement mechanism: it is bound
(`bindingHash`) to the payload hash, destination, declared transform, and a
classification digest, is time-limited, and is single-use. Tampering with
any bound field after minting — including hand-editing the token file —
produces a `StrixDatasetExportTokenBindingMismatch` on redemption, proven by
`tests/test_negative_payload_modified_after_issuance.py`,
`test_negative_destination_modified_after_issuance.py`, and
`test_negative_transform_modified_after_issuance.py`. Replay is refused
(`test_negative_token_replay.py`) and expiry is enforced
(`test_negative_expired_token.py`).

## 5. Gate G (inferred meaning: forensics / evidence completeness)

The receipt schema (§7 of `ARCHITECTURE.md`) carries capability id,
requester and approver references, destination visibility, policy id and
version, the canonical input hash, admitted row ids, barred row ids with a
specific per-row reason code, the declared transform name and version, a
`deidentified` boolean, a decision outcome distinct from an execution
outcome, the execution-token reference and status, a Merkle root over the
full evaluated row set, and a literal `completeness: "NOT_PROVEN"` field.
Tampering with any of these after signing is independently detectable
(`tests/test_negative_receipt_tampering.py`) because `verify_receipt`
recomputes the hash and signature rather than trusting the stored payload.

## 6. Gate H (inferred meaning: independent verifiability)

`verify_receipt()`/`verify_chain()` (§9 of `ARCHITECTURE.md`) recompute
`evidenceHash`, `proofChainHash`, and the Ed25519 signature from the local
key registry — proven end to end in `tests/test_offline_verification.py`
across a real two-record chain, including a broken-link detection case.
Selective disclosure of a row subset is independently checkable via a
Merkle inclusion proof against the receipt's committed root
(`tests/test_merkle_inclusion_proof.py`,
`tests/test_negative_selective_disclosure_not_completeness.py`) without
requiring the full row set to be disclosed.

## 7. Gate J (canonical local precedent: analysis-scope containment)

This skill introduces new signing and token primitives, which is exactly
the situation `docs/consent-architecture.md`'s Gate J discipline exists to
scrutinize: does a broad grant get quietly upgraded into something it
didn't authorize? Here, the answer is that nothing broadens: the new
primitives are additive, scoped to this capability's own namespace
(`<state_dir>/dataset-export/tokens/`), and share only the pre-existing,
already-scoped signing-key registry and evidence chain conventions
strix-wire established — they do not read, modify, or grant execution
authority over anything outside a single `governed_export()` call's own
bound request. There is no read-only "analysis" phase in this skill
analogous to strix-wire's scanner that could be upgraded into an execution
bypass; the entire flow is a single explicit call with explicit
`requester_id`/`approver_id`/`approval_granted` arguments the caller must
supply every time.

## 8. Honest limitations / non-claims

- This Gate lettering is a best-effort mapping onto this repo's own visible
  axis language, **not** a citation of the canonical upstream SGRF Gate
  D/F/G/H specification, which is not present in this repository (§1).
- `safe-harbor-v1` is a declared test transform; it does not certify HIPAA
  Safe Harbor conformance and does not prove de-identification correctness
  (`ARCHITECTURE.md` §4, §10).
- A signed receipt does not make the underlying transfer lawful.
- Selective disclosure proves membership, never completeness — every
  disclosure and its verification result carry this disclaimer verbatim,
  and every receipt separately carries `completeness: "NOT_PROVEN"`.
- This report covers only the `research.dataset.export` capability
  implemented in this skill directory; it makes no claim about the
  governance posture of any other capability, skill, or the hosted Strix
  platform.
