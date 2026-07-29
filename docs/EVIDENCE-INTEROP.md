# Evidence interoperability — the Local → tool-gateway projection

How a Local Mode receipt becomes checkable by the published
`npx @strixgov/verifier` without weakening either system's trust model.
Demonstrated end-to-end in [`PROOF-ATTEMPT.md`](./PROOF-ATTEMPT.md); implemented
as `export_tool_gateway_receipt()` / `export_jwks()` in
[`skills/strix-wire/helpers/governed_action_local.py`](../skills/strix-wire/helpers/governed_action_local.py).

## The two evidence ecosystems

| | Local Mode | Hosted Mode |
|---|---|---|
| Purpose | prove local governance occurred | prove Strix-governed execution |
| Trust anchor | workspace-local Ed25519 key | Strix-custody keys, public JWKS |
| Record | `local-receipt-v1` in `.strix/evidence/` | hosted evidence record, resolvable by id |
| Claim | `LOCAL_MACHINE_ASSERTION` | publicly reproducible, Strix custody |

These are different products making different claims. The projection does not
merge them — it lets the first be checked by the second's *tool* without
pretending to carry the second's *custody*.

## 1. Why tool-gateway v1 is the export target

The verifier's `receipt` subcommand accepts exactly two schemas, dispatched on
`schemaVersion` (`@strixgov/verifier@1.20.0`, `src/index.mjs`):

- **`"1"` — 11 canonical fields**, every one of which has an honest local source.
- **`"2"` — adds `policyVersion`, `tenantId`, `environment`.** The last two are
  hosted-tenancy facts. A local workspace has no tenant and no hosted
  environment; exporting v2 would mean inventing both.

So v1 is not a downgrade — it is the **environment-neutral profile** that already
exists in the published protocol. The export pins `schemaVersion: "1"` and a test
asserts `tenantId`, `environment` and `policyVersion` are absent from the output.

## 2. The field mapping — every value has a truthful source

| Tool-gateway field | Source in the signed local payload |
|---|---|
| `receiptId` | `evidenceId` |
| `capabilityId` | `capabilityId` |
| `action` | `action.name` |
| `decision` | `decision` |
| `invocationHash` | `action.paramsHash` |
| `evidenceHash` | `evidenceHash` |
| `proofChainHash` | `proofChainHash` |
| `timestamp` | `createdAt` |
| `signingKeyId` | `signingKeyId` |
| `mode` | `recordMode` = `LOCAL_SIGNED_V1` |
| `risk` | **none — see below** |

The projection is then signed with the same local key, and the JWKS handed to
the verifier is the local registry's public material (`export_jwks()`).

## 3. Fields stated rather than synthesized

Two fields have no direct local source. Neither is fabricated:

- **`risk: "UNSPECIFIED"`** — no risk assessment happens in Local Mode, and the
  schema makes the field mandatory. `UNSPECIFIED` states the absence; a reader
  of the verified receipt sees that no risk claim was made. Mutating this to a
  fabricated tier (`LOW`) fails two tests.
- **`mode: "LOCAL_SIGNED_V1"`** — the local record mode, carried through so the
  trust scope is visible **in the verifier's own output**, not only in this
  repository's documentation. Anyone running the verifier sees
  `Mode: LOCAL_SIGNED_V1` next to `Status: VERIFIED`.

And the deliberate omissions: `tenantId`, `environment`, `policyVersion` do not
appear at all, because Local Mode cannot truthfully supply them. That is the
reason the export targets v1.

## 4. The guarantees against laundering

The export signs fresh, which makes it a place where bad evidence could be
washed. Two refusals close that:

1. **A local receipt that fails its own verification is not exportable.**
   `export_tool_gateway_receipt()` runs the full local re-verification (hash,
   chain fields, signature, key resolution) first and raises unless the status
   is `VERIFIED`. Otherwise the pipeline
   `tampered receipt → export → fresh signature → looks legitimate` would exist.
   Removing this guard fails a test.
2. **A receipt signed by a different key is not re-attributed.** If the
   workspace's current key is not the key that signed the receipt, the export
   refuses. Otherwise the exporter becomes an identity-translation layer:
   evidence produced under one identity re-issued under another.

Tamper-evidence of the output was demonstrated against the real verifier, not
assumed: forging `decision` to `ALLOW` in the exported file returns
`Status: TAMPERED`, exit 1.

## 5. Externally verifiable ≠ publicly resolvable

The distinction that keeps the `VERIFIED` from being overquoted:

- **Externally verifiable** — anyone holding the exported receipt, the JWKS,
  and the published verifier can re-derive the verdict. Independent *code*
  checked the record. The export achieves this.
- **Publicly resolvable** — anyone holding only an evidence id can look the
  record up against Strix-custody keys (`strix-verify <evidenceId>`). This
  requires a hosted evidence record, which is a property of deployment and
  custody, not of the receipt or the verifier. No hosted record exists for
  Local Mode evidence, so the export does **not** achieve this — and does not
  claim to.

A `VERIFIED` on an exported receipt therefore means: independently maintained
code re-derived the Ed25519 signature under the key in the JWKS you supplied —
and that key is the workspace's local key. Independent code, local trust anchor.
It is a `LOCAL_MACHINE_ASSERTION` made externally checkable, not a hosted
custody claim.

## Verification of this design

- 9 tests in
  [`skills/strix-wire/tests/test_tool_gateway_export.py`](../skills/strix-wire/tests/test_tool_gateway_export.py),
  with the verifier's check transcribed byte-faithfully from its source and
  pinned by real `npx` runs (both the `VERIFIED` and the `TAMPERED`).
- Mutation results: laundering guard removed → 1 failed; canonical field order
  swapped → 1 failed; `risk` fabricated → 2 failed.
- The full positive and negative paths — raw receipt refused (`ERROR`,
  onboarding ends `proof_failed`) and export verified (`VERIFIED`, onboarding
  reaches `ready`) — are recorded with verbatim verifier output in
  [`PROOF-ATTEMPT.md`](./PROOF-ATTEMPT.md).

## Known limits

- The TypeScript helper (`governedAction.local.ts`) does not yet have the
  export; it exists in the Python helper only.
- The export covers a single receipt. Chain export (`verifier chain` over a
  `receipts.jsonl`) is not implemented.
- If the tool-gateway schema evolves (a v3), the question of whether
  environment-specific fields become optional-by-profile belongs in an evidence
  interoperability design review — this projection deliberately tracks the
  published protocol rather than defining a new envelope.
