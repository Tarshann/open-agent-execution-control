# Baseline: what Strix already had, and what this product reuses

Established 2026-11-12 by reading the source in this repository and the
published packages pinned in `validation/proof-bundle/package-lock.json`
(`@strixgov/mcp-proxy` 0.2.2, `@strixgov/tool-gateway` 0.5.0,
`@strixgov/mcp-adapter` 0.1.4, `@strixgov/verifier` 1.25.0), and by running
them. Paths under `node_modules/` are relative to `validation/proof-bundle/`.

**What was inspected and what was not.** This repository is the open
skills/validation repository. The hosted Strix platform (console, hosted
evaluate API, Strix-custody keys, hosted evidence store) is **not** in it and
was not inspected; every row about it is `UNKNOWN`. Portable Proof Bundle v1
is therefore built on the open gateway runtime, which is a real, published
Strix governance runtime, and not on the hosted control plane.

Classification: `VERIFIED_EXISTING`, `VERIFIED_PARTIAL`, `NOT_FOUND`,
`UNKNOWN`, `REQUIRES_VALIDATION`.

## Capability matrix

| Capability | Current implementation | Source | Evidence of behaviour | Class | Reuse / gap | Security implication | Action taken |
|---|---|---|---|---|---|---|---|
| Action interception | MCP proxy in front of an upstream MCP server; every `callTool` goes through the gateway | `@strixgov/mcp-proxy/src/proxy.mjs` | `validation/proof-bundle/run.mjs` steps A–F | VERIFIED_EXISTING | Reused as the source of governed actions | Applies only to calls routed through the proxy (step E) | Stated in every report (claim PPB-C09) |
| Policy evaluation | Exact rule → longest prefix → risk override → default → DENY | `@strixgov/tool-gateway/src/policy.mjs` | Decisions in the run match the configured rules | VERIFIED_EXISTING | Reused; verifier re-implements the lookup only to *report* which rule applies | Policy correctness is the author's responsibility | Reported as a limitation |
| Policy identity | `policyVersion` = SHA-256 of canonical `{rules, riskOverrides, default}`, signed into each receipt | `policy.mjs` `computePolicyVersion` | Recomputed from the run's ruleset; equal | VERIFIED_EXISTING | Reused for policy disclosure | Rate limits are not part of the hash | Disclosure check + stated limit |
| Decision record | Ed25519-signed authorization receipt, schema 2 (14 signed fields) | `tool-gateway/src/receipts.mjs`, `canonical.mjs` | 5 real receipts, verified by `@strixgov/verifier` and by this verifier | VERIFIED_EXISTING | Reused verbatim as `evidence/authorization-receipt.json` | See finding F-1 | — |
| Approval | File/webhook approver; result stored in `approvalReason`, `approvedBy` | `tool-gateway/src/approval.mjs` | Steps C (TIMEOUT) and D (USER_APPROVED) | VERIFIED_PARTIAL | Reused as an export-time assertion only | **Not covered by the receipt signature** (F-1) | Claim PPB-C08 says so |
| Enforcement | In-process: the adapter does not call the upstream on DENY | `mcp-adapter/src/index.mjs` | Handler log: no invocation for B and C | VERIFIED_PARTIAL | No evidence artifact exists | No independent observation; bypass by direct access is possible and demonstrated (step E) | Evidence state `NOT_CAPTURED`; never claimed |
| Enforcement observation (independent) | — | — | — | NOT_FOUND | Gap | Prevention cannot be established from evidence | Declared, not invented |
| Execution result | Ed25519-signed execution outcome linked to the receipt; `FAILED` when the tool returns `isError` | `tool-gateway/src/outcomes.mjs`, `mcp-adapter/src/index.mjs` | 3 real outcomes (2 SUCCEEDED, 1 FAILED) | VERIFIED_EXISTING | Reused verbatim as `evidence/execution-outcome.json` | Self-reported by the component that authorized | Classified SOURCE_ASSERTION |
| Evidence storage | Append-only JSONL: `receipts.jsonl`, `execution-outcomes.jsonl`, `snapshots.jsonl` | `tool-gateway/src/storage.mjs`, `outcome-storage.mjs` | Read by the exporter | VERIFIED_EXISTING | Exporter reads it; never writes records | File-level access control is the operator's | Exporter is read-only on records |
| Hash chain | `proofChainHash` links receipts | `receipts.mjs` | Present in receipts | VERIFIED_PARTIAL | Not exported in v1 | Completeness of the log is not established by one receipt | Claim PPB-C12 |
| Signing key | Ed25519; `signing-key.pem` (PKCS8, 0600) + `public-jwk.json` | `tool-gateway/src/keys.mjs` | Used by the exporter to sign manifests | VERIFIED_EXISTING | Reused: same key, no second signing authority | Key is a file on the gateway host | Exporter loads read-only, never creates |
| Key rotation | `KeyRing`: `active` pointer + one directory per kid; retired private keys kept, `Gateway.rotateKey()` | `tool-gateway/src/keyring.mjs`, `gateway.mjs` | `test/gateway-live.test.mjs`: real keyring, real rotation mid-run, records before and after exported and verified | VERIFIED_EXISTING | Exporter reads both the flat and the keyring layout; retired public keys found automatically | A relying party must hold the retired public key too | Tested against the real gateway |
| Public-key discovery | `public-jwk.json` on disk; hosted JWKS for Strix-custody keys | `keys.mjs`; README | Local file verified; hosted JWKS not inspected | VERIFIED_PARTIAL | Trust store is supplied by the relying party | No authenticated distribution channel exists for gateway keys | Trust-anchor guide; known issue K-1 |
| Revocation | A trust-mark revocation module exists in the verifier package; no published list (repo memory: TM-1 rule 10) | `@strixgov/verifier/src/trust-mark-revocation.mjs` | Not usable for gateway keys | NOT_FOUND | Gap | Revocation cannot be checked offline or online | Trust store carries status; limitation stated |
| Tenant isolation | `tenantId`, `environment` signed into schema-2 receipts (`"local"` for the proxy) | `receipts.mjs` | Present in all 5 receipts | VERIFIED_PARTIAL | Exporter requires `--tenant` and refuses mismatches | The open gateway is single-tenant; multi-tenant storage isolation is a hosted-platform property | Exporter + verifier checks; hosted side UNKNOWN |
| Actor identity | Client-supplied `_meta.strix_actor_id`, or a configured resolver; bound into `invocationHash` | `mcp-adapter/src/index.mjs` `_resolveIdentity` | Empty in the run | VERIFIED_PARTIAL | Disclosed with the invocation | Not authentication unless a trusted resolver is configured; no evidence of which | Claim PPB-C07: NOT_ESTABLISHED |
| Independent verification | `@strixgov/verifier` checks receipts and outcomes | npm package | Cross-checked in `run.mjs` and `test/interop.test.mjs` | VERIFIED_EXISTING | Used as the interoperability oracle for native records | Same vendor, separate package | — |
| Trusted timestamps | — | — | — | NOT_FOUND | Gap | All times are the signer's clock | Claim PPB-C11 |
| Transparency log | An `mcp-scitt.mjs` module exists in the verifier package | `@strixgov/verifier/src/mcp-scitt.mjs` | Not inspected in depth; not used by the gateway run | UNKNOWN | Not used | — | Not relied on |
| Hosted governed-action records | Hosted evaluate API; Sandbox Mode returned HTTP 400 on 2026-11-06 | `validation/README.md` §3 | Recorded failure | UNKNOWN / REQUIRES_VALIDATION | Not integrated | — | Blocker B-1 in `RELEASE-READINESS.md` |
| Local Mode receipts (`local-receipt-v1`) | Python helper, separate schema family | `skills/strix-wire/helpers/governed_action_local.py` | Existing tests | VERIFIED_EXISTING | Not a v1 source; reachable via the existing tool-gateway v1 projection (`docs/EVIDENCE-INTEROP.md`) but that projection has no outcome record | — | Out of scope for v1 |
| CI | GitHub Actions, pytest on Linux + Windows | `.github/workflows/tests.yml` | — | VERIFIED_EXISTING | Extended with a Node job and the Python interop suite | — | Done |

## Findings

**F-1. Six receipt fields are outside the gateway's signature.**
`canonical.mjs` signs 14 fields. `tool`, `actorId`, `actorRole`, `approvedBy`,
`approvalReason` and `denialReason` are stored next to them unsigned.
Demonstrated: changing `approvedBy`, `approvalReason`, `actorId` and `tool` on
a real receipt still returns `VERIFIED` from `@strixgov/verifier` 1.24.1 and 1.25.0
(`test/interop.test.mjs`). The gateway's own threat model
(`tool-gateway/docs/threat-model.md`, T5) states that the approval result and
`approvedBy` "are bound into the canonical signed payload"; the code does not
do that. Consequences for this product: approval facts are reported as
*export-time assertions*, never as natively signed; `actorId` is trusted only
as far as the disclosed invocation hashes to the signed `invocationHash`.
Recommended upstream fix: a receipt schema 3 that signs these fields.

**F-2. A DENY receipt is not evidence of prevention.** Step E of the
validation run performs, directly on the upstream, the same call the proxy
denied in step B. The handler runs; no record is produced; the bundle for the
DENY still verifies. This is the designed boundary of an inline proxy, and it
is why the verifier never reports prevention.

**F-3. Execution outcomes are first-party.** The proxy signs what it observed
from the upstream's response. There is no second observer.

**F-4. Still present upstream.** F-1 was re-checked against
`@strixgov/tool-gateway` 0.5.2 (pulled in by `@strixgov/mcp-proxy` 0.2.2): the
signed field list is unchanged.

**F-5. `@strixgov/verifier` 1.24.1 → 1.25.0.** 1.25.0 fixes acceptance of
hosted Signed Evidence records that declare an unsupported algorithm or
schema version. This product's verifier does not import that package (zero
references in `verifier/`, `exporter/`, `authority/`, `python/`); it is used
only as a cross-check oracle in tests, now pinned to 1.25.0. The equivalent
weakness was checked here and closed: a receipt declaring any
`signatureAlgorithm` other than `Ed25519`, or a non-string or unknown
`schemaVersion`, is refused (`error-receipt-declares-algorithm`,
`error-receipt-schema-number`). The Signed Evidence conformance corpus
(`conformance/corpus/se_v1`) is not shipped in the npm package and lives in
the platform repository; it was **not** re-run here.

## Decisions

| # | Decision | Alternatives considered | Why |
|---|---|---|---|
| D-1 | Source = mcp-proxy/tool-gateway store | Local Mode receipts; hosted API | Only source in reach with a signed decision **and** a signed execution outcome; hosted API not accessible/working |
| D-2 | Sign the manifest with the gateway's existing key | A dedicated export key | No second signing authority; the relying party trusts one key per gateway |
| D-3 | DSSE pre-authentication encoding over raw manifest bytes | JCS canonicalization; JWS | Byte-exact verification with no canonicalization step for the manifest; standard domain separation; no new dependency |
| D-4 | Native records included verbatim | Normalizing into a new schema | Their own signatures stay checkable by `@strixgov/verifier`; no re-signing, no laundering |
| D-5 | Directory + single-file JSON carrier; no zip/tar | Zip archive | Removes archive-extraction attacks entirely; verifier never writes to disk |
| D-6 | Zero-dependency Node verifier, one file | Python; npm package with deps | Runs on a clean machine with Node ≥ 18 and nothing to install; auditable in one sitting |
| D-7 | Fail closed on unknown versions/algorithms/fields | Best-effort | Ambiguous input must not produce a verdict |
| D-8 | Revoked key fails regardless of record dates | Honour `revokedAt` | Record dates are signer-asserted; a stolen key can backdate |
| D-9 | Gateway-key standing by a root-signed authorization carried with the bundle | Online key lookup; one shared Strix signing key; listing every gateway key | Offline; no deployment holds the root's private key; one anchor for the relying party. Modelled on the existing trust-mark grant |
| D-10 | Authorization encoded as DSSE over exact bytes, not SCJ-canonical like TM-1 | SCJ + hex signature | No second canonical form in either verifier; encoding is confined to SPEC §7.4 if Strix prefers SCJ |
| D-11 | Tenant filter before any other decision in the exporter; one refusal code | Distinct `TENANT_MISMATCH` | Removes a cross-tenant existence oracle found in review |
