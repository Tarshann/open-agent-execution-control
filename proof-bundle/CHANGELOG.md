# Changelog

## 1.0.0-rc.2 — 2026-11-12

Not published, not deployed. Bundle format is still `1.0`; rc.1 was never
released, so these changes are folded into it rather than versioned.

### Added
- **Issuer authorization** (SPEC §7.4–7.5): an issuer root authorizes a
  gateway key for named tenants, environments, record kinds and a validity
  interval; signed revocation list with tri-state standing. Trust-store
  `role: issuer-root`. New artifact `trust/issuer-authorizations.json`.
- `strix-proof-authorize` 1.0.0: offline authority tool (`init-root`,
  `trust-store`, `issue`, `revoke`).
- Exporter: `--issuer-authorization`; reads the gateway `KeyRing` layout and
  its retired public keys.
- Verifier: `--issuer-authorizations`, `--revocations`; report fields
  `authority`, `authorizationId`, `issuerRootKeyId`, `gatewayId`, `scope`,
  `standing`.
- 47 new vectors (116 total); `test/hardening.test.mjs`,
  `test/gateway-live.test.mjs`.

### Fixed (found by independent review)
- Lookups of bundle-supplied names could reach inherited object properties:
  a `risk` of `constructor` skipped the policy-contradiction check; an
  artifact named `constructor` was refused; a `schemaVersion` of
  `constructor` crashed.
- The two implementations disagreed on impossible dates, hour 24, offset
  minute 60, non-ASCII digits, policy rule values that are not strings,
  JSON `null`, unpaired surrogates, and malformed trust-store entries.
  Timestamps are now parsed field by field in both.
- Text report: bundle content could forge report lines. All bundle-derived
  text is now escaped.
- Claims attributed the approval fields and the execution outcome to the
  receipt signer even when another key signed them.
- A disclosed invocation naming a different capability or action than the
  receipt it hashes to was accepted.
- A schema-1 receipt could carry an unsigned tenant that then steered tenant
  scoping.
- Non-canonical base64url signatures and keys were accepted.
- A large carrier member overflowed the stack instead of being refused by
  size.
- Python CLI ignored unknown options (dropping `--expect-*` pins), followed
  Windows junctions, and could exit 1 on a crash.
- Exporter: reported "nothing was exported" after writing a bundle when the
  carrier failed; a trailing slash on `--out` stranded an empty directory;
  refusal codes distinguished "other tenant" from "not found";
  `TENANT_MISMATCH` is replaced by `RECEIPT_NOT_FOUND`.

### Changed
- Receipts declaring a `signatureAlgorithm` other than `Ed25519` are refused.
- Validation harness pinned to `@strixgov/mcp-proxy` 0.2.2 and
  `@strixgov/verifier` 1.25.0; example bundles are verified with a trust
  store that holds only a demo issuer root.

## 1.0.0-rc.1 — 2026-11-12

First release candidate of Portable Proof Bundle v1. Not published to a
package registry and not deployed anywhere.

### Added
- Bundle format `strix-portable-proof-bundle` `1.0` (`docs/SPEC.md`):
  directory and single-file carrier forms, signed inventory, DSSE-encoded
  Ed25519 manifest signature, explicit evidence states.
- `strix-proof-verify` 1.0.0: zero-dependency offline verifier with separate
  integrity / signature / signer-trust / consistency results, twelve
  rule-derived claims, JSON and text reports, exit codes 0/1/2/3.
- `strix-proof-export` 1.0.0: exports one governed action from a
  `@strixgov/tool-gateway` 0.5.0 / `@strixgov/mcp-proxy` 0.2.1 store, signing
  with the gateway's existing key; tenant-scoped; refuses unverifiable,
  ambiguous or contradictory records; never overwrites; audit log.
- `ppb_verify.py` 1.0.0: second implementation, verdicts only.
- 69 public test vectors; five example bundles from a real proxy run.

### Known issues
See `RELEASE-READINESS.md` §8.

### Compatibility
- Receipts: tool-gateway schema `"1"` and `"2"`. Execution outcomes: schema `"1"`.
- Node.js ≥ 18 (tested on 24.21, Windows 11). Python ≥ 3.11 for the second
  implementation (tested on 3.12).
