# Issuer authorization: giving a gateway key standing

Written 2026-11-12 in response to the gate assessment that held Portable
Proof Bundle v1 at release candidate. The assessment's central point:

> A cryptographically valid bundle is not necessarily a bundle from an
> authorized Strix issuer.

That was true of `1.0.0-rc.1`: a relying party could only trust a gateway key
by listing it, and nothing linked that key to any issuer. This document
records what already existed, what was built, what it does and does not
solve, and what is still undecided. The normative rules are in
[`SPEC.md`](SPEC.md) §7.4–7.5.

## 1. Status in one paragraph

**Built and tested:** an offline authorization chain — *issuer root → signed
authorization → gateway key* — bound to gateway identity, key id, tenants,
environments, record kinds and a validity interval, with a signed revocation
list; implemented in both verifiers, the exporter and an offline authority
tool; covered by 26 vectors and an end-to-end run against the real proxy.
**Not done, and not doable from this repository:** no Strix issuer root
exists. Every authorization so far was signed by a test or demo root created
for the purpose. Until Strix decides who holds a root key and how its public
half reaches customers, a bundle can be shown to come from *a gateway that
some root authorized* — not from *a Strix-authorized gateway*.

## 2. Inventory: what Strix already has

Inspected in the packages pinned by `validation/proof-bundle/package-lock.json`
and in this repository. The hosted platform (`strix-platform`) is not in this
repository and was not inspected.

| Existing capability | Where | What it does | Usable here? |
|---|---|---|---|
| Trust-mark grant (TM-1) | `@strixgov/verifier` `src/trust-mark.mjs` | An authority key signs a grant that authorizes a subordinate (heartbeat) key for one surface and a validity window; fixed rule order; nested `{payload, signature, kid}` envelope | **Pattern reused.** Same shape of problem: authority → bounded subordinate key. The grant itself is about web surfaces, not gateway keys. |
| Trust-mark revocation list | `src/trust-mark-revocation.mjs` | Offline-signed list keyed by grant id; tri-state `REVOKED` / `NOT_REVOKED` / `UNAVAILABLE`; "never a silent allow" | **Pattern reused** (§7.5). No list is published for TM-1 today, so there is no distribution channel to reuse. |
| Key-rotation snapshot | `@strixgov/tool-gateway` `src/snapshots.mjs` | At rotation, old and new key both sign a record naming the handoff | Complementary. Proves the same operator held both keys; does not say who the operator is. Not exported in v1. |
| Gateway keyring | `tool-gateway` `src/keyring.mjs` | Active + retired keys on the gateway host | Reused by the exporter. |
| Strix JWKS | hosted endpoint, used by `@strixgov/verifier` for hosted evidence | Publishes Strix-custody public keys | The natural home for an issuer root's public key. Not reachable/inspectable from here, and an online fetch cannot be the verification path. |
| Signed capability registry | `tool-gateway` `src/registry.mjs` | Signs shared capability definitions | Not about key standing. |
| Device attestation, agent session, SCITT modules | `@strixgov/verifier` `src/*.mjs` | Other evidence types | Not about gateway key standing. Not used. |
| Local-mode attestations | `skills/strix-wire/helpers/governed_action_local.py` | Workspace-local issuer keys and revocation for Local Mode | Different trust domain (one workspace). Not used. |
| Issuer registration / gateway enrolment | — | — | **Not found** in anything inspected. |

Conclusion: Strix has the *pattern* (TM-1) but no mechanism that authorizes a
gateway signing key. Nothing existing was replaced.

## 3. What was built

```
relying party's trust store        bundle (or supplied separately)            bundle
┌──────────────────────┐  signs   ┌──────────────────────────────┐  names   ┌──────────────────────┐
│ issuer root (public) │ ───────► │ issuer authorization          │ ───────► │ gateway key signs     │
│ role: issuer-root    │          │ gateway id, key id + key      │          │ manifest / receipt /  │
└──────────────────────┘          │ tenants, environments, kinds  │          │ outcome               │
        ▲                         │ notBefore .. notAfter         │          └──────────────────────┘
        │ optional                └──────────────────────────────┘
        │ revocation list (signed by the root)
```

- **No second signing authority for evidence.** The gateway still signs its
  own records and manifest with its own key. The root signs only
  authorizations and revocation lists, offline, and never touches a gateway.
- **Verification stays offline.** The authorization travels with the bundle
  (or is held by the customer). No Strix API is consulted.
- **The gateway cannot widen its own scope.** Editing the authorization
  breaks the root's signature (`auth-scope-widened-by-gateway`).
- **The key bytes come from the root-signed statement**, so a look-alike key
  with the same id fails (`auth-gateway-key-substituted`).
- **Direct trust still works.** A customer who prefers to list a gateway key
  themselves can; the two models coexist, and the report says which applied.

Components: `authority/strix-proof-authorize.mjs` (`init-root`, `trust-store`,
`issue`, `revoke`), `--issuer-authorization` on the exporter,
`--issuer-authorizations` / `--revocations` on the verifier, and the same
logic in `python/ppb_verify.py`.

### Why this encoding

TM-1 signs an SCJ-canonicalized payload with a hex signature. The bundle
format signs **exact bytes** under a DSSE pre-authentication encoding and has
no canonicalization step for signed documents. The authorization follows the
bundle's encoding so that the two verifiers need no additional canonical
form. It follows TM-1 in everything that is semantics: a single authority
key, a bounded subject, an explicit validity window, a fixed evaluation
order, and tri-state revocation. If Strix prefers SCJ for consistency with
TM-1, that is an encoding change confined to SPEC §7.4.

## 4. The assessment's acceptance cases

The assessment listed twelve cases and noted it had not verified them against
the corpus. Each is mapped to a vector and its actual result. Result names
differ from the assessment's suggestions; the mapping is given.

| Assessment case | Assessment's expected result | Vector(s) | Actual result |
|---|---|---|---|
| Valid bundle under trusted issuer | VERIFIED within declared scope | `auth-valid-root-only`, `auth-valid-supplied-out-of-band` | `PASSED`; claim PPB-C03 names the root, authorization, gateway, tenants, interval and revocation standing |
| Valid signature under unknown key | ISSUER_NOT_ESTABLISHED | `auth-missing`; `trust-none-supplied` | `FAILED SIGNER_UNTRUSTED` with a trust store; `INCOMPLETE` (signer trust `NOT_ESTABLISHED`) without one |
| Substituted public key | REFUSED | `auth-gateway-key-substituted`, `trust-attacker-resigned`, `tamper-embedded-key-swapped`, `auth-issuer-root-impersonated` | `FAILED SIGNATURE_INVALID` / `DIGEST_MISMATCH` / `SIGNER_AUTHORIZATION_INVALID` |
| Modified manifest | INVALID | `tamper-manifest-field`, `tamper-manifest-digest-and-artifact` | `FAILED SIGNATURE_INVALID` / `DIGEST_MISMATCH` |
| Modified receipt or outcome | INVALID | `tamper-evidence-byte`, `tamper-native-receipt-field`, `tamper-artifact-replaced` | `FAILED DIGEST_MISMATCH` / `SIGNATURE_INVALID` |
| Missing referenced artifact | INCOMPLETE | `tamper-artifact-removed` | `FAILED MISSING_ARTIFACT`. Deliberately not "incomplete": a file the signed inventory lists and the bundle lacks is tampering. `INCOMPLETE` is reserved for "nothing failed, origin not authenticated". |
| Wrong signing algorithm | REFUSED | `error-signature-algorithm-none`, `error-signature-envelope-algorithm`, `error-digest-algorithm-downgrade`, `error-receipt-declares-algorithm`, `error-auth-algorithm` | `ERROR UNSUPPORTED_ALGORITHM` |
| Unsupported bundle version | REFUSED | `error-unsupported-format-version`, `error-unknown-critical-extension`, `error-unsupported-receipt-schema` | `ERROR UNSUPPORTED_VERSION` / `UNKNOWN_CRITICAL_EXTENSION` / `UNSUPPORTED_RECORD_VERSION` |
| Revoked or expired issuer authorization | Standing per signed validity rules | `auth-revoked`, `auth-expired`, `auth-not-yet-valid`, `auth-root-revoked`, `auth-root-outside-validity`, `auth-valid-revocation-checked` | `FAILED SIGNER_REVOKED` / `SIGNER_OUTSIDE_VALIDITY`; standing reported as `REVOKED` / `NOT_REVOKED` / `NOT_CHECKED` |
| Gateway key rotation | Historical bundles remain verifiable | `auth-valid-rotation`, `valid-rotated-keys`; `test/gateway-live.test.mjs` (real keyring, real rotation) | `PASSED`; without the old key's authorization, `auth-rotation-old-key-unauthorized` → `FAILED SIGNER_UNTRUSTED` |
| Valid receipt without observed execution | No execution-proof claim | `valid-allow-no-outcome`, `valid-deny` | `PASSED`; PPB-C10 `NOT_ESTABLISHED`; enforcement always `NOT_ESTABLISHED` |
| Valid manifest with untrusted receipt signer | Receipt authority not established | `auth-receipt-signer-unauthorized`, `trust-rotation-old-key-missing` | `FAILED SIGNER_UNTRUSTED`, naming the receipt |

The seven properties the assessment asks a verifier to keep apart, and where
each appears in a report:

| Property | Report field |
|---|---|
| Bundle integrity | `result.integrity` |
| Receipt integrity, outcome integrity | `result.signatures.records[]` (per record) |
| Signing-key identity | `result.signatures.records[].keyId`, `keySource` |
| Signing-key authority and standing | `result.signerTrust.records[]`: `authority` (`DIRECT` / `ISSUER_AUTHORIZATION`), `authorizationId`, `issuerRootKeyId`, `gatewayId`, `scope`, `standing` |
| Evidence completeness | `evidence` states; claim PPB-C12 (always not established) |
| Whether execution was independently observed | claims PPB-C09 and PPB-C10 (never established) |

## 5. What this does not solve

- **There is no Strix root.** The mechanism is ready; the authority is not.
- **Who is "the issuer" is a business decision.** Options, none chosen:
  1. *Strix-held root.* Strix signs authorizations for customers' gateways.
     One anchor for every customer; requires an enrolment process in which
     Strix establishes that a key belongs to a named gateway.
  2. *Customer-held root.* Each enterprise runs its own root for its own
     gateways. No Strix involvement; proves "ours", not "Strix-authorized".
  3. *Both.* A Strix root authorizes hosted and Strix-operated gateways; a
     customer root authorizes self-hosted ones. A trust store can hold both.
- **Root key distribution** is still out of band. Publishing the root's
  public key at Strix's existing JWKS would give customers a fetchable
  anchor, but the *act of trusting it* must not be an online call at
  verification time.
- **Revocation freshness.** A list is only as current as the copy the relying
  party supplies. Without one, standing is reported `NOT_CHECKED`.
- **Backdating.** Validity is compared with the record's own time, which the
  gateway asserts. A stolen gateway key can sign a record dated inside an
  expired authorization. Only revocation stops that.
- **Authorization is not attestation.** It says a root vouched for a key. It
  says nothing about how the gateway is deployed or whether calls can bypass
  it.

## 6. One trust model for every deployment

The assessment's closing question: how does every Strix deployment — hosted,
customer-hosted, gateway, local — produce portable evidence under one model
without sharing Strix's private key?

The chain built here is that model in miniature, and it generalizes without a
format change:

| Deployment | Signs its own records with | Gets standing from |
|---|---|---|
| Open gateway / MCP proxy | Its own key (today) | An authorization for that key — **implemented** |
| Customer-hosted Strix | Its own deployment key | The same authorization, from a Strix or customer root |
| Hosted Strix | A Strix-custody operational key | The same authorization from the Strix root, instead of trusting the operational key directly — **requires a hosted evidence source for the exporter** |
| Local Mode | A workspace key | Deliberately none: it stays a local assertion unless someone authorizes that key |

No deployment ever holds the root's private key; each holds only its own key
and a statement about it. What remains is not format work: it is the root
ceremony, the enrolment process, and a hosted evidence adapter.
