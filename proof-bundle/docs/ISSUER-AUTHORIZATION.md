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
| Strix JWKS | hosted endpoint, used by `@strixgov/verifier` for hosted evidence | Publishes Strix-custody public keys | The natural home for an issuer root's public key, and an online fetch cannot be the verification path. The public document was examined on 2026-11-13 and cannot be used as a trust store as it stands: see §7. |
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

## 7. Existing Strix JWKS Compatibility and Issuer-Root Reuse Assessment

Added 2026-11-13. Documentation only. It bears on release blockers **B-1**
(decide the issuer model, create a real root, define enrolment) and **B-2**
(publish the root's public key through a channel customers can authenticate)
in [`../RELEASE-READINESS.md`](../RELEASE-READINESS.md) §9.

The question: can Strix establish gateway issuer authority with its existing
production key-standing architecture, instead of creating a second,
disconnected trust hierarchy?

**What this section changes: nothing but this document.** The issuer-root
design in §3 and SPEC §7.4–7.5 is unchanged. The frozen implementation
revision remains `166216d`. No JWKS, signing key, verifier behaviour,
production configuration, published trust anchor or release checksum was
modified, and nothing below asks for one to be modified without an owner
decision. Commercial release remains on **HOLD**.

Statements are separated by how they are known. Read the label before the
statement.

### 7.1 Directly observed public configuration

`GET https://www.strixgov.com/.well-known/strix-jwks.json`, unauthenticated,
fetched twice: the responses carry `servedAt` `2026-11-14T04:28:53.436Z` and
`2026-11-14T05:37:00.009Z` (the evening of 13 November 2026, US time). The
`keys` array and every `_meta` field other than `servedAt` were identical in
both. HTTP 200, `Content-Type: application/json`,
`Cache-Control: public, max-age=300`.

The document has five entries, in this order:

| # | `kid` | Other fields present | RFC 7638 thumbprint (SHA-256, base64url) |
|---|---|---|---|
| 0 | `strix-prod-2026-06` | `use: sig`, `alg: EdDSA`, `key_ops: [verify]` | `6B8yFcz8aPRZSVs-jR-Qv4bp3GGuwlmXsoAvB5aLIy0` |
| 1 | `strix-prod-2026-05` | `use: sig`, `alg: EdDSA`, `key_ops: [verify]` | `3Beg31w1GyGnzUrBq29A3KPvfts6sR_PtYP5FJln55U` |
| 2 | `strix-prod-2026-05` | `use: sig`, `alg: EdDSA`, `key_ops: [verify]` | `6B8yFcz8aPRZSVs-jR-Qv4bp3GGuwlmXsoAvB5aLIy0` |
| 3 | `strix-dev-2026-05` | `use: sig` | `6B8yFcz8aPRZSVs-jR-Qv4bp3GGuwlmXsoAvB5aLIy0` |
| 4 | `strix-prod-2026-07` | `use: sig` | `6B8yFcz8aPRZSVs-jR-Qv4bp3GGuwlmXsoAvB5aLIy0` |

All five are `kty: OKP`, `crv: Ed25519`. From that table:

- **Two distinct keys.** Call them key A (`6B8y…LIy0`, `x` =
  `awOoXq8mWFYM2hz6acwlOPvazXvpzKLoR4BYdP-MuLY`) and key B (`3Beg…n55U`, `x` =
  `f-3EhLmVCOLUWEGP8F3j3Yl8BdXCZMa5Pvf4uQYpkmo`).
- **Key-byte aliasing.** Key A is published under four key ids:
  `strix-dev-2026-05`, `strix-prod-2026-05`, `strix-prod-2026-06`,
  `strix-prod-2026-07`. One of those ids names a `dev` environment and three
  name `prod`.
- **A duplicate key id.** `strix-prod-2026-05` appears twice, once with key A
  and once with key B.
- **No issuer-root role.** Every entry is `use: sig`. No entry carries a
  field distinguishing an authority, root or issuer key from an operational
  signing key, and no entry's key id is outside the two namespaces below.
- **The document describes itself.** `_meta` contains: `contractVersion: 2`,
  `schemaVersion: "1"`, `algorithm: "EdDSA"`, `curve: "Ed25519"`,
  `keyCount: 5`, `distinctKeyCount: 2`,
  `aliasedKidGroups: [["strix-dev-2026-05", "strix-prod-2026-05", "strix-prod-2026-06", "strix-prod-2026-07"]]`,
  `retentionPolicy: "minimum-24-months"`, and
  `namespaces: { platform: "strix-<env>-<YYYY-MM>", agent: "agent-<agentId>-<YYYY-MM>" }`.
  The aliasing is therefore declared by the publisher, not an accident of
  observation. No entry in the `agent` namespace was present.

These are observations of one public endpoint at two moments. They say
nothing about what the endpoint served before or will serve later.

### 7.2 Verified behaviour of the offline bundle verifier

Run on the `166216d` tree against the second response saved to a file, with
`examples/01-allow-succeeded` as the bundle:

```
$ node verifier/strix-proof-verify.mjs verify examples/01-allow-succeeded --trust-store strix-jwks.json
ERROR MALFORMED_TRUST_STORE: duplicate keyId 'strix-prod-2026-05' (ambiguous)
The bundle was not evaluated; no conclusion may be drawn from it.
(exit 2)
```

`python/ppb_verify.py` gives the same result: `overall ERROR`,
`errorCode MALFORMED_TRUST_STORE`, exit 2.

This is the specified behaviour, not a defect: SPEC §7.1 makes a trust store
with a repeated `keyId` malformed, because the verifier resolves each
signature by key id and must never choose between two keys. It is unrelated
to the example bundle; the refusal happens while reading the trust store.

Two consequences, both verified by reading the code that produced the above:

- A relying party **cannot pass Strix's published JWKS to `--trust-store`
  as it stands.** They would have to extract the entry they mean to trust
  into a trust store of their own.
- The refusal is triggered by the duplicate key id only. Aliasing — one key
  under several ids — is accepted by the parser; each id is simply a separate
  entry.

For contrast, the published `@strixgov/verifier` 1.25.0 handles the same
document differently, by design. Its `resolveJwksByKid` returns **every**
entry matching a key id, and its source comment says verify functions "must
try each candidate". That is a property of that package's code, read from
`src/index.mjs`; it was not exercised here against a hosted record.

### 7.3 Stated by published Strix code, not independently verified

The same source comment in `@strixgov/verifier` 1.25.0 gives a reason for the
duplicate: it describes "Academy's retired key + strix-platform's active key
both bound to `strix-prod-2026-05`" as "a legitimate kid collision". The
trust-mark modules state that grants and their revocation list share one
"authority trust root", resolved by key id from this same JWKS, and that
"the authority key NEVER touches the platform runtime — the list is signed
offline".

These are the package authors' statements about production. They are
consistent with §7.1, and they are not evidence of how any production key is
actually held.

### 7.4 Inferences about key rotation and environment separation

None of the following is established. Each is the most direct reading of
§7.1 and could be wrong.

- **Rotation.** Key ids follow a monthly pattern, yet `2026-05`, `2026-06`
  and `2026-07` under `prod` resolve to the same key. The inference is that
  the monthly key id changed while the key did not — a relabelling rather
  than a rotation — at least across those three months. An alternative
  reading is that the aliases were added for verification compatibility after
  the fact and do not reflect what each month's signer used.
- **Environment separation.** A `dev` key id and three `prod` key ids
  resolve to the same key. The inference is that, for this key, dev and prod
  signing were not separated by key. The alternative: the `dev` id is a
  historical alias and no dev system holds that private key today.
- **Which key is current.** No entry exists for any month after `2026-07`,
  and the document was served in November 2026. Either signing still uses a
  key id from July or earlier, or newer key ids are not published. The
  document does not say which.
- **Key id as identity.** In this document a key id identifies neither a
  unique key nor an environment. Any design that treats "the key id says
  `prod`" as a fact about custody or scope would be relying on something
  this document does not provide.

The practical point for issuer authority: an issuer root must be identified
by its **key bytes** (thumbprint), never by a key id pattern.

### 7.5 Unverified: production key custody and trust-mark authority identity

Not known, and not knowable from this repository or from the public
endpoint:

- Which key, A or B, is the trust-mark authority key — or whether it is
  either. No trust-mark grant was fetched; nothing here ties a grant's
  signature to a thumbprint.
- Whether any private key behind this JWKS is held offline, in a hardware
  module, in a cloud key service, or in application configuration. §7.3
  quotes a claim that the authority key is offline; no custody evidence has
  been seen.
- Who can cause a signature with key A or key B, and under what approval.
- Whether key A's private half exists on any development system.
- Whether the trust-mark authority's permitted scope — as a matter of policy
  or of any written key-ceremony record — extends to anything beyond
  trust-mark grants and their revocation list.
- How entries enter and leave the JWKS, and who controls that.
- Whether a trust-mark revocation list is published. As of 2026-09-10 none
  was, which is a separate open item.

The hosted platform repository was not inspected for this assessment.

### 7.6 Minimum read-only investigation

The smallest set of read-only steps that would settle whether the existing
trust-mark authority can be reused. Nothing here signs, rotates, publishes
or reconfigures anything. Each step names its evidence and what would count
against reuse.

| # | Step | Evidence to record | Counts against reuse if |
|---|---|---|---|
| 1 | **Key fingerprint comparison.** Fetch one production trust-mark grant and, if one exists, the revocation list. Verify each signature against key A and key B separately. Compare the verifying key's RFC 7638 thumbprint with §7.1. | Grant id, the thumbprint that verifies, the `kid` and `iss` in the grant | The verifying key is not in the JWKS; or it is key A, which is also published under a `dev` id and under operational `prod` ids; or grant and list verify under different keys |
| 2 | **Authoritative role metadata.** Find where Strix records what each key is *for*: the JWKS generator's configuration, the ADR that defines the trust-mark authority (ADR-029 is cited by the verifier source), any key registry. | The source of truth and its text for each of key A and key B | No such record exists; or the record assigns the authority key an operational role as well |
| 3 | **Custody evidence.** For the key identified in step 1: where the private half is stored, who can use it, how a signature is produced, and whether a ceremony record or access log exists. | Storage type, access list, signing procedure, last-use record. A statement in code comments is not custody evidence | The private key is reachable from a running service; or it is present in more than one environment; or nobody can say |
| 4 | **Permitted scope.** Read the policy or ADR text governing that key for what it may sign. | The exact wording | Scope is limited to trust-mark artifacts and widening it would need a new decision — which is then the decision to make, not a blocker by itself |
| 5 | **Historical verification compatibility.** List every record type currently verified through this JWKS and how each selects a key (by id, trying all matches, by thumbprint). Confirm that *adding* an entry changes no existing result, and identify what would break if the duplicate id or the aliases were ever removed. | The list; for each, the selection rule and a sample record that still verifies | Existing verification depends on the duplicate or the aliases in a way that forbids ever giving a root an unambiguous id in this document |
| 6 | **Signature-domain check.** Confirm the bytes a trust-mark grant signs cannot be confused with the bytes an issuer authorization signs. | The two signing inputs, side by side | — (expected to pass: authorizations are signed over a DSSE pre-authentication encoding with their own payload type, SPEC §7.4; grants sign an SCJ-canonical payload. Recorded so that reuse does not rest on an assumption) |

Steps 1 and 5 need only public endpoints and published packages. Steps 2, 3
and 4 need access to the platform repository and to whoever operates the
keys; they cannot be done from here.

### 7.7 Two options for owner review

Both keep the design in §3 exactly as built: the gateway signs its own
evidence, an offline root signs only authorizations and revocation lists,
and relying parties verify offline. Neither needs a change to the bundle
format, the verifier or revision `166216d`. They differ only in **which key
is the issuer root**.

**Option 1 — Reuse the existing offline trust-mark authority.**
The key that signs trust-mark grants also signs gateway authorizations.

- *Requires, from §7.6:* its identity fixed by thumbprint (step 1); custody
  shown to be offline and single-environment (step 3); its permitted scope
  either already covering, or explicitly extended to, gateway authorizations
  (step 4); role metadata that says so (step 2).
- *For:* one Strix authority, one ceremony, no new key to protect; customers
  who already rely on trust marks rely on the same anchor.
- *Against:* one key then vouches for two unrelated things — public web
  surfaces and customer gateways — so a compromise or a forced rotation of
  either use takes the other with it; the key's trust-store entry must be
  built by thumbprint, since the JWKS cannot be used directly (§7.2); and if
  step 1 shows the authority is key A, reuse would make an issuer root of a
  key that is published under a `dev` id and under operational ids, which is
  hard to defend to a customer.

**Option 2 — A dedicated offline issuer root under the existing
trust-distribution architecture.**
A new Ed25519 key, used for nothing but gateway authorizations and their
revocation list, published through the same JWKS endpoint Strix already
operates.

- *Requires:* an owner decision and a key ceremony (neither is authorized by
  this document); an unambiguous key id for the root, outside the monthly
  `strix-<env>-<YYYY-MM>` pattern and never aliased; a way for a relying
  party to tell it is a root — which the JWKS has no field for today (§7.1),
  so either role metadata is added there or the root is distributed as a
  ready-made trust-store entry; and step 5, to confirm that adding the entry
  disturbs nothing.
- *For:* scope separation — a gateway-authorization compromise does not
  touch trust marks, and the reverse; custody can be established cleanly at
  creation rather than reconstructed; nothing about the key's history needs
  explaining; it is additive to the JWKS.
- *Against:* a second Strix authority key to hold, rotate and account for;
  it does not by itself resolve the duplicate key id, so customers still
  cannot use the whole JWKS as a trust store and need the root's entry
  extracted for them.

Under either option the **distribution channel** is the existing one, so
neither creates a disconnected hierarchy. What differs is whether the anchor
is an existing key with a history or a new key with none.

### 7.8 Recommendation

**None yet.** The choice turns on facts in §7.5 that have not been
established: which key the trust-mark authority is, how it is held, and what
it is permitted to sign. Recommending Option 1 now would assert custody
nobody has shown; recommending Option 2 now would dismiss an existing
authority that may be exactly suitable.

What can be said in advance is how the evidence maps to the choice:

- If step 1 identifies a key that is **not** aliased to any operational or
  `dev` id, step 3 shows offline single-environment custody, and step 4
  permits or is extended to cover gateway authorizations → Option 1 is
  justified.
- If the authority turns out to be key A, or custody cannot be shown, or the
  owner does not want one key vouching for both trust marks and gateways →
  Option 2.
- If steps 2–4 cannot be completed at all → Option 2, because a root whose
  custody cannot be evidenced should not be the thing customers are asked to
  trust.

Until the evidence exists, B-1 and B-2 stay open and the release stays on
hold. This section is a proposal for review; it does not authorize creating,
publishing or changing any key.
