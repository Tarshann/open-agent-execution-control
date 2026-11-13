# Strix Portable Proof Bundle — format and verification specification, v1.0

Status: release candidate. This document is normative. It is intended to be
sufficient to write an interoperable verifier without reading Strix source
code; `python/ppb_verify.py` was written from it and agrees with
`verifier/strix-proof-verify.mjs` on every vector in `vectors/`. Sections
2.3, 5, 6.1, 6.3, 6.4, 6.6 and 7 were tightened after an independent review
found inputs on which the two implementations disagreed; each such input is
now a vector.

Key words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.

## 1. Scope

A bundle describes **exactly one governed action**: one authorization decision
recorded by a Strix gateway (`@strixgov/tool-gateway`, as embedded in
`@strixgov/mcp-proxy`), plus the execution outcome the gateway recorded for
it, if any. A bundle is a set of files, an inventory of those files, and one
signature over the inventory.

A bundle carries *records*. Section 8 defines which statements a verifier may
derive from them. Nothing in a bundle is evidence that an action could not
bypass the gateway.

## 2. Container

A bundle is a set of `(path, bytes)` pairs. Two encodings are defined and are
equivalent:

- **Directory form.** A directory tree. Every regular file is a member; its
  path is its location relative to the root, with `/` separators.
- **Carrier form.** One JSON file (suggested suffix `.ppb.json`):

  ```json
  { "format": "strix-ppb-carrier", "formatVersion": "1.0",
    "files": { "<path>": "<standard base64 of the bytes, with padding>" } }
  ```

  No other top-level fields are allowed. Base64 MUST be canonical (decoding
  and re-encoding yields the same string).

No archive format (zip, tar) is part of this specification. A verifier MUST
NOT extract a bundle to disk in order to verify it.

### 2.1 Paths

A path MUST match `^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$`,
MUST be at most 200 characters, and no segment may end in `.`. This excludes
`..`, absolute paths, backslashes, hidden files, spaces and non-ASCII names.
Two members whose paths are equal ignoring ASCII case MUST NOT both exist. In
directory form, a symbolic link or any non-regular file anywhere in the tree
is an error.

### 2.2 Limits

| Limit | Value |
|---|---|
| Member size | 1,048,576 bytes |
| Members | 64 |
| Total size | 8,388,608 bytes |
| Carrier file size | 12,582,912 bytes |
| JSON nesting depth | 32 |

A verifier MUST reject input exceeding a limit before processing its content.

### 2.3 Strict JSON

Every JSON document in a bundle, the carrier and the trust store MUST be
parsed strictly: RFC 8259 grammar; UTF-8 with no byte-order mark and no
invalid sequences; **no duplicate object keys at any depth**; no key named
`__proto__`; numbers that are finite IEEE-754 doubles; **no string or key
containing an unpaired UTF-16 surrogate** (as produced by an escape such as
`"\ud800"`). A document violating any of these is `MALFORMED_JSON`.

JSON `null` is a value, not absence. Wherever this specification says a field
is optional, "absent" means the key is not present; a key present with `null`
is a type error unless `null` is explicitly allowed. Lookups of
bundle-supplied names (paths, schema versions, rule names) MUST NOT consult
language-level inherited properties: `constructor` is an ordinary name. (Duplicate keys are rejected because two
parsers that pick different duplicates would disagree about what was signed.)

## 3. Members

| Path | Role | Required | Content |
|---|---|---|---|
| `manifest.json` | — | yes | Section 4. The signed inventory. |
| `manifest.sig.json` | — | yes | Section 5. The signature envelope. |
| `evidence/authorization-receipt.json` | `authorization-receipt` | yes | The gateway's receipt, as stored (Section 6.1). |
| `evidence/execution-outcome.json` | `execution-outcome` | no | The gateway's execution outcome (Section 6.2). |
| `disclosures/invocation.json` | `invocation-disclosure` | no | Section 6.3. |
| `disclosures/policy-ruleset.json` | `policy-disclosure` | no | Section 6.4. |
| `trust/embedded-signer-keys.json` | `embedded-signer-keys` | no | Public keys in any trust-store shape (Section 7.1). **Never trusted** (Section 7.3). A malformed file is ignored, never an error. |
| `trust/issuer-authorizations.json` | `issuer-authorizations` | no | Issuer authorizations for the keys that signed this bundle (Section 7.4). Has effect only through an issuer root in the relying party's trust store. |
| any other path | `explanatory` | no | Human-readable material. A verifier MUST NOT read it for any purpose other than checking its digest. |

The path ↔ role binding is fixed. A manifest that assigns a role to a
different path is `MALFORMED_MANIFEST`.

## 4. Manifest

`manifest.json` is a JSON object with exactly these fields (`extensions` is
optional; any other field is `MALFORMED_MANIFEST`):

| Field | Type | Meaning |
|---|---|---|
| `format` | string | `"strix-portable-proof-bundle"` |
| `formatVersion` | string | `"1.0"` |
| `critical` | string[] | Names of extensions a verifier MUST understand. v1.0 defines none: a non-empty list is `UNKNOWN_CRITICAL_EXTENSION`. |
| `bundleId` | string | Section 4.2. |
| `createdAt` | RFC 3339 | Exporter's clock at export. An assertion, not proof of time. |
| `exporter` | `{name, version}` | Informational. |
| `subject` | object | Section 4.1. |
| `evidence` | object | Section 4.3. |
| `digestAlgorithm` | string | `"sha-256"`. Anything else is `UNSUPPORTED_ALGORITHM`. |
| `artifacts` | object[] | One `{path, role, sha256, size}` per member other than `manifest.json` and `manifest.sig.json`. `sha256` is 64 lowercase hex; `size` is the byte length. |
| `signer` | `{keyId, algorithm}` | `algorithm` MUST be `"Ed25519"`, else `UNSUPPORTED_ALGORITHM`. |
| `extensions` | object | Non-critical extensions. A verifier MUST ignore the content and MUST NOT derive claims from it. |

The manifest is signed as **the exact bytes of the file**. It is never
re-serialized or canonicalized for verification.

### 4.1 Subject

`subject` has exactly: `kind` = `"governed-action"`, `receiptId`, `tenantId`,
`environment`, `capabilityId`, `action`, `invocationHash`; all non-empty
strings, each equal to the same field of the authorization receipt. For a
schema-1 receipt, which has no tenant fields, `tenantId` and `environment`
MUST be the literal `"UNSPECIFIED"`.

### 4.2 Bundle identifier

```
bundleId = "ppb_" + first 32 hex chars of
           SHA-256( canonicalJSON({ formatVersion, subject,
                                    artifacts: [ {path, sha256}, ... in manifest order ] }) )
```

`canonicalJSON` is defined in Section 6.5. The identifier depends only on the
evidence, not on `createdAt`: exporting the same evidence twice yields the
same `bundleId`; any change in evidence (for example an execution outcome
recorded after the first export) yields a different one. An exporter MUST NOT
overwrite an existing bundle.

### 4.3 Evidence states

`evidence` has exactly these fields. The state is the exporter's signed
statement about its store at export time.

| Field | Allowed values and meaning |
|---|---|
| `authorizationDecision` | `PRESENT` (always). |
| `executionOutcome` | `PRESENT` — the member exists. `ABSENT` — decision was ALLOW and the store held no outcome record. `NOT_APPLICABLE` — decision was not ALLOW; the gateway issues no outcome for a denied call. |
| `enforcementObservation` | `NOT_CAPTURED` (always in v1.0: no such artifact exists). |
| `invocationDisclosure` | `PRESENT` or `NOT_DISCLOSED`. |
| `policyDisclosure` | `PRESENT` or `NOT_DISCLOSED`. |

A state that does not match the bundle's content is `EVIDENCE_STATE_MISMATCH`.
`ABSENT` and `NOT_APPLICABLE` are statements about records; neither is
evidence that nothing executed.

## 5. Signature envelope

```json
{ "format": "strix-ppb-signature", "formatVersion": "1.0",
  "payloadType": "application/vnd.strix.ppb.manifest.v1+json",
  "signatures": [ { "keyId": "...", "algorithm": "Ed25519", "signature": "<base64url, no padding>" } ] }
```

v1.0 requires **exactly one** signature (otherwise `MALFORMED_SIGNATURE`);
its `keyId` MUST equal `manifest.signer.keyId` (`SIGNER_MISMATCH`). The
signed message is the DSSE v1 pre-authentication encoding of the manifest
bytes:

```
"DSSEv1" SP len(payloadType) SP payloadType SP len(manifestBytes) SP manifestBytes
```

where `len` is the decimal byte length and `SP` is one space (0x20). The
payload type acts as domain separation: a manifest signature can never be
replayed as a gateway receipt signature or vice versa. The envelope itself
is not signed; `format`, `formatVersion` and `payloadType` are checked for
equality with the values above, and nothing else in it other than `keyId`,
`algorithm` and `signature` is used.

Every base64url value that carries a signature or a public key MUST be
canonical: unpadded, and equal to the re-encoding of its decoded bytes. A
non-canonical signature is treated as not verifying (`SIGNATURE_INVALID`); a
non-canonical key is `MALFORMED_KEY`. An Ed25519 signature is exactly 64
bytes and a public key exactly 32.

## 6. Native records and disclosures

Members under `evidence/` are the gateway's own records, unchanged. Their
formats are defined by `@strixgov/tool-gateway` 0.5.0 and restated here.

In the following, `ordered(obj, fields)` is the string
`{"f1":v1,"f2":v2,...}` with the listed fields in the listed order, no
whitespace, each name and value serialized with ECMAScript `JSON.stringify`.

### 6.1 Authorization receipt

Signed fields, by `schemaVersion`:

- `"1"`: schemaVersion, receiptId, capabilityId, action, decision, risk, mode,
  invocationHash, evidenceHash, proofChainHash, timestamp
- `"2"`: schemaVersion, receiptId, capabilityId, action, decision, risk, mode,
  policyVersion, tenantId, environment, invocationHash, evidenceHash,
  proofChainHash, timestamp

All are non-empty strings. Signature: Ed25519 over the UTF-8 bytes of
`ordered(receipt, fields)`, base64url in `signature`, key named by
`signingKeyId`. `schemaVersion` MUST be the JSON string `"1"` or `"2"`; any
other value or type is `UNSUPPORTED_RECORD_VERSION`.

Further rules, each `MALFORMED_RECORD` unless stated:

- `invocationHash`, `evidenceHash` and `proofChainHash` are exactly 64
  lowercase hexadecimal characters.
- A schema-`"1"` receipt MUST NOT contain `policyVersion`, `tenantId` or
  `environment`. Schema 1 signs none of them; a tenant written beside the
  signed fields would steer tenant scoping without being signed. Its tenant
  and environment are the literal `UNSPECIFIED` everywhere (subject, trust
  scoping, issuer-authorization scope).
- These schemas are Ed25519 by definition and define no algorithm field. A
  receipt that nevertheless contains `signatureAlgorithm` MUST have it equal
  to `"Ed25519"`; otherwise `UNSUPPORTED_ALGORITHM`.

`evidenceHash` MUST equal `hex(SHA-256(invocationHash + "|" + decision + "|" + timestamp))`.
`decision` MUST be `ALLOW` or `DENY`.

**Fields outside the signed list are not protected by the gateway's
signature.** That includes `signingKeyId`, `tool`, `actorId`, `actorRole`,
`approvedBy`, `approvalReason` and `denialReason`. Inside a bundle they are
covered by the manifest digest, so they are fixed from the moment of export —
but not between issuance and export. A verifier MUST present them as
assertions of the **manifest signer** (which may be a different key from the
receipt signer), never of the gateway that made the decision (see
`docs/BASELINE.md`, finding F-1).

### 6.2 Execution outcome

`schemaVersion` `"1"`, `signatureAlgorithm` `"Ed25519"`. Core fields, in
order: schemaVersion, outcomeId, authorizationReceiptId,
authorizationProofChainHash, capabilityId, action, decision,
executionAttempted, executionStatus, invocationHash, resultHash, errorCode,
policyVersion, tenantId, environment, completedAt, signingKeyId,
signatureAlgorithm. All strings except `executionAttempted`, which MUST be
`true`.

- `outcomeHash` = `"sha256:" + hex(SHA-256(ordered(outcome, core fields)))`
- signature = Ed25519 over `ordered(outcome, core fields + ["outcomeHash"])`

An outcome containing any field other than these and `signature` is
`MALFORMED_RECORD`. Coherence: `executionStatus` ∈ {SUCCEEDED, FAILED,
UNKNOWN}; `resultHash` is `sha256:<64 hex>` iff SUCCEEDED, else empty;
`errorCode` is non-empty iff FAILED.

### 6.3 Invocation disclosure

An object with exactly `capabilityId`, `action`, `args`, `actorId`,
`actorRole`; all strings except `args`, which is any JSON value (`actorId`
and `actorRole` are empty when the gateway recorded none). Any other shape is
`MALFORMED_RECORD`. It is valid only if
`hex(SHA-256(canonicalJSON(disclosure)))` equals the receipt's
`invocationHash`; otherwise `DISCLOSURE_MISMATCH`.

If it hashes correctly but its `capabilityId` or `action` differs from the
receipt's own signed `capabilityId` or `action`, the receipt describes one
action and its hash commits to another: `CONTRADICTORY_RECORDS`.

### 6.4 Policy disclosure

An object with exactly `rules`, `riskOverrides`, `default`. `rules` and
`riskOverrides` are objects whose every value is one of `"ALLOW"`, `"DENY"`,
`"APPROVAL_REQUIRED"`; `default` is one of those or `null`. Any other shape
or value is `MALFORMED_RECORD`. Valid only if
`"sha256:" + hex(SHA-256(canonicalJSON(disclosure)))` equals the receipt's
`policyVersion`. (An exporter normalizes an operator's ruleset to this shape:
missing `rules` or `riskOverrides` become `{}`, missing `default` becomes
`null`. That is the form the gateway hashes.)

The gateway's evaluation order, used to report which rule applies: `rules`
has the key `capabilityId`; else the longest key `prefix.*` in `rules` where
`capabilityId` starts with `prefix.`; else `riskOverrides` has the key
`risk`; else `default` if not `null`; else `DENY`. "Has the key" means an own
key of that object. If the disclosed ruleset
yields `DENY` and the receipt's decision is `ALLOW`, the bundle is
`CONTRADICTORY_RECORDS`. (The converse is not a contradiction: rate limits
and identity failures deny calls an ALLOW rule would permit.)

### 6.5 canonicalJSON

`null`, `true`, `false` literally; strings and numbers as ECMAScript
`JSON.stringify` produces them (numbers per `Number::toString`: `1`, `-0.5`,
`1e+21`, `1e-7`; `-0` is `0`); arrays in order; objects with keys sorted by
**UTF-16 code unit** order; no whitespace. Output is encoded as UTF-8.

### 6.6 Timestamps

`YYYY-MM-DDTHH:MM:SS[.f]Z` or with a numeric offset `±HH:MM` in place of
`Z`, where every digit is an ASCII digit `0`–`9`, the separator is an
uppercase `T`, and `.f` is a point followed by 1 to 9 digits. Fields are
validated individually: year 1970–9999; month 01–12; day valid for that
month and year (Gregorian leap rule); hour 00–23; minute and second 00–59
(a leap second `60` is rejected); offset hour 00–23 and minute 00–59. A
value failing any of these is not a timestamp (`BAD_TIMESTAMP`, or the
document's malformed code where the field is structural). An implementation
MUST NOT delegate to a lenient date parser.

Comparisons are made at millisecond precision (further digits truncated).

## 7. Trust

### 7.1 Trust store

Supplied by the relying party, out of band. Three shapes are accepted:

```json
{ "format": "strix-ppb-trust-store", "formatVersion": "1.0",
  "keys": [ { "keyId": "...", "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." },
              "owner": "text", "status": "active | retired | revoked",
              "notBefore": "RFC 3339", "notAfter": "RFC 3339",
              "tenants": ["..."], "environments": ["..."] } ] }
```

a JWKS (`{"keys":[jwk,...]}`, each entry `active` and unconstrained, `keyId`
= `kid`), or a single JWK. Only `keyId` and `jwk` are required. Duplicate
`keyId`s, an entry without `jwk`, or a `null` where a value is expected make
the store `MALFORMED_TRUST_STORE`.

An entry may carry `"role"`:

| Role | Meaning |
|---|---|
| `signer` (default) | A gateway key the relying party trusts directly to sign records. |
| `issuer-root` | A key that authorizes gateway keys (Section 7.4) and signs revocation lists (Section 7.5). It is **not** accepted as the signer of a manifest, receipt or outcome. |

### 7.2 Evaluation

Each signature (manifest, receipt, outcome) is resolved by its key id. If the
trust store has an entry with that id and role `signer`, the key is evaluated
directly, as follows; otherwise Section 7.4 applies. The tenant and
environment used are the receipt's (`UNSPECIFIED` for schema 1).

| Condition | Result |
|---|---|
| `status` is `revoked` | `REVOKED` |
| the record's own time is before `notBefore` or after `notAfter` | `OUTSIDE_VALIDITY` |
| `tenants` present and lacks the receipt's `tenantId`, or `environments` lacks its `environment` | `TENANT_NOT_AUTHORIZED` |
| otherwise | `TRUSTED` |

"The record's own time" is `createdAt`, `timestamp` or `completedAt`
respectively. These are signer-asserted, so the validity window is a policy
check, not proof of signing time; a compromised key can backdate. For that
reason `revoked` fails **regardless of dates**. `retired` keys verify
normally: retirement means "no longer used to sign", not "untrustworthy".

A key id that is neither a `signer` entry nor covered by Section 7.4 is
`UNTRUSTED`. If no trust store is supplied, every signature is
`NOT_ESTABLISHED`, whatever the bundle contains.

### 7.3 Embedded keys

`trust/embedded-signer-keys.json` MAY be used **only** to compute whether a
signature is mathematically valid when the trust store has no key with that
id. It MUST NOT change any trust result. If the trust store has a key with
the same id, the embedded copy is ignored.

### 7.4 Issuer authorization

An issuer authorization is a statement, signed by an issuer root, that one
gateway key may sign the named kinds of record, for the named tenants and
environments, during a validity interval. It lets a relying party trust one
root instead of every gateway key, and verify that standing offline.

Envelope (DSSE; exactly these three fields, exactly one signature with
exactly `keyId`, `algorithm`, `signature`):

```json
{ "payloadType": "application/vnd.strix.ppb.issuer-authorization.v1+json",
  "payload": "<canonical standard base64 of the payload bytes>",
  "signatures": [ { "keyId": "<issuer root key id>", "algorithm": "Ed25519", "signature": "<base64url>" } ] }
```

The signature is over `PAE(payloadType, payload bytes)` as in Section 5. The
payload is a strict-JSON object with exactly:

| Field | Meaning |
|---|---|
| `type` | `"strix-ppb-issuer-authorization"` |
| `version` | `"1.0"` (else `UNSUPPORTED_VERSION`) |
| `authorizationId` | `ia_` followed by 1–64 of `A-Za-z0-9._-` |
| `issuer` | Non-empty text naming the issuer. Informational. |
| `issuedAt`, `notBefore`, `notAfter` | Timestamps (Section 6.6); `notAfter` ≥ `notBefore`. |
| `subject` | Exactly `gatewayId` (non-empty string), `keyId` (the gateway key id), `jwk` (Ed25519 OKP public key). |
| `scope` | Exactly `tenants`, `environments`, `records`: non-empty arrays of distinct non-empty strings; `records` ⊆ {`manifest`, `authorization-receipt`, `execution-outcome`}. There is no wildcard. |

Anything else is `MALFORMED_AUTHORIZATION`. Authorizations reach the verifier
in `trust/issuer-authorizations.json` —
`{"format":"strix-ppb-issuer-authorizations","formatVersion":"1.0","authorizations":[envelope, ...]}`
with 1 to 16 entries — and/or are supplied by the relying party, as that
container or as a single envelope. Two authorizations with the same
`authorizationId` and different payload bytes are `MALFORMED_AUTHORIZATION`.
Being inside the bundle gives an authorization no standing.

**Evaluation.** For a signature by key id *K* with no `signer` entry, take
the authorizations whose `subject.keyId` is *K*, in ascending
`authorizationId` order, and judge each for this record in exactly this
order, stopping at the first that applies:

| # | Condition | Result |
|---|---|---|
| 1 | The envelope's `keyId` is not an `issuer-root` entry in the trust store | `UNTRUSTED` |
| 2 | The envelope signature does not verify under that root | `AUTHORIZATION_INVALID` |
| 3 | The root, evaluated by Section 7.2 at `issuedAt`, is not `TRUSTED` | that result (`REVOKED`, `OUTSIDE_VALIDITY`, `TENANT_NOT_AUTHORIZED`) |
| 4 | A revocation list from the same root names `authorizationId` (Section 7.5) | `REVOKED` |
| 5 | The record's own time is before `notBefore` or after `notAfter`, or is not a timestamp | `OUTSIDE_VALIDITY` |
| 6 | The receipt's tenant ∉ `scope.tenants`, or its environment ∉ `scope.environments` | `TENANT_NOT_AUTHORIZED` |
| 7 | The record kind ∉ `scope.records` | `RECORD_NOT_AUTHORIZED` |
| 8 | otherwise | `TRUSTED` |

The signature's result is `TRUSTED` if any authorization is `TRUSTED`;
otherwise it is the result of the first authorization in the order above; if
there is none, `UNTRUSTED`.

**Which key bytes verify the record.** If the chosen authorization passed
step 2, the record signature is checked against `subject.jwk` — bytes the
root signed. Otherwise the embedded key (Section 7.3) may be used for the
mathematics only. A key that merely shares *K*'s id but differs from
`subject.jwk` therefore fails as `SIGNATURE_INVALID`.

The record's own time is signer-asserted (Section 7.2): an authorization
bounds what a gateway key may *claim*, and expiry is not revocation.

### 7.5 Revocation list

Optional relying-party input. A DSSE envelope as in Section 7.4 with
`payloadType` `application/vnd.strix.ppb.authorization-revocations.v1+json`
and a payload with exactly `type` (`"strix-ppb-authorization-revocations"`),
`version` (`"1.0"`), `issuer`, `issuedAt`, and `revoked`: an array of at most
4096 `{authorizationId, revokedAt}`.

A supplied list MUST be signed by an `issuer-root` entry in the trust store
that is not `revoked`, and its signature MUST verify; otherwise the input is
`REVOCATION_LIST_INVALID` (an error — an unverifiable list is never read as
"nothing is revoked"). A list affects only authorizations signed by the same
root key id. A revoked authorization fails regardless of record dates.

Standing is tri-state and MUST be reported: `REVOKED`; `NOT_REVOKED` (a list
from that root was supplied and does not name the authorization);
`NOT_CHECKED` (no list from that root was supplied). `NOT_CHECKED` does not
fail verification, and MUST be stated in the report.

## 8. Verification procedure

A verifier MUST perform these stages in order and report each separately.

1. **Load** (Section 2). Failure → `ERROR`.
2. **Manifest** (Section 4). Parse strictly and validate. Failure → `ERROR`.
3. **Integrity.** Every listed artifact MUST exist with the listed size and
   SHA-256 (`MISSING_ARTIFACT`, `DIGEST_MISMATCH`). Every member other than
   the manifest and the envelope MUST be listed (`UNEXPECTED_ARTIFACT`). The
   envelope MUST exist (`MISSING_SIGNATURE`). If any of these fail, the
   verifier stops: later stages are `NOT_EVALUATED`.
4. **Signatures** (Sections 5, 6) and **signer trust** (Section 7), reported
   as two results. Malformed records or envelopes → `ERROR`.
5. **Consistency.** Subject ↔ receipt (`SUBJECT_MISMATCH`); bundle id
   (`BUNDLE_ID_MISMATCH`); receipt hash (`RECEIPT_HASH_MISMATCH`); decision
   value (`UNRECOGNIZED_DECISION`); evidence states
   (`EVIDENCE_STATE_MISMATCH`); outcome present with a non-ALLOW decision, or
   incoherent outcome, or policy contradiction (`CONTRADICTORY_RECORDS`);
   outcome ↔ receipt link on `authorizationReceiptId`,
   `authorizationProofChainHash`, `capabilityId`, `action`, `invocationHash`,
   `policyVersion`, `tenantId`, `environment` (`OUTCOME_LINK_MISMATCH`);
   `OUTCOME_HASH_MISMATCH`; `DISCLOSURE_MISMATCH`; timestamps parse
   (`BAD_TIMESTAMP`) and are ordered decision ≤ completion and decision ≤
   export (`TIMESTAMP_ORDER`).
6. **Expectations.** Optional relying-party pins on receipt id, tenant,
   environment, bundle id (`EXPECTATION_MISMATCH`).
7. **Claims** (`docs/CLAIMS-AND-LIMITATIONS.md`). Derived only if nothing
   failed and every signature was mathematically checked.

### 8.1 Result

| Overall | Exit | Condition |
|---|---|---|
| `ERROR` | 2 | Input could not be evaluated. No conclusion may be drawn. |
| `FAILED` | 1 | Any failure in stages 3–6, including an untrusted, revoked, out-of-window or wrong-tenant signer. Claims are not evaluated. |
| `INCOMPLETE` | 3 | Nothing failed, but not every signer is `TRUSTED` (no trust store). Claims, if evaluated, are attributed to an unidentified key holder. |
| `PASSED` | 0 | Integrity verified, all signatures valid, all signers trusted, content consistent. |

`PASSED` is a statement about those four checks only. A verifier MUST present
the claims and the list of unsupported conclusions alongside it.

A verifier that prints a human-readable report MUST escape, in every string
taken from a bundle, trust store or authorization: C0 and C1 control
characters, U+2028, U+2029 and bidirectional controls. Bundle content is
untrusted even when it verifies, and must not be able to forge report lines.

Each statement in a report MUST be attributed to the key that signed the
record it comes from: the decision to the receipt signer, the execution
outcome to the outcome signer, and natively unsigned receipt fields to the
manifest signer. These may be three different keys.

### 8.2 Failure and error codes

Errors: `NOT_FOUND`, `NOT_A_BUNDLE`, `MALFORMED_JSON`, `MALFORMED_CARRIER`,
`MALFORMED_MANIFEST`, `MALFORMED_SIGNATURE`, `MALFORMED_RECORD`,
`MALFORMED_KEY`, `MALFORMED_TRUST_STORE`, `MALFORMED_AUTHORIZATION`,
`REVOCATION_LIST_INVALID`, `UNSAFE_PATH`, `DUPLICATE_PATH`,
`FILE_TOO_LARGE`, `TOO_MANY_FILES`, `BUNDLE_TOO_LARGE`,
`UNSUPPORTED_VERSION`, `UNSUPPORTED_ALGORITHM`,
`UNSUPPORTED_RECORD_VERSION`, `UNKNOWN_CRITICAL_EXTENSION`.

Failures: those named in stages 3–6, plus `SIGNATURE_INVALID`,
`SIGNER_MISMATCH`, `SIGNER_UNTRUSTED`, `SIGNER_REVOKED`,
`SIGNER_OUTSIDE_VALIDITY`, `SIGNER_TENANT_NOT_AUTHORIZED`,
`SIGNER_AUTHORIZATION_INVALID`, `SIGNER_RECORD_NOT_AUTHORIZED`.

Codes are stable within major version 1.

## 9. Versioning and compatibility

- `formatVersion` is `MAJOR.MINOR`. A verifier accepts exactly the versions it
  lists; v1.0 verifiers accept `"1.0"` only and reject everything else with
  `UNSUPPORTED_VERSION`. There is no "best effort" verification of a newer
  bundle.
- A future minor version may add optional members and `extensions` content. A
  feature that a verifier must understand to verify safely MUST be named in
  `critical`, so older verifiers fail closed.
- New native record schema versions (receipt `"3"`, outcome `"2"`) require a
  new verifier; until then they are `UNSUPPORTED_RECORD_VERSION`.
- Cryptographic agility is by version, not negotiation: v1.0 is SHA-256 and
  Ed25519 only. Any other declared algorithm is an error, never a fallback.

## 10. Test vectors

`vectors/index.json` lists 116 carrier bundles, each with a trust store,
optional relying-party inputs (issuer authorizations held out of band, a
revocation list) and the required result (overall, exit code, failure or
error code, and claim classifications). They are byte-reproducible with `node vectors/generate.mjs
--check`. All are synthetic and signed with published test keys.
