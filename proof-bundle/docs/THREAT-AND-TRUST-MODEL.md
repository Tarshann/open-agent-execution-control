# Threat and trust model — Portable Proof Bundle v1

## The one principle

A valid signature proves that particular bytes were signed by a key. It does
not prove that a policy was enforced, that an action executed, that the actor
was authenticated, or that the event was reported truthfully. Every design
choice below exists to keep those apart.

## Parties and what each is trusted for

| Party | Trusted for | Not trusted for |
|---|---|---|
| **Signer** (the gateway process and whoever controls its key) | Having signed the records and the manifest | Telling the truth; having enforced anything; keeping its key safe |
| **Exporter** (runs beside the gateway, uses the same key) | Selecting records for one action without altering them | Same as signer — it *is* the signer for the manifest |
| **Carrier** (email, ticket, storage, whoever relays the bundle) | Nothing | Everything; may modify, drop, substitute, replay |
| **Relying party** (the customer running the verifier) | Choosing which keys to trust; running an unmodified verifier | — |
| **Verifier code** | Implementing `SPEC.md` | The relying party should pin it by checksum (`release/SHA256SUMS`) |

The relying party's trust store is the root of trust. It must arrive by a
channel independent of the bundle. Nothing inside a bundle can add to it.

## Transition-by-transition

| Step | Source | Evidence produced | Guarantee | Not guaranteed | Failure mode |
|---|---|---|---|---|---|
| Request reaches the proxy | MCP client | none | — | That every request takes this path | Direct call to the upstream: no record at all |
| Identity resolved | client metadata or configured resolver | `actorId` inside `invocationHash` | Value is bound to the receipt | That it was authenticated | Resolver missing → signed DENY |
| Policy evaluated | gateway, in process | `decision`, `policyVersion` in the signed receipt | Signer committed to this decision and ruleset hash | That evaluation was correct; that the policy is good | Evaluation throws → no execution |
| Approval | file/webhook approver | `approvalReason`, `approvedBy` (unsigned natively) | Fixed from export onward | Who approved; that anyone did | Timeout → DENY |
| Enforcement | adapter does not call the upstream on DENY | **none** | — | That the action did not happen | Bypass path |
| Execution | upstream tool | signed outcome from the proxy's view | Signer committed to SUCCEEDED / FAILED / UNKNOWN and a result hash | Side effects; truth of the tool's response | Outcome cannot be persisted → error to caller |
| Storage | JSONL files | records at rest | — | Integrity of unsigned fields; completeness | File edited → native signature fails for signed fields |
| Export | exporter + gateway key | manifest + signature | Inventory and evidence states fixed at export | That the store was complete | Refusal with a reason code |
| Delivery | untrusted | — | — | Anything | Detected at verification |
| Verification | relying party, offline | report | The four checks in `SPEC.md` §8 | Anything in "Never established" | Non-zero exit |

## Threats

Status: **A** addressed, **P** partially addressed, **N** not addressed (and
stated as such in every report).

| # | Threat | Status | How | Residual risk | Evidence |
|---|---|---|---|---|---|
| 1 | Evidence file modified | A | SHA-256 per artifact in the signed manifest | SHA-256 break | vector `tamper-evidence-byte`; exhaustive single-byte test |
| 2 | File deleted | A | Listed artifact must exist | — | `tamper-artifact-removed`, `tamper-signature-removed` |
| 3 | File substituted | A | Digest mismatch, even for another validly signed record | — | `tamper-artifact-replaced` |
| 4 | Manifest modified | A | Signature over exact manifest bytes | Key compromise | `tamper-manifest-field`, `tamper-manifest-digest-and-artifact` |
| 5 | Signature substituted | A | Signature binds to these manifest bytes | — | `tamper-signature-swapped` |
| 6 | Untrusted signer substitution | A | Keys come only from the relying party's trust store, or from an authorization signed by an issuer root in it; embedded keys never confer trust | Relying party trusts the wrong key or root | `trust-attacker-resigned`, `trust-wrong-key-same-id`, `tamper-embedded-key-swapped`, `auth-gateway-key-substituted` |
| 6a | Issuer impersonation | A | An authorization counts only if signed by an `issuer-root` entry; a root is never accepted as a record signer | Root key compromise | `auth-issuer-root-impersonated`, `auth-issuer-root-unknown`, `auth-root-used-as-record-signer` |
| 6b | Gateway exceeds its authorization | A | Scope (tenants, environments, record kinds) and dates are inside the root's signature | Dates are checked against signer-asserted record time | `auth-scope-widened-by-gateway`, `auth-wrong-tenant`, `auth-record-kind-not-authorized`, `auth-expired` |
| 6c | Withdrawn authorization still used | P | Signed revocation list; an unverifiable list is an error | Only as fresh as the list supplied; absent a list, standing is `NOT_CHECKED` | `auth-revoked`, `error-revocation-list-forged` |
| 6d | Report forged from inside a bundle | A | Every bundle-derived string is escaped in the text report | — | `test/hardening.test.mjs` (F4) |
| 6e | Statement attributed to the wrong signer | A | Decision → receipt signer; outcome → outcome signer; unsigned receipt fields → manifest signer | — | `test/hardening.test.mjs` (F5) |
| 7 | Compromised signing key | N | Trust store can mark a key `revoked`; nothing detects an undisclosed compromise | An attacker with the key can produce bundles that pass | `trust-revoked`; limitation in every report |
| 8 | Replay of a valid bundle | P | `bundleId` and `receiptId` are stable identifiers; `--expect-*` pins | The relying party must track identifiers; no nonce or audience binding | `expect-wrong-receipt` |
| 9 | Cross-tenant confusion | P | `tenantId` signed in the receipt and repeated in the subject; exporter requires and checks `--tenant`; trust store keys can be tenant-scoped; `--expect-tenant` | Open gateway is single-tenant (`"local"`); hosted isolation not inspected | `signed-tenant-substituted`, `trust-other-tenant`, exporter tests |
| 10 | Action identifier substitution | A | Subject must equal the signed receipt; relying party can pin the id | — | `signed-subject-substituted` |
| 11 | Policy identifier substitution | A | `policyVersion` is inside the receipt signature; a disclosed ruleset must hash to it | Without disclosure the policy is an opaque hash | `signed-policy-disclosure-mismatch` |
| 12 | Misleading timestamps | N | Ordering sanity checks only | Signer can assert any time; no timestamp authority | `signed-outcome-before-decision`; claim PPB-C11 |
| 13 | Forged execution-result statement | P | Outcome is signed, hash-checked and linked to the receipt | A signer (or key thief) can sign a false outcome | `signed-outcome-of-other-action`, `signed-outcome-incoherent` |
| 14 | Correctly signed but false source event | N | Cannot be detected cryptographically | The whole class | Classified `SOURCE_ASSERTION`, never `ESTABLISHED` |
| 15 | Incomplete evidence presented as complete | P | Evidence states are explicit and checked against content; an absent outcome is reported as NOT ESTABLISHED | Exporter can omit a record that existed; the hash chain is not exported | `signed-missing-outcome-called-not-applicable`; claim PPB-C12 |
| 16 | Unsupported verification claims | A | Claims come from fixed rules over verified inputs; unlisted files and `extensions` are never read; enforcement cannot be claimed | — | `tamper-artifact-inserted`, `signed-evidence-state-overclaims`, claims invariants test |
| 17 | Malformed or oversized input | A | Strict JSON, hard limits, typed errors | Parser bugs | `error-*` vectors; limit tests |
| 18 | Path traversal / archive extraction | A | No archive format; verifier never writes files; strict path grammar; no symlinks | — | `error-path-*`, directory tests |
| 19 | Algorithm downgrade | A | SHA-256 and Ed25519 only; any other declared algorithm is an error | — | `error-digest-algorithm-downgrade`, `error-signature-algorithm-none`, `error-signature-envelope-algorithm` |
| 20 | Parser differential (duplicate keys) | A | Duplicate keys rejected everywhere | — | `error-duplicate-key-*` |
| 21 | Laundering a bad record through export | A | Exporter refuses any record that fails its own signature; runs the verifier on its output before writing | — | exporter tests; `run.mjs` |
| 22 | Unsigned native fields altered before export | N | Not detectable (finding F-1) | Approval and tool fields could be edited in the store before export | Claim PPB-C08 limitation |
| 23 | Gateway bypass | N | Out of scope for evidence | Demonstrated in `run.mjs` step E | Claim PPB-C09 |

## What Strix does not have (and this product does not pretend to)

No trusted execution environment, no hardware attestation, no independently
witnessed enforcement event, no timestamp authority, no transparency log in
the gateway path, no published revocation list for gateway keys. If any of
these is added later, it enters the format as a new artifact role named in
`critical`, so old verifiers fail closed rather than ignore it.

## Key lifecycle policy

- **Rotation.** Keep the old public key in the trust store as `retired`,
  optionally with `notAfter` set to the rotation time. Records it signed keep
  verifying. A bundle's manifest may be signed by the new key while its
  records carry the old one; both must be trusted.
- **Compromise.** Mark the key `revoked`. Every bundle it signed then fails,
  whatever dates the records carry.
- **Historical trust.** Trusting a key now does not show it was uncompromised
  when it signed. The verifier says so (claim PPB-C03).
- **Revocation freshness.** The verifier checks only the store you give it.
  How often you refresh that store is your control, not the verifier's.
