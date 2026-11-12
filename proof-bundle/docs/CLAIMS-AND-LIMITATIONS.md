# Claims and limitations

The verifier does not print "verified". It prints four separate results and
then twelve claims, each with a classification, a status, the artifacts it
rests on, the trust it assumes, and its limits. This page defines them.

## The four results

| Result | Question it answers | Values |
|---|---|---|
| Integrity | Are the files exactly the ones the manifest lists? | `VERIFIED`, `FAILED` |
| Signature mathematics | Do the signatures verify under *some* key with that id? | `VALID`, `INVALID`, `NOT_EVALUATED` |
| Signer trust | Is that key one **you** decided to trust? | `TRUSTED`, `NOT_ESTABLISHED`, `UNTRUSTED`, `REVOKED`, `OUTSIDE_VALIDITY`, `TENANT_NOT_AUTHORIZED`, `NOT_EVALUATED` |
| Evidence consistency | Do the signed records agree with each other? | `CONSISTENT`, `INCONSISTENT`, `NOT_EVALUATED` |

`Overall` is `PASSED` only when the four are `VERIFIED`, `VALID`, `TRUSTED`,
`CONSISTENT`. It summarizes those checks and nothing else.

## Classifications

| Classification | Meaning |
|---|---|
| `CRYPTOGRAPHIC_FINDING` | Follows from hashes and signatures alone. |
| `TRUST_EVALUATION` | Follows from comparing signers with your trust store. |
| `SOURCE_ASSERTION` | The signer says so. The verifier confirmed *who said it*, not *that it is true*. |
| `CORROBORATED` | A disclosed artifact was checked against a value inside a signature (a hash match). |
| `NOT_ESTABLISHED` | The evidence does not support the conclusion. |

## Statuses

`ESTABLISHED` · `ASSERTED` (a trusted signer's statement) ·
`ASSERTED_BY_UNTRUSTED_KEY` (same statement, signer not authenticated) ·
`NOT_ESTABLISHED` · `NOT_APPLICABLE`.

## The claims

| Id | Topic | Rule | Best possible result |
|---|---|---|---|
| PPB-C01 | Integrity | All digests match; no unlisted file | CRYPTOGRAPHIC_FINDING / ESTABLISHED |
| PPB-C02 | Signatures | Manifest, receipt and (if present) outcome signatures verify | CRYPTOGRAPHIC_FINDING / ESTABLISHED |
| PPB-C03 | Signer trust | Every key is trusted per `SPEC.md` §7: listed directly, or authorized by an issuer root. The statement says which, and for an authorization names the root, the gateway, the scope, the dates and whether revocation was checked | TRUST_EVALUATION / ESTABLISHED |
| PPB-C04 | Policy decision | From the signed receipt: decision, action, capability, risk, mode, tenant | SOURCE_ASSERTION / ASSERTED |
| PPB-C05 | Policy identity | Disclosed ruleset hashes to the signed `policyVersion` → corroborated; otherwise the policy is only a hash | CORROBORATED / ESTABLISHED |
| PPB-C06 | Invocation binding | Disclosed arguments hash to the signed `invocationHash` → corroborated; otherwise not established | CORROBORATED / ESTABLISHED |
| PPB-C07 | Actor identity | Always | NOT_ESTABLISHED |
| PPB-C08 | Approval | Receipt carries `approvalReason` / `approvedBy` | SOURCE_ASSERTION / ASSERTED |
| PPB-C09 | Enforcement | Always | NOT_ESTABLISHED |
| PPB-C10 | Execution outcome | Outcome present → signer's assertion of SUCCEEDED / FAILED / UNKNOWN; ALLOW with no outcome → not established; DENY → not applicable | SOURCE_ASSERTION / ASSERTED |
| PPB-C11 | Time | Always the signer's clock | SOURCE_ASSERTION / ASSERTED |
| PPB-C12 | Record completeness | Always | NOT_ESTABLISHED |

Three of these can never improve in v1, whatever the bundle contains:
**actor identity, enforcement, and record completeness**. The test suite
asserts this for every vector.

**Who is saying it.** A bundle can involve three keys: the one that signed
the decision, the one that signed the execution outcome, and the one that
signed the export. Each claim names the key behind it. The decision (C04) is
the receipt signer's; the outcome (C10) is the outcome signer's; approval and
the other natively unsigned receipt fields (C08) are the **export signer's**
statement, and the report says so when that is a different key from the
gateway that decided.

Claims are produced only when nothing failed. A `FAILED` bundle yields **no
claims** — a tampered file does not get a partial credit. An `INCOMPLETE`
bundle (no trust store) yields claims attributed to "the holder of key …,
whose identity is NOT established".

## Reading the common cases

**ALLOW, outcome SUCCEEDED.** A trusted signer recorded that it allowed the
action and then observed the tool return without error. You know who said
this and that the record is intact. You do not know that the tool did what
its response said, or that nothing else ran.

**ALLOW, outcome FAILED.** The signer recorded an attempt that failed. This is
not evidence that the action had no effect.

**ALLOW, no outcome.** The signer recorded a permission. Whether the action
ran is not established.

**DENY.** The signer recorded a refusal. Whether the action was actually
prevented is not established: the gateway is an inline decision point, and a
caller that reaches the tool another way leaves no record. The validation run
does exactly that (`validation/proof-bundle/run.mjs`, step E) and the DENY
bundle still passes, as it should — it is a true record of a decision.

**Signed but false.** If the signer signs a false statement with its real key,
verification passes. That is what `SOURCE_ASSERTION` means. Whether to rely
on the signer is your decision; the verifier only tells you it was them.

## Effect of withholding (redaction)

The exporter includes arguments and the policy ruleset only when asked. What
you lose when they are withheld:

| Withheld | Claim affected | Result |
|---|---|---|
| Invocation arguments | PPB-C06 | `NOT_ESTABLISHED`: you cannot tell what was requested, only that *something* with that hash was |
| Policy ruleset | PPB-C05 | Policy is an opaque hash; you cannot see which rule applied |
| Embedded key copy | none | No effect when you supply a trust store |

Partial redaction of arguments is not possible in v1: the gateway hashes the
arguments as a whole, so they are disclosed entirely or not at all. The tool's
result is never included; only its hash is.

## Never established by a v1 bundle

Printed at the end of every report:

1. That the action could not have been performed by a path that bypasses the gateway.
2. That no other executions of this action occurred outside the recorded one.
3. That the policy was correct, adequate, or compliant with any standard.
4. That the signing key was uncompromised when it signed, or that the signer reported events truthfully.
5. That the execution environment, the gateway process, or the upstream tool were uncompromised.
6. That all downstream side effects of the action were observed or recorded.
7. That any timestamp is correct.
8. That the actor named in the evidence was authenticated.
9. That a key marked trusted in your trust store has not been revoked since you last updated it.

## Words this product does not use

"Tamper-proof", "non-bypassable", "proves execution", "proves enforcement",
"guaranteed", "secure execution", "compliant". A bundle is tamper-*evident*;
it is evidence of what a named signer *recorded*.
