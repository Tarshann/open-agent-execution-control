# Proof attempt — one real governed action, handed to the published verifier

`docs/VALIDATION.md` listed two gaps together:

> 5. **No real governed action executed, and therefore no evidence id.**
> 6. **No public verifier output.** No `npx @strixgov/verifier <id>` run against a
>    publicly resolvable record is included, so "anyone can check it" is unproven here.

This document closes the first and **replaces the second with a specific, named
blocker** rather than leaving it as "not attempted". Everything below was run;
nothing is asserted from reading code.

The headline outcome, stated before the detail so it cannot be skimmed past:

> A real governed action executed and produced a real signed receipt. Handed the
> raw `local-receipt-v1`, the published verifier **refused it** (wrong schema
> family) and the onboarding model correctly ended at `proof_failed`. A
> tool-gateway **projection** of the same receipt — every field honestly derived,
> nothing invented — then returned **`Status: VERIFIED`, exit 0** from
> `npx @strixgov/verifier@1.20.0`, and the onboarding model reached **READY** on
> it. The trust anchor is still the local key; see the trust-scope section
> before quoting the verdict.

## Reproducing

```bash
git rev-parse HEAD                      # f46cee5 at time of writing
npx --yes @strixgov/verifier --help     # 1.20.0
```

The two scripts are not committed — they are ~120 lines of glue over the public
API, and a committed demo script would be a fixture. The steps are listed in full
below so they can be re-run by hand.

## 1. The governed action — real, and irreversible

A file on disk was mutated through `governed_action_local()`:

| | |
|---|---|
| Capability | `data.write` |
| Action | `upgrade_customer_plan` |
| Payload | `{"recordId": "cust_0001", "field": "plan", "from": "trial", "to": "enterprise"}` |
| Before | `customer-record.json` contained `"plan": "trial"` |
| After | `"plan": "enterprise"` |
| Decision | `REQUIRE_APPROVAL_GRANTED` |
| Execution | `SUCCEEDED` |

The mutation was verified by re-reading the file, not by trusting the return
value. `approval_granted=True` was passed explicitly — the truthiness fix from #1
means nothing else would have satisfied the gate.

## 2. The evidence id and receipt

```
evidence id : local_ev_19280411de58494ebd98ef099e9d8fee
```

The signed payload, verbatim:

```json
{
  "action": {
    "name": "upgrade_customer_plan",
    "paramsHash": "c387128df150129a12a250fc4292814ecdbbe0686e7d4adf224f5bad672cdcc9",
    "paramsSchemaHash": "338f62196c6cfd113d81c252b75d7b7127e685a0b1c9cd93d83e83c646bc9e30"
  },
  "capabilityId": "data.write",
  "chainSeq": 0,
  "createdAt": "2026-07-29T20:07:33Z",
  "decision": "REQUIRE_APPROVAL_GRANTED",
  "evidenceHash": "8e566304e242553ef6cc1a5e7c5914fb28acc76f2414548d8f60593b021478db",
  "evidenceId": "local_ev_19280411de58494ebd98ef099e9d8fee",
  "executionStatus": "SUCCEEDED",
  "policyRef": { "hash": "b89f4e29…c599141", "version": "local-policy-v1" },
  "prevHash": null,
  "proofChainHash": "1cd7f7dd7baf09b38fd1627e9ce51d00563dfdf69acb6bf70c074eb5e4c2b408",
  "publicKeyFingerprint": "744c02d8284506d0c5de0ef30c6036e7aea54132b4f8abc3d7c05fd69a471473",
  "recordMode": "LOCAL_SIGNED_V1",
  "runtimeVersion": "strix-wire-local-helper/1.0.0",
  "schemaVersion": "local-receipt-v1",
  "signingKeyId": "local-744c02d8284506d0",
  "workspaceFingerprint": "47eac66bac139e4f7bcae20227d1da1f2b825ab048a684a5af6aee5c2fd1bcd9"
}
```

Signature (Ed25519, hex):
`f9911e2873658a4173012bb732bfa93049a5457b50bcff1bfea3504a701d3078e5b493049bba6495538f6af0c54d585a1603dcc8fbfddf9175c4554aa4ab120e`

**These values are single-use.** The key is generated per workspace, so re-running
produces a different `evidenceId`, `signingKeyId` and signature. They are quoted
so the shape and field set can be inspected, not so anyone can re-verify *this*
record — which is itself part of the finding: a workspace-local key is not a
publicly resolvable one.

## 3. Public key, exported as JWKS

The local registry's public key, converted to the JWKS form the verifier accepts:

```json
{
  "keys": [{
    "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
    "kid": "local-744c02d8284506d0",
    "x": "c_rxTou5c1E4HQkXICO3FvLFb9wwEseQomSpaLqcGWs"
  }]
}
```

## 4. This repository's own verification — signature holds

`verify_local_chain([receipt], state_dir=…)` reports, per record:

```json
{
  "hashValid": true,
  "chainValid": true,
  "signaturePresent": true,
  "signatureValid": true,
  "keyResolved": true,
  "status": "VERIFIED"
}
```

The call's top-level `ok` is `false`, and that is **not** a verification failure:
`verify_local_chain` expects `local-receipt-v3` chain steps, and this is a single
`local-receipt-v1` receipt with no `chainRef`. Wrong API for a single receipt; the
per-record verdict above is the relevant one. Recorded because quoting `ok: false`
without that distinction would read as a failed signature check.

## 5. The published independent verifier — refuses

`@strixgov/verifier@1.20.0`, installed fresh from npm. Two attempts:

**As persisted** (`{payload: {...}, signature: "..."}`):

```
$ npx --yes @strixgov/verifier receipt receipt.json --jwks jwks.json
  Signing key id:    undefined
  Hash valid:        false
  Signature valid:   false
  Status:            ERROR
  Error:             missing signingKeyId
exit 2
```

The verifier expects a **flat** receipt; this repository nests the signed fields
under `payload`.

**Flattened** (`{...payload, signature}`):

```
$ npx --yes @strixgov/verifier receipt receipt-flat.json --jwks jwks.json
  Capability:        data.write
  Decision:          REQUIRE_APPROVAL_GRANTED
  Signing key id:    local-744c02d8284506d0
  Action:            [object Object]
  Hash valid:        false
  Signature valid:   false
  Status:            ERROR
  Error:             buildReceiptCanonicalPayload: unknown schemaVersion 'local-receipt-v1'
exit 2
```

Note what *did* work: the JWKS loaded, the `kid` resolved, `capabilityId` and
`decision` were read correctly. The refusal is specific and it is at
`src/index.mjs:1309`:

```js
if (v === "1") order = RECEIPT_FIELD_ORDER_V1;
else if (v === "2") order = RECEIPT_FIELD_ORDER_V2;
else throw new Error(`buildReceiptCanonicalPayload: unknown schemaVersion '${v}'`);
```

**The `receipt` subcommand supports the `@strixgov/tool-gateway` receipt schema —
`schemaVersion` `"1"` (11 fields) and `"2"` (14 fields, adding `policyVersion`,
`tenantId`, `environment`) — and nothing else.** This repository's
`local-receipt-v1` is a different schema family: 18 fields, different names
(`workspaceFingerprint`, `publicKeyFingerprint`, `runtimeVersion`, `chainSeq`, a
nested `action` object), and no `tenantId` or `environment` at all.

So the incompatibility is structural, not a serialization detail. Renaming a field
would not fix it; the two schemas describe different things.

### The other two routes, also attempted

| Route | Result |
|---|---|
| `strix-verify <evidenceId>` against the hosted proof API | Needs a **hosted** evidence record. `local_ev_…` exists only in a local `.strix/` directory, so there is nothing for the proof API to resolve. |
| The `strix_verify` MCP tool (no auth, returns the `npx` command) | **`MCP error -32003: requires approval`** — an approval this non-interactive session cannot grant. Same blocker class as the `Strixgov/skills` attach. |

## 6. The onboarding model, driven by that reality

The full path was walked with the real evidence id and the real verdict — no
fixtures:

```
DRAFT                        state=draft
record_organization          state=tenant_created
register_system              state=systems_registered
define_capability            state=capabilities_defined
configure_policy             state=policies_configured
activate_integration         state=integrations_configured   <- MAX_CONFIGURED_STATE
  is_ready                   False                            <- fully configured, deliberately not ready
record_connectivity          state=ready_for_smoke_test
begin_smoke_test             state=smoke_test_running
record_smoke_test            state=proof_pending    evidence=local_ev_19280411de58494ebd98ef099e9d8fee
record_verification          state=proof_failed     verdict=ERROR
```

Readiness view:

```
  [done]  Create tenant
  [done]  Identify systems
  [done]  Select governed actions
  [done]  Configure approvals and policies
  [done]  Connect credentials and adapters
  [done]  Validate integration
  [done]  Run governed smoke test
  [FAIL]  Verify evidence independently

  READY       no

  Not proven: npx @strixgov/verifier receipt (ERROR) returned ERROR for
  evidence local_ev_19280411de58494ebd98ef099e9d8fee.
```

**This is the model working, not failing.** Seven stages of real configuration and
a real executed governed action, and it still refuses to say ready, because the
one thing that would justify the claim — an independent verdict attesting the
signature — did not arrive. `is_ready` is derived, so nothing short of that
verdict produces a `yes`.

## 7. What this changed in the code

The verdict vocabulary had no term for what actually happened. The available
refusals each assert something untrue about this outcome:

| Verdict | Why it would have been a lie here |
|---|---|
| `KID_NOT_FOUND` | The `kid` **did** resolve — the verifier printed it. |
| `LEGACY_UNSIGNED` | The record is signed, and the signature is valid. |
| `COMPLIANCE_VIOLATION` | Nothing was found non-compliant; the check never ran. |

`VerificationVerdict.ERROR = "ERROR"` was added — non-proof-bearing, and taken
verbatim from the verifier's own output rather than invented, which keeps the
"borrowed from the verifier surface" discipline intact. Collapsing "could not
check" into "checked and failed" is the same class of error as collapsing "we did
not finish looking" into "we looked and it is clean", which this repository has
already fixed twice (`unreadableFiles`, `unscannedSubtrees`).

## Second attempt — the export, and a VERIFIED

The section above ended at the protocol boundary. Reading the verifier's source
dissolved the design dilemma it posed: **tool-gateway `schemaVersion: "1"` has no
`tenantId` and no `environment`** — those exist only in v2. Its eleven canonical
fields all have honest local sources, so Local Mode can emit v1 without inventing
a single hosted-tenancy value.

`export_tool_gateway_receipt()` (in `governed_action_local.py`) projects a
verified local receipt into that shape and signs the projection with the same
local key:

| Tool-gateway field | Source in the local receipt |
|---|---|
| `receiptId` | `evidenceId` |
| `capabilityId`, `decision` | same fields |
| `action` | `action.name` |
| `invocationHash` | `action.paramsHash` |
| `evidenceHash`, `proofChainHash`, `timestamp` | same fields (`createdAt`) |
| `mode` | `recordMode` = `LOCAL_SIGNED_V1` — the trust scope, visible in the verifier's output |
| `risk` | **`UNSPECIFIED`** — no risk assessment happens in Local Mode; the schema makes the field mandatory, so it states the absence instead of fabricating a tier |

Two refusals are built in: a local receipt that fails its own verification is not
exportable (the export signs fresh, so exporting a tampered record would launder
it through a valid signature), and a receipt signed by a different key than the
workspace's current one is not re-attributed.

**The verifier's verdict, observed:**

```
$ npx --yes @strixgov/verifier receipt receipt-tg.json --jwks jwks.json
  Receipt ID:        local_ev_19280411de58494ebd98ef099e9d8fee
  Capability:        data.write
  Action:            upgrade_customer_plan
  Decision:          REQUIRE_APPROVAL_GRANTED
  Risk:              UNSPECIFIED
  Mode:              LOCAL_SIGNED_V1
  Signing key id:    local-744c02d8284506d0
  Hash valid:        true
  Signature valid:   true
  Status:            VERIFIED
exit 0
```

And the discrimination check — the same export with `decision` forged to `ALLOW`:

```
  Decision:          ALLOW
  Signature valid:   false
  Status:            TAMPERED
exit 1
```

A `VERIFIED` that could not fail would prove nothing; this one fails on a
one-field edit.

## The onboarding path, re-run on the VERIFIED verdict

Same real evidence id, same model, no fixtures — only the verdict changed,
because the verifier now actually returned one:

```
record_smoke_test            state=proof_pending   evidence=local_ev_19280411de58494ebd98ef099e9d8fee
record_verification          state=ready           verdict=VERIFIED

  [done]  Run governed smoke test
  [done]  Verify evidence independently
  READY   yes

  VERIFIED: evidence local_ev_19280411de58494ebd98ef099e9d8fee was independently
  checked by npx @strixgov/verifier@1.20.0 receipt (local JWKS). This attests
  that the record is signed and unmodified — not that the governed system is
  secure or compliant.
```

Both terminal outcomes of the onboarding machine have now been produced by real
verifier runs: `proof_failed` on the raw receipt's `ERROR`, `ready` on the
export's `VERIFIED`.

## Trust scope of the VERIFIED — read before quoting it

What `VERIFIED` means here: **independently maintained code** — a published npm
package this repository does not control, transcribed and pinned by nothing local
— re-derived the Ed25519 signature over the exported fields under the key in the
supplied JWKS. **And that key is this workspace's local key.**

Independent *code*, local *trust anchor*. So:

- It is still a `LOCAL_MACHINE_ASSERTION`, now checkable by an external tool.
  The verifier's own output says so: `Mode: LOCAL_SIGNED_V1`.
- It is reproducible by **anyone holding the two files** (`receipt-tg.json`,
  `jwks.json`) — but the record is not publicly *resolvable*: there is no hosted
  evidence id to look up, no Strix-custody JWKS endpoint serving this key.
- It does not attest that the governed system is secure, compliant, or that the
  mutation was a good idea — only that this record is signed and unmodified.

What would upgrade it to the hosted claim: a hosted evidence record and
`strix-verify <evidenceId>` against Strix-custody keys. That requires the hosted
platform, which is not in this repository. Local Mode and Hosted Mode are two
evidence ecosystems with different trust anchors; the export makes the first one
checkable by the second one's tool without pretending to be it.
