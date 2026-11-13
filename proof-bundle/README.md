# Strix Governance — Portable Proof Bundle v1

**Status: release candidate (`1.0.0-rc.2`). Not deployed, not published.**
See [`RELEASE-READINESS.md`](RELEASE-READINESS.md) for exactly what was built,
what was tested, and what is still open.

A Portable Proof Bundle is an evidence package for **one governed action**.
You receive it as a directory or a single file, verify it on your own machine
with a one-file verifier and a key you chose to trust, and get a report that
says what the evidence supports and what it does not.

> Receive an independently verifiable evidence package for a governed action,
> validate its integrity using an offline verifier, and understand precisely
> what can and cannot be concluded from the evidence.

## What it tells you — and what it doesn't

| A passing verification establishes | It does not establish |
|---|---|
| The files are unchanged since they were signed | That the policy was enforced |
| The signatures are valid | That the action executed (beyond the signer's own report) |
| The signer is one **you** trust | That the action could not bypass the gateway |
| The records agree with each other | That the signer told the truth, or that the policy was right |

A valid signature proves that particular bytes were signed by a key. The
verifier keeps that separate from everything else:
[`docs/CLAIMS-AND-LIMITATIONS.md`](docs/CLAIMS-AND-LIMITATIONS.md).

## Quick start (customer)

Requires Node.js ≥ 18. Nothing to install; no network is used.

```bash
cd proof-bundle
node verifier/strix-proof-verify.mjs verify examples/01-allow-succeeded --trust-store examples/trust-store.demo.json
```

You should see `Overall ... PASSED` followed by twelve claims and a list
headed "Never established by a v1 bundle". Then:

```bash
node verifier/strix-proof-verify.mjs verify examples/02-deny --trust-store examples/trust-store.demo.json
```

A denied action: note claim `PPB-C09` — prevention is **not** established.

```bash
node verifier/strix-proof-verify.mjs verify examples/01-allow-succeeded
```

No trust store: `INCOMPLETE`, exit code 3. The key inside a bundle is never
trusted.

`trust-store.demo.json` holds **only a demo issuer root**. The gateway key's
standing comes from an authorization inside each bundle, signed by that root
and limited to tenant `local`. `trust-store.demo-direct.json` is the other
model: the gateway key listed directly.

For your own bundles, build a trust store from a key you obtained out of
band: [`docs/VERIFIER-GUIDE.md`](docs/VERIFIER-GUIDE.md).

## Quick start (operator)

```bash
node exporter/strix-proof-export.mjs list   --store <storagePath> --tenant <tenantId>
node exporter/strix-proof-export.mjs export --store <storagePath> --key-dir <keyPath> \
     --receipt-id <rcpt_...> --tenant <tenantId> --out ./bundle --carrier ./bundle.ppb.json
```

The exporter reads the store of an existing `@strixgov/mcp-proxy` /
`@strixgov/tool-gateway` and signs with the gateway's existing key:
[`docs/OPERATIONS.md`](docs/OPERATIONS.md).

## What is in a bundle

```
manifest.json                          signed inventory: subject, evidence states, SHA-256 of every file
manifest.sig.json                      one Ed25519 signature over the exact manifest bytes
evidence/authorization-receipt.json    the gateway's signed decision record, unchanged
evidence/execution-outcome.json        the gateway's signed execution record, if one exists
disclosures/invocation.json            optional: the arguments, checked against the signed hash
disclosures/policy-ruleset.json        optional: the policy, checked against the signed hash
trust/issuer-authorizations.json       optional: an issuer root's signed authorization of the gateway key
trust/embedded-signer-keys.json        optional convenience copy of the public key - never trusted
README.md                              explanatory only - never read by the verifier
```

Missing evidence is stated, not papered over: `executionOutcome` is
`PRESENT`, `ABSENT` or `NOT_APPLICABLE`; `enforcementObservation` is always
`NOT_CAPTURED` in v1.

## Contents of this directory

| Path | What |
|---|---|
| `verifier/strix-proof-verify.mjs` | The offline verifier. One file, zero dependencies. |
| `exporter/strix-proof-export.mjs` | The exporter (operator side). |
| `python/ppb_verify.py` | Second, independent verifier implementation (verdicts only). |
| `examples/` | Five bundles exported from real `@strixgov/mcp-proxy` records (synthetic workload, demo key), their reports, and provenance. |
| `authority/strix-proof-authorize.mjs` | Offline issuer-authority tool: create a root, authorize a gateway key, revoke. |
| `vectors/` | 116 public test vectors with expected results; byte-reproducible. All synthetic. |
| `test/` | Node test suite. `python/test_ppb_python_interop.py` runs the vectors through the Python implementation. |
| `docs/SPEC.md` | Normative format and verification specification. |
| `docs/THREAT-AND-TRUST-MODEL.md` | Threats, trust boundaries, key lifecycle. |
| `docs/CLAIMS-AND-LIMITATIONS.md` | Every claim the verifier can make, and the ones it never makes. |
| `docs/VERIFIER-GUIDE.md` | Install, trust-anchor setup, usage, walkthrough, troubleshooting. |
| `docs/SECURITY-FAQ.md` | Enterprise security FAQ. |
| `docs/OPERATIONS.md` | Exporter usage, refusal codes, audit, retention, compatibility, rollback. |
| `docs/ISSUER-AUTHORIZATION.md` | How a gateway key gets standing from an issuer root; what exists, what was built, what is undecided. |
| `docs/BASELINE.md` | What Strix already had (capability matrix), findings, design decisions. |
| `release/` | `SHA256SUMS` and the release manifest. |
| `../validation/proof-bundle/` | End-to-end harness that drives the real proxy and produced `examples/`. |

## Running the tests

```bash
cd proof-bundle
node --test test/*.test.mjs                 # Node suite (no dependencies)
node vectors/generate.mjs --check           # vectors reproduce byte-for-byte
node scripts/build-release.mjs --check      # release checksums are current
python -m pytest python -q -rs              # second implementation (needs: pip install cryptography pytest)

cd ../validation/proof-bundle
npm ci && node run.mjs --refresh            # real proxy -> export -> offline verify; rewrites examples/
```

`test/interop.test.mjs` cross-checks against the published
`@strixgov/verifier` and is skipped, visibly, unless `npm ci` has been run in
`validation/proof-bundle`.

## License

MIT, as the rest of this repository.
