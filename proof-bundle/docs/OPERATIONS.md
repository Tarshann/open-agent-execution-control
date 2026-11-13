# Operations: exporting bundles

For the operator of a Strix gateway (`@strixgov/mcp-proxy` /
`@strixgov/tool-gateway`). The exporter runs on the gateway host, reads the
gateway's store and uses the gateway's signing key. It makes no decisions and
records no events.

## Integration point

```
governed action -> policy decision -> (execution) -> store on disk
                                                        |
        <storagePath>/receipts.jsonl                    |  read-only
        <storagePath>/execution-outcomes.jsonl          v
        <keyPath>/signing-key.pem, public-jwk.json -> strix-proof-export -> bundle
```

`storagePath` and `keyPath` are the values in the proxy's config. Nothing in
the gateway changes; the exporter is a separate process.

## Commands

```bash
# what can be exported for a tenant
node exporter/strix-proof-export.mjs list --store <storagePath> --tenant <tenantId>

# export one action
node exporter/strix-proof-export.mjs export \
  --store <storagePath> --key-dir <keyPath> \
  --receipt-id rcpt_... --tenant <tenantId> \
  --out ./bundles/rcpt_... [--carrier ./bundles/rcpt_....ppb.json] \
  [--disclose-invocation inv.json] [--disclose-policy policy.json]

# one-file form of an existing bundle
node exporter/strix-proof-export.mjs pack ./bundles/rcpt_... ./rcpt_....ppb.json

# a trust-store entry for your public key, to hand to customers OUT OF BAND
node exporter/strix-proof-export.mjs trust-store --key-dir <keyPath> --owner "Acme prod gateway" --tenant <tenantId>
```

`--tenant` is mandatory. `--disclose-invocation` takes
`{"args": ..., "actorId": "...", "actorRole": "..."}`; `--disclose-policy`
takes the ruleset from the proxy config. Each is included only if it hashes
to the value already inside the signed receipt.

## What the exporter refuses, and why

Exit 1 with `REFUSED <CODE>` on stderr. Nothing is written.

| Code | Situation | Action |
|---|---|---|
| `STORE_NOT_FOUND`, `STORE_CORRUPT`, `STORE_TOO_LARGE` | Store unreadable. A torn final line (write in progress) is tolerated; any other bad line is not. | Investigate the store. |
| `RECEIPT_NOT_FOUND` | No receipt with that id **for this tenant** (and environment, if given). A receipt that belongs to another tenant gives exactly the same answer as one that does not exist. | Check the id (`list`) and the tenant. |
| `AMBIGUOUS_RECEIPT` | The id appears more than once within this tenant. | Investigate; never choose. |
| `AUTHORIZATION_MISMATCH` | An `--issuer-authorization` file is malformed or names a key that did not sign this bundle's records. | Attach the authorization issued for this gateway's key. |
| `WRITE_FAILED` | The directory or the carrier could not be written. Neither is left behind. | Fix the path and retry. |
| `SIGNING_UNAVAILABLE` | Key missing, unreadable, not Ed25519, or the JWK does not match the PEM. The exporter never creates a key. | Restore the key; do not generate a new one for old records. |
| `REFUSED_UNVERIFIED_RECORD` | A stored record fails its own signature, or was signed by a key not supplied. | For rotated keys pass `--historical-keys`. Otherwise treat as store tampering. |
| `AMBIGUOUS_OUTCOME` | More than one execution outcome for one receipt. v1 describes one attempt. | Investigate. |
| `CONTRADICTORY_RECORDS` | An outcome exists for a denied action. | Investigate as a possible bypass or bug; do not export. |
| `DISCLOSURE_MISMATCH` | The arguments or policy you supplied are not the ones signed. | Supply the real ones or omit the flag. |
| `OUTPUT_EXISTS` | The output path exists. | Choose a new path. Bundles are never overwritten. |
| `EXPORT_SELF_CHECK_FAILED` | The finished bundle did not pass the verifier. | Report a bug. |

An operational failure is never turned into a bundle.

## Issuer authorization

If an issuer root has authorized this gateway's key
([`ISSUER-AUTHORIZATION.md`](ISSUER-AUTHORIZATION.md)), attach the
authorization so customers who trust the root need nothing else:

```bash
node exporter/strix-proof-export.mjs export ... --issuer-authorization ./authorization.json
```

Repeat the flag after a key rotation (one authorization per key). The
exporter checks only that each authorization names a key used in this bundle;
whether its root is trusted is the customer's decision. The authority side —
creating a root, issuing and revoking — is `authority/strix-proof-authorize.mjs`
and belongs on a machine that is not the gateway.

No Strix issuer root exists yet. Until one does, an authorization you attach
is signed by a root you or your customer created.

## Evidence that changes after export

A bundle is a snapshot. If an execution outcome is recorded after you
exported an ALLOW with `executionOutcome: ABSENT`, exporting again produces a
**different** `bundleId`. The earlier bundle remains valid and keeps its
meaning ("no outcome record at that time"). Give customers the newer one and
tell them it supersedes the older; nothing in the format links them.

## Access control and audit

- The exporter needs read access to the store and the private key. Run it as
  the gateway's service account, and restrict who can invoke it: anyone who
  can run it can disclose evidence for the tenant they name.
- Each run appends one JSON line to `<store>/proof-bundle-exports.jsonl`
  (`--audit-log <file>` to move it, `none` to disable): time, result,
  `bundleId`, `receiptId`, `tenantId`, signer key id, whether disclosures
  were included, or the refusal code. It never contains evidence content,
  arguments or key material.
- The store limit is 256 MB per file; a member limit of 1 MB applies to every
  artifact.

There is no HTTP endpoint, queue, or rate limiter in v1: export is a local
CLI. Put your own job control around it if you batch.

## Key handling

- The private key stays where the gateway keeps it. It is never copied into a
  bundle; the release test and the validation run both scan every exported
  file for it.
- Hand your public key to customers through a channel that is not the bundle
  (`trust-store` command output). The copy inside
  `trust/embedded-signer-keys.json` is a convenience and is never trusted by
  the verifier; `--no-embed-keys` omits it.
- **Key directory layouts.** `--key-dir` accepts both layouts the gateway
  writes: the proxy's flat directory (`signing-key.pem`, `public-jwk.json`)
  and the gateway `KeyRing` (`active` pointer plus one directory per key id).
  With a keyring the exporter signs with the active key and reads the
  **public** JWK of every retired key, so pre-rotation records export without
  extra flags; `trust-store` lists the active key and the retired ones.
- **Rotation:** with the flat layout, export old records with
  `--historical-keys <jwks of old public keys>`. Tell customers to add the new
  key and mark the old one `retired`. An export attempted in the instant the
  keyring is being rotated may be refused with `SIGNING_UNAVAILABLE`; retry.
- **Compromise:** tell customers to mark the key `revoked`. All bundles
  signed with it will fail. There is no automated revocation channel.

## Retention

Bundles are self-contained; they can outlive the store. Keep the public keys
of every key that ever signed, indefinitely — a bundle is unverifiable
without them. Treat bundles as security logs: they reveal action names,
tenants and timing, and arguments if you disclosed them.

## Compatibility

| Situation | Behaviour |
|---|---|
| Verifier older than bundle (`formatVersion` it does not list) | `ERROR UNSUPPORTED_VERSION`. No partial result. |
| Verifier newer than bundle | Verifies, as long as it still lists `1.0`. |
| New receipt/outcome schema from a newer gateway | Exporter and verifier refuse (`UNSUPPORTED_RECORD_VERSION`) until updated. |
| Customer has no trust anchor | `INCOMPLETE`, exit 3. |
| Action spanning several systems, or several executions under one correlation id | Not representable in v1: one receipt, at most one outcome. Export each receipt separately. |

## Rollback

The exporter and verifier are additive files; removing `proof-bundle/` removes
the product. Nothing in the gateway, its store or its keys is modified
(the only file written beside the store is the audit log). Bundles already
delivered stay verifiable with the verifier version that matches their
`formatVersion`.

## Troubleshooting

Run `node verifier/strix-proof-verify.mjs verify <bundle> --trust-store <(…trust-store output)>`
on your own output before sending it. If a customer reports
`DIGEST_MISMATCH` on a directory bundle, a transfer tool changed line
endings: send the `.ppb.json` carrier instead.
