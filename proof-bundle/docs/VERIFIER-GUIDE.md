# Verifier guide

For the engineer who received a bundle and has never seen Strix internals.

## 1. Install

The verifier is one file with no dependencies. You need Node.js 18 or later
and nothing else — no `npm install`, no account, no network.

1. Obtain `strix-proof-verify.mjs` (in this repository:
   `proof-bundle/verifier/strix-proof-verify.mjs`).
2. Check it against the checksum you were given out of band, or against
   `proof-bundle/release/SHA256SUMS`:

   ```bash
   sha256sum strix-proof-verify.mjs
   ```

   ```powershell
   Get-FileHash strix-proof-verify.mjs -Algorithm SHA256
   ```

3. Run it:

   ```bash
   node strix-proof-verify.mjs --help
   ```

A second implementation in Python (`proof-bundle/python/ppb_verify.py`,
needs `pip install cryptography`) prints verdicts only. Use it if you want a
cross-check from code that shares nothing with the Node verifier.

## 2. Set up your trust anchor

The verifier will not tell you a bundle is authentic unless **you** tell it
which keys you trust. A key that arrives inside the bundle is never trusted.

**Get the signer's public key through a channel that is not the bundle** —
a contract annex, a call where the fingerprint is read out, your vendor
portal, a previous onboarding exchange. Then write a trust store:

```json
{
  "format": "strix-ppb-trust-store",
  "formatVersion": "1.0",
  "keys": [
    {
      "keyId": "strix-demo",
      "owner": "Acme production gateway (received 2026-11-12 via onboarding call)",
      "status": "active",
      "tenants": ["local"],
      "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "<43 base64url characters>" }
    }
  ]
}
```

| Field | Use |
|---|---|
| `keyId`, `jwk` | Required. The key id must match the one in the bundle; the key bytes are what you received out of band. |
| `owner` | Your own note. Printed in reports. |
| `status` | `active`, `retired` (rotated out; still verifies old records) or `revoked` (fails everything). |
| `notBefore`, `notAfter` | Optional window the key was in use. Compared with the record's own (signer-asserted) time. |
| `tenants`, `environments` | Optional. Restrict the key to bundles for these tenants. Recommended: it stops a bundle for another tenant from passing under your key. |

A plain JWKS file or a single JWK is also accepted, with no constraints.

### Trusting an issuer root instead of each gateway key

If the signer gives you an **issuer root** key rather than a gateway key, add
it with `"role": "issuer-root"`:

```json
{ "keyId": "example-issuer-root", "role": "issuer-root", "owner": "Example issuer root (received 2026-11-12)",
  "status": "active", "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "..." } }
```

The bundle then carries an *issuer authorization*: a statement signed by that
root saying which gateway key may sign, for which tenants and environments,
and between which dates. You trust one root; the verifier checks the rest
offline. A root key is never accepted as the signer of a bundle itself.

- If you were given the authorization separately, pass it with
  `--issuer-authorizations <file>`.
- If the issuer publishes a revocation list, pass it with
  `--revocations <file>`. Without one the report says revocation was **not
  checked**; that is a statement, not a failure.
- No Strix issuer root exists yet. A root you are given today belongs to
  whoever created it.

Comparing a fingerprint: the fingerprint of an Ed25519 JWK here is simply its
`x` value. Compare all 43 characters.

**Rotation.** When the signer rotates keys, add the new key and change the old
one to `"status": "retired"`. **Compromise.** If the signer tells you a key
was compromised, set `"status": "revoked"`; every bundle signed with it will
then fail. The verifier never checks revocation online — the store you give
it is the only source.

## 3. Verify

```bash
node strix-proof-verify.mjs verify ./bundle-dir --trust-store ./my-trust-store.json
```

A bundle is either a directory or a single `.ppb.json` file; both work the
same way. Useful options:

| Option | Purpose |
|---|---|
| `--expect-receipt-id <id>` | Fail unless this bundle is about the action you asked about. |
| `--expect-tenant <id>` / `--expect-environment <e>` | Fail unless it is for your tenant / environment. |
| `--expect-bundle-id <id>` | Fail unless it is the exact bundle you were told to expect. |
| `--json` | Machine-readable report on stdout. |
| `--report <file>` | Also save the JSON report (keep it with the bundle). |

`inspect <bundle>` lists what a bundle says about itself **without checking
anything**; its output begins with `UNVERIFIED`.

### Exit codes

| Code | Result | Meaning |
|---|---|---|
| 0 | `PASSED` | Files intact, signatures valid, signer trusted by you, records consistent. |
| 1 | `FAILED` | Tampering, bad signature, untrusted/revoked signer, contradictory records, or an `--expect-*` mismatch. No claims are produced. |
| 2 | `ERROR` | The input could not be evaluated: malformed, unsafe paths, too large, or a version/algorithm this verifier does not support. |
| 3 | `INCOMPLETE` | Nothing failed, but you supplied no trust store, so origin is not authenticated. |

Only `0` should be treated as success in automation.

## 4. Read the report

Real output for the example bundle `examples/02-deny` (a denied action) is in
`examples/reports/02-deny.report.txt`. The top:

```
  Integrity .............. VERIFIED      6 artifacts in signed inventory
  Signature mathematics .. VALID         manifest:valid authorization-receipt:valid
  Signer trust ........... TRUSTED       strix-demo:TRUSTED
  Evidence consistency ... CONSISTENT
  Claims ................. EVALUATED
  Overall ................ PASSED
```

Then read, in this order:

1. **PPB-C04** — what decision the signer recorded.
2. **PPB-C10** — what, if anything, the signer recorded about execution.
3. **PPB-C09** — enforcement. It always says NOT established; read why.
4. **"Never established by a v1 bundle"** — the list at the bottom.

`docs/CLAIMS-AND-LIMITATIONS.md` explains every claim.

The JSON report has the same content: `result` (five separate fields plus
`overall`), `failures[]` (`stage`, `code`, `message`), `claims[]`,
`unsupportedConclusions[]`, `notes[]`.

## 5. Walkthrough with the example bundles

From `proof-bundle/`:

```bash
node verifier/strix-proof-verify.mjs verify examples/01-allow-succeeded --trust-store examples/trust-store.demo.json
```

Expected: `Overall ... PASSED`, exit 0.

Now see what the verifier refuses:

```bash
node verifier/strix-proof-verify.mjs verify examples/01-allow-succeeded
```

Expected: `INCOMPLETE`, exit 3 — valid mathematics, origin not authenticated.

Copy the bundle, change one character in
`evidence/execution-outcome.json`, verify the copy with the trust store.
Expected: `FAILED`, `DIGEST_MISMATCH`, exit 1, and no claims.

The example bundles are real records from the real `@strixgov/mcp-proxy`
governing a synthetic, inert tool, signed with a demo key whose private half
was destroyed (`examples/PROVENANCE.json`). `trust-store.demo.json` exists so
the walkthrough runs; it is not a key you should trust for anything else.

## 6. Troubleshooting

| You see | Cause | What to do |
|---|---|---|
| `INCOMPLETE` | No `--trust-store` | Supply one (section 2). |
| `SIGNER_UNTRUSTED` | The bundle's key id is not in your store | Confirm with the signer which key they use; do not copy the key out of the bundle. |
| `SIGNATURE_INVALID` with a trust store | Your store has a different key under that id, or the bundle was altered or forged | Re-confirm the key out of band. If it matches, treat the bundle as forged. |
| `SIGNER_REVOKED` / `SIGNER_OUTSIDE_VALIDITY` / `SIGNER_TENANT_NOT_AUTHORIZED` | Your trust store rules, the issuer authorization's scope or dates, or a revocation list excluded the key | Intended. The failure message names the authorization and root involved. |
| `SIGNER_AUTHORIZATION_INVALID` | An authorization claims to be from a root you trust but its signature does not verify | Treat as forged or altered. |
| `SIGNER_RECORD_NOT_AUTHORIZED` | The key is authorized, but not for this kind of record | Ask the issuer; do not widen anything yourself. |
| `REVOCATION_LIST_INVALID` (exit 2) | The revocation list you supplied is not signed by a root in your trust store | Obtain the genuine list. It is never treated as empty. |
| `DIGEST_MISMATCH`, `MISSING_ARTIFACT`, `UNEXPECTED_ARTIFACT` | A file changed, vanished or was added after signing | Ask for the bundle again. Tools that rewrite line endings (some mail gateways, `git` with autocrlf) cause this: transfer the single-file `.ppb.json` form instead. |
| `UNSUPPORTED_VERSION`, `UNKNOWN_CRITICAL_EXTENSION` | The bundle is newer than your verifier | Get a newer verifier. There is no partial verification. |
| `UNSAFE_PATH` in directory form | A stray file (`.DS_Store`, `Thumbs.db`, editor backup) or a symlink is in the directory | Remove it, or use the carrier form. |
| `MALFORMED_JSON … duplicate key` | A JSON file repeats a key | Treat as hostile or corrupt. |
| `EXPECTATION_MISMATCH` | The bundle is about a different action/tenant than you pinned | You were given the wrong bundle, or a replayed one. |

## 7. Keeping results

Store the bundle, the JSON report, the verifier checksum and the trust store
you used, together. A report is reproducible from those three inputs by
anyone, with no Strix service involved.
