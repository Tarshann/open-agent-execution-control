# Portable Proof Bundle v1 — end-to-end validation

Drives the real `strix-mcp-proxy` CLI (`@strixgov/mcp-proxy` 0.2.2, pinned in
`package-lock.json`) in front of a disposable, inert fixture tool server,
creates a demo issuer root and authorizes the proxy's key with it, exports
every recorded governed action as a Portable Proof Bundle carrying that
authorization, verifies each one offline with the network blocked against a
trust store that holds **only the root**, cross-checks the native records
with `@strixgov/verifier` 1.25.0, runs negative controls (tampering, wrong
keys, a revoked authorization, a bundle with no authorization), and destroys
both private keys.

The issuer root here is a demo key made by the harness. It is not a Strix
key, and no Strix issuer root exists.

```bash
npm ci
node run.mjs --refresh
```

`--refresh` deletes and regenerates `../../proof-bundle/examples/` (new key,
new ids, new reports) and rewrites `evidence/results.json`. Without it the
script refuses to run when examples already exist: bundles are never silently
overwritten.

What is real and what is not: the proxy, its policy decisions, its signed
receipts and execution outcomes, and the key handling are the real runtime.
The tools are synthetic (`fixture-upstream.mjs`), the approver is the harness,
and the signing key is generated for the run. This is not a production or
customer event, and no hosted Strix service is contacted.

Step E calls, directly on the upstream, the action the proxy denied in step
B. It runs. That is the boundary the verifier's report describes: a DENY
record is not evidence of prevention.

Last run: 2026-11-12, Windows 11, Node 24.21.0 — 31 checks, 31 pass
(`evidence/results.json`). Product documentation:
[`../../proof-bundle/README.md`](../../proof-bundle/README.md).
