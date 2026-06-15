---
description: Independently verify a Strix record (evidence, approval, quorum, or swarm run) against the public JWKS. Read-only, no account required.
argument-hint: "<evidenceId> | approval <artifactId> | quorum <decisionId> | swarm <swarmRunId>"
---

# /strix-verify - independently verify a Strix record

Verify a Strix-signed record with the standalone @strixgov/verifier (Ed25519 +
SHA-256 against the public JWKS at
https://www.strixgov.com/.well-known/strix-jwks.json). No account, API key, or
trust in Strix tooling required - the same primitive an external auditor uses.

## What to do

1. Run the verifier with the user's argument:

   npx --yes @strixgov/verifier@latest $ARGUMENTS

   Forms: <evidenceId> | approval <artifactId> | quorum <decisionId> | swarm <swarmRunId>.
   Add --json to reason over the structured result.

2. Report the verdict plainly:
   - VERIFIED: signed by the claimed kid; pinned and live JWKS agree.
   - VERIFIED_PINNED_ONLY / VERIFIED_LIVE_ONLY: verified, only one JWKS reachable.
   - LEGACY_UNSIGNED: predates signing (expected for earliest records; not a failure).
   - COMPLIANCE_VIOLATION: Ed25519 verification failed. Treat as INVALID.
   - KID_NOT_FOUND: signing key unknown to both JWKS -> cannot verify (not invalid).

3. Render proof; never upgrade it. Report exactly what the verdict says.

For offline checks of a local receipt/chain file, use /strix-verify-offline.