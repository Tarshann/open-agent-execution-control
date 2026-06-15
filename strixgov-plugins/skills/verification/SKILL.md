---
name: strix-verification
description: Explain how to independently verify Strix proof and interpret the result. Use when the user asks "is this record real", "how do I verify a Strix receipt/evidence/approval", "what does VERIFIED or LEGACY_UNSIGNED mean", "verify this offline", or wants to audit a governance record without trusting Strix.
---

# Strix verification - prove a record is real (and read the verdict)

Anyone can confirm a record was produced by the holder of the Strix signing key
using standard cryptography (Ed25519 + SHA-256) against the public JWKS - no
account, no API key, no trust in Strix tooling. The tool is @strixgov/verifier
(MIT, npm). Two commands wrap it: /strix-verify (online) and
/strix-verify-offline (local files, air-gapped).

## What can be verified

- Evidence record:  /strix-verify <evidenceId>            (online)
- Approval:         /strix-verify approval <artifactId>   (online)
- Quorum:           /strix-verify quorum <decisionId>     (online)
- Swarm run:        /strix-verify swarm <swarmRunId>      (online)
- Receipt (file):   /strix-verify-offline receipt <file> --jwks <jwks>   (offline)
- Receipt chain:    /strix-verify-offline chain <file.jsonl> --jwks <jwks> (offline)

## How to read the verdict

- VERIFIED: signed by the claimed kid; pinned + live JWKS agree. Clean pass.
- VERIFIED_PINNED_ONLY / VERIFIED_LIVE_ONLY: valid, only one JWKS source reached.
- LEGACY_UNSIGNED: predates signing. Expected for earliest records; NOT a failure.
- COMPLIANCE_VIOLATION: Ed25519 verification failed. This is the real INVALID.
- KID_NOT_FOUND: key unknown to both JWKS -> cannot verify (distinct from invalid;
  usually a stale local JWKS - re-fetch and retry).

## Discipline

- Render proof; never upgrade it. Do not translate VERIFIED into "compliant" or "safe".
- Cannot-verify (KID_NOT_FOUND) is honest, not a failure to hide.
- Offline against a pinned jwks.json proves a record with nothing leaving the machine.

To produce governed actions and receipts (not just verify), use the
strix-personal plugin (/strix-scan -> /strix-plan -> /strix-apply). This plugin
only verifies.