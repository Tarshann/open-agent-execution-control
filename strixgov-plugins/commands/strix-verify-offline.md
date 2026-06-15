---
description: Verify a LOCAL Strix receipt or receipt-chain file fully offline against a local JWKS snapshot. Nothing leaves your machine.
argument-hint: "receipt <file.json> --jwks <jwks.json> | chain <file.jsonl> --jwks <jwks.json>"
---

# /strix-verify-offline - air-gapped verification of a local file

Verify a tool-gateway / MCP-proxy receipt or an append-only receipt chain you
already have on disk, against a local JWKS snapshot - no network calls.

## What to do

1. Pin a JWKS once (needs network that one time):

   curl -s https://www.strixgov.com/.well-known/strix-jwks.json -o jwks.json

2. Run the offline verifier:

   npx --yes @strixgov/verifier@latest receipt <file.json> --jwks <jwks.json>
   npx --yes @strixgov/verifier@latest chain <file.jsonl> --jwks <jwks.json>

   Pass $ARGUMENTS through if the user gave the subcommand + paths. Add --json.

3. Report the verdict (VERIFIED / LEGACY_UNSIGNED / COMPLIANCE_VIOLATION /
   KID_NOT_FOUND). For a chain, also report whether prev-hash linkage is intact.

Online records (evidenceId, approval, quorum, swarm) use /strix-verify instead.
KID_NOT_FOUND here usually means a stale local jwks.json - re-fetch and retry.