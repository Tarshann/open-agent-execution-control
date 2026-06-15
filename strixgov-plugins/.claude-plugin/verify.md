description: Independently verify a Strix evidence record, approval, quorum, swarm run, or receipt chain
argument-hint: "<evidenceId> | approval <id> | quorum <decisionId> | swarm <id> | chain <path>"
allowed-tools: ["Bash(strix-verify:*)"]
---
Run the bundled Strix verifier on the user's argument and report the verdict.
 
Argument: $ARGUMENTS
 
1. Run `${CLAUDE_PLUGIN_ROOT}/bin/strix-verify $ARGUMENTS`.
2. Show the verifier's full stdout verbatim.
3. State the verdict (VERIFIED / INVALID / LEGACY_UNSIGNED / UNVERIFIABLE). If
   not VERIFIED, name the failing step. Do not assert validity beyond what the
   verifier reports.
