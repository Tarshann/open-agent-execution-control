# Strix Portable Proof Bundle

This directory is an evidence package for ONE governed action. This file is
explanatory only: the verifier never reads it, and nothing in it is a finding.

| | |
|---|---|
| Bundle | `(see manifest.json)` (format 1.0) |
| Action | `mcp.callTool:delete_note` (capability `mcp.demo.delete_note`) |
| Receipt | `rcpt_c1b48240f5061b7e0d571109` |
| Tenant / environment | `local` / `local` |
| Recorded decision | DENY |
| Execution outcome record | NOT_APPLICABLE |
| Signed by key | `strix-demo` |

## Verify it yourself, offline

```
node strix-proof-verify.mjs verify <this-directory> --trust-store <your-trust-store.json>
```

Use a trust store you obtained from the signer through a channel that is
independent of this bundle. `trust/embedded-signer-keys.json` is a
convenience copy and is never treated as trusted.

## What a passing verification means

It means the files are unchanged since they were signed, the signatures are
valid, the signer is one you chose to trust, and the records agree with each
other. It does **not** mean the action was enforced, executed, safe, or
compliant. The verifier prints exactly which statements the evidence supports
and which it does not.
