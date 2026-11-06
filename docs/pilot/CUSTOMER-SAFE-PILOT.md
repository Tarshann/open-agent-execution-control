# Customer-safe pilot: one action, one route

A bounded first evaluation. It produces a short report about **one action on one route**. It does
not produce a certification, a compliance statement or a whole-system safety claim.

## Scope (fixed before anything runs)

| | |
|---|---|
| Codebase | one codebase the customer selects, evaluated on an agreed **copy or branch** |
| Action | one consequential action (e.g. "delete a record", "send an email"), named up front |
| Route | one named route the action takes (e.g. "agent → MCP server X, tool `delete_note`") |
| Excluded in this first evaluation | production writes, PHI or other regulated data, live payments, customer credentials, hosted modes on real data |
| Data | synthetic only. Hosted Sandbox Mode sends the action's parameters to Strix in plain text, so it stays out unless the customer has accepted that for synthetic values |

Write the scope, the package versions and the date into the report's first page before starting.

## Phase 1 — read-only

1. **Static inventory.** Copy the agreed branch to a directory that is *not* inside a git repo
   (`--root` inside a checkout resolves to the enclosing repo root in 0.4.1), then:
   `PYTHONUTF8=1 solo govern scan --include-ai --json --limit 500`.
   `solo govern` is a pattern-based static inventory for known Python and JS/TS patterns. It
   exits 0 with `ok: true` whatever it can't see.
2. **Manual check against the chosen action.** Open the code for the named action and answer, by
   reading it: did the scan flag it? Are there other call sites for the same action it did not flag
   (other languages, shell, SQL, aliased or dynamic calls, subprocess, outbound HTTP)? Record each
   path as **covered**, **uncovered** or **unknown**. Never infer "covered" from "not flagged".
3. **Advisory review.** Run the SGRF lens that fits (`/runtime-governance-review` for the system,
   `/govern-pr` for a change, `/release-readiness` for a release) in Claude Code against the same
   copy. Keep the output verbatim. It is a model-generated advisory review: not a merge gate, not a
   runtime control, not a certification. Treat its "Unverified" sections as open items.

## Phase 2 — enforcement in a sandbox (only after Phase 1 is agreed)

Use a **throwaway** target. Either one mock MCP server behind `@strixgov/mcp-proxy`, or Wire on a
throwaway repo in **Offline Mode**.

Run these, in this order, and record the handler's own log for each:

| Step | Expected | What to capture |
|------|----------|-----------------|
| Safe read, policy ALLOW | handler runs once | handler log line, ALLOW receipt, execution outcome |
| Write that policy denies | handler does **not** run | handler log (no entry), DENY receipt |
| Write needing approval, nobody approves | waits, then handler does **not** run | handler log (no entry), DENY receipt with `approvalReason: TIMEOUT` |
| **Only with explicit test approval from the customer**: the same write, approved | one inert operation runs | the approval request/response, handler log, ALLOW receipt, outcome |
| **Route check:** call the upstream directly, outside the proxy | expected to run, with no receipt | handler log, absence of a receipt. This is the point of the step |

"Inert" means the operation's only effect is appending a line to a file inside the throwaway
directory. No real credentials, no real endpoints.

A working reference is in `validation/mcp-proxy-boundary/` (`run.mjs`, `fixture-upstream.mjs`).
Adapt the fixture to the customer's tool names; keep the handler log.

**Show that the protected route is the only route being tested.** State how the client reaches the
upstream (config file, process tree), and state what else can reach it. If anything else can, the
report says so under "uncovered".

## Evidence trail

Keep, in one folder per pilot:

- package names, versions and integrity (`npm ls`, `package-lock.json`, `pip freeze`); for any
  Strix npm package, run `node validation/mcp-proxy-release/release-provenance.mjs verify <manifest>`
  and record the source commit it names
- the fixture, the proxy config and the invocation commands
- invocation logs, the handler log, and the receipt and outcome files
- the independent verification output (`@strixgov/verifier`, per-receipt `verificationStatus`;
  do not rely on `chainValid` alone) and a tampered-copy negative control

Label every result with exactly one of:

| Label | Means |
|-------|-------|
| **Advisory** | a model-generated review (SGRF lens) |
| **Static finding** | something `solo govern` or a reader found in code, not executed |
| **Intercepted attempt** | a routed call that was denied or timed out (a DENY receipt); nothing executed |
| **Successful synthetic operation** | an inert operation that ran and has an outcome record plus a handler-log entry |

Keep interception receipts separate from successful-operation evidence. A signature verifies the
signed record. It does not prove broader coverage, that other paths are safe, or production readiness.

## Closing report (2 pages, bounded)

1. **The action tested** and the named route, with package versions and source commits.
2. **What happened** in each Phase 2 step, in a table like the one above.
3. **Evidence links** to the files in the evidence folder.
4. **Limitations:** covered / uncovered / unknown paths listed separately; what was not tested
   (see `validation/README.md` §5 for the standing list); data was synthetic; the mode used.
5. **Next control gap:** the single most important uncovered or unknown path.

Do not write "certified", "compliant", "secure", "non-bypassable" (unqualified), "governs the whole
agent", or any PHI/egress statement.
