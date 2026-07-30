# Strix Wire

**One call site. Three clicks. A signed receipt anyone can verify.**

*Takes a codebase from zero to one cryptographically signed, kernel-evaluated decision — in about two minutes, with no Strix account.*

---

## What it does, in one sentence

`/strix-wire` finds one irreversible call in your code — a charge, a delete, an email send, a schema migration — wraps it in `governedAction()`, runs it once, and hands you a receipt anyone can verify. Your business logic doesn't change; `git diff` shows exactly what was added.

## Three clicks, three decisions

| Click | What you're approving | If you say no |
|---|---|---|
| **1. Analyze** | One-time, read-only scan for irreversible calls. Cannot write, install, or reach the network. | Nothing — ends here. |
| **2. Wrap** | Shows the exact one-line diff first. Card reads "Actions that will execute: 0." | Your code stays untouched. |
| **3. Run once** | Executes with test-safe inputs, after the kernel evaluates it. A denial means the call never runs. | Stopping here is a valid ending, not a failure. |

## Sandbox Mode vs. Offline Mode

| | Sandbox Mode (default) | Offline Mode |
|---|---|---|
| Account | None — auto-provisions a short-lived credential | None |
| Network | Up to 4 calls to strixgov.com, non-secret params only | **Zero** |
| Who signs | The hosted Strix kernel | A local Ed25519 key on your machine |
| Verify with | `npx @strixgov/verifier@latest <id>` | `solo strix-wire verify <path>` |

## What it finds

The scanner recognizes 19 capability categories, generated from a single-source pattern catalog: `payment.charge`, `database.delete`, `storage.delete`, `email.send`, `sms.send`, `filesystem.delete`, `database.migrate`, `infra.apply` / `infra.destroy`, `iam.grant` / `iam.revoke`, `flag.flip`, `data.export`, `message.publish` — and on AI-native codebases, `ai.agent_run` and `ai.tool_use` rank first, ahead of the incidental Stripe call.

## Install & run

```
/plugin marketplace add Tarshann/open-agent-execution-control
/plugin install strix-governance@strixgov
```

Then, in any non-production repo: `/strix-governance:strix-wire` (or just ask — *"wire Strix into this project"*).

## Verify your proof

```bash
npx @strixgov/verifier@latest <decisionId>   # Status: VERIFIED
```

An independent MIT tool. It recomputes hashes, resolves the signing key, and verifies the signature itself — no access to your systems required.

## FAQ

**What exactly did the first click authorize?** Read-only analysis, once. No writes, no installs, no network calls, no reading outside the disclosed repository root.

**What if Strix says no to an action?** The original action never runs. No charge, no delete, no email — nothing.

**Can I undo it?** Yes. It's a normal, visible code change — `git diff` shows exactly what was added.

**What about the other risky spots it found?** Reported as a count so you know the size of the gap. Run `/strix-wire` again to wrap the next one.

---

*Strix Wire is a Claude Code skill in the strix-governance plugin. Open source (MIT), Velaris Group LLC. Runs locally. strixgov.com*
