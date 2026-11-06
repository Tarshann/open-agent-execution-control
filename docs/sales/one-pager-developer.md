# Strix for Developers

**Govern one real call and walk away with a verifiable receipt. MIT-licensed skills. Offline Mode runs on your machine with no account and no network; Sandbox Mode is hosted and uses the network.**

*A call routed through a governed call site is evaluated before it runs, and each decision produces a signed record anyone can verify. Calls that don't go through that route are not covered.*

---

## What it is

Strix is capability control for AI agents: fail-closed by default, independently verifiable. The open layer ships as two Claude Code skills:

- **`/strix-wire`** finds one consequential call site (a Stripe charge, a `DELETE`, an email send, a migration), wraps it in `governedAction()`, runs it once through a real decision path, and emits an **Ed25519-signed evidence record** anyone can check with the public MIT verifier.
- **`/strix-onboard`** is the reference onboarding workflow: tenant, systems, governed capabilities, policies and approval routes, credential *references* (never values), connectivity, one governed smoke test, then an external verifier's verdict. Readiness is **derived** from the verified proof, never asserted.

The wrap is a thin layer: check permission, run the original call only if allowed, write signed proof. Your business logic doesn't change, and `git diff` shows exactly what was added.

## Install

```
/plugin marketplace add Tarshann/open-agent-execution-control
/plugin install strix-governance@strixgov
```

Then in any non-production repo: `/strix-governance:strix-wire`

Prefer no marketplace? Clone the repo and copy `skills/strix-wire` and `skills/strix-onboard` into `.claude/skills/`.

## Modes

| | Sandbox Mode (hosted) | Offline Mode |
|---|---|---|
| Account | None required by design (short-lived shared sandbox credential) | None |
| Network | **Yes.** Up to 4 HTTPS calls to strixgov.com. Sends your IP, capability name, actor id, a parameter hash and the parameters in plain text (use synthetic values only) | **None** (verified with sockets blocked) |
| Signature | Hosted kernel signs | Local key signs |
| Trust claim | The hosted kernel evaluated and signed the decision | Tamper-evident, self-attested (`LOCAL_MACHINE_ASSERTION`) |
| Status, 2026-11-06 | **Did not complete end to end:** provisioning worked, evaluate returned HTTP 400 for all 10 listed capabilities | Passed end to end; a tampered copy failed verification |

Have a real account? Set `STRIX_API_KEY` and `STRIX_TENANT_ID`, and your own policy governs runs instead of the sandbox default.

## Why it's 3 clicks, not 11

**The rule: collapse mechanical permissions, never governance decisions.**

1. **Analyze.** One scoped, expiring grant covers every read-only phase in a single process (`analyze.py`). The analyzer contains **no write, subprocess, socket, or network primitive**. That's enforced by AST-level source-scan tests, an `open()` audit hook, and hostile-repo symlink-escape suites. The root is confined to your working directory, and scope containment survives symlinks.
2. **Wrap.** A separate approval. You see the exact diff, plus the card "Actions that will execute: 0".
3. **Run once.** Another separate approval. The kernel or policy gate evaluates *before* the call fires, so a denial means the original call never runs. Offline approval rides a per-invocation env var (`STRIX_WIRE_RUN_APPROVED=1`), so committed source at rest grants nothing.

Stopping after any click is a valid terminal state.

## Safety guarantees (tested, not asserted)

- **Preflight fails closed.** Production markers (`sk_live_`, `.env.production`, deploy domains) or existing governance mean `STOP`. Unreadable files or subtrees mean "incomplete", never "clean".
- **271 tests, measured on Linux and Windows** at commit `3d1e4db`; the current tree has 282 (279 passed, 3 skipped), re-measured on Windows only on 2026-11-06. Every security fix was validated by mutation testing or a pre-fix-commit run. See `docs/VALIDATION.md`, including its known-gaps list; the manifest reports what did *not* run, too.
- **Token and receipt discipline** in the dataset-export helper: signed execution tokens, atomic redemption under an OS-level lock (double-spend measured at 2 of 16 before the fix, 1 of 16 after), domain-separated Merkle nodes, leaf count bound into the root.
- **Secrets.** Credential *references* only. A `secret_ref` that looks like a secret value is refused, and the readiness view is tested to contain no credential material.

## Verify anything, from anywhere

```bash
npx @strixgov/verifier@latest <decisionId>   # Status: VERIFIED
```

An independent MIT tool. It recomputes hashes, resolves the key by `kid`, and verifies the signature itself. No access to your systems needed, and no trusting Strix's word either.

## FAQ

**Does the analyzer really not touch anything?** Its only output is stdout. The test suite fails if a write, subprocess, or network primitive ever appears in it, including `pathlib` spellings and non-literal `open()` modes.

**What's actually in the receipt?** For the dataset-export helper: hashes and metadata, and canary tests confirm no row content reaches evidence records. For Sandbox Mode's `governed_action`: the parameters you pass are sent in plain text, so pass synthetic values only.

**What does a verified receipt prove?** That the record is signed and unmodified. Not that your system is secure or compliant. The skill's own docs forbid overclaiming, and that discipline is pinned by contract tests.

**Second run says "already governed"?** Correct. Your first wrap is real governance, so the preflight flags it, and continuing takes an explicit yes. A deliberate speed bump.

**Python deps?** Sandbox Mode's helper is stdlib only. Offline Mode's signing needs the `cryptography` package. Install `requirements-test.txt` to run the signing-gated tests; some skip without it, and they're the evidence and verifiability ones.

---

*Open layer: MIT, Velaris Group LLC. The hosted runtime and control plane are the commercial layer. strixgov.com*
