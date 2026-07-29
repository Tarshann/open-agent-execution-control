# Installing Strix: the complete guide

This walks you from a bare machine to a working `/strix-wire` run and a verified receipt, on Windows, macOS, or Linux. Nothing here needs a Strix account, and nothing here costs anything.

If you only want the short version, the [Getting Started one-pager](sales/one-pager-getting-started.md) covers the happy path in four steps. This document is the detailed version: every prerequisite, both install methods, every environment variable, mode selection, test-suite setup, and a troubleshooting section for the failures we know about.

---

## 1. Prerequisites

| Requirement | Minimum | Used for | Check with |
|---|---|---|---|
| **Claude Code** | any current version | Strix ships as Claude Code skills, not a standalone binary | `claude --version` |
| **Python 3** | 3.11+ recommended (3.11 is what the validation manifest measures) | The scanner, the safety preflight, and the onboarding state machine. Runtime is stdlib only; nothing to `pip install` for normal use | `python --version` or `python3 --version` |
| **Node + npm** | any current LTS | Only the receipt verifier (`npx @strixgov/verifier`) | `node --version` |
| **git** | any | Cloning (manual install), and reverting a wrap like any other edit | `git --version` |

Platform notes:

- **Windows:** the suite is validated on Windows, including the Microsoft Store Python build. If `python` opens the Store instead of running, either install Python from python.org or disable the `python.exe` app-execution alias in Settings.
- **macOS / Linux:** the command is often `python3`, not `python`. Everywhere this guide says `python`, substitute what your system uses.
- **Corporate proxies:** Offline Mode needs no network at all. Sandbox Mode needs HTTPS to `www.strixgov.com` only.

### Pick a practice repository

Your first run fires **one real action**, so start on a scratch project, not production. The preflight enforces this and **fails closed**: it refuses to run against a repo with production markers (`sk_live_` keys, `.env.production`, real deploy domains) or existing governance (`governedProcedure`, evidence tables). A scan error also stops the run. This is a feature; don't fight it, switch repos.

---

## 2. Install method A: Claude Code plugin (recommended)

Inside Claude Code, run:

```
/plugin marketplace add Tarshann/open-agent-execution-control
/plugin install strix-governance@strixgov
/reload-plugins
```

This installs exactly two skills, namespaced by the plugin:

```
/strix-governance:strix-wire
/strix-governance:strix-onboard
```

Already installed and want the latest? `/plugin update strix-governance@strixgov`.

**What this does NOT install:** the three SGRF review lenses (`/runtime-governance-review`, `/govern-pr`, `/release-readiness`) live in a separate marketplace. Add it too if you want them:

```
/plugin marketplace add Strixgov/skills
```

## 3. Install method B: manual copy (no marketplace)

Clone the repo and copy the two skill folders into your project's `.claude/skills/`:

```bash
git clone https://github.com/Tarshann/open-agent-execution-control strix-open
mkdir -p .claude/skills
cp -r strix-open/skills/strix-wire strix-open/skills/strix-onboard .claude/skills/
```

On Windows PowerShell:

```powershell
git clone https://github.com/Tarshann/open-agent-execution-control strix-open
New-Item -ItemType Directory -Force .claude\skills
Copy-Item -Recurse strix-open\skills\strix-wire,strix-open\skills\strix-onboard .claude\skills\
```

Restart Claude Code (or `/reload-plugins`). Manually copied skills appear **unnamespaced**: `/strix-wire` and `/strix-onboard`.

> Which name do I type? If you installed the plugin (method A), use the namespaced form. The bare `/strix-wire` only exists when the skills repo itself is open in Claude Code or you copied the folders in by hand (method B).

---

## 4. Choose a mode (strix-wire)

You don't have to configure anything to start. With no environment variables set, Sandbox Mode picks itself.

| | **Sandbox Mode** (default) | **Offline Mode** | **Real account** |
|---|---|---|---|
| Setup | None. Auto-provisions a short-lived sandbox credential | None | Two env vars (below) |
| Network | Up to 4 HTTPS calls to `www.strixgov.com`: provision credential, evaluate, ingest evidence, fetch receipt | **None, ever** | Your tenant's evaluation surface |
| What travels | The action's non-secret parameters (amounts, IDs). Never API keys, tokens, or card numbers | Nothing | Same as sandbox, under your policy |
| Who signs the receipt | The hosted kernel | A key generated on your machine | The hosted kernel |
| Trust claim | Strix witnessed the decision | Tamper-evident, self-attested | Strix witnessed it, under your policy |

For a real account, set per-tenant credentials in your shell or a git-ignored `.env.local` (**never** in a file the agent will commit):

```bash
export STRIX_API_KEY=sk_test_...     # per-tenant API key
export STRIX_TENANT_ID=your-tenant   # tenant slug
# optional: export STRIX_API_URL=https://www.strixgov.com   (the default)
```

PowerShell equivalents: `$env:STRIX_API_KEY = "sk_test_..."` and `$env:STRIX_TENANT_ID = "your-tenant"`.

One more variable you'll meet but should never set globally: `STRIX_WIRE_RUN_APPROVED=1` is how Offline Mode carries your run approval on the **single command you approved**. Setting it permanently would turn a one-run approval into standing authorization, which is exactly what the consent design forbids.

---

## 5. First run

Open your practice repo in Claude Code and invoke:

```
/strix-governance:strix-wire
```

Plain English works too: "wire Strix into this project."

You'll make exactly three decisions, each on its own card:

1. **Analyze** (one click): a single scoped authorization for all read-only inspection. The analyzer cannot write, install, execute, or reach the network, and the grant expires when the run ends.
2. **Wrap** (one click): the exact one-line diff, shown before anything changes. The card states "Actions that will execute: 0".
3. **Run once** (one click): a separate yes. The action runs one time with test-safe inputs, evaluated by the decision path **before** it fires.

Stopping after any click is a valid ending. One click gets you the analysis, two get you a wrapped-but-unrun codebase, three get you the proof.

## 6. Verify your receipt

The final output line is a ready-to-run command. Paste it **as-is**:

```bash
npx @strixgov/verifier@latest <decisionId>   # Status: VERIFIED
```

Careful with ids: the run prints both an unsigned `evidenceId` and a signed decision id. **Only the id inside the printed verify command verifies.** The verifier is an independent MIT tool that recomputes hashes and checks the signature itself; it needs no access to your systems.

---

## 7. Optional: run the test suites

If you want to see the safety claims hold on your own machine (or you're evaluating for an enterprise), install the test dependencies first. This matters more than it looks:

```bash
pip install -r requirements-test.txt
python -m pytest skills -q -rs
```

Without `requirements-test.txt`, the cryptography path degrades **silently**: 40 of the 271 tests skip, and they are the signing and evidence ones, i.e. the tests that substantiate the verifiability claims. Always pass `-rs` so skips are named, not just counted.

Expected results (from [`docs/VALIDATION.md`](VALIDATION.md)):

| Environment | Result |
|---|---|
| Linux, cffi installed | 271 passed, 0 skipped |
| Linux, no cffi | 231 passed, 40 skipped |
| Windows (hosts that can create symlinks) | 268 passed, 3 skipped |
| Windows (hosts that cannot) | 260 passed, 11 skipped |

The remaining Windows skips are control-character filename tests: those filenames are illegal on NTFS, which is itself a mitigation.

## 8. Optional: the zero-install demo

See the whole deny, approve, execute, re-verify flow without touching your own code:

```bash
pip install solo-builder-core
solo demo adversarial                          # air-gapped end-to-end walkthrough
npx @strixgov/verifier@latest dec_2f8a1c94     # a real Strix record
```

---

## 9. Troubleshooting

**`/strix-wire` isn't recognized.**
Plugin installs are namespaced: type `/strix-governance:strix-wire`. After a manual copy, restart Claude Code or run `/reload-plugins`. Check that the folders landed in `.claude/skills/strix-wire/`, not one level deeper.

**Preflight says STOP: production markers found.**
Working as designed. You pointed it at a live or already-governed repo. Use a scratch project. It will not fail open, and a scan error is also a STOP.

**Second run says "already governed".**
Also working as designed: your first wrap is real governance, so the preflight flags the repo. Continuing takes an explicit "yes, wire the next one anyway."

**Tests report ~230 passed and dozens skipped.**
You're missing `cffi`/`cryptography`. `pip install -r requirements-test.txt` and re-run. A missing `_cffi_backend` makes the crypto library panic rather than raise, so the suite skips loudly instead of failing mysteriously; the fix is the install, not the code.

**`npx` verifier fails or hangs.**
Check Node is installed and you're online (the verifier fetches the record and key material). Confirm you pasted the decision id from the printed command, not the `evidenceId`.

**Windows: `python` opens the Microsoft Store.**
Disable the app-execution alias or install from python.org. The Store build itself is fine; the suite is validated on it.

**Permission prompt fatigue.**
You should see very few. One analysis authorization covers all read-only work; only the wrap and the run ask again. If your harness echoes an extra confirmation for a file edit or command you already approved, that echo is not a second governance decision.

---

## 10. Where to go next

- **[`skills/strix-wire/GETTING-STARTED.md`](../skills/strix-wire/GETTING-STARTED.md)**: the quickstart with the full FAQ.
- **[`skills/strix-wire/README.md`](../skills/strix-wire/README.md)**: the skill reference, `governedAction()` contract, capability-ID table, and the full mode comparison.
- **[`skills/strix-onboard/`](../skills/strix-onboard/)**: take a whole client org from zero configuration to a verified first governed action.
- **[`docs/VALIDATION.md`](VALIDATION.md)**: what has actually been tested, on what, and what has not. Read the known-gaps list before making claims to anyone.
- **[`docs/consent-architecture.md`](consent-architecture.md)**: why the flow asks exactly three times.
