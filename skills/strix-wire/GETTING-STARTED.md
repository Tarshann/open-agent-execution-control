# strix-wire — first-time quickstart

Govern one real action in a few minutes. strix-wire finds one irreversible
call in your code, wraps it in governance, runs it once, and hands you a
**signed receipt you can verify** — with no Strix account. There are two
modes, and they are different things (not a lesser and a greater version of
one thing): **Offline Mode** stays on your machine; **Sandbox Mode** is
hosted and uses the network.

**What leaves your machine.** The analysis and the wrap are entirely local.
The *run* depends on which mode you use:

- **Sandbox Mode (hosted — uses the network).** Makes up to four HTTPS calls
  to `www.strixgov.com`: provision a short-lived sandbox credential, evaluate
  the action, ingest the evidence record, and fetch the signed decision
  receipt. What leaves the machine: your IP address (as with any HTTPS
  request), the capability name (e.g. `payment.charge`), the actor id, a hash
  of the parameters, timestamps, and — on the success path — **the action's
  parameters themselves, in plain text**, as the evidence record's metadata.
  Put only non-secret, non-personal test values in them: never API keys,
  tokens, card numbers, health data, or customer data. The sandbox tenant is
  shared (`strix-sandbox`), its credential expires after about an hour, and
  records you send are stored by the hosted service.
- **Offline Mode (no network).** Makes no network call, needs no account and
  no credential; the receipt is signed by a key generated on your machine and
  proves only that *that local key* signed it.

> **Status check, 2026-11-06 — read before promising Sandbox Mode.**
> Provisioning worked: `POST /api/public/sandbox/provision` returned a
> credential and a list of 10 capabilities. But the next call,
> `POST /api/v1/evaluate`, answered **HTTP 400 `Unknown action type`** for all
> 10 of them (including `payment.charge`), so the hosted run did not complete
> and no hosted receipt was produced. Offline Mode was verified end to end with
> network access disabled (zero connection attempts), and its receipt verified
> with `solo strix-wire verify`; a tampered copy failed. Until the hosted path
> is re-run and passes, do not describe accountless hosted provisioning as
> working. Evidence and re-run commands:
> [`validation/wire-hosted/`](../../validation/wire-hosted/) and
> [`validation/wire-offline/`](../../validation/wire-offline/).

See the mode comparison in [`README.md`](./README.md) before you pick.

## Plain English first — what do these words actually mean?

You don't need any background in this to use strix-wire. Three words carry
almost all the meaning:

| Word | What it actually means |
|------|-------------------------|
| **Governing** an action | Before something consequential happens in your app — a card gets charged, a row gets deleted, an email goes out — a rule-checker looks at it first and decides **allow**, **deny**, or **ask a human**. Whatever it decides gets written down, time-stamped, with a signature no one can forge afterward. |
| **Wrapping** a call | Taking the *one line* of your existing code that does the consequential thing, and putting a thin layer around it: check permission → do the real thing (only if allowed) → write down proof. Your code still does exactly what it did before. Nothing about the business logic changes. |
| What governing an action **gives you** | A tamper-evident, independently checkable record of a decision and (when it ran) its outcome: "this action was evaluated at this time and allowed." Anyone — an auditor, a customer, a curious engineer — can check that the record is signed and unmodified with a free public tool. The signature covers the record; it does not show that other, ungoverned paths were safe. |

If you remember nothing else: **strix-wire doesn't change what your code does.
It adds a checkpoint in front of one risky line, and a receipt behind it.**

## The flow, at a glance — three clicks, three decisions

You approve exactly three things, and each one is a real decision:

```
 YOUR CODEBASE
      │
      ▼
 CLICK ① ANALYZE   One up-front authorization covers ALL the read-only
                   inspection: the safety preflight, the language check,
                   and the scan for anything hard to undo — a payment, a
                   delete, an email/SMS send, a schema migration. One
                   card tells you exactly what it will and won't do.
      │
      ▼
 FOUND             One clear candidate, e.g.:
                   src/billing/charge.py:47 — a Stripe card charge
                   (plus a running count of every OTHER risky spot found
                   but left untouched — see "the map" in your results).
                   No click needed — this is just the report.
      │
      ▼
 CLICK ② WRAP      Shows you the exact one-line diff first. If you
                   approve, it adds the permission-check + proof-writer
                   around that ONE line. Nothing executes yet — the card
                   says so: "Actions that will execute: 0".
      │
      ▼
 CLICK ③ RUN ONCE  A separate yes, asked separately. Executes it for
                   real, once, with test-safe inputs. The check happens
                   BEFORE the action — if it's denied, the original
                   action never runs at all.
      │
      ▼
 PROOF             A signed record, checkable by anyone:
                   npx @strixgov/verifier@latest <id>   →   Status: VERIFIED
```

Click ① never touches your files — and can't: the analysis tool has no
ability to write, install, execute, or reach the network. Only click ②
writes anything. Only click ③ runs anything. Stop after any click and
that's a valid ending, not a failure — one click gets you the analysis,
two get you a wrapped-but-unrun codebase, three get you the proof.

## Before you start — what you need

| Need | Why |
|------|-----|
| **Claude Code** (CLI or desktop) | strix-wire is a Claude Code skill, not a standalone binary. |
| **Python 3** | Runs the scanner + the safety preflight (stdlib only). Offline Mode's signing also needs the `cryptography` package (`pip install -r requirements-test.txt` pulls it in); it fails loudly rather than writing an unsigned record if it is missing. |
| **Node + npm** | Only for the final self-check (`npx @strixgov/verifier`). |
| **No Strix account** | Offline Mode needs none and contacts nothing. Sandbox Mode (hosted) is *designed* to auto-provision a short-lived credential when no API key is set, but as of the 2026-11-06 status check above the hosted evaluate step failed, so treat it as unverified. |

> **Use a non-production sandbox repo the first time.** strix-wire fires one
> real action. The preflight guard refuses to run in a live or already-governed
> codebase (live Stripe keys, `.env.production`, real deploy domains, or existing
> `governedProcedure` / Canonical Proof Flow). Start on a scratch project.

## Step 1 — (optional) see it work with zero install

Watch the full deny → approve → execute → re-verify flow offline, then check a
real production record. Needs the `solo` CLI (`pip install solo-builder-core`).
Skip this if you just want to wire your own repo.

```bash
solo demo adversarial                 # air-gapped end-to-end walkthrough
npx @strixgov/verifier@latest dec_2f8a1c94   # a real Strix record → Status: VERIFIED
```

## Step 2 — install the skill in Claude Code

Adds `strix-wire` and `strix-onboard`. Already installed? Run
`/plugin update strix-governance@strixgov` to pull the latest.

```
/plugin marketplace add Tarshann/open-agent-execution-control
/plugin install strix-governance@strixgov
```

> The three SGRF review lenses (`runtime-governance-review`, `govern-pr`,
> `release-readiness`) are a separate marketplace and are not installed by the
> command above. Add `Strixgov/skills` as well if you want them.

## Step 3 — open your project and run it

Open your sandbox repo in Claude Code, then invoke the command — or just ask in
plain English ("wire Strix into this project", "set up a governed action") and
it triggers.

```
/strix-wire
```

> From the **installed plugin** the command is namespaced:
> `/strix-governance:strix-wire`. The bare `/strix-wire` appears only when
> the skills repo itself is open in Claude Code (or the skill directory was
> copied into your project's `.claude/skills/`).

## Step 4 — verify your own proof

strix-wire's final output line is a ready-to-run verify command. Paste that
command **as-is** — the id inside it is the signed decision id, which is
NOT the same value as the unsigned `evidenceId` printed earlier in the run
(both are shown; only the command's id verifies). The receipt is
Ed25519-signed and checkable by anyone, with no access to your systems.

```bash
npx @strixgov/verifier@latest <decisionId>   # → Status: VERIFIED
```

## What happens when you run it — it asks before it acts

**Nothing changes until you confirm the proposed wrap, and nothing runs
until you separately confirm the run.**

| Stage | Your click? | What it does |
|-------|-------------|--------------|
| **1. Analyze** | **Click ①** | One authorization for everything read-only: the safety preflight (stops if the repo is production or already governed), the language check, and the scan that finds one irreversible call — a charge, delete, send, or migration. |
| **2. Report** | no | Shows what was scanned, what was found, and the recommended target. |
| **3. Wrap** | **Click ②** | Shows the exact diff and the card "Files that will change / Actions that will execute: 0". Only on your yes does it wrap the call in `governedAction()`. |
| **4. Run once** | **Click ③** | A separate confirmation. Runs it via the hosted kernel with test-safe inputs, then signs a receipt. |
| **5. Verify** | no | Prints the runnable verifier command. |

## The safety guard — why a first run can't go wrong

The preflight (`preflight.py`) scans the repo **before** anything is wrapped or
run, and fails **closed**:

- **STOP (exit 3)** — production markers (`sk_live_`, `.env.production`, real
  deploy domains) or existing governance (`governedProcedure`, evidence tables,
  Canonical Proof Flow). A scan error also stops. It never fails open.
- **OK (exit 0)** — only an ungoverned, non-production repo gets wired.

## FAQ

**What exactly did I authorize with the first click?**
Read-only analysis of this repository, once. The card lists it precisely:
read source files, detect runtimes, run the preflight, run the scanner,
analyze candidates, and check the bundled helper files' integrity — and
what it will NOT do: modify files, install packages, look outside the
repository, use credentials, contact external services, or execute
anything. The authorization expires when the analysis finishes; running
the analysis again, or on a different folder, asks again.

**Why so few permission prompts?**
Because the prompts that remain are the ones that matter. Everything
read-only happens inside one analysis command under one disclosed
authorization; the flow then pauses only at the two decisions that can
change code or cause an action — the wrap and the run. Fewer routine
prompts means the important ones actually get read.

**Did this change what my code actually does?**
No. The one line you approved still does exactly what it did before — same
arguments, same behavior. All that's added is a permission check in front of
it and a proof-writer behind it.

**What happens if Strix says no?**
The original action **never runs**. No charge, no delete, no email — nothing.
You'd see a "denied" or "needs approval" message in place of the result.

**Do I need to sign up for anything?**
Not for Offline Mode: it needs no account and no network. Sandbox Mode is
designed to auto-provision a short-lived, scoped credential without an
account, but it is hosted (it uses the network) and its last end-to-end check
did not complete — see the status note at the top. See the mode comparison in
[`README.md`](./README.md).

**Is any of my data or code sent somewhere?**
Your source code is not sent. In Sandbox Mode the capability name, actor id,
a parameter hash, timestamps and the action's parameters (in plain text) go to
the hosted service, plus your IP address — so use synthetic values only. In
Offline Mode nothing is sent; the helper makes no network calls.

**What's this "proof" / "evidence record" actually good for?**
It's a signed, timestamped statement — "this action happened, at this time,
and was approved" — that anyone can check themselves with a free, independent
tool (`npx @strixgov/verifier`), without trusting your word, your database, or
Strix's word either. Useful for audits, compliance evidence, customer trust,
or just knowing exactly what an automated agent did and when.

**What about the OTHER risky spots you found but didn't touch?**
strix-wire only ever wraps the **one** call you approved. Everything else it
found is reported as a count ("…and 14 more ungoverned action points") so you
know the size of the gap — nothing else is modified. Run `/strix-wire` again
to wrap the next one (expect the already-governed preflight check described
in "Next steps"), or `solo govern scan` / `solo govern coverage` for a **static
inventory** of known patterns. That inventory is not a complete map: in
`solo-builder-core` 0.4.1 it found 9 of 13 hand-labelled supported-language
actions and 0 of 10 in other languages or indirect calls, and it reports hits,
not what it cannot see (see [`validation/solo-govern/`](../../validation/solo-govern/)).

**Can I undo this?**
Yes — it's a normal code change. `git diff` shows exactly the helper file
added and the one call site rewritten; `git checkout -- <file>` (or your
usual revert) removes it like any other edit.

**What's the difference between "Sandbox Mode" and "Offline Mode"?**
Sandbox Mode talks to the hosted Strix service over the network (designed to
need no account) and gets a record Strix itself signs. Offline Mode never
leaves your machine — a key you hold signs the record instead, which proves it's
tamper-evident but not that a third party (Strix) witnessed it. Pick Offline
Mode if you have no network access or don't want any hosted dependency at
all. Full comparison table in [`README.md`](./README.md).

## Next steps — now that you have one proof

1. **Check the proof yourself.** Run the printed
   `npx @strixgov/verifier@latest <id>` command — it's independent of this
   skill and of Strix's own servers vouching for themselves.
2. **Wrap the next risky spot.** Re-run `/strix-wire` — it will find and
   propose the next candidate. Heads up: its safety preflight will now
   correctly flag your repo as *already governed* (your first wrap is real
   governance), so continuing takes an explicit "yes, wire the next one
   anyway" — a deliberate speed bump, not a malfunction.
3. **See the whole map.** `solo govern coverage` (from `solo-builder-core`)
   reports what fraction of your risky action points are governed vs. not —
   a measurement, not a proof, but useful for prioritizing.
4. **Let automated agents run this safely.** `solo kernel approve
   <capability_id>` pre-authorizes future automated runs of this exact
   action so an agent doesn't need a human to click "yes" every time.
5. **Ready for more than a demo?** Sign up for a real Strix account so your
   own risk policy — not the sandbox default — governs future runs.

See [`README.md`](./README.md) for the full skill reference, the
`governedAction()` contract, and the capability-ID table.
