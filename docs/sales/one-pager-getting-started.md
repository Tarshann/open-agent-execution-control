# Get Started with Strix

**Your first governed action in minutes. No coding background needed. No account. No credit card.**

*Models decide. Agents orchestrate. Strix controls execution.*

---

## What Strix does, in one sentence

Before your software (or an AI agent working inside it) does something risky, like charging a card, deleting data, or sending an email, **Strix checks it first and hands you a tamper-proof receipt that anyone can verify.**

Think of it as a checkpoint in front of one risky action, and a signed receipt behind it. Your software still does exactly what it did before.

---

## What you need

| You need | Why |
|---|---|
| **Claude Code** (free CLI or desktop app) | Strix ships as a Claude Code skill |
| **Python 3** | Runs the built-in safety checks. Nothing extra to install |
| **Node + npm** | Only for the final "check the receipt yourself" step |
| **A practice project** | Your first run fires one real action, so start on a scratch copy, not production. Strix refuses to run on production code anyway. That guard is built in |

**No Strix account.** Sandbox Mode sets itself up automatically the first time.

---

## The steps

**1. Install the skill.** Paste these two lines into Claude Code:

```
/plugin marketplace add Tarshann/open-agent-execution-control
/plugin install strix-governance@strixgov
```

**2. Open your practice project** in Claude Code and type:

```
/strix-governance:strix-wire
```

Or just ask in plain English: *"wire Strix into this project."*

**3. Make three decisions.** That's the whole flow. You click exactly three times, and each click is a real decision, clearly explained on a card before you approve:

| Click | What you're approving | What happens if you say no |
|---|---|---|
| 1. **Analyze** | A one-time, read-only look at your project. It cannot change, install, or run anything | Nothing. Saying no just ends it |
| 2. **Wrap** | One small, visible code change around ONE risky line. You see the exact change first. Nothing executes | Nothing. Your code is untouched |
| 3. **Run once** | The action runs one time with safe test inputs, and only after the checkpoint approves it | Nothing. Stopping here is a valid ending, not a failure |

**4. Check your receipt.** Strix prints a ready-to-run command at the end. Paste it as-is:

```
npx @strixgov/verifier@latest <id>
```

You'll see **`Status: VERIFIED`**. That's proof, checkable by anyone, that the action happened, when it happened, and that it was allowed.

---

## FAQ

**Do I have to sign up for anything?**
No. Sandbox Mode auto-provisions a short-lived credential for you. Offline Mode needs nothing at all, not even internet.

**Is my code or data sent anywhere?**
In Sandbox Mode, only the one action's non-secret details (amounts, IDs, never passwords, API keys, or card numbers). In Offline Mode, nothing leaves your machine, ever.

**Did this change what my software does?**
No. The one line you approved still does exactly what it did before. Strix adds a permission check in front and a receipt behind.

**What if Strix says no to an action?**
Then the action simply never runs. No charge, no delete, no email.

**Can I undo it?**
Yes. It's a normal, visible code change, removable like any other edit.

**Why so few permission prompts?**
On purpose. Routine read-only steps share one up-front approval so the two prompts that matter, changing code and running an action, actually get read.

**What about the other risky spots it found?**
Strix only touches the one you approved. The rest are reported as a count so you know the size of the gap. Run it again to wrap the next one.

---

*Strix is an execution-control system for AI agents by Velaris Group LLC. The skills above are open source (MIT) and run locally. Learn more at strixgov.com.*
