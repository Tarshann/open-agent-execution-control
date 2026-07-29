# Sales Claims Cheat-Sheet: What We Say, What We Never Say

Strix's product *is* the honesty discipline. Our own software refuses to overclaim, and contract tests enforce it. A rep who oversells Strix undermines the core differentiator. Use the right column, never the left.

| Never say | Say instead |
|---|---|
| "The Console onboards clients end to end" | "The reference onboarding workflow takes a client to a verified first governed action; the hosted Console is the commercial control plane" |
| "Production tenant isolation is proven" | "Records are bound to the operator's tenant and cross-tenant attachments are refused, with production isolation layered on in the hosted platform" |
| "Independently verified" (unqualified) | Name the tool, the verdict, and the evidence id: "the public verifier returned VERIFIED for record `<id>`" |
| "Anyone can check this signature" | Only when a publicly resolvable evidence id exists. Otherwise: "verification was performed locally" |
| "Secrets live in the Strix vault" | "Strix stores a credential *reference*; the secret never leaves the customer's secret store" |
| "Every action is now governed" | "Each run governs one capability on one system. Coverage grows action by action, visibly" |
| "This proves the system is compliant / secure" | "The receipt proves the record is signed and unmodified. It's audit *evidence*, not a compliance certificate" |
| "No data leaves the machine" | Name the mode: "Offline Mode contacts nothing; Sandbox Mode sends only the action's non-secret parameters" |
| "Fewer security prompts" | "Strix asks once for read-only analysis, then pauses only at decisions that can change code or cause an action" |
| "AI-proof / hack-proof / unhackable" | "Non-bypassable at the governed call site, fail-closed on errors, tamper-evident evidence" |

## The numbers reps can quote (and the conditions that go with them)

| Claim | Condition to state with it |
|---|---|
| **About 2 minutes** to a first signed, governed action | In a sandbox repo, Sandbox Mode, no account |
| **3 approvals** end to end (analyze, wrap, run) | Plus one more only if environment setup is genuinely needed |
| **271 automated tests**, measured on Linux *and* Windows | Repository-layer validation; the manifest also lists known gaps. That transparency is a selling point, so lead with it |

## Brand language (approved)

- *"Models decide. Agents orchestrate. Strix controls execution."*
- *"Capability control for AI agents. Fail-closed by default. Independently verifiable."*
- *"Nothing executes until evaluated, and every decision produces cryptographically signed proof anyone can verify."*

## Objection handling

**"How do I know the receipt isn't faked?"** The verifier is open source (MIT), runs on the prospect's own machine, and recomputes every hash and signature itself. They never have to trust us.

**"What if the AI goes around the checkpoint?"** A governed call site evaluates policy *before* execution, so a denial means the original action never runs. Ungoverned call sites are reported as a count, which makes coverage measurable rather than assumed.

**"Is this just prompts and prayers?"** No. The open layer's safety properties are pinned by mutation-tested suites (every guard was disabled in turn, and the tests caught it), documented in a public validation manifest.

**"What's the catch on the free layer?"** None; it's MIT. The commercial layer is the hosted kernel, console, policy management, and approval routing: the operational control plane, not the trust primitives.
