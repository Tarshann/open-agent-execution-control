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
| "No data leaves the machine" / "only non-secret parameters travel" | Name the mode and the data flow: "Offline Mode makes no network calls. Sandbox Mode is hosted: it sends your IP, the capability name, an actor id, a parameter hash, timestamps and the parameters in plain text, so use synthetic values only" |
| "Fewer security prompts" | "Strix asks once for read-only analysis, then pauses only at decisions that can change code or cause an action" |
| "AI-proof / hack-proof / unhackable" / "non-bypassable" (unqualified) | "Enforced on the routed path: in the fixture test a denial and an approval timeout left the handler unrun. A direct call to the upstream, outside the route, ran with no receipt" |
| "Governs your whole agent" / "every tool call" | "Governs the one route we wire (e.g. one MCP server behind the proxy). Other routes are listed as uncovered or unknown" |
| Any healthcare, PHI, HIPAA or data-egress claim | Don't make one. No test covers PHI or egress control. Pilots use synthetic data; say "not tested for PHI or egress" if asked |
| "Compliant", "certified", "audit-ready" | "Evidence input for your audit. Not a certification or attestation" |
| "Accountless hosted sandbox works" | Only with a fresh pass of `validation/wire-hosted/`. On 2026-11-06 it did not complete; offer Offline Mode |
| "`solo govern` finds your risky actions" | "A static inventory of known patterns in Python and JS/TS. In our fixture it found 9 of 13 labelled supported-language actions and 0 of 10 in other languages or indirect calls; the output lists hits, not what is missing" |
| "A signature proves it is safe" | "A signature verifies the signed record. It doesn't prove broader coverage or production readiness" |
| "SGRF review gates merges / certifies" | "Advisory review lenses run in Claude Code. They don't enforce, gate or certify" |

## The numbers reps can quote (and the conditions that go with them)

| Claim | Condition to state with it |
|---|---|
| **A few minutes** to a first signed, governed action | In a throwaway repo, **Offline Mode** (verified 2026-11-06). Do not quote a time for hosted Sandbox Mode until it passes again |
| **3 approvals** end to end (analyze, wrap, run) | Plus one more only if environment setup is genuinely needed |
| **271 automated tests**, measured on Linux *and* Windows at `3d1e4db`; **282** on the current tree (279 passed, 3 skipped), re-measured on Windows only on 2026-11-06 | Repository-layer validation; the manifest also lists known gaps. That transparency is a selling point, so lead with it |

## Brand language (approved)

- *"Models decide. Agents orchestrate. Strix controls execution."*
- *"Capability control for AI agents. Fail-closed by default. Independently verifiable."*
- *"On a governed route, nothing executes until it's evaluated, and every decision produces a signed record anyone can verify."*

## Objection handling

**"How do I know the receipt isn't faked?"** The verifier is open source (MIT), runs on the prospect's own machine, and recomputes every hash and signature itself. They never have to trust us.

**"What if the AI goes around the checkpoint?"** On the governed route, a denial means the original action never runs. A caller that reaches the upstream directly, outside the route, is not stopped: we tested exactly that and it ran with no receipt. So the pilot proves the route is the only route under test, and reports covered, uncovered and unknown paths separately. `solo govern` gives a static inventory of known patterns, not a coverage guarantee.

**"Is this just prompts and prayers?"** No. The open layer's safety properties are pinned by mutation-tested suites (every guard was disabled in turn, and the tests caught it), documented in a public validation manifest.

**"What's the catch on the free layer?"** None; it's MIT. The commercial layer is the hosted kernel, console, policy management, and approval routing: the operational control plane, not the trust primitives.
