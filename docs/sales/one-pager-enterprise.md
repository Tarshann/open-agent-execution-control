# Strix: Execution Control for AI Agents

**Models decide. Agents orchestrate. Strix controls execution.**

When an AI agent can charge cards, delete records, and send messages, "we trust the model" is not a control. Strix is.

---

## The problem

Enterprises are handing AI agents real authority over payments, data, customer communication, and infrastructure. Existing controls were built for humans and services, not for autonomous software that decides at machine speed. Three questions now land on every CISO's and auditor's desk:

1. **Can you stop a consequential action before it happens?**
2. **Can you prove, after the fact, exactly what happened and that it was authorized?**
3. **Can a third party check that proof without trusting your logs, or your vendor?**

## The Strix answer

Strix places a **decision point in front of the consequential actions you route through it** and a **signed, independently verifiable evidence record behind them**. On a routed path, a denial or an approval timeout means the action does not run. A call that bypasses the route is not covered, so each pilot lists covered, uncovered and unknown paths separately.

- **Before:** every governed action is evaluated against your policy (allow, deny, or route to a human approver) *before* it executes. A denied action never runs.
- **After:** an Ed25519-signed, timestamped receipt records what ran, when, and under what decision. Anyone, including your auditor, your customer, or your own engineers, can verify it with a free open-source tool (`npx @strixgov/verifier`) with zero access to your systems and without taking Strix's word for it.
- **Secrets stay yours:** Strix stores credential *references*, never credential values. In hosted modes, what travels includes the action's parameters (in plain text in the evidence record), so pilots use synthetic data only: no API keys, tokens, card data or health data. Offline Mode sends nothing.

Strix's hosted runtime is in private beta for new tenants. The open skills and proxy are evaluated first on synthetic data in a sandbox.

## Architecture: open trust, commercial control

| Layer | What | License |
|---|---|---|
| **Verification** | Public receipt verifier. Anyone can audit any Strix record | Open source (MIT) |
| **Methodology** | SGRF: a published governance-review framework scoring systems on four orthogonal axes: Capability, Governance, Runtime Enforcement, Independent Verification | Open (MIT) |
| **Skills** | Governed-action wiring and a reference onboarding workflow, runnable today with no account | Open (MIT) |
| **Runtime & Console** | Hosted policy kernel, tenant management, approval routing, evidence service | Commercial |

The trust primitives are open on purpose. **A proof you can only check by asking the vendor is not a proof.**

## Governance discipline you can inspect

Strix's claims are engineered to be checkable, and bounded:

- **Readiness is derived, never asserted.** The onboarding model refuses to report a client "ready" until an external verifier's verdict is on file for the actual smoke-test evidence. Configuration alone cannot be promoted to readiness, and tests pin that rule.
- **Approvals are decisions, not clickstreams.** One scoped grant covers read-only analysis; separate explicit approvals gate any code change and any execution. Cutting routine prompts is what makes the consequential ones meaningful.
- **A public validation manifest** records what was tested, on which platforms, with what result, including what was *not* tested. Every security fix is validated by mutation testing or pre-fix reproduction, on Linux and Windows.
- **The honesty policy is enforced in the product.** The skills are contractually tested against overclaiming. A verified receipt "attests the record is signed and unmodified," never "the system is compliant." Vendors that oversell governance move your risk without reducing it.

## What this means for your teams

| Stakeholder | Outcome |
|---|---|
| **CISO / Risk** | Policy-enforced pre-execution control on the routes you wire, a deny-by-default policy on those routes, and an explicit list of paths that remain uncovered |
| **Compliance / Audit** | Tamper-evident, independently verifiable evidence records that can serve as *input* to an audit; not a compliance attestation or certification |
| **Engineering** | Minutes to a first governed action, a one-line wrap with business logic unchanged, MIT tooling with no lock-in at the trust layer |
| **Procurement** | Open-core: evaluate the full methodology and skills free before any commercial commitment |

## Evaluation path: a zero-risk pilot

1. **Day 1:** engineers install the open skills and wire one governed action in a throwaway repo. Offline Mode needs no account and no network. Sandbox Mode is hosted, sends the action's parameters to Strix, and should be used with synthetic values only.
2. **Week 1:** verify receipts independently, and run the SGRF review lenses against a copy of a system you operate. The lenses are advisory reviews, not a merge gate, runtime control or certification.
3. **Pilot:** one customer-selected codebase, one consequential action, one named route; no production writes, PHI, live payments or customer credentials. See `docs/pilot/CUSTOMER-SAFE-PILOT.md`. Book a demo at strixgov.com.

---

*Strix Governance is a product of Velaris Group LLC. Open layer MIT-licensed. Private beta: strixgov.com*
