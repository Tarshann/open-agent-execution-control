# Strix Governance

**Wire one governed action. Onboard a client to a verified first proof. Zero account required.**

*The open-source Claude Code plugin that gives any codebase its first signed, kernel-evaluated decision — and any client organization its first externally verified one. MIT licensed, v0.4.2, zero account required.*

---

## What's in the plugin

| Skill | What it does |
|---|---|
| **`/strix-governance:strix-wire`** | Wires one consequential call site through `governedAction()` — one read-only analysis authorization, then separate approvals for the source change and the sandbox execution. |
| **`/strix-governance:strix-onboard`** | The reference client-onboarding workflow — tenant, systems, capabilities, policies, credential references, connectivity, one governed smoke test, then an external verifier's verdict. Readiness is **derived** from that verdict, never asserted. |

Both skills run with zero Strix account (Sandbox or Offline Mode), namespaced `/strix-governance:<skill>`.

## Why "governed," not "observed"

- **Not "AI guardrails."** Guardrails filter model inputs and outputs. Strix governs the side effect — the tool call that actually changes state.
- **Not "AI observability."** Observability tells you what happened. Strix decides whether it's allowed to happen, before it happens.
- **Not "a policy engine."** Policy engines evaluate rules outside the execution path. Strix is *in* the execution path — the kernel is the call site.

## Open layer, commercial layer

| Layer | What | License |
|---|---|---|
| Verification | Public receipt verifier. Anyone can audit any Strix record | Open (MIT) |
| Skills | `strix-wire` + `strix-onboard`, runnable today with no account | Open (MIT) |
| Runtime & Console | Hosted policy kernel, tenant management, approval routing, evidence service | Commercial |

## Install

```
/plugin marketplace add Tarshann/open-agent-execution-control
/plugin install strix-governance@strixgov
```

Not included: the three SGRF review lenses (`runtime-governance-review`, `govern-pr`, `release-readiness`) — those live in the separate `Strixgov/skills` marketplace.

## The onboarding discipline

`strix-onboard`'s load-bearing rule: **never convert "configured" directly into "ready."** Every terminal state requires a matching, passing signal, and **READY** additionally requires a verification verdict whose evidence id matches the smoke test's. Forcing the state label doesn't make a project ready — a test pins that rule.

## Verify anything

```bash
npx @strixgov/verifier@latest <decisionId>   # Status: VERIFIED
```

An independent MIT tool with zero access to your systems, and no need to take Strix's word for it.

---

*Strix Governance is an MIT-licensed Claude Code plugin, Velaris Group LLC. github.com/Tarshann/open-agent-execution-control · strixgov.com*
