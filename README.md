# Strix Open — governance skills (SGRF v1)

> **Scope:** this repository ships two governed-action skills — `/strix-wire`
> and `/strix-onboard` — and is their distribution source (see "Where these
> skills come from" below). The three SGRF review lenses
> (`/runtime-governance-review`, `/govern-pr`, `/release-readiness`) are
> **not** included here; they live in the separate
> [Strixgov/skills](https://github.com/Strixgov/skills) marketplace
> (`/plugin marketplace add Strixgov/skills`) — see "Not in this plugin" below.

The open methodology layer of [Strix](https://www.strixgov.com), an
execution-control system for AI agents. These are **Claude Code skills** that run
the **Strix Governance Review Framework (SGRF v1)**: review how any system governs
execution, score it on four orthogonal axes, and — when you're ready — wire a
first governed, recorded action.

**MIT-licensed, runs locally, no Strix account required.** The three review
lenses are advisory by construction — they read and report, they never enforce.

## What's inside

This repository ships **two** skills, and the plugin installed from it contains
exactly those two:

| Skill | Lens | What it does |
|---|---|---|
| `/strix-onboard` | onboarding | The **reference onboarding workflow**: tenant, systems, governed capabilities, policies and approval routes, adapters and credential references, connectivity validation, one governed smoke test through the real decision path, then an external verifier's verdict. Readiness is derived from that verdict, never asserted. Open skills-layer model — not the hosted Console, and not a production provisioning system. See [`skills/strix-onboard/`](skills/strix-onboard/) and [`docs/VALIDATION.md`](docs/VALIDATION.md). |
| `/strix-wire` | remediation | Wire one consequential call site through `governedAction()`: one scoped read-only analysis authorization, then separate explicit approvals for the source change and the sandbox execution (three clicks end-to-end — see [`docs/consent-architecture.md`](docs/consent-architecture.md)). The kernel evaluates the action before it runs and a signed, queryable evidence record is produced. No Strix account required (Sandbox Mode auto-provisions; Offline Mode never leaves the machine). |

`strix-wire` is the bridge from the open advisory layer to the Strix runtime —
open skill, commercial control plane. `strix-onboard` is a reference model, not
the hosted Console; see [`docs/VALIDATION.md`](docs/VALIDATION.md) for what has
and has not been validated.

Local receipts are checkable by the published `npx @strixgov/verifier` via a
projection that invents no hosted-tenancy fields — demonstrated end-to-end
(`VERIFIED` on a real receipt, `TAMPERED` on a forged one) in
[`docs/PROOF-ATTEMPT.md`](docs/PROOF-ATTEMPT.md), with the design in
[`docs/EVIDENCE-INTEROP.md`](docs/EVIDENCE-INTEROP.md). The trust anchor stays
local: externally *verifiable*, not publicly *resolvable*.

### Not in this plugin

The three SGRF review lenses — `/runtime-governance-review` (system),
`/govern-pr` (change), and `/release-readiness` (release) — and the frozen
13-section / 4-axis methodology spec live in the separate upstream
[`Strixgov/skills`](https://github.com/Strixgov/skills) marketplace. They are
**not** installed by the plugin in this repository. Add that marketplace as well
if you want them:

```
/plugin marketplace add Strixgov/skills
```

This repository also carries two other plugins that are not part of
`strix-governance`: `strix-personal` (`plugins/strix-personal/`) and the
verifier (`strixgov-plugins/`).

## Install

### Option A — Claude Code plugin (recommended)

Add the marketplace, then install the plugin:

```
/plugin marketplace add Tarshann/open-agent-execution-control
/plugin install strix-governance@strixgov
/reload-plugins
```

Then invoke a skill (they are namespaced by the plugin):

```
/strix-governance:strix-wire
/strix-governance:strix-onboard
```

### Option B — manual copy (no marketplace)

Clone this repo and copy the skills into your project's `.claude/skills/`:

```bash
git clone https://github.com/Tarshann/open-agent-execution-control strix-open
mkdir -p .claude/skills
cp -r strix-open/skills/strix-wire strix-open/skills/strix-onboard .claude/skills/
```

Restart Claude Code (or `/reload-plugins`); the skills appear unnamespaced
(`/strix-wire`, `/strix-onboard`).

### Prerequisites for `/strix-wire` only

The three review lenses need nothing. `strix-wire` talks to a Strix runtime:

```bash
export STRIX_API_KEY=sk_test_...     # per-tenant API key
export STRIX_TENANT_ID=your-tenant   # tenant slug
# optional: export STRIX_API_URL=https://www.strixgov.com (the default)
```

Keys go in shell exports or a git-ignored `.env.local` — never in a file the
agent will commit.

### Zero-install verification

Any Strix signed record can be checked without installing anything from this
repo:

```
npx @strixgov/verifier@latest <evidenceId>
```

## What you get

A recognizable review every time: an **applicability declaration**, **declared vs
observed scope**, the 13 SGRF sections, and the **four orthogonal axes** —
Capability · Governance · Runtime Enforcement · Independent Verification — rendered
as bars, never blended into one number. The gap between the axes is the finding: a
very capable system can be barely verifiable, and a single score would hide it.

## Advisory, and honest about it

The review skills run nothing and produce no signed record — they reason and
report. They never claim a system is "secure"; they score it for what it is and
mark anything unverified as exactly that. Where a Strix runtime is actually present
(`STRIX_API_KEY` + `STRIX_TENANT_ID` and a reachable evaluation surface), a lens
may *optionally* fold in a real verdict + signed receipt — never a fabricated one.

The upgrade path is explicit: a review improves how an agent *thinks* about
governance; a runtime makes the decision non-bypassable and produces an
independently verifiable record. Verify any Strix record yourself with the open
MIT verifier:

```
npx @strixgov/verifier@latest <evidenceId>
```

## Where these skills come from

This repository is the **distribution source** for the two skills it ships: the
`strix-governance` marketplace entry points here, so `/plugin install` serves
`skills/strix-wire/` and `skills/strix-onboard/` from this tree at the pinned
version. Fix them here.

The SGRF review lenses and the frozen methodology spec are a different story —
they are canonical in the Strix monorepo and published through the separate
[`Strixgov/skills`](https://github.com/Strixgov/skills) marketplace. Changes to
*those* flow upstream first and are checked for drift against the frozen spec.

The `strix-wire` helpers under `skills/strix-wire/helpers/` are vendored from the
monorepo; the analyzer, preflight and scanner in this tree now carry local
security fixes that should be flowed upstream rather than overwritten by the next
sync.

## License

MIT — see [`LICENSE`](LICENSE). Copyright is held by **Velaris Group LLC**;
Strix Governance is that entity's product name, which is why the licence holder
and the plugin's declared author differ. Strix's open trust primitives (the
[`@strixgov/verifier`](https://www.npmjs.com/package/@strixgov/verifier) and the
tool-gateway) are MIT too; the hosted runtime/control plane is the commercial
layer.

The licence covers everything in this tree, including the files vendored from
the Strix monorepo (`skills/strix-wire/helpers/`, `preflight.py`, `scanner.py`)
— same copyright holder, same terms, so no separate attribution applies.
