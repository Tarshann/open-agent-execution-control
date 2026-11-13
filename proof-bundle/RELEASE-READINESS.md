# STRIX GOVERNANCE — PORTABLE PROOF BUNDLE V1

Readiness report for `1.0.0-rc.2`, 2026-11-12. It supersedes the rc.1 report
and answers the gate assessment of the same date (HOLD commercial release; GO
for bounded integration engineering). Every result below comes from a command
that was run; commands are in §6.

Hosts: Windows 11 (Node 24.21.0, Python 3.12.10) and Ubuntu on WSL2 (Node
18.20.8, Node 22.23.3, Python 3.14.4).

## 1. Executive delivery status

**RELEASE_CANDIDATE. Not RELEASE_READY. Commercial release remains on HOLD.**

Since rc.1:

- The architectural gap the assessment named — a customer could not tell an
  authorized gateway key from any other key — now has a **mechanism**: an
  offline chain *issuer root → signed authorization → gateway key*, bound to
  gateway identity, key, tenants, environments, record kinds and dates, with
  a signed revocation list. It is in both verifiers, the exporter and a new
  offline authority tool.
- An independent review found **no way to forge a passing result** and **17
  other defects**. All 17 are fixed, each with a vector or regression test.
- The suites now pass on Linux under Node 18 and 22; the harness is pinned to
  `@strixgov/mcp-proxy` 0.2.2 and `@strixgov/verifier` 1.25.0; the gateway's
  keyring layout and a live key rotation are tested against the real gateway.

Not done: nothing is committed, pushed, published or deployed. No production
system was touched.

**Most important remaining risk.** The mechanism exists; the authority does
not. **No Strix issuer root exists.** Every authorization so far was signed
by a test or demo root. A bundle can be shown to come from a gateway that
*some root the customer trusts* authorized; it cannot yet be shown to come
from a *Strix-authorized* gateway. Closing that needs decisions and systems
outside this repository: who holds the root, how gateways are enrolled, how
the root's public key reaches customers, and a hosted evidence source.

## 2. Existing capabilities reused

| Capability | Location | How it is used |
|---|---|---|
| Signed authorization receipt (schema 1/2) and execution outcome (schema 1) | `@strixgov/tool-gateway` `src/receipts.mjs`, `src/outcomes.mjs` | Included verbatim; their own signatures re-verified |
| Evidence store | `receipts.jsonl`, `execution-outcomes.jsonl` | Read-only exporter input |
| Gateway signing key, flat and `KeyRing` layouts | `src/keys.mjs`, `src/keyring.mjs` | Signs the manifest; retired public keys read for rotated records; never created |
| Policy-version and invocation hashes | `src/policy.mjs`, `src/receipts.mjs` | Disclosure checks |
| Trust-mark grant and its revocation list (TM-1) | `@strixgov/verifier` `src/trust-mark.mjs`, `src/trust-mark-revocation.mjs` | **Pattern** for the issuer authorization: one authority key, bounded subordinate key, validity window, fixed rule order, tri-state revocation |
| Governed-action runtime | `@strixgov/mcp-proxy` 0.2.2 CLI | Produces the records in the validation run |
| Independent native verifier | `@strixgov/verifier` 1.25.0 | Cross-check oracle in tests only; no product code imports it |

Inventory of key-standing and attestation capabilities, including what was
not found (no gateway enrolment or issuer registration):
`docs/ISSUER-AUTHORIZATION.md` §2 and `docs/BASELINE.md`.

## 3. Implemented components

| Component | Function | Path |
|---|---|---|
| Verifier | Integrity, signatures, signer authority and standing, consistency, claims; escaped text report, JSON report | `verifier/strix-proof-verify.mjs` |
| Exporter | One action → bundle; tenant-first filtering; attaches issuer authorizations; flat and keyring key layouts | `exporter/strix-proof-export.mjs` |
| Authority tool (new) | Offline: create a root, publish its trust-store entry, issue and revoke authorizations | `authority/strix-proof-authorize.mjs` |
| Second implementation | Same verdicts, failure codes and claim classes | `python/ppb_verify.py` |
| Vectors | 116 bundles, 13 trust stores, 5 relying-party inputs | `vectors/` |
| Tests | 154 Node tests, 124 Python tests | `test/`, `python/` |
| E2E harness | Real proxy → demo root authorizes its key → export → offline verify with a root-only trust store → negative controls | `../validation/proof-bundle/` |
| Release assets | Checksums, release manifest, changelog | `release/`, `CHANGELOG.md` |

## 4. End-to-end demonstration

`validation/proof-bundle/run.mjs`, recorded in `evidence/results.json`: 31
checks, 31 pass.

- **Source.** The real `strix-mcp-proxy` 0.2.2 CLI governing an inert fixture
  tool: allow, deny, approval timeout, approved, allowed-but-tool-failed.
  Five signed receipts, three signed outcomes. Synthetic workload; real
  runtime, records and signatures. Not a production or customer event.
- **Authority.** A demo issuer root is created offline and authorizes the
  proxy's key for tenant and environment `local` for one year.
- **Export and signing.** One bundle per receipt, manifest signed with the
  proxy's own key, the authorization attached.
- **Offline verification.** With every network primitive blocked and a trust
  store holding **only the root**: five `PASSED`, zero network attempts,
  every signature's standing reported as coming from the root's
  authorization.
- **Negative controls.** Byte and field tampering; wrong and missing keys;
  the authorization revoked (`FAILED`); a bundle with valid signatures and no
  authorization (`FAILED`, issuer not established); the same bundle with the
  authorization supplied separately (`PASSED`).
- **Boundary.** The denied call, made directly to the tool, executes and
  leaves no record; the DENY bundle still verifies. The report never claims
  prevention.
- Both private keys (proxy and demo root) are destroyed at the end.

## 5. Security and trust findings

- **Integrity.** SHA-256 per file under an Ed25519-signed manifest. Flipping
  any single byte of a real bundle never yields `PASSED`, except whitespace
  in the unsigned signature envelope.
- **Signer authority and standing** are reported per signature and separately
  from signature validity: `DIRECT` or `ISSUER_AUTHORIZATION`, with the root,
  authorization id, gateway id, scope, and revocation standing (`REVOKED`,
  `NOT_REVOKED`, `NOT_CHECKED`). No trust store → `INCOMPLETE`, never passed.
  A root is never accepted as a record signer. A gateway cannot widen its own
  authorization. A look-alike key under the gateway's key id fails.
- **Governance assertions** remain the signer's statements; each is now
  attributed to the key that actually signed it (three keys are possible).
- **Enforcement** and **execution**: unchanged. No enforcement evidence
  exists; execution is the proxy's first-party report.
- **Upstream finding F-1 persists** in `tool-gateway` 0.5.2: approval, actor
  and tool fields are outside the receipt signature.
- **Verifier 1.24.1 concern.** No product code depends on
  `@strixgov/verifier`. The equivalent weakness was checked in this verifier
  and closed: a receipt declaring any algorithm other than `Ed25519`, or a
  non-string or unknown schema version, is refused.
- **Independent review** (separate reviewer, no knowledge of the
  implementation; 568 generated cases plus targeted probes): no forgery or
  trust bypass; 17 defects, all fixed — details in `CHANGELOG.md`. Its
  differential harness now reports 0 of 568 cases differing between the two
  implementations (74 before), and no internal errors.

## 6. Test evidence

| Command | Windows | Linux |
|---|---|---|
| `node --test test/*.test.mjs` | 154 pass, 0 fail, 0 skipped | Node 18.20.8 and 22.23.3: 149 pass, 0 fail, 5 skipped |
| `node vectors/generate.mjs --check` | 135 files reproduce byte-for-byte | same |
| `node scripts/build-release.mjs --check` | current | current |
| `python -m pytest proof-bundle/python` | 124 passed (3.12.10) | 124 passed (3.14.4) |
| `node run.mjs --refresh` (real proxy) | 31 of 31 | not run |
| `python -m pytest skills plugins` (pre-existing) | 279 passed, 3 skipped | not run |
| Reviewer's differential harness | 568 cases, 0 differ | not run |
| `test/gateway-live.test.mjs` repeated | 30 runs before the final changes and 5 after, 0 failures | skipped |

The five Linux skips are tests that need the `@strixgov` npm packages or a
`python` executable, neither of which was installed in the Linux copy.

**Not tested:** macOS; GitHub CI (configured, never run); the Signed Evidence
conformance corpus (it is not in the npm package — it lives in the platform
repository); any hosted-tenant record; an authorization from a real root.

**Frozen revision:** there is none yet. The work is uncommitted; the bytes
tested are identified by `release/SHA256SUMS`. A commit is needed before
anyone can reproduce "this revision".

## 7. Customer delivery package

| Item | Path |
|---|---|
| Product explanation, quick start | `proof-bundle/README.md` |
| Verifier (install = copy one file) | `proof-bundle/verifier/strix-proof-verify.mjs` |
| Verifier guide, trust anchors and issuer roots, troubleshooting | `proof-bundle/docs/VERIFIER-GUIDE.md` |
| Specification | `proof-bundle/docs/SPEC.md` |
| Issuer authorization: design, inventory, acceptance cases, open decisions | `proof-bundle/docs/ISSUER-AUTHORIZATION.md` |
| Claims and limitations; security FAQ; threat and trust model | `proof-bundle/docs/` |
| Example bundles, demo trust stores (root-only and direct), reports | `proof-bundle/examples/` |
| Test vectors | `proof-bundle/vectors/` |
| Checksums | `proof-bundle/release/SHA256SUMS` |

Install: Node ≥ 18, copy the verifier, compare its SHA-256. Verify:
`node strix-proof-verify.mjs verify <bundle> --trust-store <store>`.

## 8. Known limitations

Missing product capabilities
- K-1. **No Strix issuer root, no enrolment process, no published anchor.**
  The authorization mechanism is exercised only with test and demo roots.
- K-2. Revocation is only as fresh as the list the relying party supplies;
  without one, standing is `NOT_CHECKED`.
- K-3. Authorization validity is compared with signer-asserted record time; a
  stolen gateway key can backdate into an expired authorization.
- K-4. No enforcement evidence, no trusted timestamps, no exported hash chain.
- K-5. One action per bundle, one execution attempt per action.
- K-6. Arguments are disclosed whole or not at all.
- K-7. Exporter and authority tool are local CLIs: no API, no role-based
  access control.
- K-8. The Python implementation prints verdicts, not claim text.
- K-9. No hosted evidence source; Local Mode records are not a source.

Security assumptions
- The gateway key and the issuer root key are uncompromised; signers report
  truthfully.
- The trust store reached the relying party independently of the bundle.
- SHA-256 and Ed25519 hold; neither is post-quantum.

Operational constraints
- Checksums are unsigned; nothing is published; no external audit.
- The independent review was one reviewer in one pass, not an audit.

## 9. Release readiness

Acceptance criteria (the original eleven):

| # | Criterion | Result |
|---|---|---|
| 1 | Authentic source | PASSED for the open gateway runtime only; not the hosted platform |
| 2 | Real cryptography | PASSED |
| 3 | Independent verification | PASSED |
| 4 | Trust independence | PASSED |
| 5 | Tamper detection | PASSED |
| 6 | Claim precision | PASSED; attribution corrected after review |
| 7 | Missing evidence | PASSED |
| 8 | Enterprise usability | **NOT DEMONSTRATED** — no engineer unfamiliar with Strix has followed the docs |
| 9 | Negative tests | PASSED |
| 10 | Release assets | PASSED with limits (unsigned checksums, no package) |
| 11 | Release honesty | This report |

Evidence against the assessment's gates. These are not self-awarded passes;
the gate decisions are the assessor's.

| Gate | Assessment | What changed | What still holds it |
|---|---|---|---|
| D — Architecture | HOLD | Gateway-to-issuer trust relationship designed and implemented offline; one model for all deployment types described | Who the issuer is; enrolment; alignment of the encoding with TM-1 if required |
| E — Security | HOLD | A customer can authenticate a gateway key's authority against a root; impersonation, substitution, scope and standing cases covered | No Strix root to authenticate against |
| F — Integration | HOLD | Nothing | Hosted platform not integrated; needs access |
| G — Reliability | Provisional PASS | Reproduced on two operating systems and three Node versions; live gateway and rotation tested | Reproduction by someone else, at a committed revision |
| H — Evidence | HOLD | Signature validity, key identity, key authority and standing are separate report fields; statements attributed per signer | Same as E |
| J — Adversarial | HOLD | 26 issuer and key-substitution vectors; independent adversarial review with all findings closed | Acceptance of that evidence by the assessor |

Approval requirements: owner review of this report, of
`docs/ISSUER-AUTHORIZATION.md` §5 (the issuer decision) and of finding F-1; a
decision to commit, so that a revision can be frozen.

Blocking tasks for `RELEASE_READY`
- B-1. Decide the issuer model and create a real root under an offline
  ceremony; define gateway enrolment. *Decision; not engineering in this
  repository.*
- B-2. Publish the root's public key through a channel customers can
  authenticate.
- B-3. Integrate one real hosted Strix evidence path with the exporter.
  *Needs hosted access.*
- B-4. Re-run the Signed Evidence refusal corpus against verifier 1.25.0 in
  the platform repository.
- B-5. Commit, run CI, and have a second party reproduce the corpus at that
  revision.
- B-6. Have an engineer unfamiliar with Strix follow the verifier guide.
- B-7. Independent audit.

## 10. Next engineering priority

**B-1.** Decide who the issuer is. Everything needed to use that decision is
built: once a root exists, authorizing a gateway is one offline command and
customers need one key. Without it, the product verifies integrity and a
customer's own trust choices, and stops there.
