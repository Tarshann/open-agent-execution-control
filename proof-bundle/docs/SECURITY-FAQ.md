# Enterprise security FAQ

**Does verification contact Strix?**
No. The verifier is one file that imports only Node's `crypto`, `fs`, `path`
and `url` modules. The test suite runs it with every network primitive
replaced by one that throws, and records zero attempts.

**What do I have to trust?**
(1) The key you put in your trust store, and whoever holds its private half.
(2) The verifier file — it is one file of about 1,000 lines; pin it by SHA-256.
(3) SHA-256 and Ed25519. You do not have to trust Strix's servers, the
channel the bundle arrived through, or anything inside the bundle.

**The bundle includes a public key. Why isn't that enough?**
Because anyone can generate a key, sign a bundle of their own invention, and
include that key. With only the embedded key the verifier reports the
mathematics as valid, signer trust as `NOT_ESTABLISHED`, and exits 3. See the
vector `trust-attacker-resigned-no-store`.

**How do I know the signing key belongs to an authorized gateway, not just to someone?**
Either you list that gateway key in your trust store yourself, or you trust
an issuer root and the bundle carries the root's signed authorization for the
key, limited to named tenants, environments and dates. The report states
which applied. Today no Strix issuer root exists: a root is whoever created
it. See `ISSUER-AUTHORIZATION.md`.

**If verification passes, was the policy enforced?**
Not established. The bundle shows that a signer you trust *recorded* a
decision. The gateway is an inline proxy; a caller that reaches the tool by
another route is not governed and leaves no record. The validation run does
this deliberately and the denied action executes. v1 has no enforcement
evidence, says so (`enforcementObservation: NOT_CAPTURED`), and the verifier
cannot be made to claim otherwise.

**If verification passes, did the action execute?**
If an execution outcome is included, the signer recorded that it attempted
the call and what came back. That is a first-party report by the component
that made the decision. If no outcome is included, execution is not
established either way.

**Can Strix (or the operator) lie in a bundle?**
Yes. A signer can sign a false record, and it will verify. The bundle makes
the statement attributable and unalterable; it does not make it true. This
is the meaning of `SOURCE_ASSERTION` in reports.

**Can the operator leave things out?**
Yes. A bundle covers one action. It does not show that the operator's log is
complete, and the exporter could be pointed at a store from which a record
was removed. The evidence state `ABSENT` means "the exporter says its store
had no such record".

**What is and isn't covered by signatures?**
The gateway's own signature covers 14 receipt fields (decision, capability,
action, risk, mode, policy version, tenant, environment, hashes, timestamp)
and the whole execution outcome. It does **not** cover the approval result,
approver name, actor fields or tool label; those are fixed only from the
moment of export by the manifest signature. Reports mark them accordingly.

**Are timestamps trustworthy?**
They are the signer's clock. There is no timestamp authority. The verifier
checks only that they are well-formed and ordered.

**How is the actor identified?**
By a value supplied to the gateway. No authentication evidence is in the
bundle; actor identity is always reported as not established.

**What about key compromise and revocation?**
There is no revocation list and no online check. You mark a key `revoked` in
your own trust store, after which everything it signed fails. An undisclosed
compromise is undetectable.

**How does key rotation work?**
Keep the old key as `retired`. Old records keep verifying. See
`THREAT-AND-TRUST-MODEL.md`.

**Can a valid bundle be replayed?**
Yes — it is a static file. `bundleId` and `receiptId` are stable, so track
them, and use `--expect-receipt-id` when you asked about a specific action.

**Can a bundle for another customer pass as mine?**
The tenant is in the signed receipt and shown in the report. Use
`--expect-tenant`, and scope the key in your trust store with `tenants`.

**Is the bundle confidential?**
No. It is signed, not encrypted. By default it contains the action name,
capability, risk, decision, hashes and times, but not the arguments or the
policy; those are included only if the operator chooses to disclose them.
The tool's result is never included. Protect bundles as you would audit logs.

**Is opening a bundle safe?**
The verifier never extracts or executes anything. There is no archive
format; paths are restricted to a strict ASCII grammar; symlinks, oversize
files and duplicate JSON keys are rejected; all limits are checked before
content is processed.

**Which algorithms?**
SHA-256 and Ed25519, fixed by the format version. A bundle that declares
anything else is rejected. Neither is post-quantum.

**Can we write our own verifier?**
Yes. `SPEC.md` is normative, `vectors/` has 116 cases with expected results,
and `python/ppb_verify.py` is an existing second implementation written from
the spec.

**Was this audited?**
No external audit has been performed. One review by a separate reviewer with
no knowledge of the implementation found no way to forge a passing result,
and 17 other defects (disagreements between the two implementations, a way to
forge lines in the text report, wrong attribution of statements, exporter
edge cases). All 17 are fixed and each has a regression test or vector. See `RELEASE-READINESS.md` for what was
tested and what was not.

**Does this make us compliant with anything?**
No claim of compliance with any framework is made.
