"""The tool-gateway export makes a local receipt checkable by the PUBLISHED verifier.

`docs/PROOF-ATTEMPT.md` established that `npx @strixgov/verifier receipt` refuses
`local-receipt-v1` outright (`unknown schemaVersion`, exit 2) — its `receipt`
subcommand knows only the tool-gateway schema, versions "1" and "2".
`export_tool_gateway_receipt()` closes that by *projection*: every field of the
export is derived from the already-signed local receipt, then the projection is
signed with the same local key. Run against the real verifier (1.20.0), the
export returned `Status: VERIFIED`, exit 0 — and a tampered copy returned
`TAMPERED`, exit 1.

These tests cannot invoke npm, so the verification here is a byte-faithful
Python reimplementation of the verifier's check, transcribed from
`@strixgov/verifier/src/index.mjs`: rebuild the canonical string
(`{"field":<json>,...}` in the frozen v1 order, no whitespace), resolve the key
from the JWKS by `signingKeyId`, verify Ed25519 over the UTF-8 bytes. The
transcription is pinned by the real npx run recorded in PROOF-ATTEMPT.md.

The honesty constraints matter more than the plumbing:

  - **v1, never v2.** v2 adds `tenantId` and `environment` — hosted-tenancy
    facts a local workspace does not possess. Exporting v2 would mean inventing
    them.
  - **`risk` is `UNSPECIFIED`.** No risk assessment happens in Local Mode, and
    the schema makes the field mandatory. Stating the absence beats fabricating
    a tier.
  - **No laundering.** A local receipt that fails its own verification must not
    be exportable: the export signs fresh, so exporting a tampered record would
    wash it through a valid signature.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import sys
from pathlib import Path

import pytest

from test_approval_gate import HELPERS, requires_signing  # same gate, same reason


@pytest.fixture(scope="module")
def local_mod():
    path = HELPERS / "governed_action_local.py"
    spec = importlib.util.spec_from_file_location("strix_wire_tg_export_under_test", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def receipt_and_state(local_mod, tmp_path):
    """One real governed action; returns (record, state_dir)."""
    state = tmp_path / ".strix"
    result = local_mod.governed_action_local(
        "data.write",
        "upgrade_customer_plan",
        {"recordId": "cust_0001", "to": "enterprise"},
        lambda: "done",
        approval_granted=True,
        workspace_root=tmp_path,
        state_dir=state,
    )
    return result.record, state


def _verify_like_the_published_verifier(exported: dict, jwks: dict) -> bool:
    """Transcription of @strixgov/verifier's verifyReceipt() for schema "1"."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    order = (
        "schemaVersion", "receiptId", "capabilityId", "action", "decision",
        "risk", "mode", "invocationHash", "evidenceHash", "proofChainHash",
        "timestamp",
    )
    parts = []
    for field in order:
        value = exported[field]
        if value is None:
            return False
        parts.append(
            f"{json.dumps(field)}:{json.dumps(value, separators=(',', ':'), ensure_ascii=False)}"
        )
    canonical = "{" + ",".join(parts) + "}"

    jwk = next((k for k in jwks["keys"] if k["kid"] == exported["signingKeyId"]), None)
    if jwk is None or jwk["kty"] != "OKP" or jwk["crv"] != "Ed25519":
        return False
    pub = Ed25519PublicKey.from_public_bytes(
        base64.urlsafe_b64decode(jwk["x"] + "=" * (-len(jwk["x"]) % 4))
    )
    sig = base64.urlsafe_b64decode(
        exported["signature"] + "=" * (-len(exported["signature"]) % 4)
    )
    try:
        pub.verify(sig, canonical.encode("utf-8"))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# The export verifies under the published algorithm.
# ---------------------------------------------------------------------------


@requires_signing
def test_the_export_verifies_under_the_published_algorithm(local_mod, receipt_and_state):
    record, state = receipt_and_state
    exported = local_mod.export_tool_gateway_receipt(record, state_dir=state)
    jwks = local_mod.export_jwks(state)
    assert _verify_like_the_published_verifier(exported, jwks) is True


@requires_signing
def test_tampering_any_canonical_field_breaks_verification(local_mod, receipt_and_state):
    # The check must discriminate: a VERIFIED that survives edits proves nothing.
    record, state = receipt_and_state
    exported = local_mod.export_tool_gateway_receipt(record, state_dir=state)
    jwks = local_mod.export_jwks(state)
    for field, forged in [
        ("decision", "ALLOW"),                       # friendlier decision
        ("capabilityId", "data.read"),               # milder capability
        ("evidenceHash", "0" * 64),                  # detached evidence
        ("timestamp", "2020-01-01T00:00:00Z"),       # backdated
        ("risk", "LOW"),                             # invented risk tier
        ("mode", "HOSTED_SIGNED_V1"),                # inflated trust scope
    ]:
        tampered = {**exported, field: forged}
        assert _verify_like_the_published_verifier(tampered, jwks) is False, (
            f"forging {field!r} still verified — the signature does not cover it"
        )


# ---------------------------------------------------------------------------
# The honesty constraints.
# ---------------------------------------------------------------------------


@requires_signing
def test_the_export_is_v1_and_carries_no_hosted_tenancy_fields(local_mod, receipt_and_state):
    record, state = receipt_and_state
    exported = local_mod.export_tool_gateway_receipt(record, state_dir=state)
    assert exported["schemaVersion"] == "1"
    # v2's additions are exactly the fields a local workspace would have to
    # invent. Their absence is the point, so pin it.
    assert "tenantId" not in exported
    assert "environment" not in exported
    assert "policyVersion" not in exported


@requires_signing
def test_risk_states_its_absence_rather_than_inventing_a_tier(local_mod, receipt_and_state):
    record, state = receipt_and_state
    exported = local_mod.export_tool_gateway_receipt(record, state_dir=state)
    assert exported["risk"] == "UNSPECIFIED"


@requires_signing
def test_mode_preserves_the_local_trust_scope_label(local_mod, receipt_and_state):
    record, state = receipt_and_state
    exported = local_mod.export_tool_gateway_receipt(record, state_dir=state)
    assert exported["mode"] == "LOCAL_SIGNED_V1", (
        "the export must label itself local — a verifier user reading `Mode` "
        "must see the trust anchor, not a hosted-looking value"
    )


@requires_signing
def test_every_exported_value_traces_to_the_signed_local_payload(local_mod, receipt_and_state):
    record, state = receipt_and_state
    exported = local_mod.export_tool_gateway_receipt(record, state_dir=state)
    pl = record["payload"]
    assert exported["receiptId"] == pl["evidenceId"]
    assert exported["capabilityId"] == pl["capabilityId"]
    assert exported["action"] == pl["action"]["name"]
    assert exported["decision"] == pl["decision"]
    assert exported["invocationHash"] == pl["action"]["paramsHash"]
    assert exported["evidenceHash"] == pl["evidenceHash"]
    assert exported["proofChainHash"] == pl["proofChainHash"]
    assert exported["timestamp"] == pl["createdAt"]
    assert exported["signingKeyId"] == pl["signingKeyId"]


# ---------------------------------------------------------------------------
# The laundering guard.
# ---------------------------------------------------------------------------


@requires_signing
def test_a_tampered_local_receipt_is_refused_not_laundered(local_mod, receipt_and_state):
    """The export signs fresh, so exporting an unverified record would wash a
    tampered receipt through a brand-new valid signature."""
    record, state = receipt_and_state
    forged = json.loads(json.dumps(record))
    forged["payload"]["decision"] = "ALLOW"
    with pytest.raises(local_mod.StrixLocalError, match="unverified"):
        local_mod.export_tool_gateway_receipt(forged, state_dir=state)


@requires_signing
def test_a_receipt_signed_by_a_different_key_is_not_reattributed(local_mod, receipt_and_state, tmp_path):
    record, state = receipt_and_state
    other_state = tmp_path / "other" / ".strix"
    local_mod.generate_or_load_key(other_state)  # a different workspace's key
    with pytest.raises(local_mod.StrixLocalError):
        local_mod.export_tool_gateway_receipt(record, state_dir=other_state)


@requires_signing
def test_the_jwks_export_contains_only_public_material(local_mod, receipt_and_state):
    record, state = receipt_and_state
    jwks = local_mod.export_jwks(state)
    assert jwks["keys"], "the signing key must appear"
    dumped = json.dumps(jwks)
    key = local_mod.generate_or_load_key(state)
    assert key.private_key_hex not in dumped
    for k in jwks["keys"]:
        assert set(k) == {"kty", "crv", "alg", "use", "kid", "x"}
