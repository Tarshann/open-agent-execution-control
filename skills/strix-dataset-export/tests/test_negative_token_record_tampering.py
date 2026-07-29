"""The token record is tamper-evident, not just the request it is bound to.

`bindingHash` covers the payload, destination, declared transform and
classification digest — the *request*. It does not cover `status`, `expiresAt`
or `tokenId`, and those are exactly the fields that carry the single-use and
time-limit properties. Before the record was signed, both could be defeated by
editing text in a local JSON file: resetting `status` to `MINTED` replayed a
spent token, and pushing `expiresAt` out accepted an expired one.

These tests perform those edits and assert redemption refuses. The positive
control matters as much: an untouched token must still redeem exactly once, or
the guard has simply broken the feature.

Scope of what is proven here: tamper-*evidence* against anything that cannot
sign with this project's local key. Someone holding that key can re-sign a
forged record, and the key sits under `<state_dir>/keys/` on the same machine.
That is the LOCAL_MACHINE_ASSERTION boundary, not a stronger claim.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from conftest import requires_signing

REQUEST = {
    "payload_hash": "ph-abc",
    "destination_visibility": "INTERNAL",
    "destination_id": "dest-1",
    "transform_name": None,
    "transform_version": None,
    "classification_digest": "cd-xyz",
}


def _mint(core_mod, state_dir, **overrides):
    return core_mod.mint_execution_token(**{**REQUEST, **overrides}, state_dir=state_dir)


def _record(core_mod, state_dir, token_id):
    return json.loads(core_mod._token_path(state_dir, token_id).read_text(encoding="utf-8"))


def _rewrite(core_mod, state_dir, token_id, record):
    core_mod._token_path(state_dir, token_id).write_text(json.dumps(record, indent=2), encoding="utf-8")


def _redeem(core_mod, state_dir, token_id, **kwargs):
    core_mod.redeem_execution_token(token_id, **REQUEST, state_dir=state_dir, **kwargs)


# ---------------------------------------------------------------------------
# The two properties bindingHash does not cover.
# ---------------------------------------------------------------------------


@requires_signing
def test_resetting_status_to_minted_does_not_restore_a_spent_token(core_mod, tmp_path):
    token = _mint(core_mod, tmp_path)
    _redeem(core_mod, tmp_path, token.token_id)

    record = _record(core_mod, tmp_path, token.token_id)
    assert record["status"] == "REDEEMED"
    record["status"] = "MINTED"
    record.pop("redeemedAt", None)
    _rewrite(core_mod, tmp_path, token.token_id, record)

    with pytest.raises(core_mod.StrixDatasetExportTokenSignatureInvalid):
        _redeem(core_mod, tmp_path, token.token_id)


@requires_signing
def test_extending_expiry_does_not_revive_an_expired_token(core_mod, tmp_path):
    token = _mint(core_mod, tmp_path, )
    record = _record(core_mod, tmp_path, token.token_id)
    record["expiresAt"] = core_mod._iso_from(datetime.now(timezone.utc) + timedelta(days=3650))
    _rewrite(core_mod, tmp_path, token.token_id, record)

    long_after = datetime.now(timezone.utc) + timedelta(days=30)
    with pytest.raises(core_mod.StrixDatasetExportTokenSignatureInvalid):
        _redeem(core_mod, tmp_path, token.token_id, now=long_after)


@requires_signing
def test_swapping_the_token_id_is_refused(core_mod, tmp_path):
    # tokenId is signed too, so a record cannot be lifted onto another id.
    token = _mint(core_mod, tmp_path)
    record = _record(core_mod, tmp_path, token.token_id)
    record["tokenId"] = "dsx_tok_ffffffffffffffffffffffffffffffff"
    _rewrite(core_mod, tmp_path, token.token_id, record)
    with pytest.raises(core_mod.StrixDatasetExportTokenSignatureInvalid):
        _redeem(core_mod, tmp_path, token.token_id)


# ---------------------------------------------------------------------------
# Fail closed on a missing or unusable signature.
# ---------------------------------------------------------------------------


@requires_signing
def test_an_unsigned_token_is_refused(core_mod, tmp_path):
    token = _mint(core_mod, tmp_path)
    record = _record(core_mod, tmp_path, token.token_id)
    record.pop("signature")
    _rewrite(core_mod, tmp_path, token.token_id, record)
    with pytest.raises(core_mod.StrixDatasetExportTokenSignatureInvalid):
        _redeem(core_mod, tmp_path, token.token_id)


@requires_signing
def test_a_token_signed_by_an_unknown_key_is_refused(core_mod, tmp_path):
    token = _mint(core_mod, tmp_path)
    record = _record(core_mod, tmp_path, token.token_id)
    record["signingKeyId"] = "local-deadbeefdeadbeef"
    _rewrite(core_mod, tmp_path, token.token_id, record)
    with pytest.raises(core_mod.StrixDatasetExportTokenSignatureInvalid):
        _redeem(core_mod, tmp_path, token.token_id)


@requires_signing
def test_a_garbled_signature_is_refused_not_crashed(core_mod, tmp_path):
    token = _mint(core_mod, tmp_path)
    record = _record(core_mod, tmp_path, token.token_id)
    record["signature"] = "not-hex-at-all"
    _rewrite(core_mod, tmp_path, token.token_id, record)
    with pytest.raises(core_mod.StrixDatasetExportTokenSignatureInvalid):
        _redeem(core_mod, tmp_path, token.token_id)


@requires_signing
def test_a_token_missing_expiry_is_a_token_error_not_a_keyerror(core_mod, tmp_path):
    # Malformed JSON was already handled; a structurally-valid record missing a
    # required field used to raise KeyError out of the helper.
    token = _mint(core_mod, tmp_path)
    record = _record(core_mod, tmp_path, token.token_id)
    record.pop("expiresAt")
    key = core_mod.generate_or_load_key(tmp_path)
    record["signature"] = core_mod._sign_token_record(record, key)  # legitimately re-signed
    _rewrite(core_mod, tmp_path, token.token_id, record)
    with pytest.raises(core_mod.StrixDatasetExportError):
        _redeem(core_mod, tmp_path, token.token_id)


# ---------------------------------------------------------------------------
# Positive controls — the guard must not have broken the feature.
# ---------------------------------------------------------------------------


@requires_signing
def test_an_untouched_token_redeems_exactly_once(core_mod, tmp_path):
    token = _mint(core_mod, tmp_path)
    _redeem(core_mod, tmp_path, token.token_id)  # first: succeeds
    with pytest.raises(core_mod.StrixDatasetExportTokenAlreadyRedeemed):
        _redeem(core_mod, tmp_path, token.token_id)


@requires_signing
def test_redemption_re_signs_so_the_spent_record_still_verifies(core_mod, tmp_path):
    token = _mint(core_mod, tmp_path)
    _redeem(core_mod, tmp_path, token.token_id)
    record = _record(core_mod, tmp_path, token.token_id)
    # The status flip must be signed, not left carrying the mint-time signature.
    core_mod._verify_token_record(record, tmp_path, token.token_id)
    assert record["status"] == "REDEEMED" and record["redeemedAt"]


@requires_signing
def test_the_binding_check_still_fires_on_a_properly_signed_token(core_mod, tmp_path):
    # Signature valid, request changed: must be a binding mismatch, not a
    # signature error — the two failures stay distinguishable.
    token = _mint(core_mod, tmp_path)
    with pytest.raises(core_mod.StrixDatasetExportTokenBindingMismatch):
        core_mod.redeem_execution_token(
            token.token_id, **{**REQUEST, "destination_id": "somewhere-else"}, state_dir=tmp_path
        )
