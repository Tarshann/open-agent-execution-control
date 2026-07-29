"""If the row set (and therefore its payload hash) changes after a token
was minted, redemption must refuse — the token is bound to the exact
payload it was issued against."""

from __future__ import annotations

import pytest


def test_payload_modification_after_issuance_invalidates_the_token(core_mod, tmp_path):
    state_dir = tmp_path / ".strix"
    token = core_mod.mint_execution_token(
        payload_hash="original-payload-hash",
        destination_visibility=core_mod.DESTINATION_INTERNAL,
        destination_id="internal-analytics-dept",
        transform_name=None,
        transform_version=None,
        classification_digest="original-classification-digest",
        state_dir=state_dir,
    )

    with pytest.raises(core_mod.StrixDatasetExportTokenBindingMismatch):
        core_mod.redeem_execution_token(
            token.token_id,
            payload_hash="tampered-payload-hash",
            destination_visibility=core_mod.DESTINATION_INTERNAL,
            destination_id="internal-analytics-dept",
            transform_name=None,
            transform_version=None,
            classification_digest="original-classification-digest",
            state_dir=state_dir,
        )


def test_classification_change_after_issuance_also_invalidates_the_token(core_mod, tmp_path):
    """A row's classification tag can change without touching the rest of
    the payload — the classification digest is bound independently so that
    tamper is still caught."""
    state_dir = tmp_path / ".strix"
    token = core_mod.mint_execution_token(
        payload_hash="same-payload-hash",
        destination_visibility=core_mod.DESTINATION_CROSS_PARTY,
        destination_id="partner-hospital-b",
        transform_name=None,
        transform_version=None,
        classification_digest="original-classification-digest",
        state_dir=state_dir,
    )

    with pytest.raises(core_mod.StrixDatasetExportTokenBindingMismatch):
        core_mod.redeem_execution_token(
            token.token_id,
            payload_hash="same-payload-hash",
            destination_visibility=core_mod.DESTINATION_CROSS_PARTY,
            destination_id="partner-hospital-b",
            transform_name=None,
            transform_version=None,
            classification_digest="tampered-classification-digest",
            state_dir=state_dir,
        )
