"""A token minted for one destination must not be redeemable against a
different destination — swapping the destination after issuance (e.g.
retargeting an approved internal export to an external partner) is exactly
the kind of tamper the binding hash exists to catch."""

from __future__ import annotations

import pytest


def test_destination_id_change_after_issuance_invalidates_the_token(core_mod, tmp_path):
    state_dir = tmp_path / ".strix"
    token = core_mod.mint_execution_token(
        payload_hash="deadbeef",
        destination_visibility=core_mod.DESTINATION_CROSS_PARTY,
        destination_id="partner-a",
        transform_name=None,
        transform_version=None,
        classification_digest="deadbeef",
        state_dir=state_dir,
    )

    with pytest.raises(core_mod.StrixDatasetExportTokenBindingMismatch):
        core_mod.redeem_execution_token(
            token.token_id,
            payload_hash="deadbeef",
            destination_visibility=core_mod.DESTINATION_CROSS_PARTY,
            destination_id="partner-b",
            transform_name=None,
            transform_version=None,
            classification_digest="deadbeef",
            state_dir=state_dir,
        )


def test_destination_visibility_change_after_issuance_invalidates_the_token(core_mod, tmp_path):
    """Retargeting INTERNAL -> CROSS_PARTY after mint must also be caught —
    visibility is part of the same binding as the destination id."""
    state_dir = tmp_path / ".strix"
    token = core_mod.mint_execution_token(
        payload_hash="deadbeef",
        destination_visibility=core_mod.DESTINATION_INTERNAL,
        destination_id="internal-analytics-dept",
        transform_name=None,
        transform_version=None,
        classification_digest="deadbeef",
        state_dir=state_dir,
    )

    with pytest.raises(core_mod.StrixDatasetExportTokenBindingMismatch):
        core_mod.redeem_execution_token(
            token.token_id,
            payload_hash="deadbeef",
            destination_visibility=core_mod.DESTINATION_CROSS_PARTY,
            destination_id="internal-analytics-dept",
            transform_name=None,
            transform_version=None,
            classification_digest="deadbeef",
            state_dir=state_dir,
        )
