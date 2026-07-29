"""Declaring (or un-declaring, or version-bumping) a de-identify transform
after a token was minted must invalidate it — the token authorizes exactly
the transform state it was bound to, nothing looser."""

from __future__ import annotations

import pytest


def test_declaring_a_transform_after_issuance_invalidates_the_token(core_mod, tmp_path):
    state_dir = tmp_path / ".strix"
    token = core_mod.mint_execution_token(
        payload_hash="deadbeef",
        destination_visibility=core_mod.DESTINATION_CROSS_PARTY,
        destination_id="partner-hospital-b",
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
            destination_id="partner-hospital-b",
            transform_name=core_mod.SAFE_HARBOR_V1_NAME,
            transform_version=core_mod.SAFE_HARBOR_V1_VERSION,
            classification_digest="deadbeef",
            state_dir=state_dir,
        )


def test_bumping_the_transform_version_after_issuance_invalidates_the_token(core_mod, tmp_path):
    state_dir = tmp_path / ".strix"
    token = core_mod.mint_execution_token(
        payload_hash="deadbeef",
        destination_visibility=core_mod.DESTINATION_CROSS_PARTY,
        destination_id="partner-hospital-b",
        transform_name=core_mod.SAFE_HARBOR_V1_NAME,
        transform_version=1,
        classification_digest="deadbeef",
        state_dir=state_dir,
    )

    with pytest.raises(core_mod.StrixDatasetExportTokenBindingMismatch):
        core_mod.redeem_execution_token(
            token.token_id,
            payload_hash="deadbeef",
            destination_visibility=core_mod.DESTINATION_CROSS_PARTY,
            destination_id="partner-hospital-b",
            transform_name=core_mod.SAFE_HARBOR_V1_NAME,
            transform_version=2,
            classification_digest="deadbeef",
            state_dir=state_dir,
        )
