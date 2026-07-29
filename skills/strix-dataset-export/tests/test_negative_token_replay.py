"""A token can be redeemed exactly once. Redeeming it again with identical
arguments (a replay) must fail closed, not silently succeed."""

from __future__ import annotations

import pytest

from conftest import requires_signing

# Minting now signs the token record, so these need the Ed25519 backend.
# Before the record was signed, minting was pure JSON and they ran anywhere.


@requires_signing
def test_redeeming_the_same_token_twice_fails_on_the_second_attempt(core_mod, tmp_path):
    state_dir = tmp_path / ".strix"
    bound = dict(
        payload_hash="deadbeef",
        destination_visibility=core_mod.DESTINATION_INTERNAL,
        destination_id="internal-analytics-dept",
        transform_name=None,
        transform_version=None,
        classification_digest="deadbeef",
    )
    token = core_mod.mint_execution_token(**bound, state_dir=state_dir)

    core_mod.redeem_execution_token(token.token_id, **bound, state_dir=state_dir)

    with pytest.raises(core_mod.StrixDatasetExportTokenAlreadyRedeemed):
        core_mod.redeem_execution_token(token.token_id, **bound, state_dir=state_dir)
