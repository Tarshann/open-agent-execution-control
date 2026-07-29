"""A token minted with a short TTL must be refused once its expiry has
passed, even if every other bound field still matches exactly."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from conftest import requires_signing

# Minting now signs the token record, so these need the Ed25519 backend.
# Before the record was signed, minting was pure JSON and they ran anywhere.


@requires_signing
def test_expired_token_fails_closed(core_mod, tmp_path):
    state_dir = tmp_path / ".strix"
    bound = dict(
        payload_hash="deadbeef",
        destination_visibility=core_mod.DESTINATION_INTERNAL,
        destination_id="internal-analytics-dept",
        transform_name=None,
        transform_version=None,
        classification_digest="deadbeef",
    )
    token = core_mod.mint_execution_token(**bound, state_dir=state_dir, ttl_seconds=1)

    future = datetime.now(timezone.utc) + timedelta(seconds=10)
    with pytest.raises(core_mod.StrixDatasetExportTokenExpired):
        core_mod.redeem_execution_token(token.token_id, **bound, state_dir=state_dir, now=future)
