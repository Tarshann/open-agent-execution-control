"""Redeeming a token_id that was never minted (or whose file has vanished)
must fail closed."""

from __future__ import annotations

import pytest


def test_redeeming_a_nonexistent_token_id_fails_closed(core_mod, tmp_path):
    state_dir = tmp_path / ".strix"
    with pytest.raises(core_mod.StrixDatasetExportTokenMissing):
        core_mod.redeem_execution_token(
            "dsx_tok_does_not_exist",
            payload_hash="deadbeef",
            destination_visibility=core_mod.DESTINATION_INTERNAL,
            destination_id="internal-analytics-dept",
            transform_name=None,
            transform_version=None,
            classification_digest="deadbeef",
            state_dir=state_dir,
        )
