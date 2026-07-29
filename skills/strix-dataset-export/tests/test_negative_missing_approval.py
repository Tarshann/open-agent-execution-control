"""A cross-party export with no approval grant must fail closed: the
approval error is raised, and the export adapter is never reached."""

from __future__ import annotations

import pytest

from conftest import evidence_files, requires_signing


def test_missing_approval_raises_before_token_or_export(core_mod):
    with pytest.raises(core_mod.StrixDatasetExportApprovalRequired):
        core_mod.evaluate_approval(
            destination_visibility=core_mod.DESTINATION_CROSS_PARTY,
            requester_id="alice@requester",
            approver_id=None,
            approval_granted=False,
        )


def test_approval_granted_without_a_named_approver_still_fails_closed(core_mod):
    with pytest.raises(core_mod.StrixDatasetExportApprovalRequired):
        core_mod.evaluate_approval(
            destination_visibility=core_mod.DESTINATION_CROSS_PARTY,
            requester_id="alice@requester",
            approver_id=None,
            approval_granted=True,
        )


@requires_signing
def test_end_to_end_missing_approval_never_invokes_adapter(core_mod, synthetic_rows, spy, tmp_path):
    with pytest.raises(core_mod.StrixDatasetExportApprovalRequired):
        core_mod.governed_export(
            synthetic_rows,
            destination_visibility=core_mod.DESTINATION_CROSS_PARTY,
            destination_id="partner-hospital-b",
            requester_id="alice@requester",
            export_fn=spy,
            approval_granted=False,
            workspace_root=tmp_path,
        )
    assert spy.calls == 0
    assert evidence_files(tmp_path / ".strix") == []
