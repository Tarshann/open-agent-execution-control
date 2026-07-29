"""A requester cannot approve their own cross-party export, even with
approval_granted=True — self-approval is refused before the granted flag is
even consulted."""

from __future__ import annotations

import pytest

from conftest import evidence_files, requires_signing


def test_self_approval_is_refused_even_when_granted(core_mod):
    with pytest.raises(core_mod.StrixDatasetExportSelfApprovalDenied):
        core_mod.evaluate_approval(
            destination_visibility=core_mod.DESTINATION_CROSS_PARTY,
            requester_id="alice@requester",
            approver_id="alice@requester",
            approval_granted=True,
        )


@requires_signing
def test_end_to_end_self_approval_never_invokes_adapter(core_mod, synthetic_rows, spy, tmp_path):
    with pytest.raises(core_mod.StrixDatasetExportSelfApprovalDenied):
        core_mod.governed_export(
            synthetic_rows,
            destination_visibility=core_mod.DESTINATION_CROSS_PARTY,
            destination_id="partner-hospital-b",
            requester_id="alice@requester",
            export_fn=spy,
            approver_id="alice@requester",
            approval_granted=True,
            workspace_root=tmp_path,
        )
    assert spy.calls == 0
    assert evidence_files(tmp_path / ".strix") == []
