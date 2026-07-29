"""The single behavioral proof point for "policy failure never invokes the
export adapter": every distinct way a call to governed_export can fail
before execution — zero rows admitted, missing approval, self-approval — is
parametrized here, and each one asserts the Spy was never called and no
evidence file was written to disk.
"""

from __future__ import annotations

import pytest

from conftest import evidence_files, requires_signing

ALL_PROTECTED_ROWS = [
    {"row_id": "row-001", "classification": "PHI", "fields": {"mrn": "SYN-MRN-0001"}},
    {"row_id": "row-002", "classification": "PHI", "fields": {"mrn": "SYN-MRN-0002"}},
    {"row_id": "row-004", "classification": None, "fields": {"value": "SYN-UNTAGGED-0004"}},
]


def _zero_admitted(core_mod, spy, tmp_path):
    return dict(
        rows=ALL_PROTECTED_ROWS,
        destination_visibility=core_mod.DESTINATION_CROSS_PARTY,
        destination_id="partner-hospital-b",
        requester_id="alice@requester",
        export_fn=spy,
        approver_id="bob@approver",
        approval_granted=True,
        workspace_root=tmp_path,
    ), core_mod.StrixDatasetExportPolicyDenied


def _missing_approval(core_mod, spy, tmp_path, synthetic_rows):
    return dict(
        rows=synthetic_rows,
        destination_visibility=core_mod.DESTINATION_CROSS_PARTY,
        destination_id="partner-hospital-b",
        requester_id="alice@requester",
        export_fn=spy,
        approval_granted=False,
        workspace_root=tmp_path,
    ), core_mod.StrixDatasetExportApprovalRequired


def _self_approval(core_mod, spy, tmp_path, synthetic_rows):
    return dict(
        rows=synthetic_rows,
        destination_visibility=core_mod.DESTINATION_CROSS_PARTY,
        destination_id="partner-hospital-b",
        requester_id="alice@requester",
        export_fn=spy,
        approver_id="alice@requester",
        approval_granted=True,
        workspace_root=tmp_path,
    ), core_mod.StrixDatasetExportSelfApprovalDenied


@requires_signing
@pytest.mark.parametrize("case_name", ["zero_admitted", "missing_approval", "self_approval"])
def test_every_denial_path_never_invokes_the_adapter(core_mod, synthetic_rows, spy, tmp_path, case_name):
    if case_name == "zero_admitted":
        kwargs, expected_error = _zero_admitted(core_mod, spy, tmp_path)
    elif case_name == "missing_approval":
        kwargs, expected_error = _missing_approval(core_mod, spy, tmp_path, synthetic_rows)
    else:
        kwargs, expected_error = _self_approval(core_mod, spy, tmp_path, synthetic_rows)

    with pytest.raises(expected_error):
        core_mod.governed_export(kwargs.pop("rows"), **kwargs)

    assert spy.calls == 0
    assert spy.received == []
    assert evidence_files(tmp_path / ".strix") == []
