"""The three required acceptance scenarios from the recommended test table:

  A) CROSS_PARTY, no transform      -> 1 admitted / 3 barred
  B) INTERNAL                       -> 4 admitted
  C) CROSS_PARTY + safe-harbor-v1   -> 4 admitted, deidentified=true

Each assertion checks the full receipt shape, not just row counts, so a
regression that gets the counts right but the fields wrong still fails here.
"""

from __future__ import annotations

from conftest import evidence_files, requires_signing


@requires_signing
def test_scenario_a_cross_party_no_transform_bars_protected_rows(core_mod, adapter_mod, synthetic_rows, spy, tmp_path):
    result = core_mod.governed_export(
        synthetic_rows,
        destination_visibility=core_mod.DESTINATION_CROSS_PARTY,
        destination_id="partner-hospital-b",
        requester_id="alice@requester",
        export_fn=spy,
        approver_id="bob@approver",
        approval_granted=True,
        workspace_root=tmp_path,
    )

    assert result.policy_decision.admitted_row_ids == ["row-003"]
    barred_ids = {b.row_id for b in result.policy_decision.barred}
    assert barred_ids == {"row-001", "row-002", "row-004"}
    assert result.policy_decision.decision_outcome == "ADMIT_PARTIAL"
    assert result.policy_decision.deidentified is False

    payload = result.record["payload"]
    assert payload["capabilityId"] == "research.dataset.export"
    assert payload["requester"] == {"requesterId": "alice@requester"}
    assert payload["approver"] == {"approverId": "bob@approver"}
    assert payload["destination"] == {"visibility": "CROSS_PARTY", "destinationId": "partner-hospital-b"}
    assert payload["admittedRowIds"] == ["row-003"]
    reasons = {b["rowId"]: b["reasonCode"] for b in payload["barredRowIds"]}
    assert reasons["row-001"] == "PHI_PROTECTED_NO_DEIDENTIFY_TRANSFORM"
    assert reasons["row-002"] == "PHI_PROTECTED_NO_DEIDENTIFY_TRANSFORM"
    assert reasons["row-004"] == "UNLABELLED_FAILS_CLOSED_AS_PROTECTED"
    assert payload["deidentifyTransform"] == {"name": None, "version": None}
    assert payload["deidentified"] is False
    assert payload["decisionOutcome"] == "ADMIT_PARTIAL"
    assert payload["executionOutcome"] == "SUCCEEDED"
    assert payload["executionTokenRef"]["status"] == "REDEEMED"
    assert payload["completeness"] == "NOT_PROVEN"

    assert spy.calls == 1
    assert [row["row_id"] for row in spy.received[0]["rows"]] == ["row-003"]
    assert evidence_files(tmp_path / ".strix")


@requires_signing
def test_scenario_b_internal_admits_all_rows(core_mod, synthetic_rows, spy, tmp_path):
    result = core_mod.governed_export(
        synthetic_rows,
        destination_visibility=core_mod.DESTINATION_INTERNAL,
        destination_id="internal-analytics-dept",
        requester_id="alice@requester",
        export_fn=spy,
        workspace_root=tmp_path,
    )

    assert sorted(result.policy_decision.admitted_row_ids) == ["row-001", "row-002", "row-003", "row-004"]
    assert result.policy_decision.barred == []
    assert result.policy_decision.decision_outcome == "ADMIT_ALL"
    assert result.policy_decision.deidentified is False

    payload = result.record["payload"]
    assert payload["approver"] is None
    assert payload["destination"] == {"visibility": "INTERNAL", "destinationId": "internal-analytics-dept"}
    assert payload["barredRowIds"] == []
    assert payload["deidentified"] is False
    assert payload["executionOutcome"] == "SUCCEEDED"

    assert spy.calls == 1
    assert sorted(row["row_id"] for row in spy.received[0]["rows"]) == ["row-001", "row-002", "row-003", "row-004"]


@requires_signing
def test_scenario_c_cross_party_with_safe_harbor_v1_admits_all_and_deidentifies(core_mod, synthetic_rows, spy, tmp_path):
    result = core_mod.governed_export(
        synthetic_rows,
        destination_visibility=core_mod.DESTINATION_CROSS_PARTY,
        destination_id="partner-hospital-b",
        requester_id="alice@requester",
        export_fn=spy,
        approver_id="bob@approver",
        approval_granted=True,
        transform_name=core_mod.SAFE_HARBOR_V1_NAME,
        transform_version=core_mod.SAFE_HARBOR_V1_VERSION,
        workspace_root=tmp_path,
    )

    assert sorted(result.policy_decision.admitted_row_ids) == ["row-001", "row-002", "row-003", "row-004"]
    assert result.policy_decision.barred == []
    assert result.policy_decision.deidentified is True

    payload = result.record["payload"]
    assert payload["deidentifyTransform"] == {"name": "safe-harbor-v1", "version": 1}
    assert payload["deidentified"] is True
    assert payload["decisionOutcome"] == "ADMIT_ALL"

    assert spy.calls == 1
    exported_rows = {row["row_id"]: row for row in spy.received[0]["rows"]}
    # PHI rows are masked by the declared transform ...
    assert exported_rows["row-001"]["fields"]["mrn"] == "SYN-DEIDENTIFIED"
    assert exported_rows["row-001"]["fields"]["dob"] == "SYN-DEIDENTIFIED"
    assert exported_rows["row-002"]["fields"]["mrn"] == "SYN-DEIDENTIFIED"
    # ... while the non-PHI rows this fixture has no direct identifiers on
    # pass through this transform unchanged.
    assert exported_rows["row-003"]["fields"] == {"cohort_size": 42, "mean_age": 51.2}
    assert exported_rows["row-004"]["fields"] == {"value": "SYN-UNTAGGED-0004"}
