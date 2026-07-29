"""Row-004 carries no classification tag at all. It must be treated as
protected — the same as PHI — never as safe by default."""

from __future__ import annotations


def test_unlabelled_row_is_barred_under_cross_party_with_no_transform(core_mod, synthetic_rows):
    decision = core_mod.evaluate_export_policy(
        synthetic_rows, destination_visibility=core_mod.DESTINATION_CROSS_PARTY
    )
    barred = {b.row_id: b for b in decision.barred}
    assert "row-004" in barred
    assert barred["row-004"].reason_code == "UNLABELLED_FAILS_CLOSED_AS_PROTECTED"
    assert "row-004" not in decision.admitted_row_ids


def test_unlabelled_row_is_admitted_internally(core_mod, synthetic_rows):
    decision = core_mod.evaluate_export_policy(synthetic_rows, destination_visibility=core_mod.DESTINATION_INTERNAL)
    assert "row-004" in decision.admitted_row_ids


def test_an_unrecognized_classification_string_also_fails_closed(core_mod):
    rows = [{"row_id": "row-x", "classification": "SOMETHING_NOBODY_REGISTERED", "fields": {}}]
    decision = core_mod.evaluate_export_policy(rows, destination_visibility=core_mod.DESTINATION_CROSS_PARTY)
    assert decision.admitted_row_ids == []
    assert decision.barred[0].reason_code == "UNKNOWN_CLASSIFICATION_FAILS_CLOSED_AS_PROTECTED"
