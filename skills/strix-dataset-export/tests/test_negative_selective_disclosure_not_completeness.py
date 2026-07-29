"""Disclosing the barred-row slice must prove those rows are members of the
receipted set — and must NOT claim, anywhere in its output, that they are
the complete set. This is the property an IRB or regulator would actually
need: enough to check specific barred rows without handing over the whole
dataset, and without being misled into thinking three disclosed rows out of
four is "everything."
"""

from __future__ import annotations


def test_barred_row_disclosure_proves_membership_not_completeness(core_mod, synthetic_rows):
    tree = core_mod.build_merkle_tree(synthetic_rows)
    barred_row_ids = ["row-001", "row-002", "row-004"]  # the 3 barred rows from Scenario A

    disclosure = core_mod.build_selective_disclosure(synthetic_rows, barred_row_ids)
    assert disclosure["merkleRoot"] == tree.root
    assert {row["row_id"] for row in disclosure["disclosedRows"]} == set(barred_row_ids)
    # The disclosure records the total committed count but never asserts the
    # disclosed rows exhaust it.
    assert disclosure["totalRowCountCommitted"] == 4
    assert "complete" not in disclosure["provesOnly"].lower()
    assert "does not prove" in disclosure["doesNotProve"].lower() or disclosure["doesNotProve"]

    verdict = core_mod.verify_selective_disclosure(disclosure, tree.root)
    assert verdict["rootMatches"] is True
    assert verdict["allVerified"] is True
    assert "does not prove" in verdict["completeness_claim"].lower()
    assert "not prove" in verdict["completeness_claim"].lower()


def test_a_naive_all_rows_present_check_correctly_reports_false(core_mod, synthetic_rows):
    """Demonstrates the fixture doesn't accidentally over-disclose: a naive
    reviewer comparing the disclosed row-id set against the full original
    row-id set gets False, not a misleading True."""

    barred_row_ids = ["row-001", "row-002", "row-004"]
    disclosure = core_mod.build_selective_disclosure(synthetic_rows, barred_row_ids)

    all_original_row_ids = {row["row_id"] for row in synthetic_rows}
    disclosed_row_ids = {row["row_id"] for row in disclosure["disclosedRows"]}
    naive_all_rows_present = disclosed_row_ids == all_original_row_ids
    assert naive_all_rows_present is False


def test_disclosure_against_the_wrong_root_does_not_verify(core_mod, synthetic_rows):
    disclosure = core_mod.build_selective_disclosure(synthetic_rows, ["row-001"])
    verdict = core_mod.verify_selective_disclosure(disclosure, "0" * 64)
    assert verdict["rootMatches"] is False
    assert verdict["allVerified"] is False
