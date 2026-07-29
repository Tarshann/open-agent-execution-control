"""Correctness of the Merkle tree/proof primitives backing selective
disclosure: every row's proof must verify against the true root, and a
proof must be rejected once the row's content (or the tree it was built
against) has been altered.
"""

from __future__ import annotations

import copy


def test_every_row_has_a_valid_inclusion_proof(core_mod, synthetic_rows):
    tree = core_mod.build_merkle_tree(synthetic_rows)
    for row in synthetic_rows:
        proof = core_mod.merkle_inclusion_proof(tree, row["row_id"])
        assert core_mod.verify_merkle_inclusion(row, proof, tree.root, len(synthetic_rows)) is True


def test_a_proof_is_rejected_if_the_row_content_is_altered(core_mod, synthetic_rows):
    tree = core_mod.build_merkle_tree(synthetic_rows)
    row = next(r for r in synthetic_rows if r["row_id"] == "row-001")
    proof = core_mod.merkle_inclusion_proof(tree, row["row_id"])

    tampered_row = copy.deepcopy(row)
    tampered_row["fields"]["mrn"] = "SYN-MRN-TAMPERED"
    assert core_mod.verify_merkle_inclusion(tampered_row, proof, tree.root, len(synthetic_rows)) is False


def test_a_proof_is_rejected_against_a_different_roots_tree(core_mod, synthetic_rows):
    tree = core_mod.build_merkle_tree(synthetic_rows)
    row = next(r for r in synthetic_rows if r["row_id"] == "row-001")
    proof = core_mod.merkle_inclusion_proof(tree, row["row_id"])

    other_rows = [r for r in synthetic_rows if r["row_id"] != "row-004"]
    other_tree = core_mod.build_merkle_tree(other_rows)
    assert other_tree.root != tree.root
    assert core_mod.verify_merkle_inclusion(row, proof, other_tree.root, len(other_rows)) is False


def test_building_a_tree_over_zero_rows_is_refused(core_mod):
    import pytest

    with pytest.raises(ValueError):
        core_mod.build_merkle_tree([])


def test_requesting_a_proof_for_a_row_not_in_the_tree_is_refused(core_mod, synthetic_rows):
    import pytest

    tree = core_mod.build_merkle_tree(synthetic_rows)
    with pytest.raises(ValueError):
        core_mod.merkle_inclusion_proof(tree, "row-does-not-exist")
