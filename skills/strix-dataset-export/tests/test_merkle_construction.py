"""The Merkle root commits to what it claims to commit to.

Three defects were found in the original construction:

1. **Duplicate row ids were accepted.** `merkle_inclusion_proof` resolves a
   row_id to a single index, so a proof for a duplicated id silently attested
   only the first copy and read as *false* for the second. This is also what made
   the root collision reachable: `[a,b,c]` hashed identically to `[a,b,c,c]`,
   because the odd node was hashed with itself. Refusing duplicates removes both
   at once, and is the load-bearing fix.

2. **The odd node was duplicated rather than promoted.** With duplicates now
   refused, `[a,b,c,c]` cannot be built, so the specific collision is no longer
   constructible either way — promotion is defence in depth, so the root does not
   depend on the duplicate check staying in place. It is still directly
   observable: a duplicating build emits a proof step whose sibling *is* the
   node's own leaf hash, and a promoting build emits no step at all for that
   level. That signature is what the test below pins.

3. **The leaf count was not bound into the root.** A disclosure could assert any
   `totalRowCountCommitted` it liked and nothing contradicted it. The count is
   now folded into the published root, so the claim is self-verifying.

Plus a hardening: `_apply_proof` used to treat any unrecognised `position` as
"right", silently reinterpreting a malformed or hostile proof instead of
rejecting it.
"""

from __future__ import annotations

import pytest


def _row(row_id: str, value: str | None = None) -> dict:
    return {"row_id": row_id, "classification": "PUBLIC", "fields": {"v": value or row_id}}


def _rows(*ids: str) -> list[dict]:
    return [_row(i) for i in ids]


# ---------------------------------------------------------------------------
# 1. Duplicate row ids — the load-bearing fix.
# ---------------------------------------------------------------------------


def test_duplicate_row_ids_are_refused(core_mod):
    with pytest.raises(ValueError, match="duplicate row_id"):
        core_mod.build_merkle_tree([_row("a"), _row("b"), _row("a", "different-content")])


def test_the_error_names_every_duplicated_id(core_mod):
    with pytest.raises(ValueError) as exc:
        core_mod.build_merkle_tree([_row("a"), _row("a"), _row("b"), _row("b"), _row("c")])
    message = str(exc.value)
    assert "'a'" in message and "'b'" in message and "'c'" not in message


def test_the_original_collision_is_no_longer_constructible(core_mod):
    # [a,b,c] vs [a,b,c,c] was the demonstrated collision. The second input is
    # now rejected outright, so the pair cannot be formed.
    core_mod.build_merkle_tree(_rows("a", "b", "c"))  # fine
    with pytest.raises(ValueError, match="duplicate row_id"):
        core_mod.build_merkle_tree([*_rows("a", "b", "c"), _row("c")])


# ---------------------------------------------------------------------------
# 2. Odd nodes are promoted, not self-hashed.
# ---------------------------------------------------------------------------


def test_an_odd_node_has_no_self_sibling_step_in_its_proof(core_mod):
    """The observable signature of promotion.

    A duplicating build pairs the odd node with itself, so the proof contains a
    step whose sibling hash equals the node's own leaf hash. Promotion emits no
    step for that level at all.
    """
    rows = _rows("a", "b", "c")  # 3 leaves: "c" is odd at the leaf level
    tree = core_mod.build_merkle_tree(rows)
    proof = core_mod.merkle_inclusion_proof(tree, "c")
    own_leaf = core_mod._leaf_hash(_row("c"))
    assert all(step["hash"] != own_leaf for step in proof), (
        "the odd node was paired with itself — that is the duplicating construction"
    )


@pytest.mark.parametrize("count", [1, 2, 3, 4, 5, 7, 8, 9, 16, 17])
def test_every_row_verifies_at_every_tree_shape(core_mod, count):
    # Odd and even counts, powers of two and not: promotion must not break the
    # path for any position, which is the risk when changing pairing.
    rows = _rows(*[f"row-{i:03d}" for i in range(count)])
    tree = core_mod.build_merkle_tree(rows)
    for row in rows:
        proof = core_mod.merkle_inclusion_proof(tree, row["row_id"])
        assert core_mod.verify_merkle_inclusion(row, proof, tree.root, count) is True


@pytest.mark.parametrize("count", [3, 5, 7, 9])
def test_odd_trees_do_not_collide_with_their_even_neighbours(core_mod, count):
    # Distinct ids throughout, so this holds independently of the duplicate check.
    odd = _rows(*[f"row-{i:03d}" for i in range(count)])
    even = _rows(*[f"row-{i:03d}" for i in range(count + 1)])
    assert core_mod.build_merkle_tree(odd).root != core_mod.build_merkle_tree(even).root


# ---------------------------------------------------------------------------
# 3. The leaf count is bound into the root.
# ---------------------------------------------------------------------------


def test_a_wrong_leaf_count_fails_verification(core_mod):
    rows = _rows("a", "b", "c")
    tree = core_mod.build_merkle_tree(rows)
    proof = core_mod.merkle_inclusion_proof(tree, "b")
    assert core_mod.verify_merkle_inclusion(rows[1], proof, tree.root, 3) is True
    for lie in (1, 2, 4, 99):
        assert core_mod.verify_merkle_inclusion(rows[1], proof, tree.root, lie) is False, (
            f"claiming {lie} rows verified against a 3-row root"
        )


def test_a_nonsense_leaf_count_is_refused_not_crashed(core_mod):
    rows = _rows("a", "b", "c")
    tree = core_mod.build_merkle_tree(rows)
    proof = core_mod.merkle_inclusion_proof(tree, "b")
    for bad in (0, -1, True, None, "3", 2.0):
        assert core_mod.verify_merkle_inclusion(rows[1], proof, tree.root, bad) is False


def test_a_disclosure_cannot_lie_about_the_committed_row_count(core_mod):
    rows = _rows("a", "b", "c", "d", "e")
    disclosure = core_mod.build_selective_disclosure(rows, ["b", "d"])
    honest = core_mod.verify_selective_disclosure(disclosure, disclosure["merkleRoot"])
    assert honest["allVerified"] is True

    tampered = dict(disclosure)
    tampered["totalRowCountCommitted"] = 500
    result = core_mod.verify_selective_disclosure(tampered, disclosure["merkleRoot"])
    assert result["allVerified"] is False, (
        "totalRowCountCommitted is bound into the root; a false count must not verify"
    )


def test_the_completeness_disclaimer_survives_a_failed_verification(core_mod):
    rows = _rows("a", "b", "c")
    disclosure = core_mod.build_selective_disclosure(rows, ["a"])
    tampered = {**disclosure, "totalRowCountCommitted": 99}
    result = core_mod.verify_selective_disclosure(tampered, disclosure["merkleRoot"])
    # A failure must not drop the disclaimer — that is the field a reader relies
    # on to know membership was never completeness.
    assert "does NOT prove" in result["completeness_claim"]


# ---------------------------------------------------------------------------
# Proof-shape hardening.
# ---------------------------------------------------------------------------


def test_an_unrecognised_proof_position_is_rejected_not_reinterpreted(core_mod):
    rows = _rows("a", "b", "c", "d")
    tree = core_mod.build_merkle_tree(rows)
    proof = core_mod.merkle_inclusion_proof(tree, "a")
    hostile = [{**proof[0], "position": "sideways"}, *proof[1:]]
    assert core_mod.verify_merkle_inclusion(rows[0], hostile, tree.root, 4) is False
    with pytest.raises(ValueError, match="invalid Merkle proof step position"):
        core_mod._apply_proof(core_mod._leaf_hash(rows[0]), hostile)


@pytest.mark.parametrize(
    "malformed",
    [
        [{"position": "left"}],                    # no hash
        [{"hash": "abc"}],                         # no position
        [{"position": None, "hash": "abc"}],
        "not-a-list-at-all",
        [None],
    ],
)
def test_a_malformed_proof_is_a_failed_verification_not_a_crash(core_mod, malformed):
    rows = _rows("a", "b")
    tree = core_mod.build_merkle_tree(rows)
    assert core_mod.verify_merkle_inclusion(rows[0], malformed, tree.root, 2) is False


def test_an_empty_proof_does_not_verify_against_a_multi_row_root(core_mod):
    rows = _rows("a", "b", "c")
    tree = core_mod.build_merkle_tree(rows)
    assert core_mod.verify_merkle_inclusion(rows[0], [], tree.root, 3) is False


def test_the_domain_tag_is_versioned(core_mod):
    # A root computed under a different construction must not be mistakable for
    # a current one, so the tag is part of the hash and carries a version.
    assert core_mod.MERKLE_DOMAIN.endswith(".v2")
    rows = _rows("a", "b")
    tree = core_mod.build_merkle_tree(rows)
    bare = core_mod._hash_canonical({"left": core_mod._leaf_hash(rows[0]), "right": core_mod._leaf_hash(rows[1])})
    assert tree.root != bare, "the published root must not be the bare pairwise hash"
