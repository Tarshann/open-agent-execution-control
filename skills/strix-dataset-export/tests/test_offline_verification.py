"""Independent offline verification, end to end: two real governed exports
run one after another in the same workspace, and verify_receipt/verify_chain
must confirm both the signature on each and the prevHash/chainSeq
continuity between them — recomputing everything, trusting nothing stored.
"""

from __future__ import annotations

from conftest import read_chain, requires_signing


@requires_signing
def test_verify_receipt_succeeds_for_a_genuine_record(core_mod, synthetic_rows, spy, tmp_path):
    result = core_mod.governed_export(
        synthetic_rows,
        destination_visibility=core_mod.DESTINATION_INTERNAL,
        destination_id="internal-analytics-dept",
        requester_id="alice@requester",
        export_fn=spy,
        workspace_root=tmp_path,
    )
    verdict = core_mod.verify_receipt(result.record, tmp_path / ".strix")
    assert verdict == {
        "status": "VERIFIED",
        "hashValid": True,
        "chainValid": True,
        "signatureValid": True,
        "keyResolved": True,
    }


@requires_signing
def test_verify_chain_confirms_sequential_receipts_across_two_exports(core_mod, synthetic_rows, spy, tmp_path):
    core_mod.governed_export(
        synthetic_rows,
        destination_visibility=core_mod.DESTINATION_CROSS_PARTY,
        destination_id="partner-hospital-b",
        requester_id="alice@requester",
        export_fn=spy,
        approver_id="bob@approver",
        approval_granted=True,
        workspace_root=tmp_path,
    )
    core_mod.governed_export(
        synthetic_rows,
        destination_visibility=core_mod.DESTINATION_INTERNAL,
        destination_id="internal-analytics-dept",
        requester_id="alice@requester",
        export_fn=spy,
        workspace_root=tmp_path,
    )

    state_dir = tmp_path / ".strix"
    records = read_chain(state_dir)
    assert len(records) == 2
    assert records[0]["payload"]["chainSeq"] == 1
    assert records[0]["payload"]["prevHash"] is None
    assert records[1]["payload"]["chainSeq"] == 2
    assert records[1]["payload"]["prevHash"] == records[0]["payload"]["evidenceHash"]

    chain_verdict = core_mod.verify_chain(records, state_dir)
    assert chain_verdict["status"] == "VERIFIED"
    assert all(r["status"] == "VERIFIED" for r in chain_verdict["records"])


@requires_signing
def test_verify_chain_flags_a_broken_prev_hash_link(core_mod, synthetic_rows, spy, tmp_path):
    core_mod.governed_export(
        synthetic_rows,
        destination_visibility=core_mod.DESTINATION_INTERNAL,
        destination_id="internal-analytics-dept",
        requester_id="alice@requester",
        export_fn=spy,
        workspace_root=tmp_path,
    )
    core_mod.governed_export(
        synthetic_rows,
        destination_visibility=core_mod.DESTINATION_INTERNAL,
        destination_id="internal-analytics-dept",
        requester_id="alice@requester",
        export_fn=spy,
        workspace_root=tmp_path,
    )

    state_dir = tmp_path / ".strix"
    records = read_chain(state_dir)
    records[1]["payload"]["prevHash"] = "0" * 64  # break the link without touching the hash/signature fields

    chain_verdict = core_mod.verify_chain(records, state_dir)
    assert chain_verdict["status"] == "INVALID"
    assert chain_verdict["records"][1]["prevHashValid"] is False
