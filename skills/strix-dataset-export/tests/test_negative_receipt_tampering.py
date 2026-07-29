"""A receipt whose payload was altered after signing must fail independent
verification — the verifier recomputes everything from the payload itself
and trusts nothing that was merely stored."""

from __future__ import annotations

import copy

from conftest import requires_signing


@requires_signing
def test_tampering_with_admitted_row_ids_fails_verification(core_mod, synthetic_rows, spy, tmp_path):
    result = core_mod.governed_export(
        synthetic_rows,
        destination_visibility=core_mod.DESTINATION_INTERNAL,
        destination_id="internal-analytics-dept",
        requester_id="alice@requester",
        export_fn=spy,
        workspace_root=tmp_path,
    )

    state_dir = tmp_path / ".strix"
    genuine_verdict = core_mod.verify_receipt(result.record, state_dir)
    assert genuine_verdict["status"] == "VERIFIED"

    tampered = copy.deepcopy(result.record)
    tampered["payload"]["admittedRowIds"] = ["row-001"]  # attacker drops rows to hide what was really exported
    tampered_verdict = core_mod.verify_receipt(tampered, state_dir)
    assert tampered_verdict["status"] != "VERIFIED"
    assert tampered_verdict["hashValid"] is False


@requires_signing
def test_tampering_with_the_signature_fails_verification(core_mod, synthetic_rows, spy, tmp_path):
    result = core_mod.governed_export(
        synthetic_rows,
        destination_visibility=core_mod.DESTINATION_INTERNAL,
        destination_id="internal-analytics-dept",
        requester_id="alice@requester",
        export_fn=spy,
        workspace_root=tmp_path,
    )

    state_dir = tmp_path / ".strix"
    tampered = copy.deepcopy(result.record)
    genuine_sig = tampered["signature"]
    tampered["signature"] = ("0" if genuine_sig[0] != "0" else "1") + genuine_sig[1:]
    verdict = core_mod.verify_receipt(tampered, state_dir)
    assert verdict["status"] != "VERIFIED"
    assert verdict["signatureValid"] is False
