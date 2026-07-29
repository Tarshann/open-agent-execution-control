"""A token is spent exactly once, even when redemptions race.

Single-use was enforced by reading `status`, checking it, then writing — three
steps with no mutual exclusion. Two concurrent redemptions could both read
`MINTED`, both pass the check, and both proceed. Signing the record does not
help: both readers see a legitimately signed token. Measured before the fix, 16
concurrent processes against one token produced **two** successful redemptions.

Two tests, because a concurrency test alone is a weak regression guard:

  - the mechanism, deterministically: holding the lock excludes a second holder;
  - the behaviour, under real contention: N processes, exactly one success.

The second is probabilistic against a broken build — it may not lose the race on
every run — so it repeats over several rounds. The first fails immediately and
deterministically if the lock stops excluding, which is what actually pins the
fix.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
from collections import Counter
from pathlib import Path

import pytest

from conftest import HELPERS, requires_signing

HELPER = HELPERS / "dataset_export_local.py"

requires_flock = pytest.mark.skipif(
    sys.platform == "win32", reason="the deterministic exclusion probe uses fcntl"
)

_LOADER = """
import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("dx", r"{helper}")
dx = importlib.util.module_from_spec(spec)
sys.modules["dx"] = dx
spec.loader.exec_module(dx)
"""

REQUEST = dict(
    payload_hash="ph-race",
    destination_visibility="INTERNAL",
    destination_id="dest-race",
    transform_name=None,
    transform_version=None,
    classification_digest="cd-race",
)


def _run(script: str) -> subprocess.CompletedProcess:
    # Each fragment is dedented where it is built: _LOADER is flush-left, so
    # dedenting the concatenation would find an empty common prefix and leave the
    # indented body indented.
    return subprocess.run(
        [sys.executable, "-c", script], capture_output=True, text=True, timeout=120
    )


# ---------------------------------------------------------------------------
# The mechanism, deterministically.
# ---------------------------------------------------------------------------


@requires_flock
@requires_signing
def test_the_token_lock_excludes_a_second_holder(core_mod, tmp_path):
    """While the lock is held, a separate process must not be able to take it.

    Deterministic: the probe uses a non-blocking acquire, so it either gets the
    lock (the guard is not excluding — fail) or is refused (correct).
    """
    token = core_mod.mint_execution_token(**REQUEST, state_dir=tmp_path)
    lock_path = core_mod._token_path(tmp_path, token.token_id).with_suffix(".lock")

    probe = _LOADER.format(helper=HELPER) + textwrap.dedent(f"""
        import fcntl, os
        fd = os.open(r"{lock_path}", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print("ACQUIRED")
        except OSError:
            print("BLOCKED")
        finally:
            os.close(fd)
        """)

    with core_mod._token_lock(tmp_path, token.token_id):
        held = _run(probe)
    free = _run(probe)

    assert held.stdout.strip() == "BLOCKED", (
        f"a second process took the lock while it was held: {held.stdout!r} {held.stderr!r}"
    )
    assert free.stdout.strip() == "ACQUIRED", "the lock was not released afterwards"


@requires_signing
def test_the_lock_is_released_even_if_redemption_raises(core_mod, tmp_path):
    # A binding mismatch raises inside the critical section. If the lock leaked,
    # the next redemption of that token would hang rather than proceed.
    token = core_mod.mint_execution_token(**REQUEST, state_dir=tmp_path)
    with pytest.raises(core_mod.StrixDatasetExportTokenBindingMismatch):
        core_mod.redeem_execution_token(
            token.token_id, **{**REQUEST, "destination_id": "elsewhere"}, state_dir=tmp_path
        )
    # Still redeemable with the correct request, and still exactly once.
    core_mod.redeem_execution_token(token.token_id, **REQUEST, state_dir=tmp_path)
    with pytest.raises(core_mod.StrixDatasetExportTokenAlreadyRedeemed):
        core_mod.redeem_execution_token(token.token_id, **REQUEST, state_dir=tmp_path)


# ---------------------------------------------------------------------------
# The behaviour, under real contention.
# ---------------------------------------------------------------------------


@requires_signing
@pytest.mark.parametrize("round_no", range(3))
def test_concurrent_redemption_spends_the_token_exactly_once(core_mod, tmp_path, round_no):
    state = tmp_path / f"round{round_no}"
    token = core_mod.mint_execution_token(**REQUEST, state_dir=state)

    script = _LOADER.format(helper=HELPER) + textwrap.dedent(f"""
        import json
        from concurrent.futures import ProcessPoolExecutor
        from pathlib import Path

        ARGS = {REQUEST!r}
        STATE = r"{state}"
        TOKEN = "{token.token_id}"

        def attempt(_):
            import importlib.util, sys
            spec = importlib.util.spec_from_file_location("dx2", r"{HELPER}")
            m = importlib.util.module_from_spec(spec); sys.modules["dx2"] = m
            spec.loader.exec_module(m)
            try:
                m.redeem_execution_token(TOKEN, **ARGS, state_dir=Path(STATE))
                return "REDEEMED"
            except Exception as exc:
                return type(exc).__name__

        if __name__ == "__main__":
            with ProcessPoolExecutor(max_workers=16) as ex:
                print(json.dumps(list(ex.map(attempt, range(16)))))
        """)
    proc = _run(script)
    assert proc.returncode == 0, f"probe failed: {proc.stderr[-800:]}"
    outcomes = Counter(json.loads(proc.stdout.strip().splitlines()[-1]))

    assert outcomes["REDEEMED"] == 1, (
        f"token was spent {outcomes['REDEEMED']} times across 16 concurrent "
        f"redemptions; single-use is not holding. Outcomes: {dict(outcomes)}"
    )
    # Everything else must be a clean refusal, not a crash or a corrupt read.
    assert set(outcomes) <= {"REDEEMED", "StrixDatasetExportTokenAlreadyRedeemed"}, dict(outcomes)


@requires_signing
def test_the_spent_record_is_still_valid_after_a_contended_redemption(core_mod, tmp_path):
    # The winner re-signs under the lock. A torn or unsigned record afterwards
    # would mean the write escaped the critical section.
    token = core_mod.mint_execution_token(**REQUEST, state_dir=tmp_path)
    core_mod.redeem_execution_token(token.token_id, **REQUEST, state_dir=tmp_path)
    record = json.loads(core_mod._token_path(tmp_path, token.token_id).read_text(encoding="utf-8"))
    core_mod._verify_token_record(record, tmp_path, token.token_id)
    assert record["status"] == "REDEEMED"
