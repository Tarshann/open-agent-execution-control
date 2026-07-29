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

**Why plain `subprocess`, not `ProcessPoolExecutor`.** The contended probe used a
process pool, which cannot start under the Windows Store build of Python: pool
startup calls `_winapi.DuplicateHandle`, and the WindowsApps sandbox refuses it
with `PermissionError: [WinError 5]`. That made the probe fail on the one platform
whose lock implementation (`msvcrt.locking`) nothing else exercises — a harness
limitation reported as a product failure, and worse, the platform's lock left
untested either way. Independent `subprocess.Popen` children work there, so the
probe now starts N of them and releases them together through a barrier file.
Contention is created explicitly rather than inherited from a pool's scheduling.
"""

from __future__ import annotations

import json
import subprocess
import sys
import textwrap
import time
from collections import Counter
from pathlib import Path

import pytest

from conftest import HELPERS, requires_signing

HELPER = HELPERS / "dataset_export_local.py"

# Enough to lose a read-check-write race reliably on a broken build (measured: 16
# gave 2 winners), traded against N interpreter startups per round on Windows.
RACERS = 10
ROUNDS = 2

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

# The probe must contend for the same thing `_token_lock` takes: an exclusive
# non-blocking lock on the sidecar file. Both branches print the same two words so
# the assertions below are platform-independent.
_PROBE_BODY = {
    "posix": """
        import fcntl, os
        fd = os.open(r"{lock_path}", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            print("ACQUIRED")
        except OSError:
            print("BLOCKED")
        finally:
            os.close(fd)
        """,
    "win32": """
        import msvcrt, os
        fd = os.open(r"{lock_path}", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
            print("ACQUIRED")
        except OSError:
            print("BLOCKED")
        finally:
            os.close(fd)
        """,
}


@requires_signing
def test_the_token_lock_excludes_a_second_holder(core_mod, tmp_path):
    """While the lock is held, a separate process must not be able to take it.

    Deterministic: the probe acquires non-blocking, so it either gets the lock
    (the guard is not excluding — fail) or is refused (correct). Runs on both
    POSIX and Windows, because the Windows lock path needs a guard of its own —
    it is a different system call, and previously it was the branch with no test
    at all.
    """
    token = core_mod.mint_execution_token(**REQUEST, state_dir=tmp_path)
    lock_path = core_mod._token_path(tmp_path, token.token_id).with_suffix(".lock")

    body = _PROBE_BODY["win32" if sys.platform == "win32" else "posix"]
    probe = _LOADER.format(helper=HELPER) + textwrap.dedent(body).format(lock_path=lock_path)

    with core_mod._token_lock(tmp_path, token.token_id):
        held = _run(probe)
    free = _run(probe)

    assert held.stdout.strip() == "BLOCKED", (
        f"a second process took the lock while it was held: {held.stdout!r} {held.stderr!r}"
    )
    assert free.stdout.strip() == "ACQUIRED", (
        f"the lock was not released afterwards: {free.stdout!r} {free.stderr!r}"
    )


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


@requires_signing
def test_a_lock_that_cannot_be_taken_refuses_instead_of_proceeding(core_mod, tmp_path, monkeypatch):
    """The mechanism existed and failed — that must not degrade to no lock.

    The Windows branch used `LK_LOCK`, which gives up after ten one-second
    retries, and the resulting OSError was caught and ignored: under sustained
    contention the critical section would silently run unserialised. A platform
    with no locking module at all is a different case and still proceeds.
    """
    token = core_mod.mint_execution_token(**REQUEST, state_dir=tmp_path)

    class _Failing:
        LOCK_EX = LOCK_NB = 2
        LK_NBLCK = 1

        @staticmethod
        def flock(*_a, **_k):
            raise OSError(11, "Resource temporarily unavailable")

        @staticmethod
        def locking(*_a, **_k):
            raise OSError(36, "Deadlock situation detected")

    monkeypatch.setitem(sys.modules, "fcntl", _Failing)
    monkeypatch.setitem(sys.modules, "msvcrt", _Failing)
    monkeypatch.setattr(core_mod, "_TOKEN_LOCK_TIMEOUT_SECONDS", 0, raising=False)

    with pytest.raises(core_mod.StrixDatasetExportTokenLockUnavailable):
        with core_mod._token_lock(tmp_path, token.token_id):
            pytest.fail("the body ran despite the lock being unavailable")

    # And the token is untouched — a refused redemption is retryable. Restore the
    # real locking module first, or this line just re-triggers the stub.
    monkeypatch.undo()
    core_mod.redeem_execution_token(token.token_id, **REQUEST, state_dir=tmp_path)


@requires_signing
def test_a_platform_with_no_locking_module_still_redeems(core_mod, tmp_path, monkeypatch):
    # The documented best-effort case, kept distinct from the one above: absence
    # of the mechanism is not the same as the mechanism failing.
    token = core_mod.mint_execution_token(**REQUEST, state_dir=tmp_path)
    import builtins

    real_import = builtins.__import__

    def _no_locking(name, *args, **kwargs):
        if name in {"fcntl", "msvcrt"}:
            raise ImportError(f"no {name} on this platform")
        return real_import(name, *args, **kwargs)

    monkeypatch.delitem(sys.modules, "fcntl", raising=False)
    monkeypatch.delitem(sys.modules, "msvcrt", raising=False)
    monkeypatch.setattr(builtins, "__import__", _no_locking)

    with core_mod._token_lock(tmp_path, token.token_id):
        pass  # must not raise

    monkeypatch.undo()
    core_mod.redeem_execution_token(token.token_id, **REQUEST, state_dir=tmp_path)


# ---------------------------------------------------------------------------
# The behaviour, under real contention.
# ---------------------------------------------------------------------------

_RACER = '''
import json, os, sys, time
from pathlib import Path

ARGS = {args!r}
STATE = r"{state}"
TOKEN = "{token}"
READY = Path(r"{ready}")
GO = Path(r"{go}")

READY.write_text("up", encoding="utf-8")
# Spin, don't sleep-then-go: every racer must be inside redeem within the same
# few milliseconds, or they queue politely and the race never happens.
deadline = time.monotonic() + 60
while not GO.exists():
    if time.monotonic() > deadline:
        print(json.dumps({{"outcome": "BARRIER_TIMEOUT"}}))
        sys.exit(0)

try:
    dx.redeem_execution_token(TOKEN, **ARGS, state_dir=Path(STATE))
    print(json.dumps({{"outcome": "REDEEMED"}}))
except Exception as exc:
    print(json.dumps({{"outcome": type(exc).__name__}}))
'''


@requires_signing
@pytest.mark.parametrize("round_no", range(ROUNDS))
def test_concurrent_redemption_spends_the_token_exactly_once(core_mod, tmp_path, round_no):
    state = tmp_path / f"round{round_no}"
    token = core_mod.mint_execution_token(**REQUEST, state_dir=state)
    gate = tmp_path / f"gate{round_no}"
    gate.mkdir()
    go = gate / "go"

    procs = []
    for i in range(RACERS):
        script = _LOADER.format(helper=HELPER) + _RACER.format(
            args=REQUEST, state=state, token=token.token_id, ready=gate / f"ready-{i}", go=go
        )
        procs.append(
            subprocess.Popen(
                [sys.executable, "-c", script],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        )

    try:
        # Release only once every racer is parked on the barrier.
        deadline = time.monotonic() + 90
        while len(list(gate.glob("ready-*"))) < RACERS:
            if time.monotonic() > deadline:
                pytest.fail(
                    f"only {len(list(gate.glob('ready-*')))}/{RACERS} racers started; "
                    "this is a harness failure, not a lock result"
                )
            time.sleep(0.01)
        go.write_text("go", encoding="utf-8")

        outcomes = Counter()
        for proc in procs:
            out, err = proc.communicate(timeout=120)
            assert proc.returncode == 0, f"racer crashed: {err[-600:]}"
            outcomes[json.loads(out.strip().splitlines()[-1])["outcome"]] += 1
    finally:
        for proc in procs:
            if proc.poll() is None:  # pragma: no cover - only on a hung racer
                proc.kill()

    assert outcomes["BARRIER_TIMEOUT"] == 0, f"racers never released: {dict(outcomes)}"
    assert outcomes["REDEEMED"] == 1, (
        f"token was spent {outcomes['REDEEMED']} times across {RACERS} concurrent "
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
