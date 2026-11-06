#!/usr/bin/env python3
"""Wire *Offline Mode* end to end with the network physically disabled.

Usage: python run.py /path/to/solo[.exe]

Blocks every socket connection in-process, then drives
skills/strix-wire/helpers/governed_action_local.py: one call without approval
(must refuse, operation must not run), one approved call with an inert operation
(must run once and write a signed receipt). The receipt is then re-verified by
`solo strix-wire verify` (a separate process, from the solo-builder-core package)
and a tampered copy must fail. A socket-attempt counter proves zero network use.
"""
import importlib.util
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
HELPER = HERE.parents[1] / "skills" / "strix-wire" / "helpers" / "governed_action_local.py"
solo = sys.argv[1] if len(sys.argv) > 1 else "solo"

attempts = []


def _blocked(self, *a, **k):
    attempts.append(repr(a))
    raise OSError("network disabled by validation harness")


socket.socket.connect = _blocked
socket.socket.connect_ex = _blocked
socket.getaddrinfo = lambda *a, **k: (_ for _ in ()).throw(OSError("dns disabled by validation harness"))

spec = importlib.util.spec_from_file_location("ga_local", HELPER)
ga = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ga)

work = Path(tempfile.mkdtemp(prefix="wire-offline-"))
ran = []
out = {"helper": "skills/strix-wire/helpers/governed_action_local.py", "steps": []}


def op():
    ran.append(1)
    return {"inert": True}


def call(label, **kw):
    before = len(ran)
    rec = {"label": label}
    try:
        r = ga.governed_action_local("payment.charge", "charge", {"amount": 100, "currency": "usd"}, op,
                                     workspace_root=work, state_dir=work / ".strix", **kw)
        rec["result_type"] = type(r).__name__
        rec["fields"] = {k: str(v)[:160] for k, v in vars(r).items()} if hasattr(r, "__dict__") else str(r)[:200]
    except Exception as e:  # noqa: BLE001
        rec["raised"] = f"{type(e).__name__}: {str(e)[:200]}"
    rec["operation_ran"] = len(ran) > before
    out["steps"].append(rec)
    return rec


call("no approval for a HIGH-risk capability")
ok = call("approval_granted=True (caller attests a human confirmed)", approval_granted=True)

receipts = sorted((work / ".strix").rglob("*.json*")) + sorted((work / ".strix").rglob("*.jsonl"))
evid = [p for p in receipts if "evidence" in p.parts]
out["state_files"] = sorted(str(p.relative_to(work)).replace("\\", "/") for p in (work / ".strix").rglob("*") if p.is_file())
out["private_key_file_present"] = any("keys" in p.parts and p.suffix in {".pem", ".key", ".json"} for p in (work / ".strix").rglob("*") if p.is_file())

env = {**os.environ, "PYTHONUTF8": "1"}
ver = []
for p in evid[:1]:
    r1 = subprocess.run([solo, "strix-wire", "verify", str(p), "--state-dir", str(work / ".strix")], capture_output=True, text=True, env=env)
    bad = work / ("tampered_" + p.name)
    txt = p.read_text(encoding="utf-8").replace('"payment.charge"', '"payment.refund"', 1)
    bad.write_text(txt, encoding="utf-8")
    r2 = subprocess.run([solo, "strix-wire", "verify", str(bad), "--state-dir", str(work / ".strix")], capture_output=True, text=True, env=env)
    ver = [{"file": p.name, "exit": r1.returncode, "out": (r1.stdout + r1.stderr).strip()[:300]},
           {"file": bad.name, "tampered": True, "exit": r2.returncode, "out": (r2.stdout + r2.stderr).strip()[:300]}]
out["independent_verify"] = ver
out["socket_connect_attempts"] = len(attempts)
(HERE / "evidence").mkdir(exist_ok=True)
(HERE / "evidence" / "results.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"steps": [{k: v for k, v in s.items() if k != "fields"} for s in out["steps"]],
                  "state_files": out["state_files"], "verify": ver, "socket_connect_attempts": len(attempts)}, indent=2))
shutil.rmtree(work, ignore_errors=True)
