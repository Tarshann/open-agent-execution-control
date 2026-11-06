#!/usr/bin/env python3
"""End-to-end test of Wire *Sandbox Mode* (accountless, hosted) with a traffic log.

Runs skills/strix-wire/helpers/governed_action.py with every STRIX_* variable
removed, an inert operation, and synthetic non-secret inputs. Every HTTP request
the helper makes is recorded (method, URL, body) with credentials redacted, so
the "what leaves the machine" statement in the docs is checked against the wire
instead of asserted. This makes REAL calls to the hosted service (default
https://www.strixgov.com) and creates a short-lived sandbox tenant there.
"""
import importlib.util
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
HELPER = HERE.parents[1] / "skills" / "strix-wire" / "helpers" / "governed_action.py"

for k in list(os.environ):
    if k.startswith("STRIX_"):
        del os.environ[k]

spec = importlib.util.spec_from_file_location("governed_action_hosted", HELPER)
ga = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ga)

traffic = []
_orig = ga._post_json


def _redact(o):
    if isinstance(o, dict):
        return {k: ("<redacted>" if k.lower() in {"apikey", "api_key", "token", "authorization"} else _redact(v))
                for k, v in o.items()}
    if isinstance(o, list):
        return [_redact(x) for x in o]
    return o


def logged(url, body, headers, timeout=5.0):
    entry = {"method": "POST", "url": url, "request_body": _redact(body),
             "sent_authorization_header": "Authorization" in headers,
             "sent_tenant_header": "X-Tenant-Id" in headers}
    t0 = time.time()
    try:
        resp = _orig(url, body, headers, timeout)
    except Exception as e:  # record then re-raise
        entry["error"] = f"{type(e).__name__}: {str(e)[:200]}"
        entry["elapsed_ms"] = int((time.time() - t0) * 1000)
        traffic.append(entry)
        raise
    entry["elapsed_ms"] = int((time.time() - t0) * 1000)
    entry["response"] = _redact(resp)
    traffic.append(entry)
    return resp


ga._post_json = logged

ran = []
CAP = sys.argv[1] if len(sys.argv) > 1 else "payment.charge"
SYNTHETIC_PAYLOAD = {"amount": 1, "currency": "usd", "customer_id": "synthetic-001", "purpose": "validation"}
result, error = None, None
try:
    result = ga.governed_action(
        capability_id=CAP,
        payload=SYNTHETIC_PAYLOAD,
        operation=lambda: ran.append("inert-operation-ran") or {"ok": True},
        actor="validation-harness",
        timeout=15.0,
    )
except Exception as e:  # noqa: BLE001
    error = f"{type(e).__name__}: {e}"

out = {
    "capability_id": CAP,
    "helper": str(HELPER.relative_to(HERE.parents[1])).replace("\\", "/"),
    "strix_env_present": False,
    "operation_ran": bool(ran),
    "error": error,
    "result": {k: (str(v)[:200] if not isinstance(v, (bool, int, type(None))) else v)
               for k, v in (vars(result).items() if result is not None and hasattr(result, "__dict__") else
                            (result._asdict().items() if hasattr(result, "_asdict") else []))},
    "hosts_contacted": sorted({t["url"].split("/")[2] for t in traffic}),
    "paths_called": [t["url"].split("/", 3)[3] for t in traffic],
    "traffic": traffic,
}
evid = HERE / "evidence"
evid.mkdir(exist_ok=True)
(evid / f"traffic-{CAP}.json").write_text(json.dumps(out, indent=2, default=str) + "\n", encoding="utf-8")
print(json.dumps({k: out[k] for k in ("capability_id", "operation_ran", "error", "hosts_contacted", "paths_called", "result")}, indent=2, default=str))
sys.exit(0 if (not error and ran) else 1)
