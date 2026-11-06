#!/usr/bin/env python3
"""Score `solo govern scan` against a hand-labelled fixture.

Usage:  python run.py /path/to/solo[.exe]

The fixture is copied to a temp dir that is NOT inside a git repo, because
`--root DIR` inside a git checkout resolved to the enclosing repo root in 0.4.1.
Ground truth is hand-labelled below: every line that is a consequential action
in the fixture, grouped by whether the scanner claims to support that language.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
FIXTURE = HERE / "fixture-repo"

# (relative file, line) -> label. Lines are 1-based.
POSITIVE = {  # supported-language, directly called, should be found
    ("positive/payments.py", 5): "payment (stripe PaymentIntent.create)",
    ("positive/payments.py", 9): "payment (stripe Refund.create)",
    ("positive/files_and_db.py", 8): "file delete (shutil.rmtree)",
    ("positive/files_and_db.py", 12): "file delete (os.remove)",
    ("positive/files_and_db.py", 17): "db delete (cursor.execute DELETE)",
    ("positive/files_and_db.py", 22): "process exec (subprocess.run shell=True)",
    ("positive/outbound.py", 7): "email send (smtplib sendmail)",
    ("positive/outbound.py", 11): "outbound write (requests.post)",
    ("positive/service.ts", 7): "payment (stripe.charges.create)",
    ("positive/service.ts", 11): "file delete (fs.rmSync)",
    ("positive/service.ts", 15): "outbound write (fetch POST)",
    ("positive/ai_calls.py", 6): "AI call (anthropic messages.create)",
    ("positive/ai_calls.py", 10): "AI call (openai chat.completions.create)",
}
UNSUPPORTED = {  # languages / patterns outside the documented pattern set
    ("unsupported/cleanup.go", 9): "go os.RemoveAll",
    ("unsupported/cleanup.go", 11): "go http.Post",
    ("unsupported/Cleanup.java", 4): "java Files.delete",
    ("unsupported/cleanup.rb", 2): "ruby File.delete",
    ("unsupported/cleanup.sh", 2): "shell rm -rf",
    ("unsupported/cleanup.sh", 3): "shell curl -X POST",
    ("unsupported/migration.sql", 1): "sql DROP TABLE",
    ("unsupported/migration.sql", 2): "sql DELETE FROM",
    ("unsupported/indirect.py", 7): "python aliased call (rm = shutil.rmtree; rm(p))",
    ("unsupported/indirect.py", 11): "python dynamic dispatch (getattr)",
}


def main() -> int:
    solo = sys.argv[1] if len(sys.argv) > 1 else "solo"
    tmp = Path(tempfile.mkdtemp(prefix="solo-govern-fixture-"))
    work = tmp / "repo"
    shutil.copytree(FIXTURE, work)
    env = {**os.environ, "PYTHONUTF8": "1"}
    ver = subprocess.run([solo, "--version"], capture_output=True, text=True, env=env).stdout.strip()
    r = subprocess.run(
        [solo, "govern", "scan", "--include-ai", "--json", "--limit", "500"],
        cwd=work, capture_output=True, text=True, env=env,
    )
    scan = json.loads(r.stdout)
    hits = {(c["file"].replace("\\", "/"), c["line"]): c for c in scan["candidates"]}

    def table(group):
        rows = []
        for (f, ln), label in group.items():
            c = hits.get((f, ln))
            rows.append({"file": f, "line": ln, "what": label, "detected": c is not None,
                         "capability_id": c["capability_id"] if c else None})
        return rows

    pos, uns = table(POSITIVE), table(UNSUPPORTED)
    labelled = set(POSITIVE) | set(UNSUPPORTED)
    unlabelled_hits = [{"file": f, "line": ln, "capability_id": c["capability_id"], "snippet": c["snippet"].strip()}
                       for (f, ln), c in sorted(hits.items()) if (f, ln) not in labelled]
    negative_hits = [h for h in unlabelled_hits if h["file"].startswith("negative/")]
    out = {
        "solo_version": ver, "exit_code": r.returncode, "scan_ok": scan.get("ok"),
        "positive": {"total": len(pos), "detected": sum(x["detected"] for x in pos), "rows": pos},
        "unsupported": {"total": len(uns), "detected": sum(x["detected"] for x in uns), "rows": uns,
                        "scan_reported_ok_despite_misses": scan.get("ok") is True},
        "negative_dir_false_positives": negative_hits,
        "unlabelled_hits_outside_ground_truth": unlabelled_hits,
    }
    evid = HERE / "evidence"
    evid.mkdir(exist_ok=True)
    (evid / "results.json").write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    print(ver)
    print(f"positive (supported, direct):  {out['positive']['detected']}/{out['positive']['total']} detected")
    for x in pos:
        if not x["detected"]:
            print(f"   MISSED  {x['file']}:{x['line']}  {x['what']}")
    print(f"unsupported/indirect:          {out['unsupported']['detected']}/{out['unsupported']['total']} detected")
    print(f"negative-dir false positives:  {len(negative_hits)}")
    print(f"other hits not in ground truth: {len(unlabelled_hits)}")
    for h in unlabelled_hits:
        print(f"   {h['file']}:{h['line']}  {h['capability_id']}  {h['snippet'][:60]}")
    shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
