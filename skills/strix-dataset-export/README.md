# strix-dataset-export

A governed `research.dataset.export` capability: data-classification-aware
policy, a distinct-approver approval gate, a payload-bound single-use
execution token, a signed hash-chained evidence receipt, offline
verification, and a Merkle-proof selective-disclosure fixture — all local,
offline, and self-contained in this one skill directory.

## What this proves

> Strix can refuse a protected-content transfer to an external destination
> before it executes, and leave a verifiable record of exactly what was
> barred and why.

## What this does NOT prove

- That Strix would have caught any particular real-world upload — the
  detection mechanism for *finding* a call site is out of scope here (see
  `skills/strix-wire` for that).
- That it prevents data breaches generally.
- That a signed receipt makes a transfer lawful.
- That the `safe-harbor-v1` demo transform performed de-identification
  correctly, or meets any legal/regulatory standard.

See `SKILL.md` for the full non-claims list and `ARCHITECTURE.md` §10 for
the threat model this receipt actually supports.

## Quick start

```python
import sys
from pathlib import Path

HELPERS = Path("skills/strix-dataset-export/helpers")
sys.path.insert(0, str(HELPERS))
sys.path.insert(0, str(Path("skills/strix-dataset-export/fixtures")))

from dataset_export_local import governed_export, DESTINATION_CROSS_PARTY, SAFE_HARBOR_V1_NAME, SAFE_HARBOR_V1_VERSION
from export_adapter import default_export_adapter
from synthetic_rows import load_synthetic_rows

result = governed_export(
    load_synthetic_rows(),
    destination_visibility=DESTINATION_CROSS_PARTY,
    destination_id="partner-hospital-b",
    requester_id="alice@requester",
    export_fn=default_export_adapter,
    approver_id="bob@approver",
    approval_granted=True,
    transform_name=SAFE_HARBOR_V1_NAME,
    transform_version=SAFE_HARBOR_V1_VERSION,
    workspace_root=Path("."),
)

print(result.record["payload"])
```

## Files

- `helpers/dataset_export_local.py` — the governed capability: policy,
  approval, execution token, Merkle/selective-disclosure, receipt build +
  sign + chain, offline verification. Fully self-contained (only depends on
  the `cryptography` package).
- `helpers/export_adapter.py` — a demo export adapter (writes to a temp
  file); stands in for a real destination integration.
- `fixtures/synthetic_rows.py` — the four synthetic rows used by the
  acceptance scenarios (2 PHI, 1 internal aggregate, 1 unlabelled).
- `tests/` — the full acceptance + negative-path suite (see `SKILL.md`
  "Contract tests").
- `ARCHITECTURE.md` — the full design write-up.
- `GATE-REPORT.md` — a structured governance-review report for this build,
  with an explicit caveat about which Gate letters have a canonical
  definition in this repository and which don't.

## Running the tests

```bash
python -m pytest skills/strix-dataset-export/tests -q
```

Requires the `cryptography` package (`pip install cryptography`) for the
signing-dependent tests; tests that don't need signing still run without it.
