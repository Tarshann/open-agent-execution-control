"""Synthetic fixture rows for the research.dataset.export acceptance scenarios.

Every value is a fabricated placeholder (prefixed ``SYN-``) — nothing here is
real patient data. The four rows exist to exercise the four classification
outcomes the policy in ``helpers/dataset_export_local.py`` must distinguish:
two PHI rows (a medical-record identifier, a date of birth, and an
orthopedic diagnosis detail — the kind of row-level identifiers Safe-Harbor-
style de-identification exists to strip), one internal aggregate row (cohort
statistics with no row-level identifier), and one row with no classification
tag at all, standing in for data nobody remembered to label.
"""

from __future__ import annotations

import copy
from typing import Any

ROWS: list[dict[str, Any]] = [
    {
        "row_id": "row-001",
        "classification": "PHI",
        "fields": {
            "mrn": "SYN-MRN-0001",
            "dob": "SYN-1980-01-01",
            "diagnosis": "SYN-orthopedic-fracture-detail",
        },
    },
    {
        "row_id": "row-002",
        "classification": "PHI",
        "fields": {
            "mrn": "SYN-MRN-0002",
            "dob": "SYN-1975-06-15",
            "diagnosis": "SYN-orthopedic-joint-detail",
        },
    },
    {
        "row_id": "row-003",
        "classification": "INTERNAL_AGGREGATE",
        "fields": {
            "cohort_size": 42,
            "mean_age": 51.2,
        },
    },
    {
        "row_id": "row-004",
        # Deliberately unlabelled: no classification was ever assigned to
        # this row. The policy engine must treat an absent/unknown label as
        # protected (fail closed), not as "safe by default."
        "classification": None,
        "fields": {
            "value": "SYN-UNTAGGED-0004",
        },
    },
]


def load_synthetic_rows() -> list[dict[str, Any]]:
    """Return a deep copy of the fixture rows.

    Callers (including tests) must never mutate the shared ``ROWS`` list in
    place — each call gets its own copy so one test's tampering can't leak
    into another.
    """

    return copy.deepcopy(ROWS)
