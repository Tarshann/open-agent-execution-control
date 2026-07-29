"""Demo export adapter for the research.dataset.export capability.

This stands in for whatever mechanism actually moves admitted rows to their
destination in a real deployment — an object-storage upload, a `pg_dump`/
`COPY TO` invocation, an SFTP push, an API call to a partner system. It is
invoked by ``dataset_export_local.governed_export`` as the ``export_fn``
callable, and ONLY after policy evaluation, approval (when required), and
execution-token redemption have all already succeeded — never before.

It writes the rows it's given to a local temporary file rather than
transmitting anything anywhere. Nothing about this adapter is
production-grade, and using it proves nothing about what a real destination
integration would do with the same admitted rows.
"""

from __future__ import annotations

import json
import tempfile
import uuid
from pathlib import Path
from typing import Any


def default_export_adapter(request: dict[str, Any], *, output_dir: Path | None = None) -> dict[str, Any]:
    """``request`` is the plain dict ``governed_export`` builds:
    ``{"rows": [...], "destination_visibility": ..., "destination_id": ...,
    "transform_name": ..., "transform_version": ...}``. Returns a dict
    describing what was written — never raises for a well-formed request."""

    output_dir = Path(output_dir) if output_dir is not None else Path(tempfile.gettempdir()) / "strix-dataset-export-demo"
    output_dir.mkdir(parents=True, exist_ok=True)

    rows = request.get("rows", [])
    out_path = output_dir / f"export-{uuid.uuid4().hex}.json"
    out_path.write_text(
        json.dumps(
            {
                "destinationId": request.get("destination_id"),
                "destinationVisibility": request.get("destination_visibility"),
                "transform": {
                    "name": request.get("transform_name"),
                    "version": request.get("transform_version"),
                },
                "rows": rows,
            },
            indent=2,
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    return {
        "exported_row_ids": [row.get("row_id") for row in rows],
        "destination_id": request.get("destination_id"),
        "output_path": str(out_path),
    }
