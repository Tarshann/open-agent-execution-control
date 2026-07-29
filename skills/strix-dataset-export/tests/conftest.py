"""Shared fixtures for the research.dataset.export test suite.

Mirrors the conventions already established in skills/strix-wire/tests and
skills/strix-onboard/tests: dynamic `importlib.util` module loading (so
tests exercise the exact sibling file, not a package import), a hand-rolled
Spy standing in for the irreversible operation, and tmp_path-isolated
workspaces so no test can see another test's evidence chain or keys.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest

HELPERS = Path(__file__).resolve().parents[1] / "helpers"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


def load_helper_module(name: str, directory: Path = HELPERS):
    path = directory / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"strix_dataset_export_under_test_{name}", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _signing_available() -> bool:
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        Ed25519PrivateKey.generate()
        return True
    except BaseException:  # pyo3 raises a PanicException, not a plain Exception
        return False


requires_signing = pytest.mark.skipif(
    not _signing_available(), reason="cryptography's Ed25519 backend is unusable in this environment"
)


@pytest.fixture(scope="session")
def core_mod():
    return load_helper_module("dataset_export_local")


@pytest.fixture(scope="session")
def adapter_mod():
    return load_helper_module("export_adapter")


@pytest.fixture(scope="session")
def fixtures_mod():
    return load_helper_module("synthetic_rows", directory=FIXTURES)


@pytest.fixture()
def synthetic_rows(fixtures_mod):
    return fixtures_mod.load_synthetic_rows()


class Spy:
    """Stands in for the export side effect. Records every call it receives
    and never actually exports anything."""

    def __init__(self) -> None:
        self.calls = 0
        self.received: list[dict[str, Any]] = []

    def __call__(self, request: dict[str, Any]) -> dict[str, Any]:
        self.calls += 1
        self.received.append(request)
        return {"exported_row_ids": [row.get("row_id") for row in request.get("rows", [])]}


@pytest.fixture()
def spy() -> Spy:
    return Spy()


def evidence_files(state_dir: Path) -> list[Path]:
    evidence_dir = state_dir / "evidence"
    if not evidence_dir.exists():
        return []
    return sorted(evidence_dir.glob("*.json"))


def token_files(state_dir: Path) -> list[Path]:
    tokens_dir = state_dir / "dataset-export" / "tokens"
    if not tokens_dir.exists():
        return []
    return sorted(tokens_dir.glob("*.json"))


def read_chain(state_dir: Path) -> list[dict[str, Any]]:
    chain_path = state_dir / "evidence" / "receipts.jsonl"
    if not chain_path.exists():
        return []
    records = []
    for line in chain_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records
