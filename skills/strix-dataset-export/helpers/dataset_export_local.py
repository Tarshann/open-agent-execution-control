"""Local Mode helper for the `research.dataset.export` capability — offline,
zero-account, zero-hosted-dependency, self-contained (this one file has no
import of anything outside the Python standard library plus `cryptography`).

This is a NEW capability, not an extension of `/strix-wire`'s existing
`data.export` pattern-scanner entry — it adds two things that do not exist
anywhere else in this repository: (1) a data-classification-aware policy
(PHI / internal-aggregate / unlabelled, fail-closed on anything unrecognized)
gating a *cross-party* export distinctly from an *internal* one, and (2) a
minted, payload-bound, single-use execution token that must be redeemed
before the export side effect runs. Everything cryptographic below —
canonical-JSON hashing, Ed25519 signing, the local key registry, the
hash-chained receipt ledger — reuses the exact algorithm and on-disk layout
`skills/strix-wire/helpers/governed_action_local.py` already established
(vendored here, not imported, per this repo's house style of self-contained,
copyable helper files), so a workspace that already ran `/strix-wire` keeps
one signing key and one evidence chain, not two.

The flow, spelled out completely:

  1. **normalize**  — hash the exact row set being evaluated (`inputHash`),
                       and a separate digest of only the classification tags
                       (`classification_digest`) bound into the token below.
  2. **evaluate**   — `evaluate_export_policy()` decides, per row, ADMIT or
                       BAR, and whether the export as a whole counts as
                       de-identified. Zero admitted rows raises before
                       anything else happens — the adapter is never reached.
  3. **approve**    — no-op for an INTERNAL destination. For CROSS_PARTY,
                       `evaluate_approval()` requires an explicit
                       `approval_granted=True` from a named `approver_id`
                       that is NOT the `requester_id` — self-approval is
                       refused even if `approval_granted` is true.
  4. **mint**       — `mint_execution_token()` issues a token bound to the
                       payload hash, destination, declared transform, and
                       classification digest, with an expiry.
  5. **redeem**     — `redeem_execution_token()` must succeed, recomputing
                       that same binding — if the payload, destination,
                       transform, or classification changed since minting
                       (i.e. the token file or the request was edited), the
                       binding hash no longer matches and redemption fails.
                       This is the ONLY gate between "approved" and
                       "executed"; there is no lower-level path to the
                       export adapter that skips it.
  6. **execute**    — call the caller-supplied `export_fn` at most once,
                       with only the admitted (and, if applicable,
                       de-identified) rows.
  7. **record**     — build a signed, hash-chained receipt (see the field
                       list on `_build_receipt_payload`) and append it to
                       `<state_dir>/evidence/receipts.jsonl`.

**What a receipt proves, precisely — read before treating one as more than
this.** A receipt from this helper is a `LOCAL_MACHINE_ASSERTION`: it proves
the holder of a specific local Ed25519 key produced a hash-chained,
tamper-evident record of one policy evaluation and (if it proceeded) one
executed export. It does **not** prove: that the `safe-harbor-v1` transform
meets any legal or regulatory de-identification standard (see its docstring
below); that a signed receipt makes the underlying transfer lawful; that the
scanned/declared row classifications were themselves correct; or that a
disclosed subset of rows (see `build_selective_disclosure`) is the complete
row set — every receipt carries a literal `completeness: "NOT_PROVEN"` field
for exactly this reason.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CAPABILITY_ID = "research.dataset.export"
RECORD_MODE = "DATASET_EXPORT_LOCAL_SIGNED_V1"
SCHEMA_VERSION = "dataset-export-receipt-v1"
DEFAULT_STATE_DIR = ".strix"
RUNTIME_VERSION = "strix-dataset-export-local-helper/1.0.0"

POLICY_ID = "research-dataset-export-policy-v1"
POLICY_VERSION = 1
COMPLETENESS_CLAIM = "NOT_PROVEN"

DESTINATION_INTERNAL = "INTERNAL"
DESTINATION_CROSS_PARTY = "CROSS_PARTY"
_DESTINATIONS = (DESTINATION_INTERNAL, DESTINATION_CROSS_PARTY)

DEFAULT_TOKEN_TTL_SECONDS = 300  # 5 minutes — matches this project's existing approval-window convention


class Classification:
    """Known classification tags. Anything NOT in
    ``NOT_PROTECTED_CLASSIFICATIONS`` — including ``None``, an empty string,
    or a string nobody has seen before — is protected. This is an allow-list
    of exactly one entry, deliberately: adding a new "safe" classification
    must be a conscious, reviewed edit to this module, never an emergent
    property of "we didn't bar it."
    """

    PHI = "PHI"
    INTERNAL_AGGREGATE = "INTERNAL_AGGREGATE"


NOT_PROTECTED_CLASSIFICATIONS = frozenset({Classification.INTERNAL_AGGREGATE})

SAFE_HARBOR_V1_NAME = "safe-harbor-v1"
SAFE_HARBOR_V1_VERSION = 1

REASON_CODE_TEXT = {
    "PHI_PROTECTED_NO_DEIDENTIFY_TRANSFORM": (
        "row is classified PHI and no declared de-identify transform was applied to this cross-party export"
    ),
    "UNLABELLED_FAILS_CLOSED_AS_PROTECTED": (
        "row carries no classification tag; unlabelled data fails closed as protected, it is never treated as safe by default"
    ),
    "UNKNOWN_CLASSIFICATION_FAILS_CLOSED_AS_PROTECTED": (
        "row classification is not a recognized not-protected category; unrecognized classifications fail closed as protected"
    ),
    "UNREGISTERED_DEIDENTIFY_TRANSFORM": (
        "a de-identify transform was declared but is not registered; treated the same as if none had been declared"
    ),
}


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class StrixDatasetExportError(RuntimeError):
    """Base class for any research.dataset.export governance failure."""


class StrixDatasetExportPolicyDenied(StrixDatasetExportError):
    """Every row was barred — zero rows admitted. The export adapter was NOT invoked."""


class StrixDatasetExportApprovalRequired(StrixDatasetExportError):
    """A cross-party export requires an explicit, distinct-approver grant that was not present. NOT executed."""


class StrixDatasetExportSelfApprovalDenied(StrixDatasetExportError):
    """The named approver is the same identity as the requester. Refused regardless of the granted flag."""


class StrixDatasetExportTokenMissing(StrixDatasetExportError):
    """No execution token exists for the given token_id."""


class StrixDatasetExportTokenExpired(StrixDatasetExportError):
    """The execution token's time-to-live has elapsed."""


class StrixDatasetExportTokenAlreadyRedeemed(StrixDatasetExportError):
    """The execution token was already consumed once (single-use, replay refused)."""


class StrixDatasetExportTokenSignatureInvalid(StrixDatasetExportError):
    """The execution token's own signature does not verify, so the record was
    edited after minting. Raised before ``status`` or ``expiresAt`` are trusted,
    since those two fields carry the single-use and time-limit properties and are
    otherwise just text in a local file."""


class StrixDatasetExportTokenBindingMismatch(StrixDatasetExportError):
    """The payload, destination, transform, or classification bound into the
    token no longer matches what's being redeemed against — the token file
    (or the request) was edited after issuance, which voids it."""


class StrixDatasetExportKeyError(StrixDatasetExportError):
    """The local signing key is missing, corrupt, or mismatched — or the
    `cryptography` package is not installed. Never silently unsigned."""


class StrixDatasetExportReceiptPersistenceError(StrixDatasetExportError):
    """The export ran but the receipt could not be persisted durably."""


# ---------------------------------------------------------------------------
# Canonical bytes / hashing — byte-identical algorithm to
# skills/strix-wire/helpers/governed_action_local.py's `_canonicalize`
# ---------------------------------------------------------------------------


def _canonicalize(obj: Any) -> bytes:
    return json.dumps(
        obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")


def _hash_canonical(obj: Any) -> str:
    return hashlib.sha256(_canonicalize(obj)).hexdigest()


def _iso_from(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _iso_now() -> str:
    return _iso_from(datetime.now(timezone.utc))


def _parse_iso(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def _require_cryptography():
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
            Ed25519PublicKey,
        )
    except ModuleNotFoundError as exc:  # pragma: no cover - environment-dependent
        raise StrixDatasetExportKeyError(
            "the 'cryptography' package is required for signing research.dataset.export "
            "receipts (pip install cryptography). This helper never falls back to an "
            "unsigned record when it's missing."
        ) from exc
    return Ed25519PrivateKey, Ed25519PublicKey


# ---------------------------------------------------------------------------
# Local key manager — same registry file/shape as strix-wire Local Mode, so
# one workspace shares one signing key across capabilities.
# ---------------------------------------------------------------------------


class LocalSigningKey:
    __slots__ = ("created_at", "kid", "private_key_hex", "public_key_fingerprint", "public_key_hex")

    def __init__(
        self, kid: str, private_key_hex: str, public_key_hex: str, public_key_fingerprint: str, created_at: str
    ) -> None:
        self.kid = kid
        self.private_key_hex = private_key_hex
        self.public_key_hex = public_key_hex
        self.public_key_fingerprint = public_key_fingerprint
        self.created_at = created_at

    def __repr__(self) -> str:  # pragma: no cover - defensive: never print the key
        return f"LocalSigningKey(kid={self.kid!r})"


def _fingerprint(pub_bytes: bytes) -> str:
    return hashlib.sha256(pub_bytes).hexdigest()


def _kid_for(pub_bytes: bytes) -> str:
    return f"local-{_fingerprint(pub_bytes)[:16]}"


def resolve_public_key(state_dir: Path, kid: str) -> bytes | None:
    """Offline lookup used by verification — never trusts anything but the
    registry file on disk. Returns ``None`` for an unknown kid."""
    registry_path = state_dir / "keys" / "registry.json"
    if not registry_path.exists():
        return None
    try:
        data = json.loads(registry_path.read_text(encoding="utf-8"))
    except ValueError:
        return None
    meta = data.get("keys", {}).get(kid)
    if not meta or not meta.get("publicKeyHex"):
        return None
    try:
        return bytes.fromhex(meta["publicKeyHex"])
    except ValueError:
        return None


def generate_or_load_key(state_dir: Path) -> LocalSigningKey:
    """Idempotent: return the existing current key, generating one (and a
    ``.gitignore`` for the private key files) on first run. Raises
    :class:`StrixDatasetExportKeyError` on any corruption or mismatch rather
    than silently regenerating — a tampered/deleted key file is a fault."""
    Ed25519PrivateKey, _ = _require_cryptography()
    keys_dir = state_dir / "keys"
    registry_path = keys_dir / "registry.json"

    if registry_path.exists():
        try:
            data = json.loads(registry_path.read_text(encoding="utf-8"))
        except ValueError as exc:
            raise StrixDatasetExportKeyError(f"corrupt key registry at {registry_path}: {exc}") from exc
        kid = data.get("currentKid")
        if kid:
            meta = data.get("keys", {}).get(kid)
            if meta is None:
                raise StrixDatasetExportKeyError(f"registry names current kid {kid!r} but has no metadata for it")
            key_path = keys_dir / f"{kid}.key"
            if not key_path.exists():
                raise StrixDatasetExportKeyError(
                    f"private key file missing for kid {kid!r} at {key_path} — it was deleted or moved."
                )
            raw = key_path.read_text(encoding="utf-8").strip()
            try:
                priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(raw))
            except Exception as exc:  # noqa: BLE001
                raise StrixDatasetExportKeyError(f"private key file for kid {kid!r} is corrupt or invalid: {exc}") from exc
            pub_hex = priv.public_key().public_bytes_raw().hex()
            if pub_hex != meta.get("publicKeyHex"):
                raise StrixDatasetExportKeyError(
                    f"private key file for kid {kid!r} does not match its registry public key — possible tamper."
                )
            return LocalSigningKey(kid, raw, pub_hex, _fingerprint(bytes.fromhex(pub_hex)), str(meta.get("createdAt", "")))

    priv = Ed25519PrivateKey.generate()
    priv_hex = priv.private_bytes_raw().hex()
    pub_hex = priv.public_key().public_bytes_raw().hex()
    kid = _kid_for(bytes.fromhex(pub_hex))
    created_at = _iso_now()

    keys_dir.mkdir(parents=True, exist_ok=True)
    key_path = keys_dir / f"{kid}.key"
    key_path.write_text(priv_hex, encoding="utf-8")
    try:
        os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # 0600
    except OSError:
        warnings.warn(f"could not set restrictive (0600) permissions on {key_path}", stacklevel=2)

    data = {
        "currentKid": kid,
        "keys": {
            kid: {
                "publicKeyHex": pub_hex,
                "publicKeyFingerprint": _fingerprint(bytes.fromhex(pub_hex)),
                "createdAt": created_at,
                "status": "active",
                "algorithm": "ed25519",
            }
        },
    }
    if registry_path.exists():
        try:
            existing = json.loads(registry_path.read_text(encoding="utf-8"))
            existing.setdefault("keys", {}).update(data["keys"])
            existing["currentKid"] = kid
            data = existing
        except ValueError:
            pass
    tmp = registry_path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(registry_path)

    gitignore = keys_dir / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text("*.key\n", encoding="utf-8")

    return LocalSigningKey(kid, priv_hex, pub_hex, _fingerprint(bytes.fromhex(pub_hex)), created_at)


def _sign(payload: Mapping[str, Any], key: LocalSigningKey) -> dict[str, Any]:
    Ed25519PrivateKey, _ = _require_cryptography()
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key.private_key_hex))
    signature = priv.sign(_canonicalize(dict(payload))).hex()
    return {"payload": dict(payload), "signature": signature}


# ---------------------------------------------------------------------------
# Hash-chained receipt ledger — same file layout as strix-wire Local Mode:
# <state_dir>/evidence/receipts.jsonl (+ one exported file per evidenceId).
# ---------------------------------------------------------------------------


def _chain_paths(state_dir: Path) -> tuple[Path, Path]:
    evidence_dir = state_dir / "evidence"
    return evidence_dir, evidence_dir / "receipts.jsonl"


def _last_hash_and_seq(chain_path: Path) -> tuple[str | None, int]:
    """``seq`` counts every non-blank physical line, including one that fails
    to parse, so a newly minted receipt can never collide with a chain slot
    that already exists on disk. ``last_hash`` only updates from a line that
    both parses and carries a real ``evidenceHash``."""
    if not chain_path.exists():
        return None, 0
    last_hash: str | None = None
    seq = 0
    for line in chain_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        seq += 1
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        payload = entry.get("payload") if isinstance(entry, dict) else None
        evidence_hash = payload.get("evidenceHash") if isinstance(payload, dict) else None
        if evidence_hash:
            last_hash = evidence_hash
    return last_hash, seq


def _append_and_export(state_dir: Path, record: Mapping[str, Any]) -> Path:
    evidence_dir, chain_path = _chain_paths(state_dir)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    with chain_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
    evidence_id = record["payload"]["evidenceId"]
    single_path = evidence_dir / f"{evidence_id}.json"
    single_path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return single_path


# ---------------------------------------------------------------------------
# Classification / policy engine
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BarredRow:
    row_id: str
    reason_code: str
    reason: str


@dataclass(frozen=True)
class PolicyDecision:
    admitted_row_ids: list[str]
    barred: list[BarredRow]
    deidentified: bool
    decision_outcome: str  # "ADMIT_ALL" | "ADMIT_PARTIAL" | "ADMIT_NONE"
    policy_id: str
    policy_version: int
    policy_hash: str


#: (name, version) -> callable(row) -> row. A transform is applied per-row;
#: rows outside the classifications it actually masks pass through
#: unchanged by that transform (see `_apply_safe_harbor_v1`).
_TRANSFORMS: dict[tuple[str, int], Callable[[dict[str, Any]], dict[str, Any]]] = {}


def _apply_safe_harbor_v1(row: Mapping[str, Any]) -> dict[str, Any]:
    """A deterministic TEST transform for this fixture only.

    It does NOT implement, certify, or claim conformance with the HIPAA
    Safe Harbor method, and it does not prove that de-identification was
    performed correctly. It is deterministic — same input, same output — so
    receipts built from it are reproducible, nothing more.

    For a row classified PHI, it replaces the two direct-identifier fields
    this fixture uses (`mrn`, `dob`) with a fixed masked placeholder and
    leaves every other field alone. Rows of any other classification are
    returned unchanged, since this fixture places no direct identifiers on
    them.
    """

    result = dict(row)
    if row.get("classification") != Classification.PHI:
        result["fields"] = dict(row.get("fields", {}))
        return result
    masked_fields = dict(row.get("fields", {}))
    for identifying_field in ("mrn", "dob"):
        if identifying_field in masked_fields:
            masked_fields[identifying_field] = "SYN-DEIDENTIFIED"
    result["fields"] = masked_fields
    return result


_TRANSFORMS[(SAFE_HARBOR_V1_NAME, SAFE_HARBOR_V1_VERSION)] = _apply_safe_harbor_v1


def _policy_hash() -> str:
    return _hash_canonical(
        {
            "policyId": POLICY_ID,
            "policyVersion": POLICY_VERSION,
            "notProtectedClassifications": sorted(NOT_PROTECTED_CLASSIFICATIONS),
            "registeredTransforms": sorted(f"{name}:{version}" for (name, version) in _TRANSFORMS),
        }
    )


def policy_ref() -> dict[str, Any]:
    return {"policyId": POLICY_ID, "policyVersion": POLICY_VERSION, "policyHash": _policy_hash()}


def _reason_for_barred_row(classification: Any, *, transform_declared_but_unregistered: bool) -> tuple[str, str]:
    if transform_declared_but_unregistered:
        code = "UNREGISTERED_DEIDENTIFY_TRANSFORM"
    elif classification is None:
        code = "UNLABELLED_FAILS_CLOSED_AS_PROTECTED"
    elif classification == Classification.PHI:
        code = "PHI_PROTECTED_NO_DEIDENTIFY_TRANSFORM"
    else:
        code = "UNKNOWN_CLASSIFICATION_FAILS_CLOSED_AS_PROTECTED"
    return code, REASON_CODE_TEXT[code]


def evaluate_export_policy(
    rows: Sequence[Mapping[str, Any]],
    *,
    destination_visibility: str,
    transform_name: str | None = None,
    transform_version: int | None = None,
) -> PolicyDecision:
    """The policy rule, in full:

    - ``INTERNAL`` destination: every row is admitted regardless of
      classification. Nothing is barred, nothing is de-identified.
    - ``CROSS_PARTY`` destination, no *registered* transform declared:
      protected rows (PHI, unlabelled, or any classification not on the
      not-protected allow-list) are barred with a specific reason; rows on
      the not-protected allow-list are admitted as-is.
    - ``CROSS_PARTY`` destination with a registered transform declared:
      every row is admitted and the export as a whole is marked
      ``deidentified=True``.
    """

    if destination_visibility not in _DESTINATIONS:
        raise ValueError(f"unknown destination_visibility {destination_visibility!r}; expected one of {_DESTINATIONS}")

    if destination_visibility == DESTINATION_INTERNAL:
        admitted = [row["row_id"] for row in rows]
        return PolicyDecision(
            admitted_row_ids=admitted,
            barred=[],
            deidentified=False,
            decision_outcome="ADMIT_ALL",
            policy_id=POLICY_ID,
            policy_version=POLICY_VERSION,
            policy_hash=_policy_hash(),
        )

    transform_declared = transform_name is not None or transform_version is not None
    transform_registered = (transform_name, transform_version) in _TRANSFORMS

    if transform_declared and transform_registered:
        admitted = [row["row_id"] for row in rows]
        return PolicyDecision(
            admitted_row_ids=admitted,
            barred=[],
            deidentified=True,
            decision_outcome="ADMIT_ALL",
            policy_id=POLICY_ID,
            policy_version=POLICY_VERSION,
            policy_hash=_policy_hash(),
        )

    admitted = []
    barred: list[BarredRow] = []
    for row in rows:
        classification = row.get("classification")
        if classification in NOT_PROTECTED_CLASSIFICATIONS:
            admitted.append(row["row_id"])
            continue
        reason_code, reason_text = _reason_for_barred_row(
            classification, transform_declared_but_unregistered=transform_declared and not transform_registered
        )
        barred.append(BarredRow(row_id=row["row_id"], reason_code=reason_code, reason=reason_text))

    if not admitted:
        outcome = "ADMIT_NONE"
    elif barred:
        outcome = "ADMIT_PARTIAL"
    else:
        outcome = "ADMIT_ALL"

    return PolicyDecision(
        admitted_row_ids=admitted,
        barred=barred,
        deidentified=False,
        decision_outcome=outcome,
        policy_id=POLICY_ID,
        policy_version=POLICY_VERSION,
        policy_hash=_policy_hash(),
    )


# ---------------------------------------------------------------------------
# Approval gate — a named approver distinct from the requester, required
# only for CROSS_PARTY. Strict boolean, not truthiness (mirrors strix-wire's
# `approval_granted is not True` gate).
# ---------------------------------------------------------------------------


def evaluate_approval(
    *, destination_visibility: str, requester_id: str, approver_id: str | None, approval_granted: bool
) -> None:
    if destination_visibility != DESTINATION_CROSS_PARTY:
        return  # INTERNAL exports require no approval

    if not requester_id:
        raise ValueError("requester_id is required")

    if approver_id is not None and approver_id == requester_id:
        # Checked before the granted check so self-approval is never masked
        # by a coincidentally-True grant.
        raise StrixDatasetExportSelfApprovalDenied(
            f"approver_id {approver_id!r} must be distinct from requester_id {requester_id!r} for a cross-party export"
        )

    if approval_granted is not True or not approver_id:
        raise StrixDatasetExportApprovalRequired(
            "cross-party research.dataset.export requires an explicit approval_granted=True "
            "from a named approver_id distinct from the requester"
        )


# ---------------------------------------------------------------------------
# Execution token — mint, bind, expire, single-use, redeem. Net-new
# primitive: no execution-token concept exists anywhere else in this repo.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ExecutionToken:
    token_id: str
    issued_at: str
    expires_at: str
    binding_hash: str


def classification_digest(rows: Sequence[Mapping[str, Any]]) -> str:
    """Canonical hash of the ``{row_id, classification}`` snapshot actually
    evaluated by policy, bound into the execution token independently of the
    payload hash — so a run that swaps a row's classification tag (without
    changing anything else about the payload) still invalidates the token.
    """

    snapshot = sorted(
        ({"rowId": row["row_id"], "classification": row.get("classification")} for row in rows),
        key=lambda entry: entry["rowId"],
    )
    return _hash_canonical(snapshot)


def _binding_hash(
    *,
    payload_hash: str,
    destination_visibility: str,
    destination_id: str,
    transform_name: str | None,
    transform_version: int | None,
    classification_digest: str,
) -> str:
    return _hash_canonical(
        {
            "payloadHash": payload_hash,
            "destinationVisibility": destination_visibility,
            "destinationId": destination_id,
            "transformName": transform_name,
            "transformVersion": transform_version,
            "classificationDigest": classification_digest,
        }
    )


def _token_path(state_dir: Path, token_id: str) -> Path:
    return state_dir / "dataset-export" / "tokens" / f"{token_id}.json"


def _token_signing_payload(record: Mapping[str, Any]) -> dict[str, Any]:
    """Everything in the token record except its own signature.

    Deliberately the whole record rather than a chosen subset: ``bindingHash``
    already covers the request, but ``status``, ``expiresAt``, ``tokenId`` and
    ``signingKeyId`` are what carry single-use, the time limit, and identity.
    Signing the record wholesale means a new field cannot be added later that
    silently sits outside the protected set.
    """

    return {k: v for k, v in record.items() if k != "signature"}


def _sign_token_record(record: Mapping[str, Any], key: LocalSigningKey) -> str:
    Ed25519PrivateKey, _ = _require_cryptography()
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(key.private_key_hex))
    return priv.sign(_canonicalize(_token_signing_payload(record))).hex()


def _verify_token_record(record: Mapping[str, Any], state_dir: Path, token_id: str) -> None:
    """Fail closed: a token with no signature, an unknown key, or a signature
    that does not verify is refused before any of its fields are believed."""

    signature_hex = record.get("signature")
    kid = record.get("signingKeyId")
    if not signature_hex or not kid:
        raise StrixDatasetExportTokenSignatureInvalid(
            f"execution token {token_id!r} carries no signature — an unsigned token record "
            "cannot be trusted about its own status or expiry"
        )
    pub_bytes = resolve_public_key(state_dir, kid)
    if pub_bytes is None:
        raise StrixDatasetExportTokenSignatureInvalid(
            f"execution token {token_id!r} is signed by unknown key {kid!r} — not in this "
            "project's local key registry"
        )
    try:
        _, Ed25519PublicKey = _require_cryptography()
        Ed25519PublicKey.from_public_bytes(pub_bytes).verify(
            bytes.fromhex(signature_hex), _canonicalize(_token_signing_payload(record))
        )
    except StrixDatasetExportError:
        raise
    except Exception as exc:  # noqa: BLE001 - any failure means "do not trust this record"
        raise StrixDatasetExportTokenSignatureInvalid(
            f"execution token {token_id!r} signature does not verify — the record was edited "
            "after it was minted (status, expiry, and binding are all covered)"
        ) from exc


def mint_execution_token(
    *,
    payload_hash: str,
    destination_visibility: str,
    destination_id: str,
    transform_name: str | None,
    transform_version: int | None,
    classification_digest: str,
    state_dir: Path,
    ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
) -> ExecutionToken:
    token_id = f"dsx_tok_{uuid.uuid4().hex}"
    issued_at = datetime.now(timezone.utc)
    expires_at = issued_at + timedelta(seconds=ttl_seconds)
    binding_hash = _binding_hash(
        payload_hash=payload_hash,
        destination_visibility=destination_visibility,
        destination_id=destination_id,
        transform_name=transform_name,
        transform_version=transform_version,
        classification_digest=classification_digest,
    )
    key = generate_or_load_key(state_dir)
    record = {
        "tokenId": token_id,
        "status": "MINTED",
        "issuedAt": _iso_from(issued_at),
        "expiresAt": _iso_from(expires_at),
        "bindingHash": binding_hash,
        "signingKeyId": key.kid,
    }
    # Sign the record itself, not just the request it is bound to. bindingHash
    # already ties the token to the payload/destination/transform; the signature
    # is what makes status and expiresAt tamper-evident too.
    record["signature"] = _sign_token_record(record, key)
    path = _token_path(state_dir, token_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return ExecutionToken(
        token_id=token_id, issued_at=record["issuedAt"], expires_at=record["expiresAt"], binding_hash=binding_hash
    )


def redeem_execution_token(
    token_id: str,
    *,
    payload_hash: str,
    destination_visibility: str,
    destination_id: str,
    transform_name: str | None,
    transform_version: int | None,
    classification_digest: str,
    state_dir: Path,
    now: datetime | None = None,
) -> None:
    """Single dispatch point for token redemption, so every failure mode —
    missing, replayed, expired, or tampered — is proven through this one
    function. On success the token file is rewritten ``status=REDEEMED`` and
    can never be redeemed again."""

    now = now or datetime.now(timezone.utc)
    path = _token_path(state_dir, token_id)
    if not path.exists():
        raise StrixDatasetExportTokenMissing(f"no execution token found for token_id {token_id!r}")

    try:
        record = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        raise StrixDatasetExportTokenMissing(f"execution token file for {token_id!r} is corrupt: {exc}") from exc

    # Before anything in the record is believed. status and expiresAt are the two
    # fields that carry single-use and the time limit, and bindingHash does not
    # cover them — only this signature does.
    _verify_token_record(record, state_dir, token_id)

    if record.get("status") == "REDEEMED":
        raise StrixDatasetExportTokenAlreadyRedeemed(
            f"execution token {token_id!r} has already been redeemed — single-use, replay refused"
        )

    if "expiresAt" not in record:
        raise StrixDatasetExportTokenMissing(
            f"execution token file for {token_id!r} has no expiresAt field; it is not a usable token"
        )
    expires_at = _parse_iso(record["expiresAt"])
    if now > expires_at:
        raise StrixDatasetExportTokenExpired(f"execution token {token_id!r} expired at {record['expiresAt']}")

    recomputed = _binding_hash(
        payload_hash=payload_hash,
        destination_visibility=destination_visibility,
        destination_id=destination_id,
        transform_name=transform_name,
        transform_version=transform_version,
        classification_digest=classification_digest,
    )
    if recomputed != record.get("bindingHash"):
        raise StrixDatasetExportTokenBindingMismatch(
            f"execution token {token_id!r} binding no longer matches this request — the payload, "
            "destination, transform, or classification changed after the token was minted; "
            "editing the file (or the request) voids it"
        )

    record["status"] = "REDEEMED"
    record["redeemedAt"] = _iso_now()
    # Re-sign: the record changed, so the old signature must not keep verifying.
    # Without this, resetting status to MINTED would restore a valid signature.
    record["signature"] = _sign_token_record(record, generate_or_load_key(state_dir))
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Merkle tree / selective disclosure — net-new primitive, no prior art
# anywhere in this repo.
# ---------------------------------------------------------------------------


def _leaf_hash(row: Mapping[str, Any]) -> str:
    return _hash_canonical(
        {
            "rowId": row["row_id"],
            "classification": row.get("classification"),
            "fieldsHash": _hash_canonical(row.get("fields", {})),
        }
    )


@dataclass(frozen=True)
class MerkleTree:
    root: str
    levels: list[list[str]] = field(repr=False)
    row_order: list[str] = field(repr=False)


def build_merkle_tree(rows: Sequence[Mapping[str, Any]]) -> MerkleTree:
    if not rows:
        raise ValueError("cannot build a Merkle tree over zero rows")
    ordered = sorted(rows, key=lambda row: row["row_id"])
    row_order = [row["row_id"] for row in ordered]
    leaves = [_leaf_hash(row) for row in ordered]
    levels: list[list[str]] = [leaves]
    current = leaves
    while len(current) > 1:
        nxt = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            nxt.append(_hash_canonical({"left": left, "right": right}))
        levels.append(nxt)
        current = nxt
    return MerkleTree(root=current[0], levels=levels, row_order=row_order)


def merkle_inclusion_proof(tree: MerkleTree, row_id: str) -> list[dict[str, str]]:
    if row_id not in tree.row_order:
        raise ValueError(f"row_id {row_id!r} is not part of this Merkle tree")
    index = tree.row_order.index(row_id)
    proof: list[dict[str, str]] = []
    for level in tree.levels[:-1]:
        is_right = index % 2 == 1
        if is_right:
            sibling_index = index - 1
            position = "left"
        else:
            sibling_index = index + 1 if index + 1 < len(level) else index
            position = "right"
        proof.append({"position": position, "hash": level[sibling_index]})
        index //= 2
    return proof


def _apply_proof(leaf_hash: str, proof: Sequence[Mapping[str, str]]) -> str:
    current = leaf_hash
    for step in proof:
        if step["position"] == "left":
            current = _hash_canonical({"left": step["hash"], "right": current})
        else:
            current = _hash_canonical({"left": current, "right": step["hash"]})
    return current


def verify_merkle_inclusion(row: Mapping[str, Any], proof: Sequence[Mapping[str, str]], root: str) -> bool:
    return _apply_proof(_leaf_hash(row), proof) == root


_COMPLETENESS_DISCLAIMER = (
    "membership of the disclosed rows in the sealed/receipted row set was proven against the "
    "committed Merkle root; this does NOT prove the disclosed subset is the entire barred, "
    "admitted, or total row set for this export."
)


def build_selective_disclosure(rows: Sequence[Mapping[str, Any]], row_ids: Sequence[str]) -> dict[str, Any]:
    """Discloses ONLY the requested rows, plus a proof that each is a member
    of the set committed to the returned ``merkleRoot`` — never the content
    of any row outside ``row_ids``."""

    tree = build_merkle_tree(rows)
    by_id = {row["row_id"]: row for row in rows}
    disclosed = []
    proofs = {}
    for row_id in row_ids:
        row = by_id[row_id]
        disclosed.append(row)
        proofs[row_id] = merkle_inclusion_proof(tree, row_id)
    return {
        "merkleRoot": tree.root,
        "totalRowCountCommitted": len(rows),
        "disclosedRows": disclosed,
        "proofs": proofs,
        "discloses": "a subset of rows from a receipted/sealed row set",
        "provesOnly": "the disclosed rows are members of the set committed to merkleRoot",
        "doesNotProve": "that the disclosed rows are the complete barred, admitted, or total row set",
    }


def verify_selective_disclosure(disclosure: Mapping[str, Any], expected_root: str) -> dict[str, Any]:
    if disclosure.get("merkleRoot") != expected_root:
        return {
            "rootMatches": False,
            "rowsVerified": {},
            "allVerified": False,
            "completeness_claim": _COMPLETENESS_DISCLAIMER,
        }
    results = {}
    for row in disclosure.get("disclosedRows", []):
        row_id = row["row_id"]
        proof = disclosure.get("proofs", {}).get(row_id)
        results[row_id] = bool(proof) and verify_merkle_inclusion(row, proof, expected_root)
    return {
        "rootMatches": True,
        "rowsVerified": results,
        "allVerified": bool(results) and all(results.values()),
        "completeness_claim": _COMPLETENESS_DISCLAIMER,
    }


# ---------------------------------------------------------------------------
# The governed orchestrator
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class DatasetExportResult:
    evidence_id: str
    receipt_path: Path
    record: dict[str, Any]
    policy_decision: PolicyDecision


def _build_receipt_payload(
    *,
    requester_id: str,
    approver_id: str | None,
    destination_visibility: str,
    destination_id: str,
    policy_decision: PolicyDecision,
    input_hash: str,
    transform_name: str | None,
    transform_version: int | None,
    execution_outcome: str,
    token: ExecutionToken,
    workspace_fingerprint: str,
    key: LocalSigningKey,
    chain_seq: int,
    prev_hash: str | None,
    merkle_root: str,
    merkle_row_count: int,
) -> dict[str, Any]:
    core: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "recordMode": RECORD_MODE,
        "evidenceId": f"dsx_ev_{uuid.uuid4().hex}",
        "createdAt": _iso_now(),
        "capabilityId": CAPABILITY_ID,
        "requester": {"requesterId": requester_id},
        "approver": {"approverId": approver_id} if approver_id else None,
        "destination": {"visibility": destination_visibility, "destinationId": destination_id},
        "policyRef": {
            "policyId": policy_decision.policy_id,
            "policyVersion": policy_decision.policy_version,
            "policyHash": policy_decision.policy_hash,
        },
        "inputHash": input_hash,
        "admittedRowIds": list(policy_decision.admitted_row_ids),
        "barredRowIds": [
            {"rowId": b.row_id, "reasonCode": b.reason_code, "reason": b.reason} for b in policy_decision.barred
        ],
        "deidentifyTransform": {"name": transform_name, "version": transform_version},
        "deidentified": policy_decision.deidentified,
        "decisionOutcome": policy_decision.decision_outcome,
        "executionOutcome": execution_outcome,
        "executionTokenRef": {
            "tokenId": token.token_id,
            "status": "REDEEMED",
            "bindingHash": token.binding_hash,
        },
        "merkleRoot": merkle_root,
        "merkleRowCount": merkle_row_count,
        "completeness": COMPLETENESS_CLAIM,
        "workspaceFingerprint": workspace_fingerprint,
        "signingKeyId": key.kid,
        "publicKeyFingerprint": key.public_key_fingerprint,
        "runtimeVersion": RUNTIME_VERSION,
        "chainSeq": chain_seq,
        "prevHash": prev_hash,
    }
    evidence_hash = _hash_canonical(core)
    proof_chain_hash = _hash_canonical({"evidenceHash": evidence_hash, "prevHash": prev_hash, "chainSeq": chain_seq})
    core["evidenceHash"] = evidence_hash
    core["proofChainHash"] = proof_chain_hash
    return core


def governed_export(
    rows: Sequence[Mapping[str, Any]],
    *,
    destination_visibility: str,
    destination_id: str,
    requester_id: str,
    export_fn: Callable[[dict[str, Any]], Any],
    approver_id: str | None = None,
    approval_granted: bool = False,
    transform_name: str | None = None,
    transform_version: int | None = None,
    token_ttl_seconds: int = DEFAULT_TOKEN_TTL_SECONDS,
    workspace_root: Path | None = None,
    state_dir: Path | None = None,
) -> DatasetExportResult:
    """Evaluate → approve (cross-party only) → mint token → redeem token →
    execute → record, in that order. ``export_fn`` is called at most once,
    and only after every prior stage has succeeded — every failure mode
    raises before it, so it is provably unreachable on any barred, denied,
    or invalid path."""

    workspace_root = Path(workspace_root) if workspace_root is not None else Path.cwd()
    state_dir = Path(state_dir) if state_dir is not None else workspace_root / DEFAULT_STATE_DIR

    rows = [dict(row) for row in rows]
    input_hash = _hash_canonical(rows)

    decision = evaluate_export_policy(
        rows,
        destination_visibility=destination_visibility,
        transform_name=transform_name,
        transform_version=transform_version,
    )
    if not decision.admitted_row_ids:
        raise StrixDatasetExportPolicyDenied(
            f"research.dataset.export policy admitted 0 of {len(rows)} rows for destination "
            f"{destination_id!r} ({destination_visibility}); {len(decision.barred)} barred"
        )

    evaluate_approval(
        destination_visibility=destination_visibility,
        requester_id=requester_id,
        approver_id=approver_id,
        approval_granted=approval_granted,
    )

    class_digest = classification_digest(rows)
    token = mint_execution_token(
        payload_hash=input_hash,
        destination_visibility=destination_visibility,
        destination_id=destination_id,
        transform_name=transform_name,
        transform_version=transform_version,
        classification_digest=class_digest,
        state_dir=state_dir,
        ttl_seconds=token_ttl_seconds,
    )
    redeem_execution_token(
        token.token_id,
        payload_hash=input_hash,
        destination_visibility=destination_visibility,
        destination_id=destination_id,
        transform_name=transform_name,
        transform_version=transform_version,
        classification_digest=class_digest,
        state_dir=state_dir,
    )

    by_id = {row["row_id"]: row for row in rows}
    admitted_rows = [by_id[row_id] for row_id in decision.admitted_row_ids]
    if decision.deidentified and transform_name is not None:
        transform_fn = _TRANSFORMS[(transform_name, transform_version)]
        rows_to_export = [transform_fn(row) for row in admitted_rows]
    else:
        rows_to_export = admitted_rows

    key = generate_or_load_key(state_dir)
    _, chain_path = _chain_paths(state_dir)
    prev_hash, prior_seq = _last_hash_and_seq(chain_path)
    chain_seq = prior_seq + 1
    merkle_tree = build_merkle_tree(rows)
    workspace_fingerprint = _hash_canonical({"path": str(workspace_root.resolve())})

    request = {
        "rows": rows_to_export,
        "destination_visibility": destination_visibility,
        "destination_id": destination_id,
        "transform_name": transform_name,
        "transform_version": transform_version,
    }

    def _finalize(execution_outcome: str) -> dict[str, Any]:
        core = _build_receipt_payload(
            requester_id=requester_id,
            approver_id=approver_id,
            destination_visibility=destination_visibility,
            destination_id=destination_id,
            policy_decision=decision,
            input_hash=input_hash,
            transform_name=transform_name,
            transform_version=transform_version,
            execution_outcome=execution_outcome,
            token=token,
            workspace_fingerprint=workspace_fingerprint,
            key=key,
            chain_seq=chain_seq,
            prev_hash=prev_hash,
            merkle_root=merkle_tree.root,
            merkle_row_count=len(rows),
        )
        return _sign(core, key)

    try:
        export_fn(request)
    except Exception:
        try:
            _append_and_export(state_dir, _finalize("FAILED"))
        except Exception:  # noqa: BLE001 - never let receipt persistence mask the real failure
            pass
        raise

    record = _finalize("SUCCEEDED")
    try:
        receipt_path = _append_and_export(state_dir, record)
    except OSError as exc:
        raise StrixDatasetExportReceiptPersistenceError(
            f"the export ran but its receipt could not be persisted: {exc}"
        ) from exc

    return DatasetExportResult(
        evidence_id=record["payload"]["evidenceId"],
        receipt_path=receipt_path,
        record=record,
        policy_decision=decision,
    )


# ---------------------------------------------------------------------------
# Independent offline verification — a local, self-contained
# recompute-and-compare check (NOT an integration with the hosted,
# closed-source `@strixgov/verifier` CLI referenced by `strixgov-plugins`,
# which has no in-repo implementation to integrate with).
# ---------------------------------------------------------------------------


def verify_receipt(record: Mapping[str, Any], state_dir: Path) -> dict[str, Any]:
    payload = record.get("payload") if isinstance(record, Mapping) else None
    if not isinstance(payload, Mapping):
        return {"status": "INVALID", "hashValid": False, "chainValid": False, "signatureValid": False, "keyResolved": False}

    stored_hash = payload.get("evidenceHash")
    stored_chain_hash = payload.get("proofChainHash")
    core_without_hashes = {k: v for k, v in payload.items() if k not in ("evidenceHash", "proofChainHash")}
    recomputed_hash = _hash_canonical(core_without_hashes)
    hash_valid = recomputed_hash == stored_hash

    recomputed_chain_hash = _hash_canonical(
        {"evidenceHash": stored_hash, "prevHash": payload.get("prevHash"), "chainSeq": payload.get("chainSeq")}
    )
    chain_valid = recomputed_chain_hash == stored_chain_hash

    kid = payload.get("signingKeyId")
    pub_bytes = resolve_public_key(state_dir, kid) if kid else None
    key_resolved = pub_bytes is not None

    signature_hex = record.get("signature")
    signature_valid = False
    if key_resolved and signature_hex:
        try:
            _, Ed25519PublicKey = _require_cryptography()
            Ed25519PublicKey.from_public_bytes(pub_bytes).verify(bytes.fromhex(signature_hex), _canonicalize(payload))
            signature_valid = True
        except Exception:  # noqa: BLE001 - any verification failure means INVALID, not a crash
            signature_valid = False

    status = "VERIFIED" if (hash_valid and chain_valid and key_resolved and signature_valid) else "INVALID"
    return {
        "status": status,
        "hashValid": hash_valid,
        "chainValid": chain_valid,
        "signatureValid": signature_valid,
        "keyResolved": key_resolved,
    }


def verify_chain(records: Sequence[Mapping[str, Any]], state_dir: Path) -> dict[str, Any]:
    """Per-record ``verify_receipt`` plus ``prevHash``/``chainSeq``
    continuity across the ordered list supplied — trusts nothing stored,
    recomputes everything."""

    results = []
    prev_hash: str | None = None
    for index, record in enumerate(records):
        result = dict(verify_receipt(record, state_dir))
        payload = record.get("payload", {}) if isinstance(record, Mapping) else {}
        seq_valid = payload.get("chainSeq") == index + 1
        prev_valid = payload.get("prevHash") == prev_hash
        result["chainSeqValid"] = seq_valid
        result["prevHashValid"] = prev_valid
        if result["status"] == "VERIFIED" and not (seq_valid and prev_valid):
            result["status"] = "INVALID"
        results.append(result)
        prev_hash = payload.get("evidenceHash")
    overall = "VERIFIED" if results and all(r["status"] == "VERIFIED" for r in results) else "INVALID"
    return {"status": overall, "records": results}


__all__ = [
    "CAPABILITY_ID",
    "POLICY_ID",
    "POLICY_VERSION",
    "COMPLETENESS_CLAIM",
    "DESTINATION_INTERNAL",
    "DESTINATION_CROSS_PARTY",
    "DEFAULT_TOKEN_TTL_SECONDS",
    "Classification",
    "NOT_PROTECTED_CLASSIFICATIONS",
    "SAFE_HARBOR_V1_NAME",
    "SAFE_HARBOR_V1_VERSION",
    "REASON_CODE_TEXT",
    "StrixDatasetExportError",
    "StrixDatasetExportPolicyDenied",
    "StrixDatasetExportApprovalRequired",
    "StrixDatasetExportSelfApprovalDenied",
    "StrixDatasetExportTokenMissing",
    "StrixDatasetExportTokenExpired",
    "StrixDatasetExportTokenAlreadyRedeemed",
    "StrixDatasetExportTokenBindingMismatch",
    "StrixDatasetExportKeyError",
    "StrixDatasetExportReceiptPersistenceError",
    "BarredRow",
    "PolicyDecision",
    "evaluate_export_policy",
    "policy_ref",
    "evaluate_approval",
    "ExecutionToken",
    "classification_digest",
    "mint_execution_token",
    "redeem_execution_token",
    "MerkleTree",
    "build_merkle_tree",
    "merkle_inclusion_proof",
    "verify_merkle_inclusion",
    "build_selective_disclosure",
    "verify_selective_disclosure",
    "DatasetExportResult",
    "governed_export",
    "verify_receipt",
    "verify_chain",
    "generate_or_load_key",
    "resolve_public_key",
    "LocalSigningKey",
]
