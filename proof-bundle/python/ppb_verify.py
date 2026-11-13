#!/usr/bin/env python3
"""Strix Portable Proof Bundle v1 - second, independent verifier implementation.

Written from docs/SPEC.md, sharing no code with verifier/strix-proof-verify.mjs
and using a different cryptographic binding (the `cryptography` package). Its
purpose is interoperability evidence: the public vectors must produce the same
verdicts, failure codes and claim classifications in both implementations.

It reads carrier files (*.ppb.json) and bundle directories, and makes no
network connection.

    python ppb_verify.py verify <bundle> [--trust-store FILE] [--issuer-authorizations FILE]
                                         [--revocations FILE] [--expect-receipt-id ID] [--expect-tenant ID]
                                         [--expect-environment E] [--expect-bundle-id ID] [--json]

Exit codes: 0 PASSED, 1 FAILED, 2 ERROR, 3 INCOMPLETE.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import sys
from decimal import Decimal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

FORMAT = "strix-portable-proof-bundle"
VERSIONS = ("1.0",)
PAYLOAD_TYPE = "application/vnd.strix.ppb.manifest.v1+json"
AUTH_TYPE = "application/vnd.strix.ppb.issuer-authorization.v1+json"
REVOCATIONS_TYPE = "application/vnd.strix.ppb.authorization-revocations.v1+json"
RECORD_KINDS = ("manifest", "authorization-receipt", "execution-outcome")
RULE_VALUES = ("ALLOW", "DENY", "APPROVAL_REQUIRED")
MAX_FILE, MAX_FILES, MAX_TOTAL, MAX_CARRIER, MAX_DEPTH, MAX_PATH = 1024 * 1024, 64, 8 * 1024 * 1024, 12 * 1024 * 1024, 32, 200
P_MANIFEST, P_SIG = "manifest.json", "manifest.sig.json"
P_RECEIPT, P_OUTCOME = "evidence/authorization-receipt.json", "evidence/execution-outcome.json"
P_INV, P_POLICY, P_KEYS = "disclosures/invocation.json", "disclosures/policy-ruleset.json", "trust/embedded-signer-keys.json"
P_AUTH = "trust/issuer-authorizations.json"
ROLE_BY_PATH = {P_RECEIPT: "authorization-receipt", P_OUTCOME: "execution-outcome", P_INV: "invocation-disclosure", P_POLICY: "policy-disclosure", P_KEYS: "embedded-signer-keys", P_AUTH: "issuer-authorizations"}
EXIT = {"PASSED": 0, "FAILED": 1, "ERROR": 2, "INCOMPLETE": 3}
RECEIPT_ORDER = {
    "1": ["schemaVersion", "receiptId", "capabilityId", "action", "decision", "risk", "mode", "invocationHash", "evidenceHash", "proofChainHash", "timestamp"],
    "2": ["schemaVersion", "receiptId", "capabilityId", "action", "decision", "risk", "mode", "policyVersion", "tenantId", "environment", "invocationHash", "evidenceHash", "proofChainHash", "timestamp"],
}
OUTCOME_CORE = ["schemaVersion", "outcomeId", "authorizationReceiptId", "authorizationProofChainHash", "capabilityId", "action", "decision", "executionAttempted", "executionStatus", "invocationHash", "resultHash", "errorCode", "policyVersion", "tenantId", "environment", "completedAt", "signingKeyId", "signatureAlgorithm"]
OUTCOME_SIGNED = OUTCOME_CORE + ["outcomeHash"]
PATH_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*\Z")
TIME_RE = re.compile(r"^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,9}))?(?:Z|([+-])([0-9]{2}):([0-9]{2}))\Z")
ID_RE = re.compile(r"^ia_[A-Za-z0-9._-]{1,64}\Z")
MONTH_DAYS = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)
B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+\Z")
B64_RE = re.compile(r"^[A-Za-z0-9+/]*={0,2}\Z")
HEX64_RE = re.compile(r"^[0-9a-f]{64}\Z")


class BundleError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_str(v) -> bool:
    return isinstance(v, str)


# ------------------------------------------------------------------ JSON
def _pairs(pairs):
    out = {}
    for k, v in pairs:
        if k == "__proto__" or k in out:
            raise ValueError("duplicate or forbidden key")
        out[k] = v
    return out


def _const(_name):
    raise ValueError("non-JSON constant")


def _num(text):
    v = float(text)
    if v != v or v in (float("inf"), float("-inf")):
        raise ValueError("number out of range")
    return v


def _lone(text) -> bool:
    return any(0xD800 <= ord(ch) <= 0xDFFF for ch in text)


def _depth(v, d=0):
    if d > MAX_DEPTH:
        raise ValueError("too deep")
    if isinstance(v, dict):
        for k, x in v.items():
            if _lone(k):
                raise ValueError("unpaired surrogate")
            _depth(x, d + 1)
    elif isinstance(v, list):
        for x in v:
            _depth(x, d + 1)
    elif isinstance(v, str) and _lone(v):
        raise ValueError("unpaired surrogate")


def parse_strict_json(data, label="json"):
    """Strict RFC 8259: no BOM, valid UTF-8, no duplicate keys, bounded depth. All numbers become floats (as in ECMAScript)."""
    try:
        text = data if isinstance(data, str) else data.decode("utf-8", "strict")
        if text.startswith("﻿"):
            raise ValueError("BOM")
        v = json.loads(text, object_pairs_hook=_pairs, parse_constant=_const, parse_int=_num, parse_float=_num)
        _depth(v)
        return v
    except (ValueError, RecursionError, UnicodeDecodeError) as e:
        raise BundleError("MALFORMED_JSON", f"{label}: {e}") from None


def _js_number(x: float) -> str:
    """ECMAScript Number::toString for a finite double."""
    if x == 0:
        return "0"
    sign, digits, exp = Decimal(repr(x)).as_tuple()
    ds = "".join(map(str, digits)).rstrip("0") or "0"
    exp += len(digits) - len(ds)
    k, n = len(ds), len(ds) + exp
    if k <= n <= 21:
        body = ds + "0" * (n - k)
    elif 0 < n <= 21:
        body = ds[:n] + "." + ds[n:]
    elif -6 < n <= 0:
        body = "0." + "0" * (-n) + ds
    else:
        e = n - 1
        body = ds[0] + ("." + ds[1:] if k > 1 else "") + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return ("-" if sign else "") + body


_ESC = {'"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _js_string(s: str) -> str:
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch in _ESC:
            out.append(_ESC[ch])
        elif o < 0x20 or 0xD800 <= o <= 0xDFFF:
            out.append("\\u%04x" % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def canonical_json(v) -> str:
    """Gateway canonical JSON: keys sorted by UTF-16 code unit, no whitespace, ECMAScript scalars."""
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, (int, float)):
        return _js_number(float(v))
    if isinstance(v, str):
        return _js_string(v)
    if isinstance(v, list):
        return "[" + ",".join(canonical_json(x) for x in v) + "]"
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(_js_string(k) + ":" + canonical_json(v[k]) for k in keys) + "}"
    raise TypeError("unsupported")


def _scalar(v) -> str:
    """JSON.stringify of a string or boolean field inside an ordered record payload."""
    return _js_string(v) if isinstance(v, str) else canonical_json(v)


def ordered(obj: dict, fields) -> bytes:
    return ("{" + ",".join(_js_string(f) + ":" + _scalar(obj[f]) for f in fields) + "}").encode("utf-8", "surrogatepass")


def time_ms(v):
    """RFC 3339 date-time -> epoch milliseconds, or None. Parsed field by field; ASCII digits only."""
    if not is_str(v):
        return None
    m = TIME_RE.match(v)
    if not m:
        return None
    y, mo, d, h, mi, sec = (int(m.group(i)) for i in range(1, 7))
    leap = y % 4 == 0 and (y % 100 != 0 or y % 400 == 0)
    if y < 1970 or not 1 <= mo <= 12 or d < 1 or d > MONTH_DAYS[mo - 1] + (1 if mo == 2 and leap else 0) or h > 23 or mi > 59 or sec > 59:
        return None
    offset = 0
    if m.group(8):
        oh, om = int(m.group(9)), int(m.group(10))
        if oh > 23 or om > 59:
            return None
        offset = (1 if m.group(8) == "+" else -1) * (oh * 60 + om) * 60000
    yy = y - 1
    days = (y - 1970) * 365 + (yy // 4 - yy // 100 + yy // 400) - (1969 // 4 - 1969 // 100 + 1969 // 400)
    days += sum(MONTH_DAYS[: mo - 1]) + (1 if mo > 2 and leap else 0) + (d - 1)
    return ((days * 24 + h) * 60 + mi) * 60000 + sec * 1000 + int(((m.group(7) or "") + "000")[:3]) - offset


def b64_canonical(v):
    """Standard base64 with padding; None unless re-encoding reproduces the input."""
    if not is_str(v) or len(v) % 4 != 0 or not B64_RE.match(v):
        return None
    try:
        raw = base64.b64decode(v, validate=True)
    except Exception:
        return None
    return raw if base64.b64encode(raw).decode() == v else None


def b64url_canonical(v):
    if not is_str(v) or not B64URL_RE.match(v):
        return None
    try:
        raw = base64.urlsafe_b64decode(v + "=" * (-len(v) % 4))
    except Exception:
        return None
    return raw if base64.urlsafe_b64encode(raw).decode().rstrip("=") == v else None


def exact_keys(o, keys) -> bool:
    return isinstance(o, dict) and len(o) == len(keys) and all(k in o for k in keys)


# --------------------------------------------------------------- loading
def assert_safe_path(p):
    if not is_str(p) or not p or len(p) > MAX_PATH or not PATH_RE.match(p) or re.search(r"\.(/|\Z)", p):
        raise BundleError("UNSAFE_PATH", "unsafe or non-canonical path")


def _finish(files: dict) -> dict:
    folded = set()
    for p in files:
        if p.lower() in folded:
            raise BundleError("DUPLICATE_PATH", f"paths collide case-insensitively: {p}")
        folded.add(p.lower())
    if len(files) > MAX_FILES:
        raise BundleError("TOO_MANY_FILES", "too many files")
    if sum(len(b) for b in files.values()) > MAX_TOTAL:
        raise BundleError("BUNDLE_TOO_LARGE", "bundle too large")
    return files


def load_carrier(data: bytes) -> dict:
    if len(data) > MAX_CARRIER:
        raise BundleError("BUNDLE_TOO_LARGE", "carrier too large")
    doc = parse_strict_json(data, "carrier")
    if not isinstance(doc, dict) or doc.get("format") != "strix-ppb-carrier":
        raise BundleError("NOT_A_BUNDLE", "not a carrier")
    if doc.get("formatVersion") not in VERSIONS:
        raise BundleError("UNSUPPORTED_VERSION", "unsupported carrier version")
    if any(k not in ("format", "formatVersion", "files") for k in doc) or not isinstance(doc.get("files"), dict):
        raise BundleError("MALFORMED_CARRIER", "bad carrier")
    if len(doc["files"]) > MAX_FILES:
        raise BundleError("TOO_MANY_FILES", "too many files")
    files = {}
    for p, b64 in doc["files"].items():
        assert_safe_path(p)
        if is_str(b64) and len(b64) > -(-MAX_FILE // 3) * 4:
            raise BundleError("FILE_TOO_LARGE", p)
        raw = b64_canonical(b64)
        if raw is None:
            raise BundleError("MALFORMED_CARRIER", f"{p}: not canonical base64")
        files[p] = raw
    return _finish(files)


def _is_link(path: str, st) -> bool:
    if stat.S_ISLNK(st.st_mode):
        return True
    # Windows junctions and other reparse points are not symlinks to os.path.islink.
    return bool(getattr(st, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def load_directory(root: str) -> dict:
    files = {}

    def walk(directory, rel):
        for name in sorted(os.listdir(directory)):
            full = os.path.join(directory, name)
            r = f"{rel}/{name}" if rel else name
            st = os.lstat(full)
            if _is_link(full, st):
                raise BundleError("UNSAFE_PATH", f"symbolic link in bundle: {r}")
            assert_safe_path(r)
            if stat.S_ISDIR(st.st_mode):
                walk(full, r)
            elif stat.S_ISREG(st.st_mode):
                if len(files) >= MAX_FILES:
                    raise BundleError("TOO_MANY_FILES", "too many files")
                if st.st_size > MAX_FILE:
                    raise BundleError("FILE_TOO_LARGE", r)
                with open(full, "rb") as fh:
                    files[r] = fh.read()
            else:
                raise BundleError("UNSAFE_PATH", f"not a regular file: {r}")

    walk(root, "")
    return _finish(files)


def load_bundle(path: str) -> dict:
    if os.path.lexists(path) and _is_link(path, os.lstat(path)):
        raise BundleError("UNSAFE_PATH", "bundle path is a symbolic link")
    if os.path.isdir(path):
        return load_directory(path)
    if not os.path.isfile(path):
        raise BundleError("NOT_FOUND", "bundle not found")
    if os.path.getsize(path) > MAX_CARRIER:
        raise BundleError("BUNDLE_TOO_LARGE", "carrier too large")
    with open(path, "rb") as fh:
        return load_carrier(fh.read())


# ------------------------------------------------------------------ keys
def public_key(jwk):
    if not isinstance(jwk, dict) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or not is_str(jwk.get("x")) or not B64URL_RE.match(jwk["x"]):
        raise BundleError("UNSUPPORTED_ALGORITHM", "not an Ed25519 OKP JWK")
    raw = b64url_canonical(jwk["x"])
    if raw is None or len(raw) != 32:
        raise BundleError("MALFORMED_KEY", "Ed25519 public key must be 32 bytes of canonical base64url")
    return Ed25519PublicKey.from_public_bytes(raw)


def parse_trust_store(doc) -> dict:
    if isinstance(doc, (bytes, str)):
        doc = parse_strict_json(doc, "trust store")
    bad = lambda m: BundleError("MALFORMED_TRUST_STORE", m)  # noqa: E731
    if not isinstance(doc, dict):
        raise bad("must be an object")
    if "format" in doc:
        if doc["format"] != "strix-ppb-trust-store":
            raise bad("unknown format")
        if doc.get("formatVersion") not in VERSIONS:
            raise BundleError("UNSUPPORTED_VERSION", "unsupported trust store version")
        if not isinstance(doc.get("keys"), list):
            raise bad("keys must be an array")
        entries = doc["keys"]
    elif isinstance(doc.get("keys"), list):
        entries = [{"keyId": j.get("kid") if isinstance(j, dict) else None, "jwk": j} for j in doc["keys"]]
    elif "kty" in doc:
        entries = [{"keyId": doc.get("kid"), "jwk": doc}]
    else:
        raise bad("unrecognized shape")
    out = {}
    for e in entries:
        if not isinstance(e, dict) or not is_str(e.get("keyId")) or not e["keyId"]:
            raise bad("every key needs a keyId")
        if e["keyId"] in out:
            raise bad("duplicate keyId")
        if not isinstance(e.get("jwk"), dict):
            raise bad("key has no jwk")
        status = e.get("status", "active")
        if status not in ("active", "retired", "revoked"):
            raise bad("unknown status")
        role = e.get("role", "signer")
        if role not in ("signer", "issuer-root"):
            raise bad("unknown role")
        for f in ("notBefore", "notAfter"):
            if f in e and time_ms(e[f]) is None:
                raise bad(f"bad {f}")
        for f in ("tenants", "environments"):
            if f in e and not (isinstance(e[f], list) and all(is_str(x) for x in e[f])):
                raise bad(f"bad {f}")
        out[e["keyId"]] = {"key": public_key(e["jwk"]), "x": e["jwk"]["x"], "owner": e.get("owner") if is_str(e.get("owner")) else None, "role": role, "status": status,
                           "notBefore": e.get("notBefore"), "notAfter": e.get("notAfter"), "tenants": e.get("tenants"), "environments": e.get("environments")}
    return out


def ed_verify(key, data: bytes, sig) -> bool:
    raw = b64url_canonical(sig)
    if raw is None or len(raw) != 64:
        return False
    try:
        key.verify(raw, data)
        return True
    except (InvalidSignature, ValueError):
        return False


def pae(payload_type: str, payload: bytes) -> bytes:
    t = payload_type.encode()
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(payload), payload)


def _str_list(v) -> bool:
    return isinstance(v, list) and 0 < len(v) <= 64 and all(is_str(x) and x for x in v) and len(set(v)) == len(v)


def open_envelope(env, payload_type, err, label):
    def bad(m):
        return BundleError(err, f"{label}: {m}")

    if not exact_keys(env, ["payloadType", "payload", "signatures"]):
        raise bad("envelope shape")
    if env["payloadType"] != payload_type:
        raise bad("payloadType")
    if is_str(env["payload"]) and len(env["payload"]) > -(-MAX_FILE // 3) * 4:
        raise bad("payload too large")
    payload_bytes = b64_canonical(env["payload"])
    if payload_bytes is None:
        raise bad("payload is not canonical base64")
    sigs = env["signatures"]
    if not isinstance(sigs, list) or len(sigs) != 1 or not exact_keys(sigs[0], ["keyId", "algorithm", "signature"]):
        raise bad("exactly one signature")
    if sigs[0]["algorithm"] != "Ed25519":
        raise BundleError("UNSUPPORTED_ALGORITHM", f"{label}: signature algorithm")
    if not is_str(sigs[0]["keyId"]) or not sigs[0]["keyId"]:
        raise bad("keyId")
    return {"bytes": payload_bytes, "keyId": sigs[0]["keyId"], "signature": sigs[0]["signature"], "payload": parse_strict_json(payload_bytes, label)}


def parse_authorization(env, label="issuer authorization"):
    a = open_envelope(env, AUTH_TYPE, "MALFORMED_AUTHORIZATION", label)
    p = a["payload"]

    def bad(m):
        return BundleError("MALFORMED_AUTHORIZATION", f"{label}: {m}")

    if not exact_keys(p, ["type", "version", "authorizationId", "issuer", "issuedAt", "subject", "scope", "notBefore", "notAfter"]):
        raise bad("payload fields")
    if p["type"] != "strix-ppb-issuer-authorization":
        raise bad("type")
    if p["version"] != "1.0":
        raise BundleError("UNSUPPORTED_VERSION", f"{label}: authorization version")
    if not is_str(p["authorizationId"]) or not ID_RE.match(p["authorizationId"]):
        raise bad("authorizationId")
    if not is_str(p["issuer"]) or not p["issuer"]:
        raise bad("issuer")
    for f in ("issuedAt", "notBefore", "notAfter"):
        if time_ms(p[f]) is None:
            raise bad(f)
    if time_ms(p["notAfter"]) < time_ms(p["notBefore"]):
        raise bad("notAfter precedes notBefore")
    sub = p["subject"]
    if not exact_keys(sub, ["gatewayId", "keyId", "jwk"]) or not is_str(sub["gatewayId"]) or not sub["gatewayId"] or not is_str(sub["keyId"]) or not sub["keyId"]:
        raise bad("subject")
    sc = p["scope"]
    if not exact_keys(sc, ["tenants", "environments", "records"]) or not _str_list(sc["tenants"]) or not _str_list(sc["environments"]) or not _str_list(sc["records"]) or not all(r in RECORD_KINDS for r in sc["records"]):
        raise bad("scope")
    a["key"] = public_key(sub["jwk"])
    return a


def parse_authorizations(data, label="issuer authorizations"):
    doc = parse_strict_json(data, label) if isinstance(data, (bytes, str)) else data
    if isinstance(doc, dict) and "payloadType" in doc:  # a single envelope is accepted wherever a container is
        return [parse_authorization(doc, label)]
    if not exact_keys(doc, ["format", "formatVersion", "authorizations"]) or doc["format"] != "strix-ppb-issuer-authorizations":
        raise BundleError("MALFORMED_AUTHORIZATION", f"{label}: not an issuer-authorizations document")
    if doc["formatVersion"] not in VERSIONS:
        raise BundleError("UNSUPPORTED_VERSION", f"{label}: formatVersion")
    if not isinstance(doc["authorizations"], list) or not 1 <= len(doc["authorizations"]) <= 16:
        raise BundleError("MALFORMED_AUTHORIZATION", f"{label}: 1 to 16 authorizations")
    return [parse_authorization(e, f"{label}[{i}]") for i, e in enumerate(doc["authorizations"])]


def parse_revocations(data, trust_store):
    label = "revocation list"
    env = parse_strict_json(data, label) if isinstance(data, (bytes, str)) else data
    r = open_envelope(env, REVOCATIONS_TYPE, "REVOCATION_LIST_INVALID", label)

    def bad(m):
        return BundleError("REVOCATION_LIST_INVALID", f"{label}: {m}")

    p = r["payload"]
    if not exact_keys(p, ["type", "version", "issuer", "issuedAt", "revoked"]) or p["type"] != "strix-ppb-authorization-revocations" or p["version"] != "1.0":
        raise bad("payload fields")
    if not is_str(p["issuer"]) or not p["issuer"] or time_ms(p["issuedAt"]) is None or not isinstance(p["revoked"], list) or len(p["revoked"]) > 4096:
        raise bad("payload")
    for e in p["revoked"]:
        if not exact_keys(e, ["authorizationId", "revokedAt"]) or not is_str(e["authorizationId"]) or not ID_RE.match(e["authorizationId"]) or time_ms(e["revokedAt"]) is None:
            raise bad("revoked entry")
    root = (trust_store or {}).get(r["keyId"])
    if not root or root["role"] != "issuer-root" or root["status"] == "revoked":
        raise bad("not signed by an issuer root in your trust store")
    if not ed_verify(root["key"], pae(REVOCATIONS_TYPE, r["bytes"]), r["signature"]):
        raise bad("signature does not verify")
    return {"root": r["keyId"], "ids": {e["authorizationId"] for e in p["revoked"]}}


def judge_authorization(a, trust_store, revocations, kind, time, tenant, env):
    """Returns (trust, root_signed). Order of checks is fixed by SPEC 7.4."""
    p = a["payload"]
    root = trust_store.get(a["keyId"])
    if not root or root["role"] != "issuer-root":
        return "UNTRUSTED", False
    if not ed_verify(root["key"], pae(AUTH_TYPE, a["bytes"]), a["signature"]):
        return "AUTHORIZATION_INVALID", False
    rt = trust_for(root, p["issuedAt"], tenant, env)
    if rt != "TRUSTED":
        return rt, True
    if revocations and revocations["root"] == a["keyId"] and p["authorizationId"] in revocations["ids"]:
        return "REVOKED", True
    t = time_ms(time)
    if t is None or t < time_ms(p["notBefore"]) or t > time_ms(p["notAfter"]):
        return "OUTSIDE_VALIDITY", True
    if tenant not in p["scope"]["tenants"] or env not in p["scope"]["environments"]:
        return "TENANT_NOT_AUTHORIZED", True
    if kind not in p["scope"]["records"]:
        return "RECORD_NOT_AUTHORIZED", True
    return "TRUSTED", True


# ------------------------------------------------------- record canonicals
def receipt_signed_bytes(r: dict) -> bytes:
    order = RECEIPT_ORDER.get(r.get("schemaVersion")) if is_str(r.get("schemaVersion")) else None
    if not order:
        raise BundleError("UNSUPPORTED_RECORD_VERSION", "unsupported receipt schemaVersion")
    if "signatureAlgorithm" in r and r["signatureAlgorithm"] != "Ed25519":
        raise BundleError("UNSUPPORTED_ALGORITHM", "receipt declares an unsupported signatureAlgorithm")
    for f in order:
        if not is_str(r.get(f)) or r[f] == "":
            raise BundleError("MALFORMED_RECORD", f"receipt field {f}")
    for f in ("invocationHash", "evidenceHash", "proofChainHash"):
        if not HEX64_RE.match(r[f]):
            raise BundleError("MALFORMED_RECORD", f"receipt field {f} must be 64 lowercase hex characters")
    if r["schemaVersion"] == "1":
        for f in ("policyVersion", "tenantId", "environment"):
            if f in r:
                raise BundleError("MALFORMED_RECORD", f"schema 1 does not define {f}")
    return ordered(r, order)


def outcome_signed_bytes(o: dict) -> bytes:
    if o.get("schemaVersion") != "1":
        raise BundleError("UNSUPPORTED_RECORD_VERSION", "unsupported outcome schemaVersion")
    if o.get("signatureAlgorithm") != "Ed25519":
        raise BundleError("UNSUPPORTED_ALGORITHM", "unsupported outcome signatureAlgorithm")
    for k in o:
        if k not in OUTCOME_SIGNED and k != "signature":
            raise BundleError("MALFORMED_RECORD", f"outcome field {k} is not signed")
    for f in OUTCOME_SIGNED:
        if f != "executionAttempted" and not is_str(o.get(f)):
            raise BundleError("MALFORMED_RECORD", f"outcome field {f}")
    if o.get("executionAttempted") is not True:
        raise BundleError("MALFORMED_RECORD", "executionAttempted must be true")
    return ordered(o, OUTCOME_SIGNED)


def manifest_signed_bytes(manifest_bytes: bytes) -> bytes:
    return pae(PAYLOAD_TYPE, manifest_bytes)


def bundle_id(m: dict) -> str:
    basis = {"formatVersion": m["formatVersion"], "subject": m["subject"], "artifacts": [{"path": a["path"], "sha256": a["sha256"]} for a in m["artifacts"]]}
    return "ppb_" + sha256_hex(canonical_json(basis).encode("utf-8", "surrogatepass"))[:32]


def is_ruleset(v) -> bool:
    def rules_ok(o):
        return isinstance(o, dict) and all(is_str(x) and x in RULE_VALUES for x in o.values())

    return exact_keys(v, ["rules", "riskOverrides", "default"]) and rules_ok(v["rules"]) and rules_ok(v["riskOverrides"]) and (v["default"] is None or (is_str(v["default"]) and v["default"] in RULE_VALUES))


def evaluate_ruleset(rs: dict, cap: str, risk: str) -> str:
    rules = rs["rules"]
    if cap in rules:
        return rules[cap]
    best = ""
    for k in rules:
        if k.endswith(".*") and cap.startswith(k[:-2] + ".") and len(k[:-2]) > len(best):
            best = k[:-2]
    if best:
        return rules[best + ".*"]
    if risk in rs["riskOverrides"]:
        return rs["riskOverrides"][risk]
    return rs["default"] if rs["default"] is not None else "DENY"


# ------------------------------------------------------------- manifest
SUBJECT_KEYS = ["kind", "receiptId", "tenantId", "environment", "capabilityId", "action", "invocationHash"]
EVIDENCE_KEYS = ["authorizationDecision", "executionOutcome", "enforcementObservation", "invocationDisclosure", "policyDisclosure"]
MANIFEST_KEYS = ["format", "formatVersion", "critical", "bundleId", "createdAt", "exporter", "subject", "evidence", "digestAlgorithm", "artifacts", "signer", "extensions"]


def validate_manifest(m):
    def bad(msg):
        return BundleError("MALFORMED_MANIFEST", msg)

    if not isinstance(m, dict):
        raise bad("not an object")
    if m.get("format") != FORMAT:
        raise BundleError("NOT_A_BUNDLE", "wrong format")
    if m.get("formatVersion") not in VERSIONS:
        raise BundleError("UNSUPPORTED_VERSION", "unsupported formatVersion")
    crit = m.get("critical")
    if not isinstance(crit, list) or not all(is_str(x) for x in crit):
        raise bad("critical")
    if crit:
        raise BundleError("UNKNOWN_CRITICAL_EXTENSION", ", ".join(crit))
    if any(k not in MANIFEST_KEYS for k in m):
        raise bad("unknown field")
    if m.get("digestAlgorithm") != "sha-256":
        raise BundleError("UNSUPPORTED_ALGORITHM", "digestAlgorithm")
    if not is_str(m.get("bundleId")) or not re.match(r"^ppb_[0-9a-f]{32}\Z", m["bundleId"]):
        raise bad("bundleId")
    if time_ms(m.get("createdAt")) is None:
        raise bad("createdAt")
    ex = m.get("exporter")
    if not isinstance(ex, dict) or not is_str(ex.get("name")) or not is_str(ex.get("version")):
        raise bad("exporter")
    sub = m.get("subject")
    if not isinstance(sub, dict) or sorted(sub) != sorted(SUBJECT_KEYS) or sub["kind"] != "governed-action" or not all(is_str(sub[k]) and sub[k] for k in SUBJECT_KEYS):
        raise bad("subject")
    ev = m.get("evidence")
    if not isinstance(ev, dict) or sorted(ev) != sorted(EVIDENCE_KEYS) or not all(is_str(ev[k]) for k in EVIDENCE_KEYS):
        raise bad("evidence")
    sg = m.get("signer")
    if not isinstance(sg, dict) or not is_str(sg.get("keyId")) or not sg["keyId"]:
        raise bad("signer")
    if sg.get("algorithm") != "Ed25519":
        raise BundleError("UNSUPPORTED_ALGORITHM", "manifest signature algorithm")
    if "extensions" in m and not isinstance(m["extensions"], dict):
        raise bad("extensions")
    arts = m.get("artifacts")
    if not isinstance(arts, list) or not arts or len(arts) > MAX_FILES:
        raise bad("artifacts")
    seen, roles = set(), set()
    for a in arts:
        if not isinstance(a, dict) or sorted(a) != ["path", "role", "sha256", "size"]:
            raise bad("artifact shape")
        assert_safe_path(a["path"])
        if a["path"] in (P_MANIFEST, P_SIG):
            raise bad("self-listing")
        if a["path"].lower() in seen:
            raise BundleError("DUPLICATE_PATH", a["path"])
        seen.add(a["path"].lower())
        if not is_str(a["sha256"]) or not HEX64_RE.match(a["sha256"]):
            raise bad("sha256")
        sz = a["size"]
        if isinstance(sz, bool) or not isinstance(sz, float) or not sz.is_integer() or sz < 0 or sz > MAX_FILE:
            raise bad("size")
        if a["role"] != ROLE_BY_PATH.get(a["path"], "explanatory"):
            raise bad("role")
        roles.add(a["role"])
    if "authorization-receipt" not in roles:
        raise bad("no authorization receipt listed")


def trust_for(entry, time, tenant, env) -> str:
    if entry["status"] == "revoked":
        return "REVOKED"
    t = time_ms(time)
    if (entry["notBefore"] or entry["notAfter"]) and t is None:
        return "OUTSIDE_VALIDITY"
    if entry["notBefore"] and t < time_ms(entry["notBefore"]):
        return "OUTSIDE_VALIDITY"
    if entry["notAfter"] and t > time_ms(entry["notAfter"]):
        return "OUTSIDE_VALIDITY"
    if entry["tenants"] is not None and tenant not in entry["tenants"]:
        return "TENANT_NOT_AUTHORIZED"
    if entry["environments"] is not None and env not in entry["environments"]:
        return "TENANT_NOT_AUTHORIZED"
    return "TRUSTED"


# --------------------------------------------------------------- verify
def verify_bundle(files: dict, trust_store=None, expect=None, authorizations=None, revocations=None) -> dict:
    expect = expect or {}
    failures = []

    def fail(stage, code):
        failures.append({"stage": stage, "code": code})

    if P_MANIFEST not in files:
        raise BundleError("NOT_A_BUNDLE", "manifest.json is missing")
    manifest_bytes = files[P_MANIFEST]
    m = parse_strict_json(manifest_bytes, P_MANIFEST)
    validate_manifest(m)

    listed = {a["path"]: a for a in m["artifacts"]}
    for a in m["artifacts"]:
        buf = files.get(a["path"])
        if buf is None:
            fail("integrity", "MISSING_ARTIFACT")
        elif len(buf) != a["size"] or sha256_hex(buf) != a["sha256"]:
            fail("integrity", "DIGEST_MISMATCH")
    for p in files:
        if p not in (P_MANIFEST, P_SIG) and p not in listed:
            fail("integrity", "UNEXPECTED_ARTIFACT")
    if P_SIG not in files:
        fail("integrity", "MISSING_SIGNATURE")
    integrity_ok = not failures

    receipt = outcome = invocation = ruleset = sig_doc = None
    embedded = {}
    sigs = []
    if integrity_ok:
        def art(p):
            return parse_strict_json(files[p], p) if p in listed else None

        receipt = art(P_RECEIPT)
        if not isinstance(receipt, dict):
            raise BundleError("MALFORMED_RECORD", "receipt must be an object")
        outcome = art(P_OUTCOME)
        if outcome is not None and not isinstance(outcome, dict):
            raise BundleError("MALFORMED_RECORD", "outcome must be an object")
        invocation, ruleset = art(P_INV), art(P_POLICY)
        if invocation is not None and not (exact_keys(invocation, ["capabilityId", "action", "args", "actorId", "actorRole"]) and all(is_str(invocation[k]) for k in ("capabilityId", "action", "actorId", "actorRole"))):
            raise BundleError("MALFORMED_RECORD", "invocation disclosure shape")
        if ruleset is not None and not is_ruleset(ruleset):
            raise BundleError("MALFORMED_RECORD", "policy disclosure shape")
        if P_KEYS in listed:
            try:
                embedded = parse_trust_store(files[P_KEYS])
            except Exception:  # a convenience copy must never be fatal, whatever is wrong with it
                embedded = {}
        auths = {}
        for a in (parse_authorizations(files[P_AUTH], P_AUTH) if P_AUTH in listed else []) + list(authorizations or []):
            aid = a["payload"]["authorizationId"]
            if aid in auths and auths[aid]["bytes"] != a["bytes"]:
                raise BundleError("MALFORMED_AUTHORIZATION", "two different authorizations share an id")
            auths[aid] = a
        sig_doc = parse_strict_json(files[P_SIG], P_SIG)
        if not isinstance(sig_doc, dict) or sig_doc.get("format") != "strix-ppb-signature" or sig_doc.get("formatVersion") not in VERSIONS:
            raise BundleError("MALFORMED_SIGNATURE", "bad envelope")
        if sig_doc.get("payloadType") != PAYLOAD_TYPE:
            raise BundleError("MALFORMED_SIGNATURE", "payloadType")
        ss = sig_doc.get("signatures")
        if not isinstance(ss, list) or len(ss) != 1 or not isinstance(ss[0], dict):
            raise BundleError("MALFORMED_SIGNATURE", "exactly one signature")
        if ss[0].get("algorithm") != "Ed25519":
            raise BundleError("UNSUPPORTED_ALGORITHM", "signature algorithm")

        tenant, env = receipt.get("tenantId", "UNSPECIFIED"), receipt.get("environment", "UNSPECIFIED")

        def check(label, key_id, data, signature, time):
            res = {"record": label, "keyId": key_id, "math": None, "trust": "UNTRUSTED" if trust_store is not None else "NOT_ESTABLISHED"}
            entry = trust_store.get(key_id) if trust_store is not None else None
            direct = entry if entry and entry["role"] == "signer" else None
            e = embedded.get(key_id)
            if direct:
                res["math"] = ed_verify(direct["key"], data, signature)
                res["trust"] = trust_for(direct, time, tenant, env)
            else:
                cands = sorted((a for a in auths.values() if a["payload"]["subject"]["keyId"] == key_id), key=lambda a: a["payload"]["authorizationId"]) if trust_store is not None else []
                judged = [(a, judge_authorization(a, trust_store, revocations, label, time, tenant, env)) for a in cands]
                pick = next((j for j in judged if j[1][0] == "TRUSTED"), judged[0] if judged else None)
                if pick:
                    res["trust"] = pick[1][0]
                if pick and pick[1][1]:
                    res["math"] = ed_verify(pick[0]["key"], data, signature)
                elif e:
                    res["math"] = ed_verify(e["key"], data, signature)
            sigs.append(res)

        r_bytes = receipt_signed_bytes(receipt)
        if ss[0].get("keyId") != m["signer"]["keyId"]:
            fail("signatures", "SIGNER_MISMATCH")
        check("manifest", m["signer"]["keyId"], manifest_signed_bytes(manifest_bytes), ss[0].get("signature"), m["createdAt"])
        if not is_str(receipt.get("signingKeyId")) or not receipt["signingKeyId"]:
            raise BundleError("MALFORMED_RECORD", "receipt has no signingKeyId")
        check("authorization-receipt", receipt["signingKeyId"], r_bytes, receipt.get("signature"), receipt["timestamp"])
        if outcome is not None:
            o_bytes = outcome_signed_bytes(outcome)
            check("execution-outcome", outcome["signingKeyId"], o_bytes, outcome.get("signature"), outcome["completedAt"])
        for s in sigs:
            if s["math"] is False:
                fail("signatures", "SIGNATURE_INVALID")
            if s["trust"] not in ("TRUSTED", "NOT_ESTABLISHED"):
                fail("signerTrust", "SIGNER_" + s["trust"])

    math = [s["math"] for s in sigs]
    sig_status = "NOT_EVALUATED" if not integrity_ok else "INVALID" if False in math else "NOT_EVALUATED" if None in math else "VALID"
    trusts = [s["trust"] for s in sigs]
    if not integrity_ok:
        trust_status = "NOT_EVALUATED"
    elif all(t == "TRUSTED" for t in trusts):
        trust_status = "TRUSTED"
    else:
        trust_status = next((t for t in trusts if t not in ("TRUSTED", "NOT_ESTABLISHED")), "NOT_ESTABLISHED")

    if integrity_ok:
        def c(code):
            fail("consistency", code)

        sub = m["subject"]
        for k in ("receiptId", "capabilityId", "action", "invocationHash"):
            if sub[k] != receipt.get(k):
                c("SUBJECT_MISMATCH")
        for k in ("tenantId", "environment"):
            if sub[k] != receipt.get(k, "UNSPECIFIED"):
                c("SUBJECT_MISMATCH")
        if bundle_id(m) != m["bundleId"]:
            c("BUNDLE_ID_MISMATCH")
        if sha256_hex(f"{receipt['invocationHash']}|{receipt['decision']}|{receipt['timestamp']}".encode("utf-8", "surrogatepass")) != receipt["evidenceHash"]:
            c("RECEIPT_HASH_MISMATCH")
        if receipt["decision"] not in ("ALLOW", "DENY"):
            c("UNRECOGNIZED_DECISION")
        rt = time_ms(receipt["timestamp"])
        if rt is None:
            c("BAD_TIMESTAMP")
        elif time_ms(m["createdAt"]) < rt:
            c("TIMESTAMP_ORDER")
        ev = m["evidence"]
        if ev["authorizationDecision"] != "PRESENT":
            c("EVIDENCE_STATE_MISMATCH")
        if ev["enforcementObservation"] != "NOT_CAPTURED":
            c("EVIDENCE_STATE_MISMATCH")
        want = "PRESENT" if outcome is not None else "ABSENT" if receipt["decision"] == "ALLOW" else "NOT_APPLICABLE"
        if ev["executionOutcome"] != want:
            c("EVIDENCE_STATE_MISMATCH")
        if ev["invocationDisclosure"] != ("PRESENT" if invocation is not None else "NOT_DISCLOSED"):
            c("EVIDENCE_STATE_MISMATCH")
        if ev["policyDisclosure"] != ("PRESENT" if ruleset is not None else "NOT_DISCLOSED"):
            c("EVIDENCE_STATE_MISMATCH")
        if outcome is not None:
            if receipt["decision"] != "ALLOW" or outcome["decision"] != "ALLOW":
                c("CONTRADICTORY_RECORDS")
            for k in ("capabilityId", "action", "invocationHash", "policyVersion", "tenantId", "environment"):
                if outcome[k] != receipt.get(k):
                    c("OUTCOME_LINK_MISMATCH")
            if outcome["authorizationReceiptId"] != receipt["receiptId"] or outcome["authorizationProofChainHash"] != receipt["proofChainHash"]:
                c("OUTCOME_LINK_MISMATCH")
            if "sha256:" + sha256_hex(ordered(outcome, OUTCOME_CORE)) != outcome["outcomeHash"]:
                c("OUTCOME_HASH_MISMATCH")
            st = outcome["executionStatus"]
            ok = st in ("SUCCEEDED", "FAILED", "UNKNOWN")
            ok = ok and (bool(re.match(r"^sha256:[0-9a-f]{64}\Z", outcome["resultHash"])) if st == "SUCCEEDED" else outcome["resultHash"] == "")
            ok = ok and (len(outcome["errorCode"]) > 0 if st == "FAILED" else outcome["errorCode"] == "")
            if not ok:
                c("CONTRADICTORY_RECORDS")
            ot = time_ms(outcome["completedAt"])
            if ot is None:
                c("BAD_TIMESTAMP")
            elif rt is not None and ot < rt:
                c("TIMESTAMP_ORDER")
        if invocation is not None:
            if sha256_hex(canonical_json(invocation).encode("utf-8")) != receipt["invocationHash"]:
                c("DISCLOSURE_MISMATCH")
            elif invocation["capabilityId"] != receipt["capabilityId"] or invocation["action"] != receipt["action"]:
                c("CONTRADICTORY_RECORDS")
        if ruleset is not None:
            h = "sha256:" + sha256_hex(canonical_json(ruleset).encode("utf-8"))
            if h != receipt.get("policyVersion"):
                c("DISCLOSURE_MISMATCH")
            elif evaluate_ruleset(ruleset, receipt["capabilityId"], receipt["risk"]) == "DENY" and receipt["decision"] == "ALLOW":
                c("CONTRADICTORY_RECORDS")
    for k in ("receiptId", "tenantId", "environment"):
        if expect.get(k) is not None and expect[k] != m["subject"][k]:
            fail("expectation", "EXPECTATION_MISMATCH")
    if expect.get("bundleId") is not None and expect["bundleId"] != m["bundleId"]:
        fail("expectation", "EXPECTATION_MISMATCH")

    stages = {f["stage"] for f in failures}
    hard = (not integrity_ok) or sig_status == "INVALID" or bool(stages & {"consistency", "signerTrust", "expectation", "signatures"})
    overall = "FAILED" if hard else "PASSED" if sig_status == "VALID" and trust_status == "TRUSTED" else "INCOMPLETE"
    claims = {}
    if overall != "FAILED" and sig_status == "VALID":
        trusted = trust_status == "TRUSTED"
        a = "ASSERTED" if trusted else "ASSERTED_BY_UNTRUSTED_KEY"
        ne = "NOT_ESTABLISHED/NOT_ESTABLISHED"
        claims = {
            "PPB-C01": "CRYPTOGRAPHIC_FINDING/ESTABLISHED",
            "PPB-C02": "CRYPTOGRAPHIC_FINDING/ESTABLISHED",
            "PPB-C03": "TRUST_EVALUATION/" + ("ESTABLISHED" if trusted else "NOT_ESTABLISHED"),
            "PPB-C04": "SOURCE_ASSERTION/" + a,
            "PPB-C05": "CORROBORATED/ESTABLISHED" if ruleset is not None else "SOURCE_ASSERTION/" + a,
            "PPB-C06": "CORROBORATED/ESTABLISHED" if invocation is not None else ne,
            "PPB-C07": ne,
            "PPB-C08": "SOURCE_ASSERTION/" + a if ("approvalReason" in receipt or "approvedBy" in receipt) else "NOT_ESTABLISHED/NOT_APPLICABLE",
            "PPB-C09": ne,
            "PPB-C10": "SOURCE_ASSERTION/" + a if outcome is not None else ne if receipt["decision"] == "ALLOW" else "NOT_ESTABLISHED/NOT_APPLICABLE",
            "PPB-C11": "SOURCE_ASSERTION/" + a,
            "PPB-C12": ne,
        }
    return {
        "implementation": "ppb_verify.py/1.0.0",
        "bundleId": m["bundleId"],
        "overall": overall,
        "integrity": "VERIFIED" if integrity_ok else "FAILED",
        "signatures": sig_status,
        "signerTrust": trust_status,
        "consistency": "NOT_EVALUATED" if not integrity_ok else "INCONSISTENT" if "consistency" in stages else "CONSISTENT",
        "failureCodes": sorted({f["code"] for f in failures}),
        "claims": claims,
    }


OPTIONS = {"--trust-store": "trust", "--issuer-authorizations": "auths", "--revocations": "revocations", "--expect-receipt-id": "receiptId", "--expect-tenant": "tenantId", "--expect-environment": "environment", "--expect-bundle-id": "bundleId"}


def main(argv) -> int:
    opts, args, as_json, i = {}, [], False, 0
    while i < len(argv):
        a = argv[i]
        if a == "--json":
            as_json = True
        elif a in OPTIONS and i + 1 < len(argv):
            i += 1
            opts[OPTIONS[a]] = argv[i]
        elif a.startswith("--"):
            # An option that is not understood is never silently dropped: the caller may be relying on it.
            sys.stderr.write(f"ERROR USAGE: unknown or incomplete option {a}\n")
            return 2
        else:
            args.append(a)
        i += 1
    if len(args) != 2 or args[0] != "verify":
        sys.stderr.write(__doc__)
        return 2

    def read(path):
        with open(path, "rb") as fh:
            return fh.read()

    try:
        trust = parse_trust_store(read(opts["trust"])) if "trust" in opts else None
        if ("auths" in opts or "revocations" in opts) and trust is None:
            raise BundleError("USAGE", "--issuer-authorizations and --revocations need --trust-store")
        auths = parse_authorizations(read(opts["auths"])) if "auths" in opts else None
        revs = parse_revocations(read(opts["revocations"]), trust) if "revocations" in opts else None
        expect = {k: opts[k] for k in ("receiptId", "tenantId", "environment", "bundleId") if k in opts}
        report = verify_bundle(load_bundle(args[1]), trust, expect, auths, revs)
    except BundleError as e:
        report = {"implementation": "ppb_verify.py/1.0.0", "overall": "ERROR", "errorCode": e.code, "message": str(e)}
    except OSError as e:
        report = {"implementation": "ppb_verify.py/1.0.0", "overall": "ERROR", "errorCode": "NOT_FOUND", "message": str(e)}
    except Exception as e:  # never let a crash exit with the FAILED code
        report = {"implementation": "ppb_verify.py/1.0.0", "overall": "ERROR", "errorCode": "INTERNAL_ERROR", "message": type(e).__name__}
    if as_json:
        print(json.dumps(report, indent=2))
    else:
        for k in ("overall", "integrity", "signatures", "signerTrust", "consistency", "errorCode"):
            if k in report:
                print(f"{k:14} {report[k]}")
        for code in report.get("failureCodes", []):
            print(f"failure        {code}")
        for cid, v in report.get("claims", {}).items():
            print(f"{cid:14} {v}")
        print("This reference implementation prints verdicts only; use strix-proof-verify.mjs for the full claims text.")
    return EXIT[report["overall"]]


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
