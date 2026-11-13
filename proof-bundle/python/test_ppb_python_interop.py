"""The Python implementation must reach the documented result for every public
vector and for the authentic example bundles. Agreement between two
implementations that share no code is the interoperability evidence."""
import json
import pathlib

import pytest

pytest.importorskip("cryptography", reason="the second implementation needs `cryptography` (pip install -r requirements-test.txt)")

import ppb_verify as v  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
VEC = ROOT / "vectors"
INDEX = json.loads((VEC / "index.json").read_text(encoding="utf-8"))["vectors"]
EXAMPLES = ROOT / "examples"


def run(vec):
    try:
        files = v.load_carrier((VEC / vec["bundle"]).read_bytes())
        trust = v.parse_trust_store((VEC / vec["trustStore"]).read_bytes()) if vec["trustStore"] else None
        auths = v.parse_authorizations((VEC / vec["issuerAuthorizations"]).read_bytes()) if vec.get("issuerAuthorizations") else None
        revs = v.parse_revocations((VEC / vec["revocations"]).read_bytes(), trust) if vec.get("revocations") else None
        return v.verify_bundle(files, trust, vec.get("expectOptions"), auths, revs)
    except v.BundleError as e:
        return {"overall": "ERROR", "errorCode": e.code}


@pytest.mark.parametrize("vec", INDEX, ids=[x["name"] for x in INDEX])
def test_vector(vec):
    got, want = run(vec), vec["expect"]
    assert got["overall"] == want["overall"]
    assert v.EXIT[got["overall"]] == want["exit"]
    if "errorCode" in want:
        assert got["errorCode"] == want["errorCode"]
    if "failureCodes" in want:
        assert got["failureCodes"] == want["failureCodes"]
    for cid, cls in want.get("claims", {}).items():
        assert got["claims"][cid] == cls
    if want.get("noClaims") or got["overall"] == "FAILED":
        assert got.get("claims") == {}


def test_vector_count_guard():
    # An emptied index must not pass as "all vectors agree".
    assert len(INDEX) >= 60


@pytest.mark.parametrize("name", sorted(p.name for p in EXAMPLES.iterdir() if p.is_dir() and p.name[:2].isdigit()))
def test_authentic_examples_agree_with_node_reports(name):
    trust = v.parse_trust_store((EXAMPLES / "trust-store.demo.json").read_bytes())
    got = v.verify_bundle(v.load_bundle(str(EXAMPLES / name)), trust)
    node = json.loads((EXAMPLES / "reports" / f"{name}.report.json").read_text(encoding="utf-8"))
    assert got["overall"] == node["result"]["overall"] == "PASSED"
    assert got["bundleId"] == node["bundle"]["bundleId"]
    assert got["claims"] == {c["id"]: f'{c["classification"]}/{c["status"]}' for c in node["claims"]}
    assert v.verify_bundle(v.load_bundle(str(EXAMPLES / name)), None)["overall"] == "INCOMPLETE"


def test_carrier_and_directory_forms_agree():
    trust = v.parse_trust_store((EXAMPLES / "trust-store.demo.json").read_bytes())
    a = v.verify_bundle(v.load_bundle(str(EXAMPLES / "01-allow-succeeded")), trust)
    b = v.verify_bundle(v.load_bundle(str(EXAMPLES / "01-allow-succeeded.ppb.json")), trust)
    assert a == b


def test_ecmascript_number_formatting():
    cases = {0.0: "0", -0.0: "0", 1.0: "1", -0.5: "-0.5", 1e21: "1e+21", 1e20: "100000000000000000000", 1e-7: "1e-7", 0.000001: "0.000001", 1.5e-7: "1.5e-7", 123456789.125: "123456789.125", 2.0**53: "9007199254740992", 1.7976931348623157e308: "1.7976931348623157e+308", 5e-324: "5e-324"}
    for x, want in cases.items():
        assert v._js_number(x) == want
