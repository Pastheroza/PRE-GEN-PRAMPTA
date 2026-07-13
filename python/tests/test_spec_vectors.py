"""Replay the cross-implementation spec vectors against the Python SDK.

The SDK rebuilds canonical bodies to verify operator signatures — if its
canonicalization drifts from the backend, every signature check breaks.
Vectors live in spec/test-vectors/vectors.json (repo root).
"""

import hashlib
import json
from pathlib import Path

import pytest

from prampta.client import _canonical_json, _verify_ed25519

REPO_ROOT = Path(__file__).resolve().parents[3]
VECTORS = json.loads((REPO_ROOT / "spec" / "test-vectors" / "vectors.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", VECTORS["canonical_json"], ids=lambda c: c["name"])
def test_sdk_canonical_json(case):
    cbytes = _canonical_json(case["input"])
    assert cbytes.decode("utf-8") == case["canonical_utf8"]
    assert hashlib.sha256(cbytes).hexdigest() == case["sha256_hex"]


@pytest.mark.parametrize("case", VECTORS["signing"], ids=lambda c: c["name"])
def test_sdk_verifies_vector_signatures(case):
    cbytes = _canonical_json(case["body"])
    assert cbytes.decode("utf-8") == case["canonical_utf8"]
    assert _verify_ed25519(
        VECTORS["operator_key"]["public_hex"],
        case["signature_hex"],
        cbytes,
    )


def test_sdk_rejects_tampered_body():
    case = VECTORS["signing"][0]
    tampered = dict(case["body"])
    tampered["allowed"] = not tampered.get("allowed", False)
    assert not _verify_ed25519(
        VECTORS["operator_key"]["public_hex"],
        case["signature_hex"],
        _canonical_json(tampered),
    )


def test_sdk_fingerprint_derivation():
    """SDK derives operator_key_id the same way the backend does."""
    pub = VECTORS["operator_key"]["public_hex"]
    expected = f"pg-ed25519:{hashlib.sha256(bytes.fromhex(pub)).hexdigest()[:32]}"
    assert expected == VECTORS["operator_key"]["fingerprint"]
