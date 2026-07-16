"""Trust model: pinned keys, key rotation, TOFU, and the async intended-use
binding regression."""

import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from prampta import _trust
from prampta.client import Prampta, _canonical_json, PramptaSignatureError, IntendedUse


def _keypair():
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key().public_bytes_raw().hex()
    return priv, pub


def test_parse_pins_comma_and_space():
    assert _trust.parse_pins("aa, bb  cc") == ["aa", "bb", "cc"]
    assert _trust.parse_pins("") == []


def test_choose_pinned_matches_by_fingerprint():
    _, pub = _keypair()
    kid = _trust.fingerprint(pub)
    choice = _trust.choose_pinned(kid, [pub])
    assert choice is not None and choice.pinned and choice.public_key_hex == pub


def test_choose_pinned_returns_none_when_absent():
    _, pub = _keypair()
    assert _trust.choose_pinned("pg-ed25519:deadbeef", [pub]) is None


def test_multi_pin_supports_rotation():
    """Pinning current + next lets a client ride through a rotation with no
    downtime — the new key is already trusted."""
    _, old = _keypair()
    _, new = _keypair()
    new_kid = _trust.fingerprint(new)
    choice = _trust.choose_pinned(new_kid, [old, new])
    assert choice is not None and choice.public_key_hex == new


def test_pinned_mode_rejects_unpinned_key():
    err = _trust.pinned_rotation_error("pg-ed25519:unknown")
    assert "not in your pinned set" in err


def test_unpinned_tofu_resolves_with_warning():
    _, pub = _keypair()
    kid = _trust.fingerprint(pub)
    key_set = {"current_key_id": kid, "keys": [{"key_id": kid, "public_key_hex": pub}]}
    choice = _trust.resolve_unpinned(kid, key_set)
    assert choice.public_key_hex == pub
    assert choice.warning and "trust-on-first-use" in choice.warning


def test_unpinned_unknown_key_errors():
    choice = _trust.resolve_unpinned("pg-ed25519:missing", {"keys": []})
    assert choice.error and "not present" in choice.error


def test_resolver_pinned_hits_no_network():
    """A pinned-and-matching key resolves without touching /keys."""
    _, pub = _keypair()
    pg = Prampta.__new__(Prampta)
    pg.verify_signatures = True
    pg._pinned_keys = [pub]
    pg._key_set_cache = None
    pg._tofu_warned = False

    def _boom():
        raise AssertionError("/keys must not be fetched when a pin matches")
    pg._fetch_verified_key_set = _boom  # type: ignore

    assert pg._resolve_operator_key(_trust.fingerprint(pub)) == pub


# ── P4a regression: async intended-use binding ──────────────────────────

def _signed_decision(priv, iu: dict, extra=None):
    raw = {
        "allowed": True, "decision_id": "d1",
        "subject_id": "s", "provider_id": "p", "licensee_id": "l",
        "modality": "image", "model": "m",
        "intended_use": iu,
        "expires_at": int(time.time()) + 300, "prompt_hash": "h",
    }
    if extra:
        raw.update(extra)
    raw["operator_key_id"] = _trust.fingerprint(priv.public_key().public_bytes_raw().hex())
    raw["operator_signature"] = priv.sign(_canonical_json(raw)).hex()
    return raw


def test_context_binding_catches_intended_use_replay():
    """An ALLOW issued for Product A must not authorize Product B. The async
    client previously skipped this check by not passing intended_use."""
    priv, _ = _keypair()
    # Decision was issued for product B ...
    raw = _signed_decision(priv, {"product_name": "product-B", "categories": [], "channel": "", "project_name": "", "territory": ""})
    sent = IntendedUse(product_name="product-A")  # ... but we asked for product A
    with pytest.raises(PramptaSignatureError, match="product_name mismatch"):
        Prampta._verify_context_binding(raw, "s", "p", "l", "image", "m", sent)


def test_async_binding_call_signature_matches_sync():
    """Guard against the regression returning: the async client must pass the
    full intended_use into _verify_context_binding (7 positional args)."""
    import inspect
    from prampta import async_client
    src = inspect.getsource(async_client)
    # The call site must forward intended_use (the 7th argument).
    assert "modality or intended_use.modality, model, intended_use," in src


# ── Monitor mode (pilot): enforce=False must not block ──────────────────

def _refused_result():
    from prampta.client import VerifyResult
    return VerifyResult(allowed=False, decision_id="d", reason="PG_SCOPE_VIOLATION")


def test_enforce_true_raises_on_refusal(monkeypatch):
    pg = Prampta.__new__(Prampta)
    pg.enforce = True
    monkeypatch.setattr(pg, "verify", lambda *a, **k: _refused_result())
    from prampta.client import PramptaRefused
    with pytest.raises(PramptaRefused):
        pg.assert_allowed("sub", prompt="x", modality="image")


def test_enforce_false_monitor_mode_proceeds(monkeypatch, recwarn):
    pg = Prampta.__new__(Prampta)
    pg.enforce = False
    monkeypatch.setattr(pg, "verify", lambda *a, **k: _refused_result())
    result = pg.assert_allowed("sub", prompt="x", modality="image")  # must NOT raise
    assert result.allowed is False
    assert any("monitor mode" in str(w.message) for w in recwarn)
