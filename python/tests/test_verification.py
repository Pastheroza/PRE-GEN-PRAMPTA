"""Unit tests for SDK verification logic.

Tests canonical JSON, signature verification, context binding,
TTL validation, and fail-closed behavior.
"""

import json
import time
import pytest

from prampta.client import (
    Prampta, VerifyResult,
    PramptaError, PramptaSignatureError, PramptaSchemaError,
    hash_prompt, _canonical_json, _verify_ed25519,
)


# ── Canonical JSON ─────────────────────────────────────────────────────

class TestCanonicalJson:
    def test_sorted_keys(self):
        obj = {"z": 1, "a": 2, "m": 3}
        result = _canonical_json(obj)
        assert result == b'{"a":2,"m":3,"z":1}'

    def test_no_whitespace(self):
        obj = {"key": "value", "num": 42}
        result = _canonical_json(obj)
        assert b" " not in result
        assert b"\n" not in result

    def test_nested_sorted(self):
        obj = {"b": {"z": 1, "a": 2}, "a": [3, 2, 1]}
        result = _canonical_json(obj)
        parsed = json.loads(result)
        # Keys should be sorted at all levels
        assert list(json.loads(result.decode()).keys()) == ["a", "b"]

    def test_unicode(self):
        obj = {"name": "クリスティアーノ"}
        result = _canonical_json(obj)
        assert "クリスティアーノ".encode("utf-8") in result

    def test_null_value(self):
        obj = {"a": None}
        result = _canonical_json(obj)
        assert result == b'{"a":null}'

    def test_empty_object(self):
        assert _canonical_json({}) == b'{}'

    def test_empty_list(self):
        obj = {"items": []}
        assert _canonical_json(obj) == b'{"items":[]}'

    def test_boolean(self):
        obj = {"flag": True, "other": False}
        result = _canonical_json(obj)
        assert b"true" in result
        assert b"false" in result


# ── Hash Prompt ────────────────────────────────────────────────────────

class TestHashPrompt:
    def test_deterministic(self):
        h1 = hash_prompt("Da Vinci in a documentary")
        h2 = hash_prompt("Da Vinci in a documentary")
        assert h1 == h2

    def test_different_prompts(self):
        h1 = hash_prompt("Da Vinci in a documentary")
        h2 = hash_prompt("Newton in an ad")
        assert h1 != h2

    def test_hex_format(self):
        h = hash_prompt("test")
        assert len(h) == 64
        assert all(c in "0123456789abcdef" for c in h)


# ── Ed25519 Verification ──────────────────────────────────────────────

class TestEd25519:
    def _generate_keypair(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        private = Ed25519PrivateKey.generate()
        public_hex = private.public_key().public_bytes_raw().hex()
        return private, public_hex

    def test_valid_signature(self):
        private, public_hex = self._generate_keypair()
        message = b"test message"
        sig_hex = private.sign(message).hex()
        assert _verify_ed25519(public_hex, sig_hex, message) is True

    def test_invalid_signature(self):
        private, public_hex = self._generate_keypair()
        message = b"test message"
        sig_hex = private.sign(b"wrong message").hex()
        assert _verify_ed25519(public_hex, sig_hex, message) is False

    def test_wrong_key(self):
        private, _ = self._generate_keypair()
        _, wrong_public_hex = self._generate_keypair()
        message = b"test message"
        sig_hex = private.sign(message).hex()
        assert _verify_ed25519(wrong_public_hex, sig_hex, message) is False


# ── Context Binding ────────────────────────────────────────────────────

class TestContextBinding:
    def test_subject_id_mismatch(self):
        with pytest.raises(PramptaSignatureError, match="subject_id mismatch"):
            Prampta._verify_context_binding(
                {"subject_id": "alice", "provider_id": "", "licensee_id": ""},
                subject_id="bob",
                provider_id="",
                licensee_id="",
                modality="",
                model="",
            )

    def test_provider_id_mismatch(self):
        with pytest.raises(PramptaSignatureError, match="provider_id mismatch"):
            Prampta._verify_context_binding(
                {"subject_id": "alice", "provider_id": "evil-proxy", "licensee_id": "x"},
                subject_id="alice",
                provider_id="real-provider",
                licensee_id="x",
                modality="",
                model="",
            )

    def test_modality_mismatch(self):
        with pytest.raises(PramptaSignatureError, match="modality mismatch"):
            Prampta._verify_context_binding(
                {"subject_id": "a", "provider_id": "p", "licensee_id": "l", "modality": "video"},
                subject_id="a",
                provider_id="p",
                licensee_id="l",
                modality="image",
                model="",
            )

    def test_passes_when_matching(self):
        # Should not raise
        Prampta._verify_context_binding(
            {"subject_id": "alice", "provider_id": "p1", "licensee_id": "l1", "modality": "image", "model": "dall-e"},
            subject_id="alice",
            provider_id="p1",
            licensee_id="l1",
            modality="image",
            model="dall-e",
        )

    def test_empty_fields_skipped(self):
        # Empty fields in decision should not trigger mismatch
        Prampta._verify_context_binding(
            {"subject_id": "alice", "provider_id": "", "licensee_id": ""},
            subject_id="alice",
            provider_id="my-provider",
            licensee_id="my-licensee",
            modality="",
            model="",
        )


# ── Schema Validation ──────────────────────────────────────────────────

class TestSchemaValidation:
    def test_requires_prompt_or_hash(self):
        """SDK must reject verify() calls without prompt or prompt_hash."""
        # Can't actually call verify() without a server, but we can test the validation
        # by checking that empty prompt raises
        pg = Prampta.__new__(Prampta)
        pg.base_url = "http://fake"
        pg.provider_id = "p"
        pg.licensee_id = "l"
        pg.token = "t"
        pg.timeout = 1
        pg.verify_signatures = False
        pg.fail_closed = True
        pg._operator_public_key_hex = ""

        with pytest.raises(PramptaSchemaError, match="prompt or prompt_hash"):
            pg.verify("subject-id")  # No prompt, no prompt_hash


# ── TTL Validation ─────────────────────────────────────────────────────

class TestTTLValidation:
    def test_expired_decision_raises(self):
        """Decisions past expires_at should be rejected.

        Signature verification is disabled so we reach the TTL check.
        """
        import hashlib
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        # Generate a real keypair and sign a valid decision
        private_key = Ed25519PrivateKey.generate()
        public_hex = private_key.public_key().public_bytes_raw().hex()
        fingerprint = hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:32]

        expired_ts = int(time.time()) - 100  # expired 100 sec ago
        raw_data = {
            "allowed": True,
            "decision_id": "test",
            "operator_key_id": f"pg-ed25519:{fingerprint}",
            "expires_at": expired_ts,
            "prompt_hash": "abc",
        }
        canonical = _canonical_json(raw_data)
        sig_hex = private_key.sign(canonical).hex()

        pg = Prampta.__new__(Prampta)
        pg.verify_signatures = True
        pg._operator_public_key_hex = public_hex

        result = VerifyResult(
            allowed=True,
            decision_id="test",
            operator_key_id=raw_data["operator_key_id"],
            operator_signature=sig_hex,
            expires_at=expired_ts,
            prompt_hash="abc",
        )

        with pytest.raises(PramptaSignatureError, match="expired"):
            pg._verify_decision(raw_data, result, "abc")


# ── Fingerprint Verification ──────────────────────────────────────────

class TestFingerprintVerification:
    def _make_signed_decision(self):
        """Helper: generate a real keypair and sign a decision."""
        import hashlib
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        private_key = Ed25519PrivateKey.generate()
        public_hex = private_key.public_key().public_bytes_raw().hex()
        fingerprint = hashlib.sha256(bytes.fromhex(public_hex)).hexdigest()[:32]
        raw_data = {
            "allowed": True,
            "decision_id": "fp-test",
            "operator_key_id": f"pg-ed25519:{fingerprint}",
            "expires_at": int(time.time()) + 300,
            "prompt_hash": "abc123",
        }
        canonical = _canonical_json(raw_data)
        sig_hex = private_key.sign(canonical).hex()
        return private_key, public_hex, fingerprint, raw_data, sig_hex

    def test_sync_fingerprint_mismatch_raises(self):
        """Sync SDK rejects decisions with wrong operator_key_id."""
        _, public_hex, _, raw_data, sig_hex = self._make_signed_decision()

        # Tamper with operator_key_id
        raw_data["operator_key_id"] = "pg-ed25519:0000000000000000000000000000dead"
        # Re-sign with tampered data so signature passes
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        private2 = Ed25519PrivateKey.generate()
        pub2_hex = private2.public_key().public_bytes_raw().hex()
        canonical = _canonical_json(raw_data)
        sig_hex = private2.sign(canonical).hex()

        pg = Prampta.__new__(Prampta)
        pg.verify_signatures = True
        pg._operator_public_key_hex = pub2_hex

        result = VerifyResult(
            allowed=True,
            decision_id="fp-test",
            operator_key_id=raw_data["operator_key_id"],
            operator_signature=sig_hex,
            expires_at=raw_data["expires_at"],
            prompt_hash="abc123",
        )

        with pytest.raises(PramptaSignatureError, match="operator_key_id does not match"):
            pg._verify_decision(raw_data, result, "abc123")

    def test_async_fingerprint_mismatch_raises(self):
        """Async SDK rejects decisions with wrong operator_key_id.

        We test _verify_decision directly which doesn't need httpx at runtime.
        """
        pytest.importorskip("httpx")
        from prampta.async_client import AsyncPrampta
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private = Ed25519PrivateKey.generate()
        pub_hex = private.public_key().public_bytes_raw().hex()

        # Sign with correct key but claim wrong fingerprint
        raw_data = {
            "allowed": True,
            "decision_id": "async-fp-test",
            "operator_key_id": "pg-ed25519:0000000000000000000000000000dead",
            "expires_at": int(time.time()) + 300,
            "prompt_hash": "abc123",
        }
        canonical = _canonical_json(raw_data)
        sig_hex = private.sign(canonical).hex()

        app = AsyncPrampta.__new__(AsyncPrampta)
        app.verify_signatures = True
        app._operator_public_key_hex = pub_hex

        result = VerifyResult(
            allowed=True,
            decision_id="async-fp-test",
            operator_key_id=raw_data["operator_key_id"],
            operator_signature=sig_hex,
            expires_at=raw_data["expires_at"],
            prompt_hash="abc123",
        )

        with pytest.raises(PramptaSignatureError, match="operator_key_id does not match"):
            app._verify_decision(raw_data, result, "abc123")

    def test_correct_fingerprint_passes(self):
        """Valid fingerprint should not raise."""
        import hashlib
        _, public_hex, fingerprint, raw_data, sig_hex = self._make_signed_decision()

        pg = Prampta.__new__(Prampta)
        pg.verify_signatures = True
        pg._operator_public_key_hex = public_hex

        result = VerifyResult(
            allowed=True,
            decision_id="fp-test",
            operator_key_id=raw_data["operator_key_id"],
            operator_signature=sig_hex,
            expires_at=raw_data["expires_at"],
            prompt_hash="abc123",
        )

        # Should not raise
        pg._verify_decision(raw_data, result, "abc123")


# ── Retry behavior ─────────────────────────────────────────────────────

class TestRetry:
    def _client(self, **kw):
        return Prampta(
            base_url="https://x", provider_id="p", licensee_id="l", token="t",
            retry_backoff=0, **kw,
        )

    def test_retries_on_5xx_then_succeeds(self):
        c = self._client(max_retries=2)
        calls = {"n": 0}

        def fn():
            calls["n"] += 1
            if calls["n"] < 2:
                raise PramptaError(503, "down")
            return {"ok": True}

        assert c._with_retry(fn) == {"ok": True}
        assert calls["n"] == 2

    def test_retries_on_429(self):
        c = self._client(max_retries=2)
        calls = {"n": 0}

        def fn():
            calls["n"] += 1
            if calls["n"] < 2:
                raise PramptaError(429, "slow down")
            return {"ok": True}

        assert c._with_retry(fn) == {"ok": True}
        assert calls["n"] == 2

    def test_no_retry_on_4xx(self):
        c = self._client(max_retries=3)
        calls = {"n": 0}

        def fn():
            calls["n"] += 1
            raise PramptaError(401, "unauthorized")

        with pytest.raises(PramptaError):
            c._with_retry(fn)
        assert calls["n"] == 1

    def test_gives_up_after_max_retries(self):
        c = self._client(max_retries=2)
        calls = {"n": 0}

        def fn():
            calls["n"] += 1
            raise PramptaError(500, "err")

        with pytest.raises(PramptaError):
            c._with_retry(fn)
        assert calls["n"] == 3  # 1 + 2 retries

    def test_max_retries_zero_disables(self):
        c = self._client(max_retries=0)
        calls = {"n": 0}

        def fn():
            calls["n"] += 1
            raise PramptaError(503, "err")

        with pytest.raises(PramptaError):
            c._with_retry(fn)
        assert calls["n"] == 1

    def test_is_retryable_classification(self):
        c = self._client()
        assert c._is_retryable(PramptaError(500, "")) is True
        assert c._is_retryable(PramptaError(429, "")) is True
        assert c._is_retryable(PramptaError(503, "")) is True
        assert c._is_retryable(PramptaError(404, "")) is False
        assert c._is_retryable(PramptaError(401, "")) is False
        assert c._is_retryable(TimeoutError()) is True
        assert c._is_retryable(ValueError("nope")) is False
