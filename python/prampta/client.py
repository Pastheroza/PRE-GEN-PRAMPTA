"""PRAMPTA Python SDK — verification client with signature verification.

Not a blind HTTP wrapper: verifies operator Ed25519 signatures on decisions,
validates TTL and prompt hash binding, fails closed by default.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Optional, Any

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

try:
    import httpx
    _HTTP = "httpx"
except ImportError:
    import urllib.request
    import urllib.error
    _HTTP = "stdlib"


# ── Errors ──────────────────────────────────────────────────────────────

class PramptaError(Exception):
    """Raised when the PRAMPTA API returns an unexpected error."""
    def __init__(self, status: int, detail: str):
        self.status = status
        self.detail = detail
        super().__init__(f"PRAMPTA API error {status}: {detail}")


class PramptaSignatureError(Exception):
    """Decision signature verification failed — cannot be trusted."""
    pass


class PramptaSchemaError(Exception):
    """Decision is missing required fields or has invalid shape."""
    pass


class PramptaRefused(Exception):
    """Generation was NOT authorized — raised by generate_guarded so the model is
    never invoked on a refusal. Carries the signed decision for logging/handling."""
    def __init__(self, decision: "VerifyResult"):
        self.decision = decision
        self.reason = decision.reason
        super().__init__(f"PRAMPTA refused generation: {decision.reason}")


# ── Types ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class VerifyResult:
    """Signed decision from PRAMPTA verification.

    Attributes:
        allowed: Whether generation is authorized.
        decision_id: Unique ID for this decision (for audit trail).
        reason: Refusal code if not allowed (e.g. PG_NO_LICENSE).
        license_id: The license that authorized this generation.
        obligations: Required obligations (e.g. watermark, disclosure).
        watermark_payload: Hash to embed in generated content.
        is_hard_refusal: If True, this refusal cannot be overridden.
        operator_key_id: Fingerprint of operator key that signed.
        operator_signature: Ed25519 signature hex.
        issued_at: Unix timestamp when decision was issued.
        expires_at: Unix timestamp when decision expires.
        prompt_hash: SHA-256 hash of the prompt this decision is bound to.
    """
    allowed: bool
    decision_id: str
    reason: Optional[str] = None
    license_id: Optional[str] = None
    obligations: dict = field(default_factory=dict)
    watermark_payload: Optional[str] = None
    is_hard_refusal: bool = False
    operator_key_id: str = ""
    operator_signature: str = ""
    issued_at: int = 0
    expires_at: int = 0
    prompt_hash: str = ""
    #: The AI model this decision is bound to (echoed by the server).
    model: str = ""
    #: Strongest authority backing the subject: self | agency_asserted |
    #: consented | verified. "self" means only the registrant's own claim —
    #: consumers may want to require a higher tier for commercial use.
    subject_authority: str = ""

    @property
    def denied(self) -> bool:
        return not self.allowed


@dataclass
class IntendedUse:
    """Describes the intended use of the generation."""
    channel: str = ""
    product_name: str = ""
    project_name: str = ""
    categories: list[str] = field(default_factory=list)
    modality: str = ""
    territory: str = ""

    def to_dict(self) -> dict:
        return {
            "channel": self.channel,
            "product_name": self.product_name,
            "project_name": self.project_name,
            "categories": self.categories,
            "modality": self.modality,
            "territory": self.territory,
        }


# ── Helpers ─────────────────────────────────────────────────────────────

def hash_prompt(prompt: str) -> str:
    """Hash a prompt with SHA-256 — same as what PRAMPTA uses."""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def _canonical_json(obj: Any) -> bytes:
    """Canonical JSON matching Python backend's canonical_json.

    sort_keys=True, separators=(",", ":"), ensure_ascii=False.
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _verify_ed25519(public_key_hex: str, signature_hex: str, message: bytes) -> bool:
    """Verify Ed25519 signature. Requires cryptography package."""
    if not _HAS_CRYPTO:
        raise PramptaSignatureError(
            "cryptography package required for signature verification: pip install cryptography"
        )
    try:
        pub_bytes = bytes.fromhex(public_key_hex)
        sig_bytes = bytes.fromhex(signature_hex)
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        public_key.verify(sig_bytes, message)
        return True
    except Exception:
        return False


# ── Client ──────────────────────────────────────────────────────────────

class Prampta:
    """PRAMPTA verification client with signature verification.

    Args:
        base_url: The PRAMPTA registry URL (or PRAMPTA_BASE_URL env var).
        provider_id: Your provider ID (or PRAMPTA_PROVIDER_ID env var).
        licensee_id: The licensee ID (or PRAMPTA_LICENSEE_ID env var).
        token: The pair authentication token (or PRAMPTA_TOKEN env var).
        timeout: Request timeout in seconds (default 10).
        verify_signatures: If True (default), verify operator Ed25519 signatures.
        operator_public_key_hex: Pinned operator public key. If not set, fetched from /version.
        fail_closed: If True (default), deny on any error/timeout.

    Example:
        pp = Prampta(
            base_url="https://api2.prampta.com",
            provider_id="my-ai-service",
            licensee_id="acme-corp",
            token="pair-token",
        )

        # prompt or prompt_hash is REQUIRED — no empty fallback
        result = pp.verify("subject-id", prompt="Da Vinci in a documentary", modality="image")
        if result.allowed:
            generate(obligations=result.obligations)
    """

    def __init__(
        self,
        base_url: str | None = None,
        provider_id: str | None = None,
        licensee_id: str | None = None,
        token: str | None = None,
        timeout: float = 10.0,
        verify_signatures: bool = True,
        operator_public_key_hex: str | None = None,
        fail_closed: bool = True,
        max_retries: int = 2,
        retry_backoff: float = 0.2,
    ):
        self.base_url = (base_url or os.getenv("PRAMPTA_BASE_URL", "")).rstrip("/")
        self.provider_id = provider_id or os.getenv("PRAMPTA_PROVIDER_ID", "")
        self.licensee_id = licensee_id or os.getenv("PRAMPTA_LICENSEE_ID", "")
        self.token = token or os.getenv("PRAMPTA_TOKEN", "")
        self.timeout = timeout
        self.verify_signatures = verify_signatures
        self.fail_closed = fail_closed
        # Retries for transient failures only (network/timeout, HTTP 429, 5xx).
        # Non-transient errors (4xx other than 429, refusals, signature/schema
        # errors) are never retried. Set max_retries=0 to disable.
        self.max_retries = max(0, max_retries)
        self.retry_backoff = retry_backoff
        self._operator_public_key_hex = operator_public_key_hex or os.getenv("PRAMPTA_OPERATOR_PUBLIC_KEY", "")

        if not self.base_url:
            raise ValueError("base_url is required (or set PRAMPTA_BASE_URL)")
        if not self.provider_id:
            raise ValueError("provider_id is required (or set PRAMPTA_PROVIDER_ID)")
        if not self.licensee_id:
            raise ValueError("licensee_id is required (or set PRAMPTA_LICENSEE_ID)")
        if not self.token:
            raise ValueError("token is required (or set PRAMPTA_TOKEN)")

        if _HTTP == "httpx":
            self._client = httpx.Client(
                base_url=self.base_url,
                timeout=self.timeout,
                headers=self._headers(),
            )
        else:
            self._client = None

        # Lazy TTL cache for the subject detection index (see match_subjects)
        self._subject_index = None

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "X-Provider-ID": self.provider_id,
            "X-Licensee-ID": self.licensee_id,
            "Authorization": f"Bearer {self.token}",
        }

    def _get_operator_key(self) -> str:
        """Get operator public key — from config or fetched from /version."""
        if self._operator_public_key_hex:
            return self._operator_public_key_hex
        version_data = self._get("/version")
        key = version_data.get("operator_public_key", "")
        if not key or len(key) != 64:
            raise PramptaSignatureError("Operator public key from /version is invalid")
        self._operator_public_key_hex = key
        return key

    def _verify_decision(self, raw_data: dict, result: VerifyResult, sent_prompt_hash: str) -> None:
        """Verify operator signature, TTL, and prompt hash binding."""
        if not self.verify_signatures:
            return

        sig = result.operator_signature
        if not sig:
            raise PramptaSignatureError("Decision missing operator_signature")
        if not result.operator_key_id:
            raise PramptaSignatureError("Decision missing operator_key_id")

        # Rebuild canonical body (exclude signature field)
        body = {k: v for k, v in raw_data.items() if k != "operator_signature"}
        canonical = _canonical_json(body)

        pub_key = self._get_operator_key()

        # Verify operator_key_id matches the actual public key fingerprint
        expected_fp = f"pg-ed25519:{hashlib.sha256(bytes.fromhex(pub_key)).hexdigest()[:32]}"
        if result.operator_key_id != expected_fp:
            raise PramptaSignatureError(
                f"operator_key_id does not match public key: expected {expected_fp}, got {result.operator_key_id}"
            )
        if not _verify_ed25519(pub_key, sig, canonical):
            raise PramptaSignatureError(
                "Operator signature is invalid — decision cannot be trusted"
            )

        # Verify TTL
        now = int(time.time())
        if result.expires_at > 0 and result.expires_at < now:
            raise PramptaSignatureError(
                f"Decision expired at {result.expires_at}, current time {now}"
            )

        # Verify prompt hash binding
        if result.prompt_hash and result.prompt_hash != sent_prompt_hash:
            raise PramptaSignatureError(
                f"Decision prompt_hash mismatch: sent {sent_prompt_hash}, got {result.prompt_hash}"
            )

    @staticmethod
    def _verify_context_binding(
        raw_data: dict,
        subject_id: str,
        provider_id: str,
        licensee_id: str,
        modality: str,
        model: str,
        intended_use: "IntendedUse | None" = None,
    ) -> None:
        """Verify the decision is bound to the correct request context (anti-replay).

        Includes the FULL intended use (product/project/channel/territory/
        categories) — otherwise an ALLOW issued for Product A could be replayed to
        authorize Product B when subject/prompt/model/modality happen to match.
        """
        checks = [
            ("subject_id", raw_data.get("subject_id", ""), subject_id),
            ("provider_id", raw_data.get("provider_id", ""), provider_id),
            ("licensee_id", raw_data.get("licensee_id", ""), licensee_id),
        ]
        for field_name, got, sent in checks:
            if got and sent and got != sent:
                raise PramptaSignatureError(
                    f"Decision {field_name} mismatch: sent {sent!r}, got {got!r}"
                )
        if raw_data.get("modality") and modality and raw_data["modality"] != modality:
            raise PramptaSignatureError(
                f"Decision modality mismatch: sent {modality!r}, got {raw_data['modality']!r}"
            )
        if raw_data.get("model") and model and raw_data["model"] != model:
            raise PramptaSignatureError(
                f"Decision model mismatch: sent {model!r}, got {raw_data['model']!r}"
            )
        # Bind the full intended use the decision was issued for.
        if intended_use is not None:
            got_iu = raw_data.get("intended_use") or {}
            for field_name, sent in (
                ("product_name", intended_use.product_name),
                ("project_name", intended_use.project_name),
                ("channel", intended_use.channel),
                ("territory", intended_use.territory),
            ):
                got = got_iu.get(field_name, "")
                if got and sent and got != sent:
                    raise PramptaSignatureError(
                        f"Decision {field_name} mismatch: sent {sent!r}, got {got!r}"
                    )
            got_cats = set(got_iu.get("categories") or [])
            sent_cats = set(intended_use.categories or [])
            if got_cats and sent_cats and got_cats != sent_cats:
                raise PramptaSignatureError(
                    f"Decision categories mismatch: sent {sorted(sent_cats)}, got {sorted(got_cats)}"
                )

    def verify(
        self,
        subject_id: str,
        *,
        prompt: str = "",
        prompt_hash: str = "",
        modality: str = "",
        model: str = "",
        categories: list[str] | None = None,
        channel: str = "",
        product_name: str = "",
        intended_use: IntendedUse | None = None,
    ) -> VerifyResult:
        """Check if generation is authorized for a subject.

        Either `prompt` or `prompt_hash` MUST be provided.
        If `prompt` is given, it is hashed locally (never sent to PRAMPTA).

        Args:
            subject_id: The PG subject identifier (e.g. "leonardo-da-vinci").
            prompt: Raw prompt text — hashed locally, never sent.
            prompt_hash: Pre-computed SHA-256 hash. Use instead of prompt.
            modality: Generation modality ("image", "video", "audio", "text").
            model: The AI model being used (for audit).
            categories: Content categories (e.g. ["endorsement", "adult"]).
            channel: Distribution channel.
            product_name: The product this is for (for exception matching).
            intended_use: Full IntendedUse object (overrides individual params).

        Returns:
            VerifyResult with .allowed, .reason, .license_id, etc.

        Raises:
            PramptaSchemaError: If neither prompt nor prompt_hash is provided.
            PramptaSignatureError: If decision signature verification fails.
            PramptaError: On API errors (network, auth, server issues).
        """
        # Compute prompt hash — REQUIRE prompt or prompt_hash
        computed_hash = prompt_hash or (hash_prompt(prompt) if prompt else "")
        if not computed_hash:
            raise PramptaSchemaError(
                "Either prompt or prompt_hash is required. "
                "SDK does not allow empty prompt hashes to prevent unbound decisions."
            )

        if intended_use is None:
            intended_use = IntendedUse(
                channel=channel,
                product_name=product_name,
                categories=categories or [],
                modality=modality,
            )

        payload = {
            "subject_id": subject_id,
            "modality": modality or intended_use.modality,
            "model": model,
            "prompt_hash": computed_hash,
            "intended_use": intended_use.to_dict(),
        }

        try:
            data = self._post("/v1/verify/", payload)

            result = VerifyResult(
                allowed=data.get("allowed", False),
                decision_id=data.get("decision_id", ""),
                reason=data.get("reason"),
                license_id=data.get("license_id"),
                obligations=data.get("obligations", {}),
                watermark_payload=data.get("watermark_payload"),
                is_hard_refusal=data.get("is_hard_refusal", False),
                operator_key_id=data.get("operator_key_id", ""),
                operator_signature=data.get("operator_signature", ""),
                issued_at=data.get("issued_at", 0),
                expires_at=data.get("expires_at", 0),
                prompt_hash=data.get("prompt_hash", ""),
                model=data.get("model", ""),
                subject_authority=data.get("subject_authority", ""),
            )

            # Verify operator signature, TTL, and payload binding
            self._verify_decision(data, result, computed_hash)

            # Verify context binding — anti-replay
            self._verify_context_binding(
                data, subject_id, self.provider_id, self.licensee_id,
                modality or intended_use.modality, model, intended_use,
            )

            return result

        except (PramptaError, PramptaSignatureError, PramptaSchemaError):
            raise
        except Exception as e:
            if self.fail_closed:
                raise PramptaSignatureError(f"Fail-closed: {e}") from e
            raise

    def assert_allowed(self, subject_id: str, **kwargs) -> VerifyResult:
        """Assert generation is allowed. Raises on refusal."""
        result = self.verify(subject_id, **kwargs)
        if not result.allowed:
            raise PramptaError(403, f"Generation refused: {result.reason}")
        return result

    def submit_receipt(
        self,
        decision: VerifyResult,
        *,
        output_hash: str = "",
        model: str = "",
        watermark_embedded: bool = False,
        obligations_applied: dict | None = None,
        generated_at: int = 0,
    ) -> dict:
        """Submit a generation receipt AFTER generating — enforcement proof bound
        to the decision (proves the generation was authorized and executed)."""
        return self._post("/v1/receipts/", {
            "decision_id": decision.decision_id,
            "prompt_hash": decision.prompt_hash,
            "output_hash": output_hash,
            "model": model or decision.model,
            "watermark_embedded": watermark_embedded,
            "obligations_applied": obligations_applied if obligations_applied is not None else (decision.obligations or {}),
            "generated_at": generated_at or int(time.time()),
        })

    def generate_guarded(
        self,
        subject_id: str,
        generate,
        *,
        prompt: str = "",
        prompt_hash: str = "",
        modality: str = "",
        model: str = "",
        intended_use: "IntendedUse | None" = None,
        output_hash=None,
        submit_receipt: bool = True,
    ):
        """Enforce authorization AROUND a generation call — the right place for a
        provider to integrate PRAMPTA (enforcement BEFORE model invocation, not
        relying on an agent choosing to call a tool).

        Flow: verify → if not allowed raise PramptaRefused (generate is NEVER
        called) → run generate() → submit a receipt bound to the decision.

        Args:
            generate: zero-arg callable that performs the actual model call and
                returns its result. Only invoked on an ALLOW.
            output_hash: optional str, or a callable(result)->str, used for the
                receipt's tamper-evident output proof.
            submit_receipt: set False to skip the post-generation receipt.

        Returns the result of generate(). Raises PramptaRefused on a refusal.
        """
        decision = self.verify(
            subject_id, prompt=prompt, prompt_hash=prompt_hash,
            modality=modality, model=model, intended_use=intended_use,
        )
        if not decision.allowed:
            raise PramptaRefused(decision)

        result = generate()

        if submit_receipt:
            oh = output_hash(result) if callable(output_hash) else (output_hash or "")
            try:
                self.submit_receipt(decision, output_hash=oh, model=model)
            except Exception:
                # The receipt is compliance proof; a failure to record it must not
                # undo an already-authorized, already-produced generation.
                pass
        return result

    def health(self) -> dict:
        """Check if the PRAMPTA registry is reachable."""
        return self._get("/healthz")

    def version(self) -> dict:
        """Get protocol version and operator info."""
        return self._get("/version")

    # ── Subject detection ──

    def fetch_subject_index(self) -> dict:
        """Fetch the raw subject detection index (/v1/subjects/index)."""
        return self._get("/v1/subjects/index")

    def match_subjects(self, text: str, force_refresh: bool = False) -> list[dict]:
        """Detect registered subjects mentioned in *text*.

        Uses the canonical PRAMPTA matcher over a TTL-cached copy of the
        subject index. Returns matching index entries (subject_id, aliases,
        status, visibility) — call verify()/assert_allowed() for each hit.
        """
        from prampta.matcher import SubjectIndexCache, match_subjects

        if self._subject_index is None:
            self._subject_index = SubjectIndexCache(self.fetch_subject_index)
        return match_subjects(text, self._subject_index.entries(force_refresh=force_refresh))

    # ── HTTP helpers ──

    def _is_retryable(self, e: Exception) -> bool:
        """Transient errors worth retrying: connectivity, timeout, 429, 5xx."""
        if isinstance(e, PramptaError):
            return e.status >= 500 or e.status == 429
        if _HTTP == "httpx":
            if isinstance(e, (httpx.TimeoutException, httpx.TransportError)):
                return True
        else:
            if isinstance(e, urllib.error.URLError):
                return True
        return isinstance(e, TimeoutError)

    def _with_retry(self, fn):
        last_err: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                return fn()
            except Exception as e:  # noqa: BLE001 - re-raised below if not retryable
                last_err = e
                if attempt >= self.max_retries or not self._is_retryable(e):
                    raise
                time.sleep(self.retry_backoff * (2 ** attempt))
        assert last_err is not None
        raise last_err

    def _post(self, path: str, payload: dict) -> dict:
        return self._with_retry(lambda: self._post_once(path, payload))

    def _post_once(self, path: str, payload: dict) -> dict:
        if _HTTP == "httpx":
            resp = self._client.post(path, json=payload)
            if resp.status_code >= 400:
                detail = resp.json().get("detail", resp.text) if resp.headers.get("content-type", "").startswith("application/json") else resp.text
                raise PramptaError(resp.status_code, str(detail))
            return resp.json()
        else:
            return self._stdlib_request("POST", path, payload)

    def _get(self, path: str) -> dict:
        return self._with_retry(lambda: self._get_once(path))

    def _get_once(self, path: str) -> dict:
        if _HTTP == "httpx":
            resp = self._client.get(path)
            if resp.status_code >= 400:
                raise PramptaError(resp.status_code, resp.text)
            return resp.json()
        else:
            return self._stdlib_request("GET", path)

    def _stdlib_request(self, method: str, path: str, payload: dict | None = None) -> dict:
        url = f"{self.base_url}{path}"
        data = json.dumps(payload).encode() if payload else None
        req = urllib.request.Request(url, data=data, headers=self._headers(), method=method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            try:
                detail = json.loads(body).get("detail", body)
            except (json.JSONDecodeError, AttributeError):
                detail = body
            raise PramptaError(e.code, str(detail)) from e

    def close(self):
        """Close the HTTP client (only needed for httpx)."""
        if _HTTP == "httpx" and self._client:
            self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
