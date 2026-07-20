"""Async PRAMPTA client — for high-throughput AI inference pipelines.

Same trust guarantees as sync Prampta: verifies operator Ed25519 signatures,
validates TTL and prompt hash binding, fails closed by default.
"""

from __future__ import annotations

import asyncio
import hashlib
import time

from prampta.client import (
    VerifyResult, IntendedUse, Prampta,
    PramptaError, PramptaSignatureError, PramptaSchemaError, PramptaRefused,
    hash_prompt, _canonical_json, _verify_ed25519,
)

import os
import warnings

import httpx

from prampta import _trust


class AsyncPrampta:
    """Async PRAMPTA verification client with signature verification.

    Same interface as Prampta, but all methods are async.
    Requires httpx (pip install httpx).

    Example:
        async with AsyncPrampta(
            base_url="https://api2.prampta.com",
            provider_id="my-ai-service",
            licensee_id="acme-corp",
            token="pair-token",
        ) as pp:
            result = await pp.verify("subject-id", prompt="Da Vinci in a documentary", modality="image")
            if result.allowed:
                await generate(obligations=result.obligations)
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
        enforce: bool = True,
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
        self.enforce = enforce  # monitor mode when False (see sync client)
        # Retries for transient failures only (network/timeout, HTTP 429, 5xx).
        self.max_retries = max(0, max_retries)
        self.retry_backoff = retry_backoff
        self._pinned_keys = _trust.parse_pins(
            operator_public_key_hex or os.getenv("PRAMPTA_OPERATOR_PUBLIC_KEY", "")
        )
        self._key_set_cache: dict | None = None
        self._tofu_warned = False

        if not self.base_url:
            raise ValueError("base_url is required (or set PRAMPTA_BASE_URL)")
        if not self.provider_id:
            raise ValueError("provider_id is required (or set PRAMPTA_PROVIDER_ID)")
        if not self.licensee_id:
            raise ValueError("licensee_id is required (or set PRAMPTA_LICENSEE_ID)")
        if not self.token:
            raise ValueError("token is required (or set PRAMPTA_TOKEN)")

        self._client = httpx.AsyncClient(
            base_url=self.base_url,
            timeout=self.timeout,
            headers=self._headers(),
        )

    def _headers(self) -> dict[str, str]:
        return {
            "Content-Type": "application/json",
            "X-Provider-ID": self.provider_id,
            "X-Licensee-ID": self.licensee_id,
            "Authorization": f"Bearer {self.token}",
        }

    async def _fetch_verified_key_set(self) -> dict:
        """Fetch /keys and check it is self-signed by its current key. Cached."""
        if self._key_set_cache is not None:
            return self._key_set_cache
        ks = await self._get("/keys")
        entries = {e.get("key_id"): e.get("public_key_hex", "") for e in ks.get("keys", [])}
        current_hex = entries.get(ks.get("current_key_id"), "")
        sig = ks.get("signature", "")
        if not current_hex or not sig:
            raise PramptaSignatureError("Operator key set from /keys is malformed")
        body = {k: v for k, v in ks.items() if k != "signature"}
        if not _verify_ed25519(current_hex, sig, _canonical_json(body)):
            raise PramptaSignatureError("Operator key set signature is invalid")
        self._key_set_cache = ks
        return ks

    async def _resolve_operator_key(self, key_id: str) -> str:
        """Public key hex to verify a decision signed by `key_id` (see _trust)."""
        choice = _trust.choose_pinned(key_id, self._pinned_keys)
        if choice:
            return choice.public_key_hex
        # Pinned mode: never trust an unpinned key (and don't hit /keys for it).
        if self._pinned_keys:
            raise PramptaSignatureError(_trust.pinned_rotation_error(key_id))
        # Unpinned / TOFU dev mode: resolve from the self-consistent key set.
        choice = _trust.resolve_unpinned(key_id, await self._fetch_verified_key_set())
        if choice.error:
            raise PramptaSignatureError(choice.error)
        if choice.warning and not self._tofu_warned:
            warnings.warn(choice.warning, stacklevel=3)
            self._tofu_warned = True
        return choice.public_key_hex

    def _verify_decision(self, raw_data: dict, result: VerifyResult, sent_prompt_hash: str, pub_key: str) -> None:
        """Verify operator signature, TTL, and prompt hash binding. `pub_key`
        is the trust-resolved key for this decision (see _resolve_operator_key)."""
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

    async def verify(
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
        campaign_id: str = "",
        intended_use: IntendedUse | None = None,
    ) -> VerifyResult:
        """Check if generation is authorized for a subject (async).

        Either `prompt` or `prompt_hash` MUST be provided.
        If `prompt` is given, it is hashed locally (never sent to PRAMPTA).
        """
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
                campaign_id=campaign_id,
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
            data = await self._post("/v1/verify/", payload)

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

            # Verify operator signature, TTL, and payload binding. Resolve the
            # verifying key from the decision's own key_id (rotation-aware).
            pub_key = ""
            if self.verify_signatures:
                pub_key = await self._resolve_operator_key(result.operator_key_id)
            self._verify_decision(data, result, computed_hash, pub_key)

            # Verify context binding — anti-replay. Pass the FULL intended use
            # (product/project/channel/territory/categories); omitting it let an
            # ALLOW for Product A be replayed to authorize Product B.
            Prampta._verify_context_binding(
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

    async def assert_allowed(self, subject_id: str, **kwargs) -> VerifyResult:
        """Assert generation is allowed. Raises PramptaRefused (carrying the
        signed decision) if not — consistent with the sync client."""
        result = await self.verify(subject_id, **kwargs)
        if not result.allowed:
            if self.enforce:
                raise PramptaRefused(result)
            warnings.warn(
                f"PRAMPTA monitor mode: would REFUSE ({result.reason}) but enforce=False — proceeding.",
                stacklevel=2,
            )
        return result

    async def submit_receipt(
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
        return await self._post("/v1/receipts/", {
            "decision_id": decision.decision_id,
            "prompt_hash": decision.prompt_hash,
            "output_hash": output_hash,
            "model": model or decision.model,
            "watermark_embedded": watermark_embedded,
            "obligations_applied": obligations_applied if obligations_applied is not None else (decision.obligations or {}),
            "generated_at": generated_at or int(time.time()),
        })

    async def health(self) -> dict:
        """Check if the PRAMPTA registry is reachable."""
        return await self._get("/healthz")

    async def version(self) -> dict:
        """Get protocol version and operator info."""
        return await self._get("/version")

    # ── HTTP helpers ──

    def _is_retryable(self, e: Exception) -> bool:
        """Transient errors worth retrying: connectivity, timeout, 429, 5xx."""
        if isinstance(e, PramptaError):
            return e.status >= 500 or e.status == 429
        return isinstance(e, (httpx.TimeoutException, httpx.TransportError))

    async def _with_retry(self, fn):
        last_err: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                return await fn()
            except Exception as e:  # noqa: BLE001 - re-raised below if not retryable
                last_err = e
                if attempt >= self.max_retries or not self._is_retryable(e):
                    raise
                await asyncio.sleep(self.retry_backoff * (2 ** attempt))
        assert last_err is not None
        raise last_err

    async def _post(self, path: str, payload: dict) -> dict:
        return await self._with_retry(lambda: self._post_once(path, payload))

    async def _post_once(self, path: str, payload: dict) -> dict:
        resp = await self._client.post(path, json=payload)
        if resp.status_code >= 400:
            detail = (
                resp.json().get("detail", resp.text)
                if resp.headers.get("content-type", "").startswith("application/json")
                else resp.text
            )
            raise PramptaError(resp.status_code, str(detail))
        return resp.json()

    async def _get(self, path: str) -> dict:
        return await self._with_retry(lambda: self._get_once(path))

    async def _get_once(self, path: str) -> dict:
        resp = await self._client.get(path)
        if resp.status_code >= 400:
            raise PramptaError(resp.status_code, resp.text)
        return resp.json()

    async def close(self):
        """Close the HTTP client."""
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        await self.close()
