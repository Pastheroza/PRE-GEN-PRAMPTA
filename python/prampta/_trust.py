"""Operator-key trust resolution — shared by the sync and async clients.

Trust model (why it works the way it does):

* A **pinned** operator public key (`operator_public_key_hex`, one or more,
  comma/space separated) is the trust anchor. It must be obtained out of band
  (from PRAMPTA's docs / a signed channel), NOT from the same API that serves
  decisions — otherwise a man-in-the-middle could serve both a forged decision
  and a matching forged key.

* A decision is trusted only when its `operator_key_id` matches one of the
  pinned keys. Pin more than one to ride through a planned rotation with zero
  downtime (pin the current key and the announced next key).

* `GET /keys` returns the operator's key set, but it is **self-signed by the
  current key**. There is no cross-signature chaining a new key to an old one,
  so a pinned client cannot cryptographically verify a *rotated* key from
  `/keys` alone (an attacker could copy the public key list and append their
  own current key). Therefore, in pinned mode, an unknown `operator_key_id`
  fails closed with an actionable error rather than being silently trusted.

* With **no** pinned key, signature verification is trust-on-first-use: it
  proves internal consistency, not authenticity. The SDK still verifies, but
  warns loudly — do not run production this way.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass


def fingerprint(public_key_hex: str) -> str:
    """PRAMPTA operator key fingerprint (matches the backend format)."""
    return f"pg-ed25519:{hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:32]}"


def parse_pins(raw: str) -> list[str]:
    """Parse one or more pinned public keys from a comma/space separated string."""
    if not raw:
        return []
    return [k.strip() for k in raw.replace(",", " ").split() if k.strip()]


TOFU_WARNING = (
    "PRAMPTA: verifying operator signatures WITHOUT a pinned key. This is "
    "trust-on-first-use and provides no protection against a malicious or "
    "compromised endpoint. Set operator_public_key_hex (from PRAMPTA's docs) "
    "before production."
)


@dataclass
class KeyChoice:
    """Outcome of resolving which public key should verify a decision."""
    public_key_hex: str | None = None
    pinned: bool = False
    warning: str | None = None
    error: str | None = None


def choose_pinned(decision_key_id: str, pinned_hexes: list[str]) -> KeyChoice | None:
    """If a pinned key matches the decision's key id, return it (trusted).
    Returns None when no pin matches."""
    for hex_key in pinned_hexes:
        try:
            if fingerprint(hex_key) == decision_key_id:
                return KeyChoice(public_key_hex=hex_key, pinned=True)
        except ValueError:
            continue
    return None


def pinned_rotation_error(decision_key_id: str) -> str:
    """Error for a decision signed by a key that isn't in the pinned set.

    Deliberately does NOT consult /keys: a pinned client cannot safely trust a
    key it can't chain to its anchor, and skipping the fetch keeps a flood of
    foreign-key decisions from turning into a flood of outbound requests.
    """
    return (
        f"Decision was signed by operator key {decision_key_id!r}, which is not in "
        f"your pinned set. If PRAMPTA rotated keys, fetch /keys, confirm the new key "
        f"out of band, and add it to operator_public_key_hex (pin current + next to "
        f"rotate without downtime). Refusing to trust an unpinned key."
    )


def resolve_unpinned(decision_key_id: str, key_set: dict) -> KeyChoice:
    """Resolve a key for `decision_key_id` from `/keys` in UNPINNED mode.

    The caller must already have checked the key set is self-consistent. There
    is no trust anchor here, so this always carries a TOFU warning.
    """
    entries = {e.get("key_id"): e.get("public_key_hex", "") for e in key_set.get("keys", [])}
    match = entries.get(decision_key_id)
    if not match:
        return KeyChoice(error=(
            f"Decision was signed by operator key {decision_key_id!r}, which is not "
            f"present in the operator key set from /keys."
        ))
    return KeyChoice(public_key_hex=match, pinned=False, warning=TOFU_WARNING)
