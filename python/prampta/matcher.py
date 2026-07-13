"""Subject detection helper.

PRAMPTA answers "is this generation allowed?" — but the provider must first
know WHICH subject a prompt refers to. This module gives every integration
the same canonical matching behavior instead of each service inventing its
own:

    from prampta import Prampta

    pg = Prampta(...)
    hits = pg.match_subjects("a movie poster with Ada Lovelace")
    for subject_id in hits:
        pg.assert_allowed(subject_id, prompt=..., modality="image")

The index comes from ``GET /v1/subjects/index`` (id + aliases + status for
every registration, including withdrawn/disputed — those must still be
detected because they produce hard refusals).

Matching normalizes aggressively to resist obvious text evasion — case,
Latin diacritics ("Àndré"→"andre"), leetspeak ("n1kola"→"nikola"), and
letter-spacing/concatenation ("A d a", "AdaLovelace") via a length-guarded
squeezed-substring fallback. Detection is a PRE-FILTER: over-matching only
costs an extra /verify call, while under-matching is the real risk, so we err
toward catching more. It is still TEXT-only and not semantic — it will not
detect a subject referenced via an uploaded image, a voice reference, a novel
paraphrase, or prior-message context. Those require provider-side perceptual
detection (image/audio embeddings or hashing) BEFORE calling verify; this
module is the baseline text layer, not a guarantee.

The normalization here must stay in sync with the TypeScript SDK
(``matchSubjects`` in sdk/typescript).
"""

from __future__ import annotations

import re
import time
import unicodedata
from typing import Any, Iterable

# Letters/digits (unicode) and spaces survive; everything else is a separator.
_NON_WORD = re.compile(r"[^\w ]+", re.UNICODE)
_SEPARATORS = re.compile(r"[-_]+")
_SPACES = re.compile(r" +")

# Common leetspeak → letter. Detection is a pre-filter (over-matching only costs
# an extra verify call; under-matching is the real risk), so we normalize obvious
# obfuscations aggressively. Keep in sync with the TS SDK.
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
# Minimum needle length for the squeezed (space-removed) substring fallback,
# which defeats letter-spacing ("a d a") and concatenation ("AdaLovelace").
_SQUEEZE_MIN = 5


def _strip_diacritics(t: str) -> str:
    """André → andre, so accented Latin evasions still match. Only strips accents
    off Latin (ASCII) letters — Cyrillic/other scripts are left intact (e.g. "й"
    must NOT become "и")."""
    out = []
    for ch in unicodedata.normalize("NFC", t):
        decomp = unicodedata.normalize("NFKD", ch)
        base = decomp[0] if decomp else ch
        if base.isascii() and base.isalpha():
            out.append(base)
        else:
            out.append(ch)
    return "".join(out)


def normalize_for_match(text: str) -> str:
    """Canonical normalization: lowercase, strip diacritics, de-leet, separators →
    space, strip punctuation, collapse whitespace. "Ada-Lovelace!" → "ada lovelace",
    "Àndré" → "andre", "n1kola" → "nikola"."""
    t = _strip_diacritics(text.lower())
    t = t.translate(_LEET)
    t = _SEPARATORS.sub(" ", t)
    t = _NON_WORD.sub(" ", t)
    return _SPACES.sub(" ", t).strip()


def _squeeze(t: str) -> str:
    """Remove all spaces — defeats letter-spacing and concatenation evasion."""
    return t.replace(" ", "")


def match_subjects(text: str, index_entries: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return index entries whose subject_id or any alias appears in *text*
    as a whole-word phrase. Order follows the index; entries are unique."""
    norm = normalize_for_match(text)
    haystack = f" {norm} "
    squeezed_haystack = _squeeze(norm)
    hits: list[dict[str, Any]] = []
    for entry in index_entries:
        candidates = [entry.get("subject_id", "")] + list(entry.get("aliases") or [])
        for cand in candidates:
            needle = normalize_for_match(cand)
            if not needle:
                continue
            # 1) whole-word phrase containment ("...with ada lovelace...")
            if f" {needle} " in haystack:
                hits.append(entry)
                break
            # 2) squeezed substring — defeats "AdaLovelace" / "a d a l o v e l a c e"
            sq = _squeeze(needle)
            if len(sq) >= _SQUEEZE_MIN and sq in squeezed_haystack:
                hits.append(entry)
                break
    return hits


class SubjectIndexCache:
    """TTL cache around the /v1/subjects/index endpoint.

    ``fetch`` is any callable returning the parsed index payload — the
    client passes its own HTTP helper so retries/auth stay in one place.
    """

    def __init__(self, fetch, ttl_seconds: float = 300.0):
        self._fetch = fetch
        self._ttl = ttl_seconds
        self._entries: list[dict[str, Any]] | None = None
        self._fetched_at = 0.0

    def entries(self, force_refresh: bool = False) -> list[dict[str, Any]]:
        now = time.time()
        if force_refresh or self._entries is None or now - self._fetched_at > self._ttl:
            payload = self._fetch()
            self._entries = list(payload.get("subjects") or [])
            self._fetched_at = now
        return self._entries
