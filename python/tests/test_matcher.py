"""Canonical subject matcher — must stay behaviorally identical to the
TypeScript SDK's matchSubjects (sdk/typescript/tests/matcher.test.ts)."""

import time

from prampta.matcher import SubjectIndexCache, match_subjects, normalize_for_match

INDEX = [
    {"subject_id": "ada_lovelace", "aliases": ["Ada L", "Лавлейс"], "status": "active", "visibility": "private"},
    {"subject_id": "isaac_newton", "aliases": ["IN"], "status": "active", "visibility": "public"},
    {"subject_id": "leo", "aliases": [], "status": "withdrawn", "visibility": "public"},
]


def _ids(hits):
    return [h["subject_id"] for h in hits]


def test_normalize():
    assert normalize_for_match("Ada-Lovelace!") == "ada lovelace"
    assert normalize_for_match("  ISAAC__newton  ") == "isaac newton"
    assert normalize_for_match("Лавлейс, Ада") == "лавлейс ада"


def test_matches_subject_id_written_as_words():
    hits = match_subjects("a movie poster with Ada Lovelace at the desk", INDEX)
    assert _ids(hits) == ["ada_lovelace"]


def test_matches_alias():
    assert _ids(match_subjects("portrait of Ada L smiling", INDEX)) == ["ada_lovelace"]
    assert _ids(match_subjects("книга про Ньютона", INDEX)) == []  # not an alias — baseline matcher is exact
    assert _ids(match_subjects("портрет: Лавлейс крупным планом", INDEX)) == ["ada_lovelace"]


def test_whole_word_boundary():
    # "leo" must not fire inside "leonardo"
    assert _ids(match_subjects("leonardo sketches mention ada", INDEX)) == []
    assert _ids(match_subjects("a photo of leo at home", INDEX)) == ["leo"]


def test_withdrawn_subjects_still_detected():
    hits = match_subjects("generate leo please", INDEX)
    assert hits and hits[0]["status"] == "withdrawn"


def test_multiple_hits_unique_and_ordered():
    text = "Isaac Newton meets Ada Lovelace (cameo by IN)"
    assert _ids(match_subjects(text, INDEX)) == ["ada_lovelace", "isaac_newton"]


def test_index_cache_ttl():
    calls = {"n": 0}

    def fetch():
        calls["n"] += 1
        return {"subjects": [{"subject_id": f"s{calls['n']}", "aliases": []}]}

    cache = SubjectIndexCache(fetch, ttl_seconds=0.05)
    assert cache.entries()[0]["subject_id"] == "s1"
    assert cache.entries()[0]["subject_id"] == "s1"  # cached
    assert calls["n"] == 1
    time.sleep(0.06)
    assert cache.entries()[0]["subject_id"] == "s2"  # expired → refetch
    assert cache.entries(force_refresh=True)[0]["subject_id"] == "s3"


def test_detects_leetspeak_evasion():
    # 4=a, 1=i, 3=e, 0=o, 5=s, 7=t — detection over-matching is safe.
    assert _ids(match_subjects("draw 4da l0velace", INDEX)) == ["ada_lovelace"]
    assert _ids(match_subjects("1saac n3wt0n portrait", INDEX)) == ["isaac_newton"]


def test_detects_concatenation_and_letter_spacing():
    assert _ids(match_subjects("an AdaLovelace tribute", INDEX)) == ["ada_lovelace"]
    assert _ids(match_subjects("a d a l o v e l a c e please", INDEX)) == ["ada_lovelace"]


def test_detects_diacritic_evasion():
    idx = [{"subject_id": "andre", "aliases": [], "status": "active", "visibility": "public"}]
    assert _ids(match_subjects("portrait of Àndré", idx)) == ["andre"]


def test_squeeze_min_length_guards_short_ids():
    # Short ids must not match as substrings of unrelated words.
    idx = [{"subject_id": "leo", "aliases": [], "status": "active", "visibility": "public"}]
    assert match_subjects("a chameleon on a wall", idx) == []
