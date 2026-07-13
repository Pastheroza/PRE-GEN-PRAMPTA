/**
 * Canonical subject matcher — must stay behaviorally identical to the
 * Python SDK's match_subjects (sdk/python/tests/test_matcher.py).
 */
import { describe, it, expect } from "vitest";
import { matchSubjects, normalizeForMatch, type SubjectIndexEntry } from "../src/index";

const INDEX: SubjectIndexEntry[] = [
  { subject_id: "ada_lovelace", aliases: ["Ada L", "Лавлейс"], status: "active", visibility: "private" },
  { subject_id: "isaac_newton", aliases: ["IN"], status: "active", visibility: "public" },
  { subject_id: "leo", aliases: [], status: "withdrawn", visibility: "public" },
];

const ids = (hits: SubjectIndexEntry[]) => hits.map((h) => h.subject_id);

describe("normalizeForMatch", () => {
  it("lowercases, splits separators, strips punctuation", () => {
    expect(normalizeForMatch("Ada-Lovelace!")).toBe("ada lovelace");
    expect(normalizeForMatch("  ISAAC__newton  ")).toBe("isaac newton");
    expect(normalizeForMatch("Лавлейс, Ада")).toBe("лавлейс ада");
  });
});

describe("matchSubjects", () => {
  it("matches subject_id written as words", () => {
    expect(ids(matchSubjects("a movie poster with Ada Lovelace at the desk", INDEX)))
      .toEqual(["ada_lovelace"]);
  });

  it("matches aliases (incl. cyrillic, exact form only)", () => {
    expect(ids(matchSubjects("portrait of Ada L smiling", INDEX))).toEqual(["ada_lovelace"]);
    expect(ids(matchSubjects("книга про Ньютона", INDEX))).toEqual([]); // not an alias — baseline is exact
    expect(ids(matchSubjects("портрет: Лавлейс крупным планом", INDEX))).toEqual(["ada_lovelace"]);
  });

  it("respects whole-word boundaries", () => {
    expect(ids(matchSubjects("leonardo sketches mention ada", INDEX))).toEqual([]);
    expect(ids(matchSubjects("a photo of leo at home", INDEX))).toEqual(["leo"]);
  });

  it("still detects withdrawn subjects (hard refusals)", () => {
    const hits = matchSubjects("generate leo please", INDEX);
    expect(hits[0]?.status).toBe("withdrawn");
  });

  it("returns unique hits in index order", () => {
    expect(ids(matchSubjects("Isaac Newton meets Ada Lovelace (cameo by IN)", INDEX)))
      .toEqual(["ada_lovelace", "isaac_newton"]);
  });

  it("detects leetspeak evasion", () => {
    expect(ids(matchSubjects("draw 4da l0velace", INDEX))).toEqual(["ada_lovelace"]);
    expect(ids(matchSubjects("1saac n3wt0n portrait", INDEX))).toEqual(["isaac_newton"]);
  });

  it("detects concatenation and letter-spacing", () => {
    expect(ids(matchSubjects("an AdaLovelace tribute", INDEX))).toEqual(["ada_lovelace"]);
    expect(ids(matchSubjects("a d a l o v e l a c e please", INDEX))).toEqual(["ada_lovelace"]);
  });

  it("detects Latin diacritic evasion, preserves Cyrillic", () => {
    const idx: SubjectIndexEntry[] = [{ subject_id: "andre", aliases: [], status: "active", visibility: "public" }];
    expect(ids(matchSubjects("portrait of Àndré", idx))).toEqual(["andre"]);
    expect(ids(matchSubjects("портрет: Лавлейс", INDEX))).toEqual(["ada_lovelace"]);
  });

  it("min-length guard stops short ids matching inside words", () => {
    const idx: SubjectIndexEntry[] = [{ subject_id: "leo", aliases: [], status: "active", visibility: "public" }];
    expect(matchSubjects("a chameleon on a wall", idx)).toEqual([]);
  });
});
