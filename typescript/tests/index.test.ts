import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  Prampta,
  PramptaError,
  PramptaSchemaError,
  PramptaRefusalError,
  PramptaApiError,
  PramptaSignatureError,
  PramptaFailClosedError,
  REFUSAL_DESCRIPTIONS,
  HARD_REFUSAL_CODES,
  SOFT_REFUSAL_CODES,
  type SignedDecision,
} from "../src/index";

// ── Constructor validation ──────────────────────────────────────────

describe("Prampta constructor", () => {
  it("throws if baseUrl is missing", () => {
    expect(
      () =>
        new Prampta({
          providerId: "p",
          licenseeId: "l",
          token: "t",
        }),
    ).toThrow("baseUrl is required");
  });

  it("throws if providerId is missing", () => {
    expect(
      () =>
        new Prampta({
          baseUrl: "https://api.test",
          licenseeId: "l",
          token: "t",
        }),
    ).toThrow("providerId is required");
  });

  it("throws if licenseeId is missing", () => {
    expect(
      () =>
        new Prampta({
          baseUrl: "https://api.test",
          providerId: "p",
          token: "t",
        }),
    ).toThrow("licenseeId is required");
  });

  it("throws if token is missing", () => {
    expect(
      () =>
        new Prampta({
          baseUrl: "https://api.test",
          providerId: "p",
          licenseeId: "l",
        }),
    ).toThrow("token is required");
  });

  it("creates with all required fields", () => {
    const pg = new Prampta({
      baseUrl: "https://api.test",
      providerId: "p",
      licenseeId: "l",
      token: "t",
    });
    expect(pg).toBeInstanceOf(Prampta);
  });

  it("strips trailing slashes from baseUrl", () => {
    const pg = new Prampta({
      baseUrl: "https://api.test///",
      providerId: "p",
      licenseeId: "l",
      token: "t",
    });
    expect(pg).toBeInstanceOf(Prampta);
  });
});

// ── hashPrompt ──────────────────────────────────────────────────────

describe("hashPrompt", () => {
  it("returns 64-char hex SHA-256", async () => {
    const hash = await Prampta.hashPrompt("hello world");
    expect(hash).toHaveLength(64);
    expect(hash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("is deterministic", async () => {
    const a = await Prampta.hashPrompt("test prompt");
    const b = await Prampta.hashPrompt("test prompt");
    expect(a).toBe(b);
  });

  it("different inputs produce different hashes", async () => {
    const a = await Prampta.hashPrompt("prompt A");
    const b = await Prampta.hashPrompt("prompt B");
    expect(a).not.toBe(b);
  });

  it("matches known SHA-256 value", async () => {
    const hash = await Prampta.hashPrompt("");
    expect(hash).toBe(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
  });
});

// ── Error classes ───────────────────────────────────────────────────

describe("error classes", () => {
  it("PramptaError extends Error", () => {
    const e = new PramptaError("test");
    expect(e).toBeInstanceOf(Error);
    expect(e.name).toBe("PramptaError");
  });

  it("PramptaApiError has status and detail", () => {
    const e = new PramptaApiError(403, "forbidden");
    expect(e.status).toBe(403);
    expect(e.detail).toBe("forbidden");
    expect(e.message).toContain("403");
  });

  it("PramptaSchemaError includes message", () => {
    const e = new PramptaSchemaError("missing field");
    expect(e.message).toContain("missing field");
    expect(e.name).toBe("PramptaSchemaError");
  });

  it("PramptaSignatureError includes message", () => {
    const e = new PramptaSignatureError("bad sig");
    expect(e.message).toContain("bad sig");
    expect(e.name).toBe("PramptaSignatureError");
  });

  it("PramptaRefusalError exposes decision fields", () => {
    const decision: SignedDecision = {
      schemaVersion: "pg.decision.v1",
      decisionId: "dec-001",
      allowed: false,
      reason: "PG_NO_LICENSE",
      subjectId: "sub-1",
      licenseeId: "lic-1",
      providerId: "prov-1",
      licenseId: null,
      promptHash: "abc",
      model: "gpt-4",
      modality: "image",
      intendedUse: {},
      obligations: {},
      rulesText: "",
      rulesTextHash: "",
      watermarkPayload: null,
      isHardRefusal: false,
      issuedAt: 1000,
      expiresAt: 2000,
      operatorKeyId: "pg-ed25519:abc",
      operatorSignature: "def",
      denied: true,
    };
    const e = new PramptaRefusalError(decision);
    expect(e.reason).toBe("PG_NO_LICENSE");
    expect(e.isHardRefusal).toBe(false);
    expect(e.decisionId).toBe("dec-001");
    expect(e.message).toContain("No valid license");
  });

  it("PramptaFailClosedError wraps cause", () => {
    const cause = new Error("timeout");
    const e = new PramptaFailClosedError(cause);
    expect(e.cause_).toBe(cause);
    expect(e.message).toContain("fail-closed");
  });
});

// ── Constants ───────────────────────────────────────────────────────

describe("constants", () => {
  it("REFUSAL_DESCRIPTIONS covers all hard refusal codes", () => {
    for (const code of HARD_REFUSAL_CODES) {
      expect(REFUSAL_DESCRIPTIONS[code]).toBeDefined();
    }
  });

  it("REFUSAL_DESCRIPTIONS covers all soft refusal codes", () => {
    for (const code of SOFT_REFUSAL_CODES) {
      expect(REFUSAL_DESCRIPTIONS[code]).toBeDefined();
    }
  });

  it("hard and soft codes don't overlap", () => {
    for (const code of HARD_REFUSAL_CODES) {
      expect(SOFT_REFUSAL_CODES.has(code)).toBe(false);
    }
  });
});

// ── Output metadata ─────────────────────────────────────────────────

describe("createOutputMetadata", () => {
  it("produces correct metadata structure", () => {
    const pg = new Prampta({
      baseUrl: "https://api.test",
      providerId: "prov",
      licenseeId: "lic",
      token: "tok",
    });

    const decision: SignedDecision = {
      schemaVersion: "pg.decision.v1",
      decisionId: "dec-123",
      allowed: true,
      reason: null,
      subjectId: "sub-1",
      licenseeId: "lic",
      providerId: "prov",
      licenseId: "PG-STD-000001",
      promptHash: "hash",
      model: "gpt-4",
      modality: "image",
      intendedUse: {},
      obligations: { attribution: true },
      rulesText: "",
      rulesTextHash: "",
      watermarkPayload: "wm-payload",
      isHardRefusal: false,
      issuedAt: 1000,
      expiresAt: 2000,
      operatorKeyId: "pg-ed25519:abc",
      operatorSignature: "def",
      denied: false,
    };

    const meta = pg.createOutputMetadata(decision);
    expect(meta.prampta_decision_id).toBe("dec-123");
    expect(meta.prampta_license_id).toBe("PG-STD-000001");
    expect(meta.prampta_watermark).toBe("wm-payload");
    expect(meta.prampta_obligations).toEqual({ attribution: true });
    expect(meta.prampta_issued_at).toBe(1000);
  });
});

// ── verifyGeneration (mocked fetch) ─────────────────────────────────

describe("verifyGeneration", () => {
  let pg: Prampta;

  beforeEach(() => {
    pg = new Prampta({
      baseUrl: "https://api.test",
      providerId: "prov-1",
      licenseeId: "lic-1",
      token: "test-token",
      verifyDecisionSignature: false,
    });
  });

  it("rejects if neither prompt nor promptHash given", async () => {
    await expect(
      pg.verifyGeneration({ subjectId: "sub-1" }),
    ).rejects.toThrow(PramptaSchemaError);
  });

  it("sends correct request and returns decision on allow", async () => {
    const mockDecision = {
      decision_id: "dec-001",
      allowed: true,
      reason: null,
      subject_id: "sub-1",
      licensee_id: "lic-1",
      provider_id: "prov-1",
      license_id: "PG-STD-000001",
      prompt_hash: "abc123",
      model: "dall-e-3",
      modality: "image",
      intended_use: {},
      obligations: { attribution: true },
      rules_text: "",
      rules_text_hash: "",
      watermark_payload: "wm",
      is_hard_refusal: false,
      issued_at: Math.floor(Date.now() / 1000),
      expires_at: Math.floor(Date.now() / 1000) + 300,
      operator_key_id: "pg-ed25519:abc",
      operator_signature: "sig",
    };

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockDecision),
      }),
    );

    const result = await pg.verifyGeneration({
      subjectId: "sub-1",
      promptHash: "abc123",
      modality: "image",
      model: "dall-e-3",
    });

    expect(result.allowed).toBe(true);
    expect(result.decisionId).toBe("dec-001");
    expect(result.obligations).toEqual({ attribution: true });

    const fetchCall = vi.mocked(fetch).mock.calls[0];
    expect(fetchCall[0]).toBe("https://api.test/v1/verify/");

    vi.unstubAllGlobals();
  });

  it("throws PramptaApiError on HTTP error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: false,
        status: 401,
        text: () => Promise.resolve('{"detail":"Unauthorized"}'),
      }),
    );

    await expect(
      pg.verifyGeneration({ subjectId: "sub-1", promptHash: "h" }),
    ).rejects.toThrow(PramptaFailClosedError);

    vi.unstubAllGlobals();
  });
});

// ── assertAllowed ───────────────────────────────────────────────────

describe("assertAllowed", () => {
  it("throws PramptaRefusalError on denial", async () => {
    const pg = new Prampta({
      baseUrl: "https://api.test",
      providerId: "prov-1",
      licenseeId: "lic-1",
      token: "test-token",
      verifyDecisionSignature: false,
    });

    const mockRefusal = {
      decision_id: "dec-002",
      allowed: false,
      reason: "PG_SUBJECT_OPTED_OUT",
      subject_id: "sub-1",
      licensee_id: "lic-1",
      provider_id: "prov-1",
      prompt_hash: "hash",
      is_hard_refusal: true,
      issued_at: Math.floor(Date.now() / 1000),
      expires_at: Math.floor(Date.now() / 1000) + 300,
      operator_key_id: "pg-ed25519:abc",
      operator_signature: "sig",
    };

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve(mockRefusal),
      }),
    );

    try {
      await pg.assertAllowed("sub-1", { promptHash: "hash" });
      expect.fail("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(PramptaRefusalError);
      const err = e as PramptaRefusalError;
      expect(err.reason).toBe("PG_SUBJECT_OPTED_OUT");
      expect(err.isHardRefusal).toBe(true);
    }

    vi.unstubAllGlobals();
  });
});

// ── health ──────────────────────────────────────────────────────────

describe("health", () => {
  it("returns true on success", async () => {
    const pg = new Prampta({
      baseUrl: "https://api.test",
      providerId: "p",
      licenseeId: "l",
      token: "t",
    });

    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue({
        ok: true,
        json: () => Promise.resolve({ status: "ok" }),
      }),
    );

    expect(await pg.health()).toBe(true);
    vi.unstubAllGlobals();
  });

  it("returns false on failure", async () => {
    const pg = new Prampta({
      baseUrl: "https://api.test",
      providerId: "p",
      licenseeId: "l",
      token: "t",
    });

    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("network")),
    );

    expect(await pg.health()).toBe(false);
    vi.unstubAllGlobals();
  });
});

// ── Retry behavior ──────────────────────────────────────────────────

describe("retry on transient failures", () => {
  const okDecision = {
    decision_id: "dec-retry",
    allowed: true,
    reason: null,
    subject_id: "sub-1",
    licensee_id: "lic-1",
    provider_id: "prov-1",
    prompt_hash: "h",
    is_hard_refusal: false,
    issued_at: Math.floor(Date.now() / 1000),
    expires_at: Math.floor(Date.now() / 1000) + 300,
    operator_key_id: "pg-ed25519:abc",
    operator_signature: "sig",
  };

  function client(overrides = {}) {
    return new Prampta({
      baseUrl: "https://api.test",
      providerId: "prov-1",
      licenseeId: "lic-1",
      token: "t",
      verifyDecisionSignature: false,
      retryBackoffMs: 1,
      ...overrides,
    });
  }

  it("retries on 5xx then succeeds", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: false, status: 503, text: () => Promise.resolve("down") })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(okDecision) });
    vi.stubGlobal("fetch", fetchMock);

    const res = await client().verifyGeneration({ subjectId: "sub-1", promptHash: "h" });
    expect(res.allowed).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    vi.unstubAllGlobals();
  });

  it("retries on 429 then succeeds", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce({ ok: false, status: 429, text: () => Promise.resolve("slow down") })
      .mockResolvedValueOnce({ ok: true, json: () => Promise.resolve(okDecision) });
    vi.stubGlobal("fetch", fetchMock);

    const res = await client().verifyGeneration({ subjectId: "sub-1", promptHash: "h" });
    expect(res.allowed).toBe(true);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    vi.unstubAllGlobals();
  });

  it("does NOT retry on 4xx (other than 429)", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue({ ok: false, status: 401, text: () => Promise.resolve('{"detail":"no"}') });
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      client().verifyGeneration({ subjectId: "sub-1", promptHash: "h" }),
    ).rejects.toThrow(PramptaFailClosedError);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    vi.unstubAllGlobals();
  });

  it("gives up after maxRetries and fails closed", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue({ ok: false, status: 500, text: () => Promise.resolve("err") });
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      client({ maxRetries: 2 }).verifyGeneration({ subjectId: "sub-1", promptHash: "h" }),
    ).rejects.toThrow(PramptaFailClosedError);
    expect(fetchMock).toHaveBeenCalledTimes(3); // 1 + 2 retries
    vi.unstubAllGlobals();
  });

  it("maxRetries=0 disables retries", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue({ ok: false, status: 503, text: () => Promise.resolve("err") });
    vi.stubGlobal("fetch", fetchMock);

    await expect(
      client({ maxRetries: 0 }).verifyGeneration({ subjectId: "sub-1", promptHash: "h" }),
    ).rejects.toThrow(PramptaFailClosedError);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    vi.unstubAllGlobals();
  });
});
