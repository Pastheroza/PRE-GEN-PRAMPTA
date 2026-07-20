/**
 * PRAMPTA SDK for TypeScript / Node.js
 *
 * Pre-generation authorization for AI content.
 * Verifies operator Ed25519 signatures on decisions — not a blind HTTP wrapper.
 *
 * @example Basic verification
 * ```ts
 * import { Prampta } from "@prampta/sdk";
 *
 * const pg = new Prampta({
 *   baseUrl: "https://api2.prampta.com",
 *   providerId: "my-ai-service",
 *   licenseeId: "acme-corp",
 *   token: "pair-token",
 * });
 *
 * // Throws if denied — fail-closed by default
 * await pg.assertAllowed("leonardo-da-vinci", {
 *   prompt: "Da Vinci in a documentary",
 *   modality: "image",
 *   model: "gpt-image-1",
 * });
 * ```
 */

import * as ed from "@noble/ed25519";

// ── Types ──────────────────────────────────────────────────────────────

export interface PramptaConfig {
  /** The PRAMPTA registry URL. Falls back to PRAMPTA_BASE_URL env var. */
  baseUrl?: string;
  /** Your provider ID. Falls back to PRAMPTA_PROVIDER_ID env var. */
  providerId?: string;
  /** The licensee ID. Falls back to PRAMPTA_LICENSEE_ID env var. */
  licenseeId?: string;
  /** The pair authentication token. Falls back to PRAMPTA_TOKEN env var. */
  token?: string;
  /** Request timeout in milliseconds (default 3000). */
  timeoutMs?: number;
  /**
   * Max retry attempts for transient failures (network errors, timeouts,
   * HTTP 429, and 5xx). Default 2 (so up to 3 total attempts). Set 0 to disable.
   * Retries use exponential backoff. Non-transient errors (4xx other than 429,
   * refusals, signature/schema errors) are never retried.
   */
  maxRetries?: number;
  /** Base backoff in ms between retries; doubles each attempt. Default 200. */
  retryBackoffMs?: number;
  /** If true (default), deny on backend errors/timeouts. */
  failClosed?: boolean;
  /**
   * Pinned operator public key(s), hex — the trust anchor for signature
   * verification. Obtain out of band (PRAMPTA docs), not from the API that
   * serves decisions. Pass one, or several (comma/space separated) to pin the
   * current + next key and rotate with zero downtime. Falls back to
   * PRAMPTA_OPERATOR_PUBLIC_KEY. If omitted, verification runs in
   * trust-on-first-use mode (a warning is emitted) — do not do this in prod.
   */
  operatorPublicKeyHex?: string;
  /**
   * Monitor mode: when false, refusals do NOT block generation — the SDK still
   * verifies and records a signed decision, but assertAllowed / withAuthorization
   * proceed instead of throwing. Use for a pilot rollout. Default true.
   */
  enforce?: boolean;
  /**
   * If true (default), verify operator signature on every decision.
   * Set to false ONLY for local development — never in production.
   */
  verifyDecisionSignature?: boolean;
}

export interface VerifyRequest {
  /** Subject to verify authorization for. */
  subjectId: string;
  /** Raw prompt text — will be hashed, never sent to PRAMPTA. */
  prompt?: string;
  /** Pre-computed SHA-256 hash. Use instead of prompt if you've already hashed. */
  promptHash?: string;
  /** Generation modality: "image", "video", "audio", "text", "3d". */
  modality?: string;
  /** The AI model being used. */
  model?: string;
  /** Intended use metadata. */
  intendedUse?: {
    channel?: string;
    productName?: string;
    projectName?: string;
    categories?: string[];
    territory?: string;
    /** Commercial-model campaign binding — required by premium billing terms. */
    campaignId?: string;
  };
}

/** Options for the flat `pg.verify(subjectId, options)` convenience call. */
export interface VerifyOptions extends Omit<VerifyRequest, "subjectId"> {
  categories?: string[];
  channel?: string;
  productName?: string;
  projectName?: string;
  territory?: string;
  campaignId?: string;
}

export interface SignedDecision {
  schemaVersion: string;
  decisionId: string;
  allowed: boolean;
  reason: string | null;
  subjectId: string;
  licenseeId: string;
  providerId: string;
  licenseId: string | null;
  promptHash: string;
  model: string;
  modality: string;
  intendedUse: Record<string, unknown>;
  obligations: Record<string, unknown>;
  rulesText: string;
  rulesTextHash: string;
  watermarkPayload: string | null;
  isHardRefusal: boolean;
  issuedAt: number;
  expiresAt: number;
  operatorKeyId: string;
  operatorSignature: string;
  /** Strongest authority backing the subject: self | agency_asserted |
   * consented | verified. "self" is only the registrant's own claim. */
  subjectAuthority: string;
  denied: boolean;
}

export interface SubjectInfo {
  subjectId: string;
  status: string;
  visibility: string;
  rulesText: string;
  aliases: string[];
  publicKeyHex?: string;
  publicKeyFingerprint?: string;
  registeredAt: string;
}

export interface LicenseRequestInput {
  subjectId: string;
  useCase: "commercial" | "editorial" | "personal" | "educational" | "research";
  purpose?: string;
  durationDays?: number;
  message?: string;
}

export interface LicenseRequestResult {
  requestId: string;
  status: string;
}

export interface OutputMetadata {
  prampta_decision_id: string;
  prampta_license_id: string | null;
  prampta_watermark: string | null;
  prampta_obligations: Record<string, unknown>;
  prampta_issued_at: number;
}

// ── Errors ─────────────────────────────────────────────────────────────

export class PramptaError extends Error {
  constructor(message: string) { super(message); this.name = "PramptaError"; }
}

export class PramptaNetworkError extends PramptaError {
  constructor(public readonly cause_: unknown) {
    super(`PRAMPTA backend unreachable: ${cause_}`);
    this.name = "PramptaNetworkError";
  }
}

export class PramptaTimeoutError extends PramptaError {
  constructor(public readonly timeoutMs: number) {
    super(`PRAMPTA request timed out after ${timeoutMs}ms`);
    this.name = "PramptaTimeoutError";
  }
}

export class PramptaApiError extends PramptaError {
  constructor(public readonly status: number, public readonly detail: string) {
    super(`PRAMPTA API error ${status}: ${detail}`);
    this.name = "PramptaApiError";
  }
}

export class PramptaSchemaError extends PramptaError {
  constructor(message: string) {
    super(`PRAMPTA schema error: ${message}`);
    this.name = "PramptaSchemaError";
  }
}

/** Operator signature verification failed — decision cannot be trusted. */
export class PramptaSignatureError extends PramptaError {
  constructor(message: string) {
    super(`PRAMPTA signature verification failed: ${message}`);
    this.name = "PramptaSignatureError";
  }
}

export class PramptaRefusalError extends PramptaError {
  constructor(public readonly decision: SignedDecision) {
    const desc = REFUSAL_DESCRIPTIONS[decision.reason || ""] || decision.reason;
    super(`Generation refused: ${desc}`);
    this.name = "PramptaRefusalError";
  }
  get reason(): string { return this.decision.reason || "UNKNOWN"; }
  get isHardRefusal(): boolean { return this.decision.isHardRefusal; }
  get decisionId(): string { return this.decision.decisionId; }
  get licenseId(): string | null { return this.decision.licenseId; }
}

export class PramptaFailClosedError extends PramptaError {
  constructor(public readonly cause_: unknown) {
    super(`PRAMPTA fail-closed: generation blocked because verification failed (${cause_})`);
    this.name = "PramptaFailClosedError";
  }
}

// ── Constants ──────────────────────────────────────────────────────────

export const REFUSAL_DESCRIPTIONS: Record<string, string> = {
  PG_CAMPAIGN_REQUIRED: "This license requires a campaign_id on every generation",
  PG_BUDGET_EXHAUSTED: "The license's prepaid balance cannot cover this generation — top up the balance",
  PG_RECEIPTS_OVERDUE: "Too many authorized generations without receipts — submit receipts to resume",
  PG_NO_SUBJECT: "Subject not found in registry",
  PG_SUBJECT_PENDING: "Subject registration is pending approval",
  PG_SUBJECT_DISPUTED: "Subject is under dispute — generation blocked",
  PG_SUBJECT_WITHDRAWN: "Subject has been withdrawn from registry",
  PG_SUBJECT_OPTED_OUT: "Subject has opted out of AI generation",
  PG_NO_LICENSE: "No valid license for this subject/licensee pair",
  PG_NO_PAIR: "Provider-licensee pair not established",
  PG_INVALID_SIGNATURE: "License signature verification failed",
  PG_IMMUTABLE_DENIAL: "Content category permanently denied by subject",
  PG_SCOPE_VIOLATION: "Intended use outside license scope",
  PG_EXTENSION_REFUSED: "License extension constraint not satisfied",
  PG_BACKEND_UNAVAILABLE: "Backend unreachable — fail-closed",
};

export const HARD_REFUSAL_CODES = new Set([
  "PG_SUBJECT_OPTED_OUT", "PG_IMMUTABLE_DENIAL", "PG_INVALID_SIGNATURE",
  "PG_SUBJECT_DISPUTED", "PG_SUBJECT_WITHDRAWN",
]);

export const SOFT_REFUSAL_CODES = new Set([
  "PG_NO_LICENSE", "PG_SCOPE_VIOLATION",
]);

// ── Helpers ────────────────────────────────────────────────────────────

function envVar(key: string): string {
  if (typeof process !== "undefined" && process.env) return process.env[key] ?? "";
  return "";
}

/** SHA-256 of a prompt — what a decision gets bound to. Standalone twin of
 * `Prampta.hashPrompt` so it can be imported directly. */
export async function hashPrompt(prompt: string): Promise<string> {
  return sha256(prompt);
}

async function sha256(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  return sha256Bytes(data);
}

const TOFU_WARNING =
  "PRAMPTA: verifying operator signatures WITHOUT a pinned key (trust-on-first-use). " +
  "This provides no protection against a malicious or compromised endpoint. Set " +
  "operatorPublicKeyHex (from PRAMPTA's docs) before production.";

function parsePins(raw: string): string[] {
  return raw ? raw.split(/[\s,]+/).filter(Boolean) : [];
}

async function keyFingerprint(publicKeyHex: string): Promise<string> {
  return `pg-ed25519:${(await sha256Bytes(hexToBytes(publicKeyHex))).slice(0, 32)}`;
}

async function sha256Bytes(data: Uint8Array): Promise<string> {
  if (typeof globalThis.crypto?.subtle !== "undefined") {
    // Use exact byte range — data.buffer may be larger if Uint8Array has offset/length
    const exact = data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength) as ArrayBuffer;
    const hash = await globalThis.crypto.subtle.digest("SHA-256", exact);
    return Array.from(new Uint8Array(hash)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }
  const { createHash } = await import("crypto");
  return createHash("sha256").update(data).digest("hex");
}

/**
 * Canonical JSON — deterministic serialization matching Python's
 * `json.dumps(obj, sort_keys=True, separators=(",",":"), ensure_ascii=False)`.
 * Required for signature verification across languages.
 *
 * Exported so external verifiers can rebuild signed bodies and so the
 * cross-implementation spec test vectors (spec/test-vectors) can pin it.
 * Field names in signed protocol bodies are ASCII by construction — key
 * sorting is identical to Python's code-point sort in that range.
 */
export function canonicalJson(obj: unknown): string {
  if (obj === null || obj === undefined) return "null";
  if (typeof obj === "number" || typeof obj === "boolean") return JSON.stringify(obj);
  if (typeof obj === "string") return JSON.stringify(obj);
  if (Array.isArray(obj)) return "[" + obj.map(canonicalJson).join(",") + "]";
  const keys = Object.keys(obj as Record<string, unknown>).sort();
  const parts = keys.map((k) => JSON.stringify(k) + ":" + canonicalJson((obj as Record<string, unknown>)[k]));
  return "{" + parts.join(",") + "}";
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}


// ── Subject Detection ───────────────────────────────────────────────────

/** One entry of the /v1/subjects/index detection index. */
export interface SubjectIndexEntry {
  subject_id: string;
  aliases: string[];
  status: string;
  visibility: string;
}

// 0=o,1=i,3=e,4=a,5=s,7=t,@=a,$=s — detection over-matching only costs an extra
// verify; under-matching is the real risk, so we de-leet aggressively.
const LEET: Record<string, string> = { "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s" };
const SQUEEZE_MIN = 5;

/** André → andre — strip accents off Latin letters only; leave Cyrillic etc.
 * intact (e.g. "й" must NOT become "и"). */
function stripDiacritics(t: string): string {
  let out = "";
  for (const ch of t.normalize("NFC")) {
    const base = ch.normalize("NFKD")[0] || ch;
    if (/[a-zA-Z]/.test(base)) out += base;
    else out += ch;
  }
  return out;
}

/**
 * Canonical normalization for subject matching: lowercase, strip Latin
 * diacritics, de-leet, -/_ → space, strip punctuation, collapse whitespace.
 * Must stay behaviorally identical to the Python SDK's normalize_for_match.
 */
export function normalizeForMatch(text: string): string {
  let t = stripDiacritics(text.toLowerCase());
  t = t.replace(/[0134578@$]/g, (c) => LEET[c] || c);
  return t
    .replace(/[-_]+/g, " ")
    .replace(/[^\p{L}\p{N} ]+/gu, " ")
    .replace(/ +/g, " ")
    .trim();
}

const squeeze = (t: string): string => t.replace(/ /g, "");

/**
 * Detect which index entries are mentioned in `text`. Whole-word phrase
 * containment, plus a squeezed-substring fallback (min length) that defeats
 * letter-spacing ("a d a") and concatenation ("AdaLovelace"). Baseline layer —
 * text only; image/voice detection is provider-side perceptual work.
 */
export function matchSubjects(text: string, entries: SubjectIndexEntry[]): SubjectIndexEntry[] {
  const norm = normalizeForMatch(text);
  const haystack = ` ${norm} `;
  const squeezedHaystack = squeeze(norm);
  const hits: SubjectIndexEntry[] = [];
  for (const entry of entries) {
    const candidates = [entry.subject_id, ...(entry.aliases || [])];
    for (const cand of candidates) {
      const needle = normalizeForMatch(cand);
      if (!needle) continue;
      if (haystack.includes(` ${needle} `)) {
        hits.push(entry);
        break;
      }
      const sq = squeeze(needle);
      if (sq.length >= SQUEEZE_MIN && squeezedHaystack.includes(sq)) {
        hits.push(entry);
        break;
      }
    }
  }
  return hits;
}

// ── Client ─────────────────────────────────────────────────────────────

export class Prampta {
  private readonly baseUrl: string;
  private readonly providerId: string;
  private readonly licenseeId: string;
  private readonly token: string;
  private readonly timeoutMs: number;
  private readonly maxRetries: number;
  private readonly retryBackoffMs: number;
  private readonly failClosed: boolean;
  private readonly verifySignature: boolean;
  private readonly enforce: boolean;
  private pinnedKeys: string[];
  private keySetCache: Record<string, any> | null = null;
  private keySetPromise: Promise<Record<string, any>> | null = null;
  private tofuWarned = false;

  constructor(config: PramptaConfig = {}) {
    this.baseUrl = (config.baseUrl || envVar("PRAMPTA_BASE_URL")).replace(/\/+$/, "");
    this.providerId = config.providerId || envVar("PRAMPTA_PROVIDER_ID");
    this.licenseeId = config.licenseeId || envVar("PRAMPTA_LICENSEE_ID");
    this.token = config.token || envVar("PRAMPTA_TOKEN");
    this.timeoutMs = config.timeoutMs ?? 3000;
    this.maxRetries = Math.max(0, config.maxRetries ?? 2);
    this.retryBackoffMs = config.retryBackoffMs ?? 200;
    this.failClosed = config.failClosed ?? true;
    this.verifySignature = config.verifyDecisionSignature ?? true;
    this.enforce = config.enforce ?? true;
    this.pinnedKeys = parsePins(config.operatorPublicKeyHex || envVar("PRAMPTA_OPERATOR_PUBLIC_KEY") || "");

    if (!this.baseUrl) throw new PramptaError("baseUrl is required (or set PRAMPTA_BASE_URL)");
    if (!this.providerId) throw new PramptaError("providerId is required (or set PRAMPTA_PROVIDER_ID)");
    if (!this.licenseeId) throw new PramptaError("licenseeId is required (or set PRAMPTA_LICENSEE_ID)");
    if (!this.token) throw new PramptaError("token is required (or set PRAMPTA_TOKEN)");
  }

  // ── Key Discovery ───────────────────────────────────────────────────

  /** Fetch /keys and check it is self-signed by its current key. Cached. */
  private async fetchVerifiedKeySet(): Promise<Record<string, any>> {
    if (this.keySetCache) return this.keySetCache;
    if (!this.keySetPromise) {
      this.keySetPromise = (async () => {
        const ks = await this.get("/keys");
        const entries: Record<string, string> = {};
        for (const e of ks.keys || []) entries[e.key_id] = e.public_key_hex || "";
        const currentHex = entries[ks.current_key_id] || "";
        const sig = ks.signature || "";
        if (!currentHex || !sig) throw new PramptaSignatureError("Operator key set from /keys is malformed");
        const body = { ...ks }; delete body.signature;
        const ok = await ed.verifyAsync(hexToBytes(sig), new TextEncoder().encode(canonicalJson(body)), hexToBytes(currentHex));
        if (!ok) throw new PramptaSignatureError("Operator key set signature is invalid");
        this.keySetCache = ks;
        return ks;
      })();
    }
    return this.keySetPromise;
  }

  /**
   * Public key hex to verify a decision signed by `keyId`, enforcing the
   * pinning trust model. A pinned match returns immediately (no network); an
   * unpinned key id fails closed in pinned mode; unpinned/TOFU mode resolves
   * from the self-consistent /keys set with a warning.
   */
  private async resolveOperatorKey(keyId: string): Promise<string> {
    for (const hex of this.pinnedKeys) {
      if ((await keyFingerprint(hex)) === keyId) return hex;
    }
    if (this.pinnedKeys.length > 0) {
      throw new PramptaSignatureError(
        `Decision was signed by operator key '${keyId}', which is not in your pinned set. ` +
        "If PRAMPTA rotated keys, confirm the new key out of band and add it to " +
        "operatorPublicKeyHex (pin current + next to rotate without downtime). " +
        "Refusing to trust an unpinned key."
      );
    }
    const ks = await this.fetchVerifiedKeySet();
    const entries: Record<string, string> = {};
    for (const e of ks.keys || []) entries[e.key_id] = e.public_key_hex || "";
    const match = entries[keyId];
    if (!match) {
      throw new PramptaSignatureError(`Decision key '${keyId}' is not present in the operator key set from /keys.`);
    }
    if (!this.tofuWarned) { console.warn(TOFU_WARNING); this.tofuWarned = true; }
    return match;
  }

  // ── Subject Detection ────────────────────────────────────────────────

  private subjectIndexEntries: SubjectIndexEntry[] | null = null;
  private subjectIndexFetchedAt = 0;
  private static readonly SUBJECT_INDEX_TTL_MS = 300_000;

  /** Fetch the raw subject detection index (/v1/subjects/index). */
  async fetchSubjectIndex(): Promise<{ version: number; count: number; subjects: SubjectIndexEntry[] }> {
    return this.get("/v1/subjects/index");
  }

  /**
   * Detect registered subjects mentioned in `text`, using a TTL-cached
   * copy of the subject index. Call verify()/assertAllowed() per hit.
   */
  async matchSubjects(text: string, opts?: { forceRefresh?: boolean }): Promise<SubjectIndexEntry[]> {
    const now = Date.now();
    if (
      opts?.forceRefresh ||
      !this.subjectIndexEntries ||
      now - this.subjectIndexFetchedAt > Prampta.SUBJECT_INDEX_TTL_MS
    ) {
      const payload = await this.fetchSubjectIndex();
      this.subjectIndexEntries = payload.subjects || [];
      this.subjectIndexFetchedAt = now;
    }
    return matchSubjects(text, this.subjectIndexEntries);
  }

  // ── Signature Verification ──────────────────────────────────────────

  /**
   * Verify operator Ed25519 signature over decision body.
   * Fails closed on any error.
   */
  private async verifyDecision(raw: Record<string, any>, decision: SignedDecision): Promise<void> {
    if (!this.verifySignature) return;

    const sig = decision.operatorSignature;
    if (!sig) throw new PramptaSignatureError("Decision missing operator_signature");

    const keyId = decision.operatorKeyId;
    if (!keyId) throw new PramptaSignatureError("Decision missing operator_key_id");

    // Resolve the verifying key from the pinned trust anchor (or /keys),
    // then check the signature was made by exactly that key.
    const pubKeyHex = await this.resolveOperatorKey(keyId);

    // Rebuild canonical body excluding signature field
    const bodyForSigning = { ...raw };
    delete bodyForSigning.operator_signature;
    const canonical = canonicalJson(bodyForSigning);
    const messageBytes = new TextEncoder().encode(canonical);

    const pubKeyBytes = hexToBytes(pubKeyHex);
    const sigBytes = hexToBytes(sig);

    // Verify Ed25519 signature
    let valid: boolean;
    try {
      valid = await ed.verifyAsync(sigBytes, messageBytes, pubKeyBytes);
    } catch (e) {
      throw new PramptaSignatureError(`Ed25519 verification error: ${e}`);
    }

    if (!valid) {
      throw new PramptaSignatureError(
        "Operator signature is invalid — decision cannot be trusted. " +
        "This may indicate a compromised backend, proxy tampering, or key mismatch."
      );
    }

    // Verify TTL
    const now = Math.floor(Date.now() / 1000);
    if (decision.expiresAt > 0 && decision.expiresAt < now) {
      throw new PramptaSignatureError(
        `Decision expired at ${decision.expiresAt}, current time ${now}`
      );
    }
  }

  /**
   * Verify that the signed decision is bound to the correct request context.
   * Prevents replay attacks where a valid decision for one context is used in another.
   */
  private verifyContextBinding(
    decision: SignedDecision,
    expected: {
      promptHash: string;
      subjectId: string;
      providerId: string;
      licenseeId: string;
      modality: string;
      model: string;
      intendedUse?: {
        productName: string;
        projectName: string;
        channel: string;
        territory: string;
        categories: string[];
        campaignId: string;
      };
    },
  ): void {
    if (decision.promptHash && decision.promptHash !== expected.promptHash) {
      throw new PramptaSignatureError(
        `Decision prompt_hash mismatch: sent ${expected.promptHash}, got ${decision.promptHash}`
      );
    }
    if (decision.subjectId && decision.subjectId !== expected.subjectId) {
      throw new PramptaSignatureError(
        `Decision subject_id mismatch: sent ${expected.subjectId}, got ${decision.subjectId}`
      );
    }
    if (decision.providerId && decision.providerId !== expected.providerId) {
      throw new PramptaSignatureError(
        `Decision provider_id mismatch: sent ${expected.providerId}, got ${decision.providerId}`
      );
    }
    if (decision.licenseeId && decision.licenseeId !== expected.licenseeId) {
      throw new PramptaSignatureError(
        `Decision licensee_id mismatch: sent ${expected.licenseeId}, got ${decision.licenseeId}`
      );
    }
    if (decision.modality && expected.modality && decision.modality !== expected.modality) {
      throw new PramptaSignatureError(
        `Decision modality mismatch: sent ${expected.modality}, got ${decision.modality}`
      );
    }
    if (decision.model && expected.model && decision.model !== expected.model) {
      throw new PramptaSignatureError(
        `Decision model mismatch: sent ${expected.model}, got ${decision.model}`
      );
    }
    // Bind the full intended use — otherwise an ALLOW for Product A could be
    // replayed for Product B when subject/prompt/model/modality match.
    if (expected.intendedUse) {
      const iu = (decision.intendedUse || {}) as Record<string, unknown>;
      const pairs: [string, string, string][] = [
        ["product_name", String(iu.product_name || ""), expected.intendedUse.productName],
        ["project_name", String(iu.project_name || ""), expected.intendedUse.projectName],
        ["channel", String(iu.channel || ""), expected.intendedUse.channel],
        ["territory", String(iu.territory || ""), expected.intendedUse.territory],
        ["campaign_id", String(iu.campaign_id || ""), expected.intendedUse.campaignId],
      ];
      for (const [name, got, sent] of pairs) {
        if (got && sent && got !== sent) {
          throw new PramptaSignatureError(`Decision ${name} mismatch: sent ${sent}, got ${got}`);
        }
      }
      const gotCats = new Set((Array.isArray(iu.categories) ? iu.categories : []).map(String));
      const sentCats = new Set(expected.intendedUse.categories || []);
      if (gotCats.size && sentCats.size) {
        const same = gotCats.size === sentCats.size && [...sentCats].every((c) => gotCats.has(c));
        if (!same) {
          throw new PramptaSignatureError(
            `Decision categories mismatch: sent ${[...sentCats].sort()}, got ${[...gotCats].sort()}`
          );
        }
      }
    }
  }

  // ── Core API ─────────────────────────────────────────────────────────

  async verifyGeneration(request: VerifyRequest): Promise<SignedDecision> {
    const promptHash = request.promptHash
      || (request.prompt ? await sha256(request.prompt) : null);

    if (!promptHash) {
      throw new PramptaSchemaError(
        "Either prompt or promptHash is required. " +
        "SDK does not allow empty prompt hashes to prevent unbound decisions."
      );
    }

    const payload = {
      subject_id: request.subjectId,
      prompt_hash: promptHash,
      modality: request.modality || "",
      model: request.model || "",
      intended_use: {
        channel: request.intendedUse?.channel || "",
        product_name: request.intendedUse?.productName || "",
        project_name: request.intendedUse?.projectName || "",
        categories: request.intendedUse?.categories || [],
        modality: request.modality || "",
        territory: request.intendedUse?.territory || "",
        campaign_id: request.intendedUse?.campaignId || "",
      },
    };

    try {
      const data = await this.post("/v1/verify/", payload);
      const decision = this.parseDecision(data);

      // Verify operator signature, TTL, and payload binding
      await this.verifyDecision(data, decision);

      // Verify context binding — decision must match the request we sent
      this.verifyContextBinding(decision, {
        promptHash,
        subjectId: request.subjectId,
        providerId: this.providerId,
        licenseeId: this.licenseeId,
        modality: request.modality || "",
        model: request.model || "",
        intendedUse: {
          productName: request.intendedUse?.productName || "",
          projectName: request.intendedUse?.projectName || "",
          channel: request.intendedUse?.channel || "",
          territory: request.intendedUse?.territory || "",
          categories: request.intendedUse?.categories || [],
          campaignId: request.intendedUse?.campaignId || "",
        },
      });

      return decision;
    } catch (e) {
      if (this.failClosed) {
        if (e instanceof PramptaRefusalError || e instanceof PramptaSchemaError || e instanceof PramptaSignatureError) {
          throw e;
        }
        throw new PramptaFailClosedError(e);
      }
      throw e;
    }
  }

  /** Flat convenience API mirroring the Python SDK: intended-use fields
   * (categories, channel, productName, …) are accepted at the top level.
   * Either `prompt` or `promptHash` is REQUIRED — decisions are bound to
   * the prompt hash and the SDK refuses to request unbound ones. */
  async verify(subjectId: string, options: VerifyOptions = {}): Promise<SignedDecision> {
    const { categories, channel, productName, projectName, territory, campaignId, intendedUse, ...rest } = options;
    const iu = intendedUse ?? {
      ...(channel ? { channel } : {}),
      ...(productName ? { productName } : {}),
      ...(projectName ? { projectName } : {}),
      ...(categories ? { categories } : {}),
      ...(territory ? { territory } : {}),
      ...(campaignId ? { campaignId } : {}),
    };
    return this.verifyGeneration({
      subjectId, ...rest,
      ...(Object.keys(iu).length ? { intendedUse: iu } : {}),
    });
  }

  async assertAllowed(subjectId: string, options: Omit<VerifyRequest, "subjectId"> = {}): Promise<SignedDecision> {
    const decision = await this.verifyGeneration({ subjectId, ...options });
    if (!decision.allowed) {
      if (this.enforce) throw new PramptaRefusalError(decision);
      console.warn(`PRAMPTA monitor mode: would REFUSE (${decision.reason}) but enforce=false — proceeding.`);
    }
    return decision;
  }

  async withAuthorization<T>(
    request: VerifyRequest,
    generateFn: (decision: SignedDecision) => Promise<T>,
  ): Promise<{ output: T; decision: SignedDecision; metadata: OutputMetadata }> {
    const decision = await this.assertAllowed(request.subjectId, request);
    const output = await generateFn(decision);
    const metadata = this.createOutputMetadata(decision);
    return { output, decision, metadata };
  }

  // ── Subject Resolution ───────────────────────────────────────────────

  async getSubject(subjectId: string): Promise<SubjectInfo | null> {
    try {
      const data = await this.get(`/v1/subjects/${encodeURIComponent(subjectId)}`);
      return {
        subjectId: data.subject_id, status: data.status,
        visibility: data.visibility || "public", rulesText: data.rules_text || "",
        aliases: data.aliases || [], publicKeyHex: data.public_key_hex,
        registeredAt: data.registered_at,
      };
    } catch { return null; }
  }

  // ── License Request ──────────────────────────────────────────────────

  async requestLicense(input: LicenseRequestInput): Promise<LicenseRequestResult> {
    const data = await this.post("/v1/license-requests/", {
      subject_id: input.subjectId, use_case: input.useCase,
      purpose: input.purpose || "", duration_days: input.durationDays || 365,
      message: input.message || "",
    });
    return { requestId: data.request_id, status: data.status };
  }

  // ── Provenance / Output Metadata ─────────────────────────────────────

  createOutputMetadata(decision: SignedDecision): OutputMetadata {
    return {
      prampta_decision_id: decision.decisionId,
      prampta_license_id: decision.licenseId,
      prampta_watermark: decision.watermarkPayload,
      prampta_obligations: decision.obligations,
      prampta_issued_at: decision.issuedAt,
    };
  }

  /**
   * Submit a generation receipt AFTER generating — the provider's enforcement
   * proof, bound to the decision it acted on. Records that this generation was
   * authorized and executed under the decision's terms (verifiable post-hoc).
   */
  async submitReceipt(
    decision: SignedDecision,
    result: {
      outputHash?: string;
      model?: string;
      watermarkEmbedded?: boolean;
      obligationsApplied?: Record<string, unknown>;
      generatedAt?: number;
    } = {},
  ): Promise<Record<string, unknown>> {
    return this.post("/v1/receipts/", {
      decision_id: decision.decisionId,
      prompt_hash: decision.promptHash,
      output_hash: result.outputHash ?? "",
      model: result.model ?? decision.model,
      watermark_embedded: result.watermarkEmbedded ?? false,
      obligations_applied: result.obligationsApplied ?? decision.obligations ?? {},
      generated_at: result.generatedAt ?? Math.floor(Date.now() / 1000),
    });
  }

  // ── Utility ──────────────────────────────────────────────────────────

  async health(): Promise<boolean> {
    try { await this.get("/healthz"); return true; } catch { return false; }
  }

  async version(): Promise<Record<string, unknown>> {
    return this.get("/version");
  }

  static async hashPrompt(prompt: string): Promise<string> {
    return sha256(prompt);
  }

  // ── Internal ─────────────────────────────────────────────────────────

  private parseDecision(data: Record<string, any>): SignedDecision {
    if (!data.decision_id) throw new PramptaSchemaError("Response missing decision_id");
    return {
      schemaVersion: data.schema_version || "pg.decision.v1",
      decisionId: data.decision_id, allowed: data.allowed ?? false,
      reason: data.reason ?? null, subjectId: data.subject_id || "",
      licenseeId: data.licensee_id || "", providerId: data.provider_id || "",
      licenseId: data.license_id ?? null, promptHash: data.prompt_hash || "",
      model: data.model || "", modality: data.modality || "",
      intendedUse: data.intended_use || {}, obligations: data.obligations || {},
      rulesText: data.rules_text || "", rulesTextHash: data.rules_text_hash || "",
      watermarkPayload: data.watermark_payload ?? null,
      isHardRefusal: data.is_hard_refusal ?? false,
      issuedAt: data.issued_at || 0, expiresAt: data.expires_at || 0,
      operatorKeyId: data.operator_key_id || "",
      operatorSignature: data.operator_signature || "",
      subjectAuthority: data.subject_authority || "",
      denied: !(data.allowed ?? false),
    };
  }

  private headers(): Record<string, string> {
    return {
      "Content-Type": "application/json",
      "X-Provider-ID": this.providerId,
      "X-Licensee-ID": this.licenseeId,
      Authorization: `Bearer ${this.token}`,
    };
  }

  /** Transient errors worth retrying: connectivity, timeout, 429, and 5xx. */
  private isRetryable(e: unknown): boolean {
    if (e instanceof PramptaNetworkError || e instanceof PramptaTimeoutError) return true;
    if (e instanceof PramptaApiError) return e.status >= 500 || e.status === 429;
    return false;
  }

  private async withRetry<T>(fn: () => Promise<T>): Promise<T> {
    let lastErr: unknown;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      try {
        return await fn();
      } catch (e) {
        lastErr = e;
        if (attempt >= this.maxRetries || !this.isRetryable(e)) throw e;
        const delay = this.retryBackoffMs * Math.pow(2, attempt);
        await new Promise((r) => setTimeout(r, delay));
      }
    }
    throw lastErr;
  }

  private async post(path: string, payload: unknown): Promise<any> {
    return this.withRetry(() => this.postOnce(path, payload));
  }

  private async postOnce(path: string, payload: unknown): Promise<any> {
    let resp: Response;
    try {
      resp = await fetch(`${this.baseUrl}${path}`, {
        method: "POST", headers: this.headers(),
        body: JSON.stringify(payload),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e: any) {
      if (e?.name === "TimeoutError" || e?.name === "AbortError") throw new PramptaTimeoutError(this.timeoutMs);
      throw new PramptaNetworkError(e);
    }
    if (!resp.ok) {
      const text = await resp.text();
      let detail = text;
      try { detail = JSON.parse(text).detail ?? text; } catch {}
      throw new PramptaApiError(resp.status, String(detail));
    }
    return resp.json();
  }

  private async get(path: string): Promise<any> {
    return this.withRetry(() => this.getOnce(path));
  }

  private async getOnce(path: string): Promise<any> {
    let resp: Response;
    try {
      resp = await fetch(`${this.baseUrl}${path}`, {
        method: "GET", headers: this.headers(),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch (e: any) {
      if (e?.name === "TimeoutError" || e?.name === "AbortError") throw new PramptaTimeoutError(this.timeoutMs);
      throw new PramptaNetworkError(e);
    }
    if (!resp.ok) throw new PramptaApiError(resp.status, await resp.text());
    return resp.json();
  }
}
