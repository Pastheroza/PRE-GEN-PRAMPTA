import { describe, it, expect, vi, afterEach } from "vitest";
import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";
import { createHash } from "node:crypto";
import { Prampta, PramptaSignatureError, canonicalJson } from "../src/index";

// Enable synchronous ed25519 signing for the test.
(ed.hashes as { sha512?: unknown }).sha512 = sha512;

function toHex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}
function fingerprint(pubHex: string): string {
  return `pg-ed25519:${createHash("sha256").update(Buffer.from(pubHex, "hex")).digest("hex").slice(0, 32)}`;
}

/** Build a fully-signed ALLOW decision from a keypair. */
function signedDecision(secretKey: Uint8Array, publicKeyHex: string) {
  const body: Record<string, unknown> = {
    schema_version: "1.0",
    decision_id: "dec-trust",
    allowed: true,
    reason: null,
    subject_id: "sub-1",
    licensee_id: "l",
    provider_id: "p",
    license_id: "lic-1",
    prompt_hash: "h",
    model: "m",
    modality: "image",
    intended_use: {},
    obligations: {},
    rules_text: "",
    rules_text_hash: "",
    watermark_payload: null,
    is_hard_refusal: false,
    issued_at: Math.floor(Date.now() / 1000),
    expires_at: Math.floor(Date.now() / 1000) + 300,
    operator_key_id: fingerprint(publicKeyHex),
    subject_authority: "self",
  };
  const sig = ed.sign(new TextEncoder().encode(canonicalJson(body)), secretKey);
  return { ...body, operator_signature: toHex(sig) };
}

afterEach(() => vi.unstubAllGlobals());

describe("trust model", () => {
  it("accepts a decision signed by the pinned key", async () => {
    const kp = ed.keygen();
    const pubHex = toHex(kp.publicKey);
    const decision = signedDecision(kp.secretKey, pubHex);
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(decision) }));

    const pg = new Prampta({
      baseUrl: "https://api.test", providerId: "p", licenseeId: "l", token: "t",
      operatorPublicKeyHex: pubHex,
    });
    const result = await pg.verifyGeneration({ subjectId: "sub-1", promptHash: "h", modality: "image", model: "m" });
    expect(result.allowed).toBe(true);
  });

  it("fails closed on a decision signed by an UNPINNED key (rotation/MITM)", async () => {
    const real = ed.keygen();
    const attacker = ed.keygen();
    // Decision is validly self-signed by the attacker's key ...
    const decision = signedDecision(attacker.secretKey, toHex(attacker.publicKey));
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(decision) }));

    const pg = new Prampta({
      baseUrl: "https://api.test", providerId: "p", licenseeId: "l", token: "t",
      operatorPublicKeyHex: toHex(real.publicKey), // ... but we pinned the REAL key
    });
    await expect(
      pg.verifyGeneration({ subjectId: "sub-1", promptHash: "h", modality: "image", model: "m" }),
    ).rejects.toThrow(/not in your pinned set/);
  });

  it("multi-pin rides through a planned rotation", async () => {
    const oldKey = ed.keygen();
    const newKey = ed.keygen();
    const decision = signedDecision(newKey.secretKey, toHex(newKey.publicKey)); // signed by the NEW key
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue({ ok: true, json: () => Promise.resolve(decision) }));

    const pg = new Prampta({
      baseUrl: "https://api.test", providerId: "p", licenseeId: "l", token: "t",
      operatorPublicKeyHex: `${toHex(oldKey.publicKey)}, ${toHex(newKey.publicKey)}`, // pinned both
    });
    const result = await pg.verifyGeneration({ subjectId: "sub-1", promptHash: "h", modality: "image", model: "m" });
    expect(result.allowed).toBe(true);
  });
});
