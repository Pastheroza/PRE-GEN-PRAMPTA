/**
 * Replay the cross-implementation spec vectors against the TS SDK.
 *
 * canonicalJson must produce byte-identical output to the backend's
 * canonical_json — otherwise every operator-signature check breaks.
 * Vectors: spec/test-vectors/vectors.json (repo root).
 */
import { describe, it, expect } from "vitest";
import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import * as ed from "@noble/ed25519";

import { canonicalJson } from "../src/index";

// Walk upward until spec/test-vectors is found — works both in the monorepo
// (sdk/typescript/tests) and the public SDK repo (typescript/tests).
function findVectors(): string {
  let dir = __dirname;
  for (let i = 0; i < 8; i++) {
    const candidate = join(dir, "spec", "test-vectors", "vectors.json");
    if (existsSync(candidate)) return candidate;
    dir = join(dir, "..");
  }
  throw new Error("spec/test-vectors/vectors.json not found in any parent directory");
}

const vectors = JSON.parse(
  readFileSync(findVectors(), "utf-8"),
);

function sha256Hex(s: string): string {
  return createHash("sha256").update(Buffer.from(s, "utf-8")).digest("hex");
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  return bytes;
}

describe("spec test vectors: canonical JSON", () => {
  for (const c of vectors.canonical_json) {
    it(c.name, () => {
      const canonical = canonicalJson(c.input);
      expect(canonical).toBe(c.canonical_utf8);
      expect(sha256Hex(canonical)).toBe(c.sha256_hex);
    });
  }
});

describe("spec test vectors: signed bodies", () => {
  const pubKey = hexToBytes(vectors.operator_key.public_hex);

  for (const c of vectors.signing) {
    it(`${c.name} canonicalizes and verifies`, async () => {
      const canonical = canonicalJson(c.body);
      expect(canonical).toBe(c.canonical_utf8);
      expect(sha256Hex(canonical)).toBe(c.sha256_hex);

      const ok = await ed.verifyAsync(
        hexToBytes(c.signature_hex),
        new TextEncoder().encode(canonical),
        pubKey,
      );
      expect(ok).toBe(true);
    });
  }

  it("rejects a tampered body", async () => {
    const c = vectors.signing[0];
    const tampered = { ...c.body, allowed: !c.body.allowed };
    const ok = await ed.verifyAsync(
      hexToBytes(c.signature_hex),
      new TextEncoder().encode(canonicalJson(tampered)),
      pubKey,
    );
    expect(ok).toBe(false);
  });

  it("fingerprint derivation matches backend", () => {
    const fp = `pg-ed25519:${createHash("sha256").update(pubKey).digest("hex").slice(0, 32)}`;
    expect(fp).toBe(vectors.operator_key.fingerprint);
  });
});
