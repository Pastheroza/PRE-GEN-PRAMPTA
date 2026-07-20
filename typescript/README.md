# PRAMPTA TypeScript SDK

Pre-generation authorization for AI content. Verifies operator Ed25519 signatures on decisions — not a blind HTTP wrapper.

## Installation

```bash
npm install @prampta/sdk
```

Requires Node.js ≥ 18 (uses native `crypto.subtle` for SHA-256).

## Quick Start

```typescript
import { Prampta } from "@prampta/sdk";

const pg = new Prampta({
  baseUrl: "https://api2.prampta.com",
  providerId: "my-ai-service",
  licenseeId: "acme-corp",
  token: "pair-token",
});

// Option 1: Assert — throws if denied (fail-closed)
await pg.assertAllowed("leonardo-da-vinci", {
  prompt: "Da Vinci in a documentary",
  modality: "image",
  model: "gpt-image-1",
});

// Option 2: Verify — returns decision object
const result = await pg.verify("leonardo-da-vinci", {
  prompt: "Da Vinci in a documentary",
  modality: "image",
  model: "gpt-image-1",
});

if (result.allowed) {
  generate({ obligations: result.obligations });
} else {
  console.log(`Denied: ${result.reason}`);
}
```

## Security Features

- **Ed25519 signature verification** on every decision (via `@noble/ed25519`)
- **Prompt hash binding** — decision is bound to the exact prompt (SHA-256)
- **Context binding** — decision cannot be replayed for different subject/provider/licensee/modality
- **Key fingerprint validation** — operator_key_id matches pinned public key
- **TTL validation** — expired decisions are rejected
- **Fail-closed** — any error defaults to deny


## Key Pinning & Rotation (trust anchor)

Signature verification is only meaningful against a key you obtained out of
band. **Pin the operator key** — do not rely on the key the API hands you:

```typescript
const pg = new Prampta({
  baseUrl: "https://api2.prampta.com",
  providerId: "my-ai-service",
  licenseeId: "acme-corp",
  token: "pair-token",
  operatorPublicKeyHex: "<pinned key from PRAMPTA docs>",
});
```

- A decision is trusted only when signed by a pinned key. A decision signed by
  an **unpinned** key fails closed with an actionable error (no silent trust).
- **Rotation without downtime:** pin the current *and* the announced next key
  (comma/space separated). When PRAMPTA rotates, the new key is already trusted.
- **No pinned key** → trust-on-first-use: the SDK still verifies but logs a
  warning. The signature proves consistency, not authenticity. Never ship
  production this way.

## Configuration

| Parameter | Env Var | Required | Description |
|-----------|---------|----------|-------------|
| `baseUrl` | `PRAMPTA_BASE_URL` | Yes | Registry API URL |
| `providerId` | `PRAMPTA_PROVIDER_ID` | Yes | Your provider ID |
| `licenseeId` | `PRAMPTA_LICENSEE_ID` | Yes | Licensee ID |
| `token` | `PRAMPTA_TOKEN` | Yes | Pair auth token |
| `operatorPublicKeyHex` | `PRAMPTA_OPERATOR_PUBLIC_KEY` | No | Pinned operator key (recommended for production) |
| `timeoutMs` | — | No | Default `3000`. Request timeout in ms. |
| `failClosed` | — | No | Default `true`. Deny on any verification error. |
| `verifyDecisionSignature` | — | No | Default `true`. Set `false` only for local dev. |

## Error Handling

```typescript
import { Prampta, PramptaRefusalError, PramptaSignatureError } from "@prampta/sdk";

try {
  await pg.assertAllowed("subject-id", { prompt: "...", modality: "image" });
} catch (e) {
  if (e instanceof PramptaRefusalError) {
    // License denial — e.reason has the code (PG_NO_LICENSE, PG_SCOPE_VIOLATION, etc.)
    console.log(e.reason);
  } else if (e instanceof PramptaSignatureError) {
    // Operator signature invalid — potential MITM
    alert("Security: tampered decision");
  }
}
```

## Pre-hashed Prompts

If you hash prompts yourself (e.g., for privacy), pass `promptHash` instead of `prompt`:

```typescript
import { hashPrompt } from "@prampta/sdk";

const hash = await hashPrompt("Da Vinci in a documentary");
const result = await pg.verify("leonardo-da-vinci", {
  promptHash: hash,
  modality: "image",
});
```

## API Reference

### `new Prampta(config)`

Creates a client instance.

### `pg.verify(subjectId, options)`

Returns `Promise<SignedDecision>`:
- `allowed` — generation authorized
- `reason` — refusal code (`PG_NO_LICENSE`, `PG_SCOPE_VIOLATION`, `PG_SUBJECT_OPTED_OUT`)
- `licenseId` — the authorizing license
- `decisionId` — unique decision ID for audit
- `obligations` — required obligations (attribution, watermark, etc.)
- `operatorSignature` — Ed25519 signature over decision

### `pg.assertAllowed(subjectId, options)`

Same as `verify()` but throws `PramptaRefusalError` if not allowed.

### `pg.health()` / `pg.version()`

Registry health check and version info.
