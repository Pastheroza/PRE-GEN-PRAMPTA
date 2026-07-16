# PRE-GEN — PRAMPTA SDK

**Authorization before generation.** PRE-GEN is the protocol behind [PRAMPTA](https://prampta.com) — a rights registry that answers one question for AI providers: *"am I allowed to generate this subject in this context?"* — and returns a **cryptographically signed allow-or-deny decision** you can store as proof of compliance.

This repository is for **AI providers** integrating PRE-GEN: SDKs, integration docs, and the API contract.

## What's here

| Path | Contents |
|---|---|
| [`python/`](python/) | Python SDK (`prampta`) — sync + async clients, subject matcher, signature verification |
| [`typescript/`](typescript/) | TypeScript SDK (`prampta`) — client, matcher, middleware example |
| [`docs/integration.ru.md`](docs/integration.ru.md) | Full integration guide (Russian; English version coming) |
| [`openapi.json`](openapi.json) | OpenAPI 3.1 contract of the PRAMPTA API |

## The flow (three calls)

1. **Detect** — poll `GET /v1/subjects/index` (ETag-cached, cheap) and match user prompts against registered subjects with the SDK's canonical matcher. Both SDKs ship the same matching semantics.
2. **Verify** — before calling your model, `POST /v1/verify/` with the matched `subject_id`. You get a signed decision: allowed (with obligations) or refused (with a machine-readable `PG_*` reason).
3. **Prove** — verify the Ed25519 signature against the operator key set from `GET /keys` (rotation-aware) and store the decision. Anyone can independently verify it later.

### Python

```python
from prampta import Prampta

pg = Prampta(
    base_url="https://api2.prampta.com",
    provider_id="your-provider-id",
    licensee_id="your-licensee-id",
    token="pair-token",
)

hits = pg.match_subjects(user_prompt)
for h in hits:
    pg.assert_allowed(h["subject_id"], prompt=user_prompt, modality="image")
# no exception → all matched subjects authorized, proceed with generation
```

### TypeScript

```ts
import { Prampta } from "@prampta/sdk";

const pg = new Prampta({
  baseUrl: "https://api2.prampta.com",
  providerId: "your-provider-id",
  licenseeId: "your-licensee-id",
  token: process.env.PRAMPTA_TOKEN,
});

const hits = await pg.matchSubjects(userPrompt);
for (const h of hits) {
  await pg.assertAllowed(h.subject_id, { prompt: userPrompt, modality: "image" });
}
```

## Why integrate

- **One call, court-ready proof** — every decision is Ed25519-signed and written to a tamper-evident audit chain. Store it and you can show you had permission.
- **Refusals are structured** — `PG_NO_LICENSE`, `PG_SUBJECT_OPTED_OUT`, `PG_RULE_VIOLATION`, … — so your product can react (offer a license request flow, block, or rephrase).
- **Free to integrate** — a few lines before your model runs.

## Getting credentials

Provider credentials (provider id + pair tokens) are issued through [prampta.com](https://prampta.com) — see the integration guide, or contact the team.

## License

Apache License 2.0 — see [LICENSE](LICENSE). Matches the license of the PRE-GEN specification (PGspec).
