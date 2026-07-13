# PRAMPTA Python SDK

Pre-generation authorization for AI content. Verifies operator Ed25519 signatures on decisions — not a blind HTTP wrapper.

## Installation

```bash
pip install prampta

# For async support (high-throughput pipelines):
pip install prampta[async]
```

## Quick Start

```python
from prampta import Prampta

pg = Prampta(
    base_url="https://api2.prampta.com",
    provider_id="my-ai-service",
    licensee_id="acme-corp",
    token="pair-token",
)

# Check authorization before generation
result = pg.verify("leonardo-da-vinci", prompt="Da Vinci in a documentary", modality="image")

if result.allowed:
    # Generate content, respecting obligations
    generate(obligations=result.obligations)
else:
    print(f"Denied: {result.reason}")
```

## Async Usage

```python
from prampta import AsyncPrampta

async with AsyncPrampta(
    base_url="https://api2.prampta.com",
    provider_id="my-ai-service",
    licensee_id="acme-corp",
    token="pair-token",
) as pg:
    result = await pg.verify("leonardo-da-vinci", prompt="Da Vinci documentary", modality="image")
```

## Security Features

- **Ed25519 signature verification** on every decision
- **Prompt hash binding** — decision is bound to the exact prompt
- **Context binding** — decision cannot be replayed for different subject/provider/licensee
- **TTL validation** — expired decisions are rejected
- **Fail-closed** — any error defaults to deny

## Configuration

| Parameter | Env Var | Required | Description |
|-----------|---------|----------|-------------|
| `base_url` | `PRAMPTA_BASE_URL` | Yes | Registry API URL |
| `provider_id` | `PRAMPTA_PROVIDER_ID` | Yes | Your provider ID |
| `licensee_id` | `PRAMPTA_LICENSEE_ID` | Yes | Licensee ID |
| `token` | `PRAMPTA_TOKEN` | Yes | Pair auth token |
| `operator_public_key_hex` | `PRAMPTA_OPERATOR_PUBLIC_KEY` | No | Pinned operator key (recommended for production) |
| `verify_signatures` | — | No | Default `True`. Set `False` only for local dev. |
| `fail_closed` | — | No | Default `True`. Deny on any verification error. |
