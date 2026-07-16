# PRE-GEN — Pilot Testing branch

> **This branch does not block generation.** It is the monitor-only variant of
> the PRE-GEN SDK, meant for piloting PRAMPTA alongside a live AI product
> **without disrupting the provider or its users.**

## What's different from `SDK`

Only one thing: the SDK defaults to **monitor mode** (`enforce=False`).

- The SDK still calls `/v1/verify/` on every generation, so PRAMPTA sees the
  traffic and returns a **real signed decision** (allow / refuse, with the
  reason and obligations).
- But a refusal **never blocks**: `assert_allowed()` / `generate_guarded()` /
  `assertAllowed()` proceed and log a warning instead of raising.
- `verify()` still returns the true decision, so you can log, count, and review
  exactly what *would* have happened under enforcement — with zero risk to your
  users during the pilot.

Everything else (signature verification, prompt-hash binding, subject matching,
receipts) is identical to the `SDK` branch.

## Using it

### Python
```python
from prampta import Prampta

pg = Prampta(
    base_url="https://api2.prampta.com",
    provider_id="your-provider-id",
    licensee_id="your-licensee-id",
    token="pair-token",
    operator_public_key_hex="<pinned key from PRAMPTA docs>",
    # enforce defaults to False on this branch — monitor only.
)

decision = pg.verify(subject_id, prompt=user_prompt, modality="image")
if not decision.allowed:
    log.info("PRAMPTA would refuse: %s (monitoring, not blocking)", decision.reason)
generate(...)  # runs regardless during the pilot
```

### TypeScript
```typescript
import { Prampta } from "@prampta/sdk";

const pg = new Prampta({
  baseUrl: "https://api2.prampta.com",
  providerId: "your-provider-id",
  licenseeId: "your-licensee-id",
  token: "pair-token",
  operatorPublicKeyHex: "<pinned key>",
  // enforce defaults to false on this branch — monitor only.
});

const decision = await pg.verify(subjectId, { prompt, modality: "image" });
if (!decision.allowed) console.info(`PRAMPTA would refuse: ${decision.reason}`);
// generate regardless during the pilot
```

## Graduating to enforcement

When you're ready to actually block disallowed generations, either:

- switch to the [`SDK`](https://github.com/Pastheroza/PRE-GEN-PRAMPTA/tree/SDK)
  branch (enforcing by default), or
- keep this branch and pass `enforce=True` (Python) / `{ enforce: true }` (TS)
  when constructing the client.

No other code changes are required — the integration surface is identical.
