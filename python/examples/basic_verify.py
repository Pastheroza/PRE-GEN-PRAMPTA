"""Basic PRAMPTA verification example.

Before running, set up a pair between your provider and licensee:

    curl -X POST http://localhost:8000/v1/pairs/establish \
         -H "Content-Type: application/json" \
         -d '{"licensee_id": "acme-corp", "provider_id": "my-ai-service"}'

This returns a token. Use it below.
"""

from prampta import Prampta

pg = Prampta(
    base_url="http://localhost:8000",
    provider_id="my-ai-service",
    licensee_id="acme-corp",
    token="<paste-pair-token-here>",
)

# Check if generation is authorized
result = pg.verify(
    "leonardo-da-vinci",
    modality="image",
    categories=["endorsement"],
    product_name="ad-campaign-2026",
)

if result.allowed:
    print(f"ALLOWED — license: {result.license_id}")
    print(f"Watermark: {result.watermark_payload}")
    print(f"Obligations: {result.obligations}")
    # proceed with generation...
else:
    print(f"DENIED — {result.reason}")
    print(f"Hard refusal: {result.is_hard_refusal}")
    # do NOT generate
