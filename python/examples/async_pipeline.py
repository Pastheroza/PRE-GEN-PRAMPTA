"""Async PRAMPTA verification in an AI inference pipeline.

This shows how to integrate PRAMPTA into a high-throughput
image generation pipeline using asyncio.

Requires: pip install prampta[async]
"""

import asyncio
from prampta.async_client import AsyncPrampta


async def generate_image(prompt: str, subject_id: str):
    """Example AI generation function with PRAMPTA guard."""

    async with AsyncPrampta(
        base_url="http://localhost:8000",
        provider_id="my-ai-service",
        licensee_id="acme-corp",
        token="<paste-pair-token-here>",
    ) as pg:
        # Verify BEFORE generation — this is the core principle
        result = await pg.verify(
            subject_id,
            modality="image",
            categories=["likeness", "endorsement"],
        )

        if result.denied:
            return {
                "error": result.reason,
                "hard_refusal": result.is_hard_refusal,
                "message": f"Cannot generate: {result.reason}",
            }

        # Generation authorized — proceed
        # image = await my_model.generate(prompt)

        return {
            "status": "generated",
            "license_id": result.license_id,
            "decision_id": result.decision_id,
            "watermark": result.watermark_payload,
            "obligations": result.obligations,
        }


async def main():
    # Batch verification example
    subjects = ["leonardo-da-vinci", "unknown-person", "opted-out-subject"]

    tasks = [
        generate_image(f"Photo of {s} in a commercial", s)
        for s in subjects
    ]

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for subject, result in zip(subjects, results):
        if isinstance(result, Exception):
            print(f"{subject}: ERROR — {result}")
        elif result.get("error"):
            print(f"{subject}: DENIED — {result['error']}")
        else:
            print(f"{subject}: ALLOWED — {result['license_id']}")


if __name__ == "__main__":
    asyncio.run(main())
