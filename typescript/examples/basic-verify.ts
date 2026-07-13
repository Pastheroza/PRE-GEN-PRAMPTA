/**
 * Basic PRAMPTA verification example.
 *
 * Before running, set up a pair between your provider and licensee:
 *
 *   curl -X POST http://localhost:8000/v1/pairs/establish \
 *        -H "Content-Type: application/json" \
 *        -d '{"licensee_id": "acme-corp", "provider_id": "my-ai-service"}'
 *
 * This returns an access_token. Use it below.
 *
 * Run:
 *   npx tsx examples/basic-verify.ts
 */

import { Prampta } from "../src/index.js";

const pg = new Prampta({
  baseUrl: "http://localhost:8000",
  providerId: "my-ai-service",
  licenseeId: "acme-corp",
  token: "<paste-pair-token-here>",
});

const result = await pg.verify("leonardo-da-vinci", {
  modality: "image",
  categories: ["endorsement"],
  productName: "ad-campaign-2026",
});

if (result.allowed) {
  console.log(`ALLOWED — license: ${result.licenseId}`);
  console.log(`Watermark: ${result.watermarkPayload}`);
  console.log(`Obligations:`, result.obligations);
  // proceed with generation...
} else {
  console.log(`DENIED — ${result.reason}`);
  console.log(`Hard refusal: ${result.isHardRefusal}`);
  // do NOT generate
}
