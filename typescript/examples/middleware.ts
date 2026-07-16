/**
 * Express middleware example — PRAMPTA guard for AI generation endpoints.
 *
 * This shows how to add PRAMPTA verification as middleware so
 * every generation request is checked automatically.
 *
 * Run:
 *   npm install express
 *   npx tsx examples/middleware.ts
 */

import { Prampta, PramptaError } from "../src/index.js";

// Shared client — reuse across requests
const pg = new Prampta({
  baseUrl: "http://localhost:8000",
  providerId: "my-ai-service",
  licenseeId: "acme-corp",
  token: "<paste-pair-token-here>",
});

/**
 * Example: verifying multiple subjects in parallel
 * (e.g., a scene with multiple people)
 */
async function generateScene(subjects: string[], prompt: string) {
  const results = await Promise.allSettled(
    subjects.map((s) =>
      pg.verify(s, { prompt, modality: "image", categories: ["likeness"] }),
    ),
  );

  const denied: string[] = [];
  const approved: string[] = [];

  for (let i = 0; i < subjects.length; i++) {
    const r = results[i];
    if (r.status === "rejected") {
      denied.push(`${subjects[i]}: ERROR — ${r.reason}`);
    } else if (r.value.denied) {
      denied.push(`${subjects[i]}: ${r.value.reason}`);
    } else {
      approved.push(subjects[i]);
    }
  }

  if (denied.length > 0) {
    console.log("Cannot generate scene. Denied subjects:");
    denied.forEach((d) => console.log(`  - ${d}`));
    return;
  }

  console.log(`All ${approved.length} subjects approved. Generating...`);
  // proceed with generation
}

// Demo
await generateScene(
  ["leonardo-da-vinci", "unknown-person", "opted-out-subject"],
  "Renaissance figures discussing a new invention in a workshop",
);
