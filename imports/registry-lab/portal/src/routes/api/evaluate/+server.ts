// POST /api/evaluate : proxy a single field's claim to its Notary (Phase 0: the
// MockEvidenceProvider).
//
// Body: { slug, fieldId, scenarioKey?, delegated? }
//   - slug / fieldId identify the field (the catalog descriptor lives in the
//     forms layer; here we resolve a scenario by fieldId / scenarioKey).
//   - scenarioKey is an explicit state-gallery override so every UX state is
//     reachable; it never changes the redaction or the subject binding.
//   - delegated.guardianLinkVerified gates the two-hop civil reads.
//
// The session subject is resolved SERVER-SIDE (never trust a client-supplied
// target), the provider is called, a REDACTED trace is teed to the proof feed,
// and the ClaimResult is returned.

import { error, json } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import type { Field } from '$lib/types';
import { teeToFeeds } from '$lib/server/bff';
import { getSession } from '$lib/server/session';
import { getProvider } from '$lib/server/provider';

type EvaluateBody = {
  slug?: string;
  fieldId?: string;
  scenarioKey?: string;
  delegated?: { guardianLinkVerified?: boolean; selectedChild?: string };
};

export const POST: RequestHandler = async ({ request, cookies }) => {
  const session = getSession(cookies);
  if (!session) {
    throw error(401, 'not signed in');
  }

  let body: EvaluateBody;
  try {
    body = (await request.json()) as EvaluateBody;
  } catch {
    throw error(400, 'invalid JSON body');
  }

  const fieldId = body.fieldId;
  if (!fieldId || typeof fieldId !== 'string') {
    throw error(400, 'fieldId is required');
  }

  // Minimal Field stub for the provider mapping. The forms layer owns the full
  // descriptor; the provider resolves a scenario by id / scenarioKey, so this is
  // enough to drive the canned evaluation.
  const field: Field = {
    id: fieldId,
    label: fieldId,
    kind: 'verify'
  };

  // The subject is the session subject, resolved server-side. The delegated
  // target (Miguel) is selected server-side too, never from a raw client id; we
  // only accept the boolean gate + a non-identifier child token from the client.
  const ctx = {
    subject: session.subject
  };

  const provider = getProvider();
  try {
    const evaluation = await provider.evaluateDetailed(field, ctx, {
      scenarioKey: body.scenarioKey,
      guardianLinkVerified: body.delegated?.guardianLinkVerified
    });

    // Tee a REDACTED trace + rail event to the feeds (the SSE stream replays it).
    teeToFeeds(evaluation, { fieldId });

    // Return only the portal-facing ClaimResult; raw wire stays server-side.
    return json(evaluation.result);
  } catch (err) {
    // No silent failure: surface a scoped 422 with a safe message (no identifiers).
    const message = err instanceof Error ? err.message : 'evaluation failed';
    throw error(422, message);
  }
};
