// Client helper: POST /api/evaluate for a single field and return the ClaimResult.
//
// The server resolves the session subject and tees a REDACTED trace to the proof
// feed (which the SSE stream replays), so the rail/ticker/inspector light up a beat
// before this promise resolves. We never send a raw subject from the client; the
// only knobs are the field id, an optional scenario override, and the delegated
// gate boolean.

import type { ClaimResult } from '$lib/types';

export type EvaluateArgs = {
  slug: string;
  fieldId: string;
  scenarioKey?: string;
  guardianLinkVerified?: boolean;
};

// A denial / error comes back as a non-2xx in some cases (e.g. the cross-person
// 403), but the mock route returns the ClaimResult (state 'error') with a 200 for
// the in-band denial beat. We surface a network/HTTP failure as a thrown error so
// the form can land the field in ERROR rather than swallowing it.
export async function evaluateField(args: EvaluateArgs): Promise<ClaimResult> {
  const res = await fetch('/api/evaluate', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      slug: args.slug,
      fieldId: args.fieldId,
      ...(args.scenarioKey ? { scenarioKey: args.scenarioKey } : {}),
      ...(args.guardianLinkVerified === undefined
        ? {}
        : { delegated: { guardianLinkVerified: args.guardianLinkVerified } })
    })
  });

  if (!res.ok) {
    throw new Error(`evaluate failed (${res.status})`);
  }
  return (await res.json()) as ClaimResult;
}
