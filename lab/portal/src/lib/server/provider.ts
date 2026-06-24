// Server-side provider selection behind the EvidenceProvider seam (spec 5.6).
// Phase 0 boots PORTAL_PROVIDER=mock (the default). The LiveEvidenceProvider lands
// in Phase 1; asking for 'live' before then fails LOUDLY rather than silently
// serving mock data as if it were live (spec 5.7: a faked "live" result is worse
// than an honest fallback).

import { env } from '$env/dynamic/private';
import { MockEvidenceProvider } from '$lib/providers/mock';

// Memoized: a single instance per process keeps the trace sequence monotonic across
// requests (a fresh instance per call would reset the event counter).
let cached: MockEvidenceProvider | undefined;

export function getProvider(): MockEvidenceProvider {
  const mode = env.PORTAL_PROVIDER ?? 'mock';
  if (mode === 'live') {
    throw new Error('PORTAL_PROVIDER=live is not implemented yet (Phase 1). Boot with mock.');
  }
  if (mode !== 'mock') {
    throw new Error(`Unknown PORTAL_PROVIDER "${mode}". Expected "mock" or "live".`);
  }
  cached ??= new MockEvidenceProvider();
  return cached;
}
