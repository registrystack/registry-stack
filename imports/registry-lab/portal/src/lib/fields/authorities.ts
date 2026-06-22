import type { NotaryId } from '$lib/types';

// Human-readable authority names. Field-facing wait copy always names the
// authority (never a bare "Loading..."), so this map is the single source of
// truth for how a NotaryId reads to a citizen.
export const AUTHORITY_NAMES: Record<NotaryId, string> = {
  civil: 'Civil Registry',
  social: 'Social Welfare',
  agri: 'Agriculture',
  certs: 'Certificates Authority'
};

// A safe default so a wait still names *someone* if a result omits its notary.
const FALLBACK_AUTHORITY = 'the authority';

export function authorityName(notary: NotaryId | undefined): string {
  if (notary === undefined) return FALLBACK_AUTHORITY;
  return AUTHORITY_NAMES[notary];
}
