// The four ServiceForm descriptors (spec section 8: forms -> claim mapping).
//
// Each Field maps a kind/claim/notary/purpose/disclose so the form page can drive
// the EvidenceField renderer and the BFF can resolve a canned scenario by field
// id. The field ids ARE the scenario lookup keys the MockEvidenceProvider expects
// (see resolveScenarioKey), so they must match the keys in providers/mock/scenarios.ts.
//
// Exactly ONE field across all four forms is the climax manual button: the
// social-cash combined-eligibility decision (manual: true). Delegated civil reads
// in education-grant carry the `delegated` flag so the form gates them behind the
// Social guardian-link verify.

import type { Field, NotaryId, ServiceForm } from '$lib/types';

// ---------------------------------------------------------------------------
// agri-subsidy: the form fills itself from Agriculture, no delegation, no gate.
// ---------------------------------------------------------------------------
const agriSubsidy: ServiceForm = {
  slug: 'agri-subsidy',
  title: 'Agricultural Supply Subsidy',
  authorities: ['agri'],
  fields: [
    {
      id: 'agri-identity',
      label: 'Name and National ID',
      kind: 'self',
      purpose: 'agri_subsidy'
    },
    {
      id: 'registered-farmer',
      label: 'Registered farmer?',
      kind: 'verify',
      claim: 'registered-farmer',
      notary: 'agri',
      purpose: 'agri_subsidy',
      disclose: 'Not disclosed: only the yes/no, no farm details'
    },
    {
      id: 'farm-holding',
      label: 'Farm holding and parcel size',
      kind: 'fetch',
      claim: 'farm-holding',
      notary: 'agri',
      purpose: 'agri_subsidy',
      disclose: 'Not disclosed: parcel GPS coordinates and crop history'
    },
    {
      id: 'agri-requested-quantity',
      label: 'Requested input quantity',
      kind: 'self',
      selfPlaceholder: 'e.g. 4 bags of seed',
      purpose: 'agri_subsidy'
    },
    {
      id: 'voucher-eligibility',
      label: 'Eligibility',
      kind: 'decision',
      claim: 'voucher-eligibility',
      notary: 'agri',
      purpose: 'agri_subsidy',
      disclose: 'Not disclosed: the underlying parcel measurements behind the decision'
    }
  ]
};

// ---------------------------------------------------------------------------
// education-grant: the delegated two-hop. The Civil reads are flagged delegated
// and stay locked until the Social caregiver-link verify lands.
// ---------------------------------------------------------------------------
const educationGrant: ServiceForm = {
  slug: 'education-grant',
  title: 'Education Support Grant',
  authorities: ['social', 'civil'],
  fields: [
    {
      id: 'caregiver-link',
      label: 'Your dependents',
      kind: 'fetch',
      claim: 'caregiver-link',
      notary: 'social',
      purpose: 'education_grant',
      disclose: 'Not disclosed: any other dependents or household members'
    },
    {
      id: 'education-consent',
      label: 'Consent',
      kind: 'self',
      purpose: 'education_grant'
    },
    {
      id: 'guardian-link-verified',
      label: 'Guardian link verified',
      kind: 'verify',
      claim: 'caregiver-link',
      notary: 'social',
      purpose: 'education_grant',
      disclose: 'Not disclosed: any other dependents or household members'
    },
    {
      id: 'birth-event-exists',
      label: 'Child birth registered',
      kind: 'verify',
      claim: 'birth.event_exists',
      notary: 'civil',
      purpose: 'education_grant',
      disclose: 'Not disclosed: place of birth and registration officer',
      delegated: { relationshipClaim: 'caregiver-link', dependentRef: 'selected-child' }
    },
    {
      id: 'date-of-birth',
      label: 'Child date of birth',
      kind: 'fetch',
      claim: 'date-of-birth',
      notary: 'civil',
      purpose: 'education_grant',
      disclose: 'Not disclosed: full birth certificate, only the date',
      delegated: { relationshipClaim: 'caregiver-link', dependentRef: 'selected-child' }
    },
    {
      id: 'household-composition',
      label: 'Household composition',
      kind: 'fetch',
      claim: 'household-composition',
      notary: 'social',
      purpose: 'education_grant',
      disclose: 'Not disclosed: who the members are, only the count'
    }
  ]
};

// ---------------------------------------------------------------------------
// social-cash: the multi-authority climax. The combined-eligibility decision is
// the single manual button across all four forms.
// ---------------------------------------------------------------------------
const socialCash: ServiceForm = {
  slug: 'social-cash',
  title: 'Disability and Social Cash Support',
  authorities: ['civil', 'social'],
  fields: [
    {
      id: 'person-is-alive',
      label: 'Alive in civil registry?',
      kind: 'verify',
      claim: 'person-is-alive',
      notary: 'civil',
      purpose: 'social_cash',
      disclose: 'Not disclosed: any other civil record detail'
    },
    {
      id: 'disability-determination',
      label: 'Disability determination',
      kind: 'verify',
      claim: 'disability-determination',
      notary: 'social',
      purpose: 'social_cash',
      disclose: 'Not disclosed: any medical detail behind the determination'
    },
    {
      id: 'functioning-assessment',
      label: 'Functioning score',
      kind: 'fetch',
      claim: 'functioning-assessment',
      notary: 'social',
      purpose: 'social_cash',
      disclose: 'Not disclosed: the per-domain assessment breakdown'
    },
    {
      id: 'household-size',
      label: 'Household size',
      kind: 'fetch',
      claim: 'household-composition',
      notary: 'social',
      purpose: 'social_cash',
      disclose: 'Not disclosed: who the members are, only the count'
    },
    {
      id: 'social-requested-amount',
      label: 'Requested amount',
      kind: 'self',
      selfPlaceholder: 'e.g. 120 SOL / month',
      purpose: 'social_cash'
    },
    {
      id: 'combined-support-eligibility',
      label: 'Eligibility decision',
      kind: 'decision',
      claim: 'combined-support-eligibility',
      notary: 'social',
      purpose: 'social_cash',
      disclose: 'Not disclosed: the raw inputs each authority used',
      manual: true
    }
  ]
};

// ---------------------------------------------------------------------------
// civil-certificate: a single object fetch (verifiable document summary). Issues
// the wallet credential offer, so it never blocks on the delegated feature.
// ---------------------------------------------------------------------------
const civilCertificate: ServiceForm = {
  slug: 'civil-certificate',
  title: 'Birth or Marriage Certificate',
  authorities: ['certs'],
  fields: [
    {
      id: 'certificate-summary',
      label: 'Birth or marriage certificate',
      kind: 'fetch',
      claim: 'birth.certificate_summary',
      notary: 'certs',
      purpose: 'civil_certificate',
      disclose: 'Not disclosed: scanned certificate image and witness signatures'
    }
  ]
};

// The catalog: ordered for the presenter arc (agri, education, social, civil).
export const FORMS: ServiceForm[] = [agriSubsidy, educationGrant, socialCash, civilCertificate];

const FORMS_BY_SLUG: Record<string, ServiceForm> = Object.fromEntries(
  FORMS.map((f) => [f.slug, f])
) as Record<string, ServiceForm>;

export function getForm(slug: string): ServiceForm | undefined {
  return FORMS_BY_SLUG[slug];
}

// Catalog card copy. Kept beside the descriptors so the catalog and the form
// header read the same one-line summary.
export type CatalogEntry = {
  slug: string;
  title: string;
  summary: string;
  authorities: NotaryId[];
};

export const CATALOG: CatalogEntry[] = [
  {
    slug: 'agri-subsidy',
    title: agriSubsidy.title,
    summary: 'The form fills itself from the Agriculture authority: no copied database.',
    authorities: agriSubsidy.authorities
  },
  {
    slug: 'education-grant',
    title: educationGrant.title,
    summary: 'A grant for your child: read about someone else, only after a proven guardian link.',
    authorities: educationGrant.authorities
  },
  {
    slug: 'social-cash',
    title: socialCash.title,
    summary: 'One eligibility question composed from three signed authorities, no central data lake.',
    authorities: socialCash.authorities
  },
  {
    slug: 'civil-certificate',
    title: civilCertificate.title,
    summary: 'A signed certificate summary you can carry into your wallet.',
    authorities: civilCertificate.authorities
  }
];

// Helper: which fields auto-fetch on mount (verify/fetch, plus a non-manual
// decision like the agri voucher, excluding the manual climax decision and the
// consent/self placeholders). A delegated field is gated by the form page until
// the guardian link resolves, so it is excluded from the initial concurrent burst.
export function autoFetchFields(form: ServiceForm): Field[] {
  return form.fields.filter(
    (f) =>
      (f.kind === 'verify' || f.kind === 'fetch' || f.kind === 'decision') &&
      !f.manual &&
      !f.delegated
  );
}

// Helper: the single manual decision field, if the form has one.
export function manualField(form: ServiceForm): Field | undefined {
  return form.fields.find((f) => f.manual === true);
}

// Helper: the delegated fields (the second hop), in order.
export function delegatedFields(form: ServiceForm): Field[] {
  return form.fields.filter((f) => f.delegated !== undefined);
}
