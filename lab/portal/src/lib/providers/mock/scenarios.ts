// Canned scenarios driving the Phase 0 mock. Each scenario is keyed by a stable
// lookup id (field id, with a few delegated/denial variants) and carries enough
// to build both a ClaimResult and a ProofTrace whose depth-2 request/response
// bodies are STRUCTURALLY identical to the real Notary POST /v1/evaluations
// (EvaluateRequest / EvaluationResponse from registry-notary.openapi.json).
//
// Volatile fields (evaluation_id, issued_at/expires_at, signatures, freshness)
// are present but value-variable: they are stamped at evaluate() time, never
// byte-matched. Everything else (key set, types, ordering) matches the OpenAPI.

import type { FieldState, NotaryId, ProofStatus } from '$lib/types';

// Map a portal NotaryId to the human authority label the Notary returns and the
// proof inspector shows. Single canonical name per authority.
export const AUTHORITY_LABEL: Record<NotaryId, string> = {
  civil: 'Civil Registry',
  social: 'Social Protection',
  agri: 'Agriculture',
  certs: 'Civil Registry'
};

// Per-notary service id that appears in provenance.generated_by.service_id.
export const NOTARY_SERVICE_ID: Record<NotaryId, string> = {
  civil: 'civil-citizen-notary',
  social: 'social-citizen-notary',
  agri: 'agri-citizen-notary',
  certs: 'certs-citizen-notary'
};

// Per-notary public DID and signing key id (did:web), depth-3 crypto.
export const NOTARY_ISSUER_KEY: Record<NotaryId, string> = {
  civil: 'did:web:civil.notary.solmara.gov.example#key-1',
  social: 'did:web:social.notary.solmara.gov.example#key-1',
  agri: 'did:web:agri.notary.solmara.gov.example#key-1',
  certs: 'did:web:certs.notary.solmara.gov.example#key-1'
};

// What the Notary sends back as source_authority / the proof "answered" line.
// The `disclosure` mirrors the EvaluateRequest.disclosure on the wire.
export type ScenarioDisclosure = 'predicate' | 'value' | 'object' | 'decision';

// The depth-2 response value (the ClaimResultView.value). The runtime may return
// any JSON value; we keep it as unknown so booleans, dates, and objects all fit.
export type ScenarioResult = {
  // ---- routing / lookup ----
  notary: NotaryId;
  claimId: string; // the wire claim id, e.g. 'registered-farmer'
  claimVersion: string;
  // ---- request shaping (EvaluateRequest) ----
  purpose: string; // declared purpose
  disclosure: ScenarioDisclosure;
  // delegated scenarios send on_behalf_of + relationship:guardian, and read a
  // dependent subject. Non-delegated scenarios are relationship:self.
  delegated?: boolean;
  // ---- response / claim-result shaping (ClaimResultView) ----
  value: unknown; // boolean | string (date) | object summary
  satisfied: boolean | null; // null for plain value/object fetches
  subjectType: string; // 'person' | 'household' | 'holding'
  freshnessDays: number; // expires_at - issued_at, in days
  asOf: string; // human freshness date shown depth 1 (variable, demo-stable)
  // ---- portal-facing projection ----
  state: FieldState; // resulting FieldState
  display: string; // the value/predicate sentence shown in the field
  reasonCode?: string; // e.g. 'VR-RED-02'
  reasonCodes?: { code: string; authority: NotaryId; text: string }[]; // decisions
  // ---- proof depth-1 copy ----
  headline: string; // consequence-first
  answered: string; // "{Authority} answered: {claim} = {value}"
  notDisclosed: string; // ALWAYS present
  status: ProofStatus;
  // ---- denial / error shaping ----
  httpStatus: number; // 200 normally; 403 denial; 503 error
  denial?: { code: string; message: string }; // for the subject_mismatch beat
  // ---- resilience flavor ----
  // latencyMs is the deterministic delay; staggerOrder gives the top-to-bottom
  // stagger so fields land in a believable cascade, never all at once.
  latencyMs: number;
  staggerOrder: number;
  // an error scenario starts no Relay consultation (used.relay_consultation_count = 0)
  relayConsultationCount: number;
};

// Persona ids (already reconciled to real fixtures). These are SUBJECTS the BFF
// binds server-side; they NEVER reach the redacted proof feed. They live here so
// the mock can shape a realistic (then redacted) request.
export const PERSONA = {
  maria: 'NID-2001',
  miguel: 'NID-1001',
  pedro: 'NID-1010'
} as const;

// The canonical scenario table. Keys are the lookup ids the provider resolves a
// Field/ctx to (see resolveScenarioKey in index.ts).
export const SCENARIOS: Record<string, ScenarioResult> = {
  // ---------------------------------------------------------------------------
  // agri-subsidy
  // ---------------------------------------------------------------------------
  'registered-farmer': {
    notary: 'agri',
    claimId: 'registered-farmer',
    claimVersion: '2026-05',
    purpose: 'agri_subsidy',
    disclosure: 'predicate',
    value: true,
    satisfied: true,
    subjectType: 'person',
    freshnessDays: 30,
    asOf: '2026-05-01',
    state: 'verified',
    display: 'Registered farmer: yes',
    headline: 'Confirmed by Agriculture, Maria did not have to prove this herself',
    answered: 'Agriculture answered: registered-farmer = true',
    notDisclosed: 'Not disclosed: only the yes/no, no farm details',
    status: 'ok',
    httpStatus: 200,
    latencyMs: 900,
    staggerOrder: 0,
    relayConsultationCount: 1
  },
  'farm-holding': {
    notary: 'agri',
    claimId: 'farm-holding',
    claimVersion: '2026-05',
    purpose: 'agri_subsidy',
    disclosure: 'object',
    value: { holding_id: 'FARM-SOL-7741', parcel_count: 2, total_hectares: 3.4 },
    satisfied: null,
    subjectType: 'holding',
    freshnessDays: 90,
    asOf: '2026-04-18',
    state: 'fetched',
    display: '2 parcels, 3.4 ha total',
    headline: 'Fetched from Agriculture, the parcels are sealed and locked',
    answered: 'Agriculture answered: farm-holding = 2 parcels (3.4 ha)',
    notDisclosed: 'Not disclosed: parcel GPS coordinates and crop history',
    status: 'ok',
    httpStatus: 200,
    latencyMs: 1400,
    staggerOrder: 1,
    relayConsultationCount: 1
  },
  'voucher-eligibility': {
    notary: 'agri',
    claimId: 'voucher-eligibility',
    claimVersion: '2026-05',
    purpose: 'agri_subsidy',
    disclosure: 'decision',
    value: { eligible: true, voucher_tier: 'standard' },
    satisfied: true,
    subjectType: 'person',
    freshnessDays: 7,
    asOf: '2026-05-20',
    state: 'verified',
    display: 'Eligible (standard voucher)',
    reasonCodes: [
      { code: 'AG-VCH-01', authority: 'agri', text: 'Registered-farmer status confirmed' },
      { code: 'AG-VCH-04', authority: 'agri', text: 'Holding under the 4 ha smallholder ceiling' }
    ],
    headline: 'Decided by Agriculture, eligibility signed with its reasons',
    answered: 'Agriculture answered: voucher-eligibility = eligible (standard)',
    notDisclosed: 'Not disclosed: the underlying parcel measurements behind the decision',
    status: 'ok',
    httpStatus: 200,
    latencyMs: 1700,
    staggerOrder: 2,
    relayConsultationCount: 1
  },

  // ---------------------------------------------------------------------------
  // education-grant (delegated two-hop: social guardian-link, THEN civil reads)
  // ---------------------------------------------------------------------------
  'caregiver-link': {
    notary: 'social',
    claimId: 'caregiver-link',
    claimVersion: '2026-05',
    purpose: 'education_grant',
    disclosure: 'predicate',
    value: true,
    satisfied: true,
    subjectType: 'relationship',
    freshnessDays: 30,
    asOf: '2026-05-10',
    state: 'verified',
    display: 'Guardian link verified',
    headline: 'Confirmed by Social Protection, Maria is a verified guardian',
    answered: 'Social Protection answered: caregiver-link = true',
    notDisclosed: 'Not disclosed: any other dependents or household members',
    status: 'ok',
    httpStatus: 200,
    latencyMs: 1100,
    staggerOrder: 0,
    relayConsultationCount: 1
  },
  // The Civil reads below are HOP TWO: they are only authorized after the social
  // caregiver-link verify above succeeds. The provider enforces this gate.
  'birth-event-exists': {
    notary: 'civil',
    claimId: 'birth.event_exists',
    claimVersion: '2026-05',
    purpose: 'education_grant',
    disclosure: 'predicate',
    delegated: true,
    value: true,
    satisfied: true,
    subjectType: 'person',
    freshnessDays: 365,
    asOf: '2026-01-15',
    state: 'verified',
    display: 'Birth registered: yes',
    headline: 'Confirmed by Civil Registry, released only after the guardian link was proven',
    answered: 'Civil Registry answered: birth.event_exists = true',
    notDisclosed: 'Not disclosed: place of birth and registration officer',
    status: 'ok',
    httpStatus: 200,
    latencyMs: 1300,
    staggerOrder: 1,
    relayConsultationCount: 1
  },
  'date-of-birth': {
    notary: 'civil',
    claimId: 'date-of-birth',
    claimVersion: '2026-05',
    purpose: 'education_grant',
    disclosure: 'value',
    delegated: true,
    value: '2016-01-15',
    satisfied: null,
    subjectType: 'person',
    freshnessDays: 365,
    asOf: '2026-01-15',
    state: 'fetched',
    display: 'Date of birth: 2016-01-15',
    headline: 'Fetched from Civil Registry, released only after the guardian link was proven',
    answered: 'Civil Registry answered: date-of-birth = 2016-01-15',
    notDisclosed: 'Not disclosed: full birth certificate, only the date',
    status: 'ok',
    httpStatus: 200,
    latencyMs: 1500,
    staggerOrder: 2,
    relayConsultationCount: 1
  },
  'household-composition': {
    notary: 'social',
    claimId: 'household-composition',
    claimVersion: '2026-05',
    purpose: 'education_grant',
    disclosure: 'value',
    value: { household_size: 3 },
    satisfied: null,
    subjectType: 'household',
    freshnessDays: 30,
    asOf: '2026-05-09',
    state: 'fetched',
    display: 'Household size: 3',
    headline: 'Fetched from Social Protection, size only',
    answered: 'Social Protection answered: household-composition = size 3',
    notDisclosed: 'Not disclosed: who the members are, only the count',
    status: 'ok',
    httpStatus: 200,
    latencyMs: 1200,
    staggerOrder: 3,
    relayConsultationCount: 1
  },

  // ---------------------------------------------------------------------------
  // social-cash (multi-authority combined-eligibility decision)
  // ---------------------------------------------------------------------------
  'person-is-alive': {
    notary: 'civil',
    claimId: 'person-is-alive',
    claimVersion: '2026-05',
    purpose: 'social_cash',
    disclosure: 'predicate',
    value: true,
    satisfied: true,
    subjectType: 'person',
    freshnessDays: 1,
    asOf: '2026-06-21',
    state: 'verified',
    display: 'Alive: yes',
    headline: 'Confirmed by Civil Registry, liveness checked at source',
    answered: 'Civil Registry answered: person-is-alive = true',
    notDisclosed: 'Not disclosed: any other civil record detail',
    status: 'ok',
    httpStatus: 200,
    latencyMs: 800,
    staggerOrder: 0,
    relayConsultationCount: 1
  },
  'disability-determination': {
    notary: 'social',
    claimId: 'disability-determination',
    claimVersion: '2026-05',
    purpose: 'social_cash',
    disclosure: 'predicate',
    // verify FALSE (AMBER): still signed, carries a reason code, never collapses
    // to a denial. A legitimate signed "no".
    value: false,
    satisfied: false,
    subjectType: 'person',
    freshnessDays: 30,
    asOf: '2026-05-02',
    state: 'false',
    display: 'No active disability determination on file',
    reasonCode: 'SP-DIS-02',
    headline: 'Answered by Social Protection: a signed no, not a failure',
    answered: 'Social Protection answered: disability-determination = false',
    notDisclosed: 'Not disclosed: any medical detail behind the determination',
    status: 'false',
    httpStatus: 200,
    latencyMs: 1000,
    staggerOrder: 1,
    relayConsultationCount: 1
  },
  'functioning-assessment': {
    notary: 'social',
    claimId: 'functioning-assessment',
    claimVersion: '2026-05',
    purpose: 'social_cash',
    disclosure: 'value',
    value: { functioning_score: 42, scale: 'WHODAS-2.0' },
    satisfied: null,
    subjectType: 'person',
    freshnessDays: 90,
    asOf: '2026-03-15',
    state: 'fetched',
    display: 'Functioning score: 42 (WHODAS-2.0)',
    headline: 'Fetched from Social Protection, the score only',
    answered: 'Social Protection answered: functioning-assessment = 42',
    notDisclosed: 'Not disclosed: the per-domain assessment breakdown',
    status: 'ok',
    httpStatus: 200,
    latencyMs: 1350,
    staggerOrder: 2,
    relayConsultationCount: 1
  },
  'household-size': {
    notary: 'social',
    claimId: 'household-composition',
    claimVersion: '2026-05',
    purpose: 'social_cash',
    disclosure: 'value',
    value: { household_size: 3 },
    satisfied: null,
    subjectType: 'household',
    freshnessDays: 30,
    asOf: '2026-05-09',
    state: 'fetched',
    display: 'Household size: 3',
    headline: 'Fetched from Social Protection, size only not members',
    answered: 'Social Protection answered: household-composition = size 3',
    notDisclosed: 'Not disclosed: who the members are, only the count',
    status: 'ok',
    httpStatus: 200,
    latencyMs: 1250,
    staggerOrder: 3,
    relayConsultationCount: 1
  },
  'combined-support-eligibility': {
    notary: 'social',
    claimId: 'combined-support-eligibility',
    claimVersion: '2026-05',
    purpose: 'social_cash',
    disclosure: 'decision',
    value: { eligible: true, support_band: 'B' },
    satisfied: true,
    subjectType: 'person',
    freshnessDays: 7,
    asOf: '2026-06-21',
    state: 'verified',
    display: 'Eligible (support band B)',
    reasonCodes: [
      { code: 'CIV-ALV-01', authority: 'civil', text: 'Alive in the civil registry' },
      { code: 'SP-HHS-03', authority: 'social', text: 'Household size within the support threshold' },
      { code: 'SP-FNC-02', authority: 'social', text: 'Functioning score within the eligible range' }
    ],
    headline: 'Sealed by 3 authorities, no central data lake',
    answered: 'Social Protection answered: combined-support-eligibility = eligible (band B)',
    notDisclosed: 'Not disclosed: the raw inputs each authority used',
    status: 'ok',
    httpStatus: 200,
    latencyMs: 2100,
    staggerOrder: 4,
    relayConsultationCount: 3
  },

  // ---------------------------------------------------------------------------
  // civil-certificate (object fetch -> verifiable document summary)
  // ---------------------------------------------------------------------------
  'certificate-summary': {
    notary: 'certs',
    claimId: 'birth.certificate_summary',
    claimVersion: '2026-05',
    purpose: 'civil_certificate',
    disclosure: 'object',
    value: {
      certificate_type: 'birth',
      certificate_id: 'CSR-BIRTH-2001',
      issued_on: '2001-03-12',
      registry_office: 'Solmara Central Civil Registry'
    },
    satisfied: null,
    subjectType: 'person',
    freshnessDays: 365,
    asOf: '2026-06-01',
    state: 'fetched',
    display: 'Birth certificate summary (CSR-BIRTH-2001)',
    headline: 'Fetched from Civil Registry as a signed certificate summary',
    answered: 'Civil Registry answered: birth.certificate_summary = CSR-BIRTH-2001',
    notDisclosed: 'Not disclosed: scanned certificate image and witness signatures',
    status: 'ok',
    httpStatus: 200,
    latencyMs: 1600,
    staggerOrder: 0,
    relayConsultationCount: 1
  },

  // ---------------------------------------------------------------------------
  // Denial beat (cross-person, stranger Pedro NID-1010): a real denied
  // evaluation, 403 subject_mismatch, and no Relay consultation.
  // ---------------------------------------------------------------------------
  denial: {
    notary: 'civil',
    claimId: 'person-is-alive',
    claimVersion: '2026-05',
    purpose: 'social_cash',
    disclosure: 'predicate',
    value: null,
    satisfied: null,
    subjectType: 'person',
    freshnessDays: 0,
    asOf: '2026-06-21',
    state: 'error',
    display: 'Denied: you cannot query this person',
    reasonCode: 'subject_mismatch',
    headline: 'Denied by Civil Registry before any record was read',
    answered: 'Civil Registry answered: 403 subject_mismatch, no data returned',
    notDisclosed: 'Not disclosed: nothing, the boundary held and no Relay consultation ran',
    status: 'denied',
    httpStatus: 403,
    denial: { code: 'subject_mismatch', message: 'requester is not authorized for this target' },
    latencyMs: 600,
    staggerOrder: 0,
    relayConsultationCount: 0
  },

  // ---------------------------------------------------------------------------
  // Resilience states (drive the degradation UX)
  // ---------------------------------------------------------------------------
  // SLOW: a still-in-flight live call that crosses the ~6-8s SLOW threshold but
  // eventually resolves verified. The provider surfaces SLOW before VERIFIED.
  slow: {
    notary: 'agri',
    claimId: 'registered-farmer',
    claimVersion: '2026-05',
    purpose: 'agri_subsidy',
    disclosure: 'predicate',
    value: true,
    satisfied: true,
    subjectType: 'person',
    freshnessDays: 30,
    asOf: '2026-05-01',
    state: 'verified',
    display: 'Registered farmer: yes',
    headline: 'Confirmed by Agriculture after a slow but live call',
    answered: 'Agriculture answered: registered-farmer = true',
    notDisclosed: 'Not disclosed: only the yes/no, no farm details',
    status: 'ok',
    httpStatus: 200,
    latencyMs: 7000,
    staggerOrder: 0,
    relayConsultationCount: 1
  },
  // ERROR: a hard failure (503). Scoped to the field, framed as minimization. No
  // Relay consultation, no value.
  error: {
    notary: 'social',
    claimId: 'household-composition',
    claimVersion: '2026-05',
    purpose: 'social_cash',
    disclosure: 'value',
    value: null,
    satisfied: null,
    subjectType: 'household',
    freshnessDays: 0,
    asOf: '2026-06-21',
    state: 'error',
    display: 'Could not reach Social Protection; other evidence is unaffected',
    reasonCode: 'upstream_unavailable',
    headline: 'Could not reach Social Protection, the other authorities are unaffected',
    answered: 'Social Protection answered: 503, no data returned',
    notDisclosed: 'Not disclosed: nothing, there is no central lake so this failure is isolated',
    status: 'error',
    httpStatus: 503,
    latencyMs: 8000,
    staggerOrder: 0,
    relayConsultationCount: 0
  },
  // STALE: fetched but older than the freshness rule (BLUE + AMBER flag).
  stale: {
    notary: 'social',
    claimId: 'functioning-assessment',
    claimVersion: '2026-05',
    purpose: 'social_cash',
    disclosure: 'value',
    value: { functioning_score: 38, scale: 'WHODAS-2.0' },
    satisfied: null,
    subjectType: 'person',
    freshnessDays: -120, // expired: expires_at is in the past relative to issued
    asOf: '2025-09-30',
    state: 'stale',
    display: 'Functioning score: 38 (assessed 2025-09-30, past freshness window)',
    headline: 'Fetched from Social Protection, but older than the freshness rule',
    answered: 'Social Protection answered: functioning-assessment = 38 (stale)',
    notDisclosed: 'Not disclosed: the per-domain assessment breakdown',
    status: 'ok',
    httpStatus: 200,
    latencyMs: 1300,
    staggerOrder: 0,
    relayConsultationCount: 1
  },
  // AMBIGUOUS: more than one record matched; never collapses to false.
  ambiguous: {
    notary: 'civil',
    claimId: 'person-is-alive',
    claimVersion: '2026-05',
    purpose: 'social_cash',
    disclosure: 'predicate',
    value: null,
    satisfied: null,
    subjectType: 'person',
    freshnessDays: 0,
    asOf: '2026-06-21',
    state: 'ambiguous',
    display: 'More than one record matched; needs disambiguation',
    reasonCode: 'multiple_matches',
    headline: 'Civil Registry found more than one matching record',
    answered: 'Civil Registry answered: 2 candidate records, no single match',
    notDisclosed: 'Not disclosed: the candidate records themselves, only the count',
    status: 'error',
    httpStatus: 200,
    latencyMs: 1400,
    staggerOrder: 0,
    relayConsultationCount: 2
  }
};

export type ScenarioKey = keyof typeof SCENARIOS;
