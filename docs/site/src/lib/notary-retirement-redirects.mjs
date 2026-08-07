export const NOTARY_RETIREMENT_ROUTE = '/decisions/notary-retirement-2026-08-03/';

export const RETIRED_NOTARY_ROUTE_TARGETS = {
  '/journeys/registry-backed-notary-claim/': '/start/evidence-quickstart/',
  '/tutorials/configure-dhis2-claim-checks/': NOTARY_RETIREMENT_ROUTE,
  '/tutorials/getting-started-fhir-evidence/': NOTARY_RETIREMENT_ROUTE,
  '/tutorials/run-notary-standalone-for-api/': NOTARY_RETIREMENT_ROUTE,
  '/tutorials/verify-claim-own-api/': NOTARY_RETIREMENT_ROUTE,
  '/tutorials/verify-opencrvs-dci-claims/': NOTARY_RETIREMENT_ROUTE,
  '/tutorials/move-notary-to-production-signing/':
    '/tutorials/move-evidence-to-production-signing/',
  '/tutorials/verify-claim-registry-api/': '/start/evidence-quickstart/',
  '/explanation/evidence-issuance/': NOTARY_RETIREMENT_ROUTE,
  '/reference/apis/registry-notary/': '/reference/apis/registry-evidence/',
  '/reference/apis/notary/': '/reference/apis/evidence/',
  '/spec/rs-dm-claim/': NOTARY_RETIREMENT_ROUTE,
  '/spec/rs-pr-notary/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/architecture-overview/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/client-sdk-guide/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/identity-and-record-matching/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/source-claim-modeling-guide/':
    '/configure/evidence/',
  '/products/registry-notary/operator-config-reference/': '/configure/evidence/',
  '/products/registry-notary/postgresql-state-operations/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/credential-lifecycle-status/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/credential-issuance-migration/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/signing-key-provider/':
    '/tutorials/move-evidence-to-production-signing/',
  '/products/registry-notary/sd-jwt-vc-conformance-profile/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/notary-capability-matrix/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/notary-scenario-patterns/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/federated-evaluation-operator-guide/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/subject-access-operator-guide/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/deployment-hardening-runbook/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/api-reference/': '/reference/apis/registry-evidence/',
  '/products/registry-notary/oid4vci-wallet-interop/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/release-notes/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/fhir-source-adapter-guide/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/opencrvs-onboarding/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/opencrvs-dci-standalone-tutorial/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/opencrvs-dci-onboarding/': NOTARY_RETIREMENT_ROUTE,
  '/products/registry-notary/sidecar-trust-and-secrets/': NOTARY_RETIREMENT_ROUTE,
  '/projects/registry-notary/': NOTARY_RETIREMENT_ROUTE,
  '/projects/registry-notary/run-locally/': NOTARY_RETIREMENT_ROUTE,
  '/projects/registry-notary/configure-a-claim/': '/configure/evidence/',
  '/projects/registry-notary/reference/': '/configure/evidence/',
  '/api/registry-notary.html': '/reference/apis/evidence/',
};

export const RETIRED_NOTARY_API_OPERATIONS = [
  'admincapabilities',
  'adminposture',
  'adminreload',
  'batchevaluateclaims',
  'completeoid4vcioffer',
  'completerepresentativeoid4vcioffer',
  'createoid4vciregistryoffer',
  'evaluateclaims',
  'federatedevaluate',
  'getclaim',
  'getcredentialstatus',
  'getevidencejwks',
  'getevidenceservice',
  'gethealthz',
  'getopenapi',
  'getopenidcredentialissuer',
  'getready',
  'getsdjwtvctypemetadata',
  'getwellknownsdjwtvctypemetadata',
  'issuecredential',
  'issueoid4vcicredential',
  'listclaims',
  'listformats',
  'redeemoid4vcitoken',
  'renderevidence',
  'startoid4vcioffer',
  'updatecredentialstatus',
];

export function buildNotaryRetirementRedirects(currentDocsetRedirect) {
  const redirects = Object.fromEntries(
    Object.entries(RETIRED_NOTARY_ROUTE_TARGETS).map(([source, target]) => [
      source,
      currentDocsetRedirect(target),
    ]),
  );

  for (const [source] of Object.entries(RETIRED_NOTARY_ROUTE_TARGETS)) {
    if (source.endsWith('/')) {
      redirects[`${source.slice(0, -1)}.md`] = currentDocsetRedirect(NOTARY_RETIREMENT_ROUTE);
    }
  }
  for (const operation of RETIRED_NOTARY_API_OPERATIONS) {
    redirects[`/reference/apis/notary/operations/${operation}/`] =
      currentDocsetRedirect(NOTARY_RETIREMENT_ROUTE);
  }

  return redirects;
}
