// Current and historical Relay routes all resolve to the public retirement
// decision. That page explains the removed capability and the bounded retained
// alternatives without implying that another product has equivalent semantics.

export const RELAY_RETIREMENT = '/decisions/registry-relay-retirement-2026-10-03/';

export const RETIRED_RELAY_ROUTES = [
  '/configure/',
  '/configure/relay/',
  '/decisions/relay-v1-and-registryctl-retirement-2026-08-11/',
  '/explanation/consultation-flow/',
  '/explanation/governed-registry-publication/',
  '/explanation/relay-semantics-and-disclosure/',
  '/generated-artifacts/',
  '/operate/',
  '/operate/relay/',
  '/products/registry-relay/',
  '/projects/registry-relay/',
  '/projects/registry-relay/run-locally/',
  '/projects/registry-relay/authorize-callers/',
  '/projects/registry-relay/reference/',
  '/reference/apis/registry-relay/',
  '/reference/apis/relay/',
  '/reference/relay-client-api/',
  '/reference/relayctl/',
  '/reference/registryctl/',
  '/reference/project-configuration/',
  '/reference/diagnostics/authoring/',
  '/reference/diagnostics/fixture/',
  '/reference/diagnostics/operator/',
  '/spec/rs-op-posture/',
  '/spec/rs-pr-registryctl/',
  '/spec/rs-pr-relay/',
  '/spec/rs-pr-relayctl/',
  '/tutorials/author-registry-project/',
  '/tutorials/configure-project-api-key-authentication/',
  '/tutorials/configure-project-script-adapter/',
  '/tutorials/deploy-standalone-with-own-data/',
  '/tutorials/first-run-with-solmara-lab/',
  '/tutorials/publish-governed-sqlite-registry/',
  '/tutorials/publish-spreadsheet-secured-registry-api/',
  '/tutorials/query-relay-client/',
  '/tutorials/use-your-spreadsheet/',
  '/tutorials/verify-opencrvs-claims/',
  '/verify/',
  '/operate/approve-initial-baseline/',
  '/operate/backup-and-restore/',
  '/operate/single-node-compose-behind-proxy/',
  '/operate/upgrade-and-rollback/',
  '/operate/advanced/compare-and-reapprove-source-change/',
  '/operate/advanced/operate-script-workers/',
  '/operate/advanced/recover-upgrade-migrate-and-rollback/',
  '/operate/advanced/refresh-and-recover-materialization/',
  '/products/registry-relay/api/',
  '/products/registry-relay/client-integration/',
  '/products/registry-relay/configuration/',
  '/products/registry-relay/metadata/',
  '/products/registry-relay/openfn-relay-adaptor-guide/',
  '/products/registry-relay/ops/',
  '/products/registry-relay/provenance/',
  '/products/registry-relay/relay-scenario-catalog/',
  '/products/registry-relay/release-notes/',
  '/products/registry-relay/standards-adapter-operator-guide/',
  '/products/registry-relay/standards-alignment/',
  '/products/registry-relay/xlsx-readiness-contract/',
];

const RETIRED_RELAY_API_OPERATIONS = [
  'execute_consultation',
  'get_api_catalog',
  'get_consultation_profile',
  'get_docs',
  'get_docs_scalar_bundle',
  'get_health',
  'get_metadata_catalog',
  'get_metadata_dataset',
  'get_metadata_dataset_policy',
  'get_metadata_dcat',
  'get_metadata_dcat_bregdcat_ap',
  'get_metadata_entity_schema_json',
  'get_metadata_entity_shacl',
  'get_metadata_evidence_offering',
  'get_metadata_landing',
  'get_metadata_policies',
  'get_metadata_shacl',
  'get_openapi',
  'get_ready',
  'get_social_registry_aggregate_metadata',
  'get_social_registry_aggregate_structure',
  'get_social_registry_dimension',
  'get_social_registry_household_field_schema',
  'get_social_registry_household_members',
  'get_social_registry_household_record',
  'get_social_registry_measure',
  'get_social_registry_metadata',
  'list_attribute_release_profiles',
  'list_datasets',
  'list_metadata_datasets',
  'list_metadata_evidence_offerings',
  'list_social_registry_aggregates',
  'list_social_registry_dimensions',
  'list_social_registry_household_records',
  'list_social_registry_measures',
  'query_social_registry_aggregate_explicit',
  'reload_dataset_table',
  'resolve_attribute_release',
  'run_social_registry_aggregate',
];

export function buildRelayRetirementRedirects(currentDocsetRedirect) {
  const target = currentDocsetRedirect(RELAY_RETIREMENT);
  const redirects = Object.fromEntries(RETIRED_RELAY_ROUTES.map((source) => [source, target]));

  for (const source of RETIRED_RELAY_ROUTES) {
    redirects[`${source.slice(0, -1)}.md`] = target;
  }
  for (const operation of RETIRED_RELAY_API_OPERATIONS) {
    redirects[`/reference/apis/relay/operations/${operation}/`] = target;
  }
  redirects['/api/registry-relay.html'] = target;

  return redirects;
}
