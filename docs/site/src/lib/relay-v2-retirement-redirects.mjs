// Routes retired by the Relay V2 cutover.
//
// Relay V2 replaced the V1 runtime and replaced `registryctl` with `relayctl`.
// The V1 pages documented capabilities V2 does not have (HTTP and spreadsheet
// sources, Rhai adapters, source-side OAuth, API keys, approved baselines,
// materializations, standards adapters, per-product OpenAPI), so they are
// retired rather than rewritten. Every retired route keeps resolving by
// pointing at the nearest supported V2 page instead of returning 404.
//
// Same shape as src/lib/notary-retirement-redirects.mjs: a route -> target map,
// the generated API operation slugs the old Relay schema published, and a
// builder that also emits the per-page `.md` twin every trailing-slash route
// carries.

const GOVERNED_REGISTRY_TUTORIAL = '/tutorials/publish-governed-sqlite-registry/';
const RELAY_OPERATIONS = '/operate/relay/';
const RELAYCTL_REFERENCE = '/reference/relayctl/';
const API_REFERENCE_OVERVIEW = '/reference/apis/';
const RELAY_PRODUCT_DOCS = '/products/registry-relay/';

export const RETIRED_RELAY_ROUTE_TARGETS = {
  // Authoring tutorials for V1 source kinds. V2 authors one governed SQLite
  // registry, so they all land on that single tutorial.
  '/tutorials/publish-spreadsheet-secured-registry-api/': GOVERNED_REGISTRY_TUTORIAL,
  '/tutorials/use-your-spreadsheet/': GOVERNED_REGISTRY_TUTORIAL,
  '/tutorials/author-registry-project/': GOVERNED_REGISTRY_TUTORIAL,
  '/tutorials/configure-project-script-adapter/': GOVERNED_REGISTRY_TUTORIAL,
  '/tutorials/configure-project-api-key-authentication/': GOVERNED_REGISTRY_TUTORIAL,
  '/tutorials/deploy-standalone-with-own-data/': GOVERNED_REGISTRY_TUTORIAL,
  '/tutorials/verify-opencrvs-claims/': GOVERNED_REGISTRY_TUTORIAL,

  // V1 operator procedures. V2 has one operate page for the whole runtime.
  '/operate/approve-initial-baseline/': RELAY_OPERATIONS,
  '/operate/backup-and-restore/': RELAY_OPERATIONS,
  '/operate/upgrade-and-rollback/': RELAY_OPERATIONS,
  '/operate/single-node-compose-behind-proxy/': RELAY_OPERATIONS,
  '/operate/advanced/compare-and-reapprove-source-change/': RELAY_OPERATIONS,
  '/operate/advanced/operate-script-workers/': RELAY_OPERATIONS,
  '/operate/advanced/recover-upgrade-migrate-and-rollback/': RELAY_OPERATIONS,
  '/operate/advanced/refresh-and-recover-materialization/': RELAY_OPERATIONS,

  // registryctl reference surfaces. relayctl is the V2 adopter tool and the
  // only command reference that still describes a shipped binary.
  '/reference/registryctl/': RELAYCTL_REFERENCE,
  '/reference/project-configuration/': RELAYCTL_REFERENCE,
  '/reference/diagnostics/authoring/': RELAYCTL_REFERENCE,
  '/reference/diagnostics/fixture/': RELAYCTL_REFERENCE,
  '/reference/diagnostics/operator/': RELAYCTL_REFERENCE,

  // V2 generates its OpenAPI per deployment from the adopter's own registry
  // contract and serves it at GET /openapi.json, so there is no product-level
  // Relay API document left to render.
  '/reference/apis/registry-relay/': API_REFERENCE_OVERVIEW,
  '/reference/apis/relay/': API_REFERENCE_OVERVIEW,

  '/explanation/consultation-flow/': '/explanation/relay-semantics-and-disclosure/',
  '/configure/oauth-client-credentials/': '/configure/relay/',
  '/spec/rs-pr-registryctl/': '/spec/rs-pr-relayctl/',

  // Pulled V1 product docs. Only the product overview survives the retarget in
  // src/data/repo-docs.yaml.
  '/products/registry-relay/client-integration/': RELAY_PRODUCT_DOCS,
  '/products/registry-relay/configuration/': '/configure/relay/',
  '/products/registry-relay/api/': API_REFERENCE_OVERVIEW,
  '/products/registry-relay/metadata/': RELAY_PRODUCT_DOCS,
  '/products/registry-relay/ops/': RELAY_OPERATIONS,
  '/products/registry-relay/provenance/': RELAY_PRODUCT_DOCS,
  '/products/registry-relay/openfn-relay-adaptor-guide/': RELAY_PRODUCT_DOCS,
  '/products/registry-relay/standards-adapter-operator-guide/': RELAY_PRODUCT_DOCS,
  '/products/registry-relay/xlsx-readiness-contract/': RELAY_PRODUCT_DOCS,
  '/products/registry-relay/standards-assumptions/': '/products/registry-relay/standards-alignment/',
  '/products/registry-relay/relay-scenario-catalog/': RELAY_PRODUCT_DOCS,
  '/products/registry-relay/release-notes/': '/changelog/',

  // Static Redoc HTML from before the native API pages. No trailing slash, so
  // it carries no .md twin.
  '/api/registry-relay.html': API_REFERENCE_OVERVIEW,
};

// operationId values from the retired crates/registry-relay OpenAPI document,
// lowercased the way github-slugger (via starlight-openapi) slugged them into
// /reference/apis/relay/operations/<slug>/.
export const RETIRED_RELAY_API_OPERATIONS = [
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

export function buildRelayV2RetirementRedirects(currentDocsetRedirect) {
  const redirects = Object.fromEntries(
    Object.entries(RETIRED_RELAY_ROUTE_TARGETS).map(([source, target]) => [
      source,
      currentDocsetRedirect(target),
    ]),
  );

  for (const [source, target] of Object.entries(RETIRED_RELAY_ROUTE_TARGETS)) {
    if (source.endsWith('/')) {
      redirects[`${source.slice(0, -1)}.md`] = currentDocsetRedirect(target);
    }
  }
  for (const operation of RETIRED_RELAY_API_OPERATIONS) {
    redirects[`/reference/apis/relay/operations/${operation}/`] =
      currentDocsetRedirect(API_REFERENCE_OVERVIEW);
  }

  return redirects;
}
