// @ts-check
import { readFileSync } from 'node:fs';
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import starlight from '@astrojs/starlight';
import starlightLlmsTxt from 'starlight-llms-txt';
import starlightOpenAPI, { openAPISidebarGroups } from 'starlight-openapi';
import mermaid from 'astro-mermaid';
import remarkGfm from 'remark-gfm';
// Single source of truth for the machine-discovery pointer. Reused as the
// llms.txt `details` block so it can never drift from the header the per-page
// .md endpoint prepends (src/pages/[...slug].md.ts).
import { discoveryHeaderForBase } from './src/lib/page-markdown.ts';
import { cliReferenceSidebar } from './src/lib/cli-reference-sidebar.mjs';
import { flattenSidebarGroups } from './src/lib/sidebar.mjs';
import { buildNotaryRetirementRedirects } from './src/lib/notary-retirement-redirects.mjs';
import { buildRelayV2RetirementRedirects } from './src/lib/relay-v2-retirement-redirects.mjs';

// Marketing site that now owns the persuasion layer (the pitch). Old docs
// routes that migrated there redirect to these pages.
const marketing = 'https://registrystack.org';

// Product navigation is generated from src/data/repo-docs.yaml by
// scripts/generate-sidebar.mjs (run via `npm run generate`), so the menu is
// derived from the manifest's doc_type/nav_order and never drifts from it.
// Read it resiliently: a missing file (astro run without generating first)
// warns loudly and falls back to an empty product nav rather than failing the
// whole config; malformed JSON still throws.
function loadProductSidebar() {
  const path = new URL('./src/data/generated/sidebar.json', import.meta.url);
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
      console.warn(
        '[sidebar] src/data/generated/sidebar.json missing; run `npm run generate`. Product nav will be empty.',
      );
      return [];
    }
    throw error;
  }
}

function loadDocsetsManifest() {
  const path = new URL('./src/data/generated/docsets.json', import.meta.url);
  return JSON.parse(readFileSync(path, 'utf8'));
}

/**
 * @param {{ current: string, released: string, docsets: Array<{ id: string, status: string, availability: string, path: string }> }} docsets
 * @param {NodeJS.ProcessEnv} env
 */
export function resolveDocsetBuildContext(docsets, env = process.env) {
  const selectedId = env.DOCS_DOCSET || docsets.current;
  const selectedDocset = docsets.docsets.find((entry) => entry.id === selectedId);
  if (!selectedDocset) throw new Error(`selected docs docset "${selectedId}" not found`);

  const base = env.DOCS_BASE || undefined;
  const basePath = base?.replace(/\/$/, '');
  const isArchivedBuild = selectedDocset.status === 'archived';
  const isReleasedArchiveBuild =
    isArchivedBuild && env.DOCS_RELEASED_ARCHIVE === 'true';
  const isHistoricalArchiveBuild =
    isArchivedBuild && !isReleasedArchiveBuild && selectedDocset.id !== docsets.released;
  const isSearchExcludedBuild =
    isHistoricalArchiveBuild || selectedDocset.availability === 'unreleased';
  const currentDocset = docsets.docsets.find((entry) => entry.id === docsets.current);
  if (!currentDocset) throw new Error(`current docs docset "${docsets.current}" not found`);
  /** @param {string} path */
  const internalRedirect = (path) => basePath ? `${basePath}${path}` : path;
  /** @param {string} path */
  const currentDocsetRedirect = (path) =>
    isArchivedBuild
      ? `https://docs.registrystack.org${currentDocset.path.replace(/\/$/, '')}${path}`
      : internalRedirect(path);

  return {
    base,
    basePath,
    isArchivedBuild,
    isReleasedArchiveBuild,
    isHistoricalArchiveBuild,
    isSearchExcludedBuild,
    internalRedirect,
    currentDocsetRedirect,
  };
}

const docsetsManifest = loadDocsetsManifest();
const {
  base,
  isArchivedBuild,
  isHistoricalArchiveBuild,
  isSearchExcludedBuild,
  internalRedirect,
  currentDocsetRedirect,
} = resolveDocsetBuildContext(docsetsManifest);
const productSidebar = loadProductSidebar();

// Lift a generated per-product group to the top level of the sidebar.
// Fails the build loudly if the generator's labels change, so the nav can
// never silently lose a product section.
/** @param {string} label */
function generatedProduct(label) {
  const group = productSidebar.find((/** @type {{ label: string }} */ entry) => entry.label === label);
  if (!group) throw new Error(`generated sidebar group "${label}" not found`);
  return group;
}

// A product absent from this docset's generated sidebar (a product newer than
// an archived docset) yields no group instead of failing the build.
/** @param {string} label */
function optionalGeneratedProduct(label) {
  return productSidebar.find((/** @type {{ label: string }} */ entry) => entry.label === label) ?? null;
}
const disabledSitemap = {
  name: '@astrojs/sitemap',
  hooks: {},
};
const caseworkOpenApiSchema = {
  base: 'reference/apis/casework',
  schema: './openapi/registry-casework.openapi.json',
  sidebar: {
    label: 'API operations',
    collapsed: true,
    operations: { labels: /** @type {'path'} */ ('path'), badges: true },
  },
};
const caseworkCurrentOnlyRoutes = [
  '/start/casework/',
  '/tutorials/first-casework/',
  '/explanation/how-casework-works/',
  '/configure/casework/',
  '/operate/casework/',
  '/operate/casework-retention/',
  '/reference/apis/registry-casework/',
];

export default defineConfig({
  site: 'https://docs.registrystack.org',
  base,
  trailingSlash: 'always',
  markdown: {
    remarkPlugins: [remarkGfm],
  },
  // Redirects for content that moved in the docs/marketing split (Wave 4).
  // External redirects (to marketing) absorb the migrated persuasion pages;
  // internal redirects map the retired /projects/* and /capabilities/* routes
  // to their new homes so old links and search results keep resolving.
  redirects: {
    ...buildNotaryRetirementRedirects(currentDocsetRedirect),
    ...buildRelayV2RetirementRedirects(currentDocsetRedirect),
    ...(isArchivedBuild ? Object.fromEntries(caseworkCurrentOnlyRoutes.flatMap((route) => [
      [route, currentDocsetRedirect(route)],
      [`${route.slice(0, -1)}.md`, currentDocsetRedirect(route)],
    ])) : {}),
    '/start/': internalRedirect('/'),
    '/start/see-it-live/': internalRedirect('/'),
    // Retired product choosers. The homepage chooses between the products, so
    // both the second chooser and the one that outlived it land there.
    '/start/quickstart/': internalRedirect('/'),
    '/start/when-to-use/': internalRedirect('/'),
    '/explanation/trust-posture-and-security-guarantees/': internalRedirect('/security/'),
    '/reference/security-self-assessment/': internalRedirect('/security/self-assessment/'),
    '/reference/openssf-evidence/': internalRedirect('/security/openssf-evidence/'),
    // Webhook binding is an operator task with its own page; history reads
    // and the event reference are sections of the API reference page.
    '/configure/breg-webhooks/': internalRedirect('/operate/breg-webhooks/'),
    '/reference/breg-history/': internalRedirect('/reference/breg-api/'),
    '/reference/breg-events/': internalRedirect('/reference/breg-api/'),
    // The operating-requirements pages moved from Start into each product's
    // Deploy group; a first visit chooses a product before it plans a deployment.
    '/start/evaluate-evidence/': internalRedirect('/operate/evidence-requirements/'),
    '/start/evaluate-breg/': internalRedirect('/operate/breg-requirements/'),
    // One client package ships all four namespaces, so one reference page
    // documents them; the two per-product pages it absorbed keep resolving.
    '/reference/relay-client-api/': internalRedirect('/reference/client-api/'),
    '/reference/breg-client-api/': internalRedirect('/reference/client-api/'),
    // Retired pages keep old links useful by sending readers to a supported
    // task or reference page.
    '/journeys/': internalRedirect('/'),
    '/journeys/spreadsheet-protected-api/': internalRedirect('/tutorials/publish-governed-sqlite-registry/'),
    '/journeys/instance-openapi/': internalRedirect('/reference/apis/'),
    '/journeys/bounded-http/': internalRedirect('/tutorials/publish-governed-sqlite-registry/'),
    '/journeys/bounded-multi-call-script/': internalRedirect('/tutorials/publish-governed-sqlite-registry/'),
    '/journeys/exact-snapshot/': internalRedirect('/configure/'),
    '/journeys/product-input-lifecycle/': internalRedirect('/generated-artifacts/'),
    // Retired first-call and source-review routes enter the supported local path.
    '/start/your-first-call/': internalRedirect('/tutorials/publish-governed-sqlite-registry/'),
    '/start/test-current-source-revision/': internalRedirect('/'),
    // Retired lab tutorials land on the homepage or the Evidence Gateway
    // overview. The historical Solmara workflow used an obsolete Relay source
    // path and is no longer published as current guidance.
    '/tutorials/first-run-with-registry-lab/': internalRedirect('/'),
    '/tutorials/first-run-with-solmara-lab/': internalRedirect('/start/evidence-quickstart/'),
    '/tutorials/review-a-dhis2-evidence-source/': internalRedirect('/tutorials/issue-immunization-evidence-from-dhis2/'),
    // Retired monorepo lab tutorials redirect to the current integration guidance.
    // Retired advanced tutorials land on current task, explanation, or
    // reference entry points. The Relay V1 authoring tutorials are retired by
    // buildRelayV2RetirementRedirects above.
    '/tutorials/configure-project-fhir-r4/': internalRedirect('/explanation/integration-patterns/'),
    '/tutorials/configure-project-snapshot-materialization/': internalRedirect('/configure/'),
    // Problems -> marketing /why
    '/problems/': `${marketing}/why/`,
    '/problems/existing-data-not-service-ready/': `${marketing}/why/`,
    '/problems/apis-over-share-records/': `${marketing}/why/`,
    '/problems/safeguards-need-technical-enforcement/': `${marketing}/why/`,
    '/problems/one-off-integrations/': `${marketing}/why/`,
    '/problems/registry-capabilities-hard-to-discover/': `${marketing}/why/`,
    '/problems/semantics-do-not-line-up/': `${marketing}/why/`,
    '/problems/entity-identity-and-matching/': `${marketing}/why/`,
    // Use cases -> marketing /use-cases
    '/use-cases/': `${marketing}/use-cases/`,
    '/use-cases/business-registry-status/': `${marketing}/use-cases/`,
    '/use-cases/eligibility-or-entitlement-evidence/': `${marketing}/use-cases/`,
    '/use-cases/legacy-registry-api/': `${marketing}/use-cases/`,
    '/use-cases/publish-registry-metadata/': `${marketing}/use-cases/`,
    '/use-cases/inspect-before-integrating/': `${marketing}/use-cases/`,
    // Ecosystem positioning -> marketing /ecosystem
    '/ecosystem/': `${marketing}/ecosystem/`,
    // Why now -> marketing /why-now
    '/start/safer-registry-surfaces/': `${marketing}/why-now/`,
    // Capabilities taxonomy -> the Explanation pages that absorbed it (internal)
    '/capabilities/': internalRedirect('/explanation/architecture/'),
    '/capabilities/describe-registries/': internalRedirect('/explanation/architecture/'),
    '/capabilities/expose-protected-apis/': internalRedirect('/explanation/architecture/'),
    '/capabilities/certify-evidence/': internalRedirect('/explanation/architecture/'),
    '/capabilities/audit-and-operate/': internalRedirect('/explanation/architecture/'),
    '/capabilities/inspect-published-artifacts/': internalRedirect('/explanation/architecture/'),
    // Hand-authored projects/* -> pulled products/* (internal)
    '/projects/registry-relay/': internalRedirect('/products/registry-relay/'),
    '/projects/registry-relay/run-locally/': internalRedirect('/products/registry-relay/'),
    '/projects/registry-relay/authorize-callers/': internalRedirect('/configure/relay/'),
    '/projects/registry-relay/reference/': internalRedirect('/configure/relay/'),
    // Retired project routes redirect only when a current replacement exists.
    // Solmara Lab is an external adopter, not a Registry Stack product.
    '/projects/registry-lab/demo-flow/': internalRedirect('/'),
  },
  integrations: [
    // Mermaid must come BEFORE starlight: its rehype plugin rewrites
    // ```mermaid fences to <pre class="mermaid"> before Expressive Code
    // would otherwise highlight them as raw code. Diagrams render
    // client-side; autoTheme follows Starlight's data-theme (light/dark).
    mermaid({
      theme: 'default',
      autoTheme: true,
      // Quiet the per-diagram client console logging; errors still log.
      enableLog: false,
    }),
    starlight({
      title: 'Registry stack docs',
      description: 'Documentation for Registry Stack: publish existing records with Registry Relay, answer bounded questions with Evidence Gateway, or build a writable registry with the Base Registry Engine source preview.',
      // Historical archives keep their sealed search posture. A new released
      // archive is built once on the release runner and carries its exact
      // Pagefind output into production.
      pagefind: !isSearchExcludedBuild,
      plugins: [
        // Generates /llms.txt, /llms-full.txt, and /llms-small.txt for
        // machine consumption. The `details` field carries the discovery
        // pointer so LLM clients know where to find both corpus files.
        // API reference pages (reference/apis/*) are Redoc HTML embeds with
        // minimal prose; they are excluded from llms-small.txt to keep the
        // compact version useful, but remain in llms-full.txt.
        // Released archives carry their machine-readable corpus into the
        // canonical root. Historical archives retain their sealed output.
        ...(isHistoricalArchiveBuild ? [] : [starlightLlmsTxt({
          description: 'Documentation for Registry Stack: tutorials, product docs, explanation, and API reference for Registry Relay, Evidence Gateway, and the Base Registry Engine source preview.',
          details: discoveryHeaderForBase(base),
          exclude: ['reference/apis/**'],
          promote: ['index*', 'explanation/**'],
          demote: ['reference/**', 'decisions/**'],
        })]),
        // Renders the pinned OpenAPI documents as native Starlight pages, so the
        // API reference follows the light/dark theme and is indexed by Pagefind
        // search (the old Redoc HTML embeds were light-only and unsearchable).
        // Schemas are produced by scripts/fetch-openapi.mjs in `npm run generate`,
        // which runs before any build. The generated routes live alongside the
        // hand-authored narrative pages (reference/apis/registry-*), which link
        // into them; old /api/*.html links are preserved by redirects above.
        // Relay is not registered here: Relay V2 compiles its OpenAPI per
        // deployment from the adopter's own registry contract and serves it at
        // GET /openapi.json, so there is no product-level document to pin.
        starlightOpenAPI([
          {
            base: 'reference/apis/evidence',
            schema: './openapi/registry-evidence.openapi.json',
            sidebar: {
              label: 'API operations',
              collapsed: true,
              operations: { labels: 'path', badges: true },
            },
          },
          ...[caseworkOpenApiSchema].filter(() => !isArchivedBuild),
        ]),
      ],
      defaultLocale: 'root',
      locales: {
        root: {
          label: 'English',
          lang: 'en',
        },
      },
      customCss: ['./src/styles/custom.css'],
      routeMiddleware: './src/sidebar-middleware.mjs',
      // Expressive Code settings live in ec.config.mjs, not here: the
      // starlight-openapi plugin replaces this key wholesale. See that file.
      components: {
        Banner: './src/components/RegistryBanner.astro',
        Head: './src/components/RegistryHead.astro',
        Header: './src/components/RegistryHeader.astro',
        PageSidebar: './src/components/RegistryPageSidebar.astro',
        PageTitle: './src/components/RegistryPageTitle.astro',
        Footer: './src/components/RegistryFooter.astro',
        MobileMenuFooter: './src/components/RegistryMobileMenuFooter.astro',
      },
      editLink: {
        baseUrl: 'https://github.com/registrystack/registry-stack/edit/main/docs/site/',
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/registrystack/registry-stack/tree/main/docs/site',
        },
      ],
      // Product names are the scan targets; the chooser explains their jobs.
      // Start stays open. Starlight opens the active page's ancestors even
      // when their default is collapsed, keeping other journeys out of the way.
      sidebar: [
        {
          label: 'Start',
          items: [
            { label: 'Overview', link: '/' },
            { label: 'Glossary', slug: 'reference/glossary' },
          ],
        },
        {
          label: 'Evidence Gateway',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'start/evidence-quickstart' },
            { label: 'Your first assertion', slug: 'tutorials/first-evidence-assertion' },
            // Consumers need no deployment. Keep their path visible beside
            // the provider's entry points, separate from wallet delivery.
            {
              label: 'Use from applications',
              collapsed: true,
              items: [
                { label: 'Request an assertion', slug: 'tutorials/request-evidence-from-an-application' },
                { label: 'Verify and retain assertions', slug: 'tutorials/verify-an-assertion-as-a-consumer' },
                { label: 'Manage verifier trust', slug: 'tutorials/manage-evidence-verifier-trust' },
                { label: 'Automate with OpenFn', slug: 'explanation/openfn-adaptors' },
              ],
            },
            {
              label: 'Tutorials',
              collapsed: true,
              items: [
                { label: 'Explore SD-JWT VC', slug: 'tutorials/request-evidence-as-sd-jwt-vc' },
                { label: 'Return a governed value', slug: 'tutorials/return-a-governed-value' },
                { label: 'Control caller access', slug: 'tutorials/control-who-can-request-evidence' },
                { label: 'Handle safe refusals', slug: 'tutorials/refuse-unsafe-evidence-requests' },
                { label: 'Model a relationship', slug: 'tutorials/assert-a-role-bound-relationship' },
              ],
            },
            {
              label: 'Connect a source',
              collapsed: true,
              items: [
                { label: 'Connect with OpenAPI', slug: 'tutorials/connect-an-institution-source' },
                { label: 'Connect a SQLite extract', slug: 'tutorials/connect-a-sqlite-extract' },
                { label: 'Integration patterns', slug: 'explanation/integration-patterns' },
              ],
            },
            {
              label: 'Source examples',
              collapsed: true,
              items: [
                { label: 'OpenCRVS: registered parent', slug: 'tutorials/verify-a-registered-parent-with-opencrvs' },
                { label: 'OpenCRVS: birth certificate', slug: 'tutorials/issue-a-birth-certificate-vc-from-opencrvs' },
                { label: 'DHIS2: immunization summary', slug: 'tutorials/issue-immunization-evidence-from-dhis2' },
                { label: 'FHIR R4: patient coverage', slug: 'tutorials/issue-fhir-evidence-as-vcs' },
              ],
            },
            {
              label: 'Deploy',
              collapsed: true,
              items: [
                { label: 'What you need to run it', slug: 'operate/evidence-requirements' },
                { label: 'Test with fixtures', slug: 'tutorials/prove-an-evidence-project' },
                { label: 'Configure a deployment', slug: 'configure/evidence' },
                { label: 'Build a production candidate', slug: 'tutorials/build-and-deploy-evidence-project' },
                { label: 'Configure Transit signing', slug: 'tutorials/move-evidence-to-production-signing' },
                { label: 'Deploy with Docker Compose', slug: 'tutorials/integrate-evidence-candidate-with-docker-compose' },
              ],
            },
            {
              label: 'Wallet delivery',
              collapsed: true,
              items: [
                { label: 'Enable SD-JWT VC', slug: 'configure/enable-sd-jwt-vc' },
                { label: 'Configure OID4VCI', slug: 'configure/evidence-oid4vci' },
                { label: 'Check OID4VCI interoperability', slug: 'tutorials/run-oid4vci-interoperability-checks' },
              ],
            },
            { label: 'Configuration reference', slug: 'reference/evidence-configuration' },
            { label: 'Errors and problem codes', slug: 'reference/evidence-problems' },
            { label: 'API overview', slug: 'reference/apis/registry-evidence' },
            // The API plugin supplies its own operation groups. An extra HTTP
            // API wrapper would add a disclosure without helping navigation.
            ...openAPISidebarGroups.slice(0, 1),
            { label: 'Security model', slug: 'security/evidence' },
          ],
        },
        {
          label: 'Registry Relay',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'configure' },
            { label: 'Governed publication', slug: 'explanation/governed-registry-publication' },
            { label: 'Publish a SQLite registry', slug: 'tutorials/publish-governed-sqlite-registry' },
            {
              label: 'Author a project',
              collapsed: true,
              items: [
                { label: 'Project configuration', slug: 'configure/relay' },
                { label: 'Semantics and disclosure', slug: 'explanation/relay-semantics-and-disclosure' },
                { label: 'Validate a project', slug: 'verify' },
              ],
            },
            {
              label: 'Use from applications',
              collapsed: true,
              items: [
                { label: 'Query with Python', slug: 'tutorials/query-relay-client' },
                { label: 'Client API reference', slug: 'reference/client-api' },
                { label: 'Automate with OpenFn', slug: 'explanation/openfn-adaptors' },
              ],
            },
            { label: 'Run a deployment', slug: 'operate/relay' },
            { label: 'relayctl workflows', slug: 'reference/relayctl' },
            { label: 'Operational posture', slug: 'spec/rs-op-posture' },
          ],
        },
        {
          label: 'Base Registry Engine',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'start/breg-quickstart' },
            { label: 'Your first registry', slug: 'tutorials/first-breg' },
            { label: 'How registries work', slug: 'explanation/configuration-defined-registry' },
            {
              label: 'Tutorials',
              collapsed: true,
              items: [
                { label: 'Extend with a module', slug: 'tutorials/extend-a-registry-with-a-module' },
                { label: 'Derive from PublicSchema', slug: 'tutorials/derive-a-registry-from-publicschema' },
                { label: 'Review changes', slug: 'tutorials/review-registry-changes' },
                { label: 'Send events to a webhook', slug: 'tutorials/send-registry-events-to-a-webhook' },
                { label: 'Map a registry in QGIS', slug: 'tutorials/query-a-spatial-registry-from-qgis' },
              ],
            },
            {
              label: 'Model a registry',
              collapsed: true,
              items: [
                { label: 'Project configuration', slug: 'configure/breg' },
                { label: 'Access profiles', slug: 'configure/breg-access' },
                { label: 'Change requests and actions', slug: 'configure/breg-change-control' },
                { label: 'Test with journeys', slug: 'configure/breg-journeys' },
                { label: 'Modeling patterns', slug: 'explanation/registry-modeling-patterns' },
                { label: 'Governed actions', slug: 'explanation/governed-registry-actions' },
                { label: 'Native field patterns', slug: 'explanation/native-field-patterns' },
                { label: 'Membership read boundaries', slug: 'explanation/membership-read-boundaries' },
                { label: 'Deriving from a model', slug: 'explanation/deriving-a-registry-from-a-model' },
              ],
            },
            {
              label: 'Deploy',
              collapsed: true,
              items: [
                { label: 'What you need to run it', slug: 'operate/breg-requirements' },
                { label: 'Build a production candidate', slug: 'tutorials/build-a-breg-production-candidate' },
                { label: 'Deploy a registry', slug: 'operate/breg' },
                { label: 'Bind webhook receivers', slug: 'operate/breg-webhooks' },
              ],
            },
            {
              label: 'Operate',
              collapsed: true,
              items: [
                { label: 'Change an active registry', slug: 'operate/breg-changes' },
                { label: 'Retain, erase, and audit', slug: 'operate/breg-retention' },
                { label: 'Move data in bulk', slug: 'operate/breg-data' },
              ],
            },
            {
              label: 'Use from applications',
              collapsed: true,
              items: [
                { label: 'Query with Python and Node', slug: 'tutorials/query-breg-client' },
                { label: 'Client API reference', slug: 'reference/client-api' },
                { label: 'Client capabilities', slug: 'reference/breg-client-capabilities' },
                { label: 'Authenticate with eSignet', slug: 'explanation/esignet-authentication-over-breg' },
                { label: 'Automate with OpenFn', slug: 'explanation/openfn-adaptors' },
              ],
            },
            { label: 'Configuration reference', slug: 'reference/breg-configuration' },
            { label: 'API reference', slug: 'reference/breg-api' },
            { label: 'PublicSchema wizard prompts', slug: 'reference/bregctl-publicschema-wizard' },
          ],
        },
        ...(isArchivedBuild ? [] : [{
          label: 'Registry Casework',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'start/casework' },
            { label: 'Decide your first work item', slug: 'tutorials/first-casework' },
            { label: 'How Casework works', slug: 'explanation/how-casework-works' },
            { label: 'Author a policy', slug: 'configure/casework' },
            { label: 'Deploy Casework', slug: 'operate/casework' },
            { label: 'Retain, erase, and settle', slug: 'operate/casework-retention' },
            { label: 'API contract', slug: 'reference/apis/registry-casework' },
            ...openAPISidebarGroups.slice(1, 2),
            { label: 'Client API reference', slug: 'reference/client-api' },
          ],
        }]),
        {
          label: 'Registry Mint',
          collapsed: true,
          items: [
            { label: 'Configuration', slug: 'configure/mint' },
            { label: 'Add to Evidence Gateway', slug: 'tutorials/issue-evidence-access-tokens-with-registry-mint' },
            { label: 'Request an access token', slug: 'configure/request-an-access-token' },
            { label: 'Use with QGIS', slug: 'configure/use-mint-with-qgis-and-standard-oauth-clients' },
            { label: 'Reference', slug: 'reference/mint' },
          ],
        },
        {
          label: 'Registry Discovery',
          collapsed: true,
          items: [
            { label: 'How the index works', slug: 'explanation/discovery-as-an-index' },
            { label: 'Publish and consume an index', slug: 'tutorials/publish-and-consume-discovery-index' },
            { label: 'Build and run an index', slug: 'configure/discovery' },
          ],
        },
        {
          label: 'Operations',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'operate/advanced' },
            { label: 'Operator handoff', slug: 'operate' },
            { label: 'Verify the Evidence audit chain', slug: 'operate/evidence-audit' },
            { label: 'Rotate Evidence signing keys', slug: 'tutorials/rotate-evidence-signing-keys' },
            { label: 'Rotate credentials and trust', slug: 'operate/advanced/rotate-credentials-and-trust' },
            { label: 'Inspect and diagnose', slug: 'operate/advanced/inspect-and-diagnose' },
            { label: 'Retention and persistent state', slug: 'operate/retention-and-persistent-state' },
            { label: 'Generated files and ownership', slug: 'generated-artifacts' },
            { label: 'Production hardening', slug: 'security/hardening-checklist' },
            {
              label: 'Security',
              collapsed: true,
              items: [
                { label: 'Overview', slug: 'security' },
                { label: 'Threat model', slug: 'explanation/threat-model' },
                { label: 'Known limitations', slug: 'explanation/known-limitations' },
                { label: 'Report a vulnerability', slug: 'security/report-a-vulnerability' },
                { label: 'Support window', slug: 'security/support-window' },
                { label: 'Self-assessment', slug: 'security/self-assessment' },
                { label: 'Release trust', slug: 'security/openssf-evidence' },
              ],
            },
          ],
        },
        {
          label: 'Design',
          collapsed: true,
          items: [
            { label: 'Architecture', slug: 'explanation/architecture' },
            { label: 'Boundaries and map', slug: 'map/boundaries-and-map' },
            { label: 'Records stay home', slug: 'explanation/records-stay-home' },
            { label: 'Disclosure modes', slug: 'explanation/disclosure-modes-and-computed-answers' },
            { label: 'Data minimization', slug: 'explanation/data-minimization-and-purpose-limitation' },
            { label: 'Trusted context', slug: 'explanation/trusted-context-constraints' },
            { label: 'DPI safeguards', slug: 'explanation/dpi-safeguards-alignment' },
            {
              // These records have no index; keep both destinations visible.
              label: 'Decisions',
              collapsed: true,
              items: [
                { label: 'Relay V1 retirement', slug: 'decisions/relay-v1-and-registryctl-retirement-2026-08-11' },
                { label: 'Registry Notary retirement', slug: 'decisions/notary-retirement-2026-08-03' },
              ],
            },
          ],
        },
        {
          label: 'Reference',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'reference' },
            { label: 'Errors and status codes', slug: 'reference/errors' },
            { label: 'Environment variables', slug: 'reference/environment-variables' },
            { label: 'API overview', slug: 'reference/apis' },
            { label: 'evidencectl workflows', slug: 'reference/evidencectl' },
            ...cliReferenceSidebar(),
            {
              label: 'Compatibility',
              collapsed: true,
              items: [
                { label: 'Contracts', slug: 'reference/contracts' },
                { label: 'API stability and versioning', slug: 'reference/api-stability' },
                { label: 'Deprecation policy', slug: 'reference/deprecation-policy' },
                { label: 'Standards', slug: 'reference/standards' },
                { label: 'ITB and SEMIC evidence', slug: 'reference/itb-semic-evidence' },
              ],
            },
            {
              label: 'Specifications',
              collapsed: true,
              items: [
                { label: 'Register', slug: 'spec' },
                { label: 'Documentation framework', slug: 'spec/rs-doc' },
                { label: 'Terms', slug: 'spec/rs-terms' },
                { label: 'Architecture', slug: 'spec/rs-arc-g' },
                { label: 'Evidence Gateway protocol', slug: 'spec/rs-pr-evidence' },
                { label: 'relayctl contract', slug: 'spec/rs-pr-relayctl' },
                { label: 'Relay protocol', slug: 'spec/rs-pr-relay' },
                { label: 'Security model', slug: 'spec/rs-sec-g' },
                { label: 'Portable metadata model', slug: 'spec/rs-dm-manifest' },
              ],
            },
            // Flatten the generated Diataxis categories here: product and
            // page are enough context inside Reference.
            {
              label: 'Registry Relay',
              collapsed: true,
              items: flattenSidebarGroups(generatedProduct('Relay').items),
            },
            {
              label: 'Registry Manifest',
              collapsed: true,
              items: flattenSidebarGroups(generatedProduct('Manifest').items),
            },
            // Older docsets can predate the generated Evidence product pages.
            ...(optionalGeneratedProduct('Evidence Gateway')
              ? [
                  {
                    label: 'Evidence Gateway',
                    collapsed: true,
                    items: flattenSidebarGroups(generatedProduct('Evidence Gateway').items),
                  },
                ]
              : []),
            { label: 'Changelog', slug: 'changelog' },
            { label: 'Privacy', slug: 'privacy' },
            { label: 'Accessibility', slug: 'accessibility' },
          ],
        },
      ],
    }),
    ...(isSearchExcludedBuild ? [disabledSitemap] : [sitemap()]),
  ],
});
