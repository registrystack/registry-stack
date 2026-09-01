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
    '/start/': internalRedirect('/'),
    '/start/see-it-live/': internalRedirect('/start/when-to-use/'),
    // Retired: a second product chooser beside /start/when-to-use/, which
    // absorbed its job.
    '/start/quickstart/': internalRedirect('/start/when-to-use/'),
    '/explanation/trust-posture-and-security-guarantees/': internalRedirect('/security/'),
    '/reference/security-self-assessment/': internalRedirect('/security/self-assessment/'),
    '/reference/openssf-evidence/': internalRedirect('/security/openssf-evidence/'),
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
    '/start/test-current-source-revision/': internalRedirect('/start/when-to-use/'),
    // Retired lab tutorials land on the current chooser or Evidence Gateway
    // overview. The historical Solmara workflow used an obsolete Relay source
    // path and is no longer published as current guidance.
    '/tutorials/first-run-with-registry-lab/': internalRedirect('/start/when-to-use/'),
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
    '/projects/registry-lab/demo-flow/': internalRedirect('/start/when-to-use/'),
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
      description: 'Documentation for Registry Stack: publish existing records with Registry Relay, answer bounded questions with Evidence Gateway, or build a writable registry with the Registry Server source preview.',
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
          description: 'Documentation for Registry Stack: tutorials, product docs, explanation, and API reference for Registry Relay, Evidence Gateway, and the Registry Server source preview.',
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
            sidebar: { label: 'Evidence Gateway API operations', collapsed: true },
          },
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
      // Keep the first screen focused on adopter outcomes. Detailed product
      // and contract material remains available under collapsed reference
      // sections. Every top level is a task an adopter can name; the product
      // that serves the task is named inside it.
      sidebar: [
        {
          label: 'Start',
          items: [
            { label: 'Overview', link: '/' },
            { label: 'Which product fits your problem', slug: 'start/when-to-use' },
            // There is no 'Evaluate Registry Relay' beside this, and the
            // asymmetry is deliberate. Relay answers its own evaluation
            // question by running: the SQLite tutorial reaches a protected API
            // in one sitting, so a reader deciding about Relay is better served
            // by doing it than by reading about it. Evidence Gateway asks an
            // adopter to commit to signing keys and a question model before
            // anything runs, so its case has to be made before the first
            // command rather than after it.
            { label: 'Evaluate Evidence Gateway', slug: 'start/evaluate-evidence' },
            // A reader on their first page meets the vocabulary before they
            // meet a command, so the glossary sits here rather than in
            // Reference, where it was reachable only after the terms had
            // already gone by.
            { label: 'Glossary', slug: 'reference/glossary' },
          ],
        },
        {
          label: 'Answer a bounded question',
          items: [
            { label: 'Overview', slug: 'start/evidence-quickstart' },
            // The first hands-on tutorial stays in the open beside the
            // overview: a first-time reader should not have to open a group to
            // find where to start.
            { label: 'Get your first assertion', slug: 'tutorials/first-evidence-assertion' },
            {
              label: 'Learn locally',
              collapsed: true,
              items: [
                { label: 'Explore SD-JWT VC locally', slug: 'tutorials/request-evidence-as-sd-jwt-vc' },
                { label: 'Return a governed value', slug: 'tutorials/return-a-governed-value' },
                { label: 'Control caller access', slug: 'tutorials/control-who-can-request-evidence' },
                { label: 'See safe refusals', slug: 'tutorials/refuse-unsafe-evidence-requests' },
                { label: 'Model a two-subject relationship', slug: 'tutorials/assert-a-role-bound-relationship' },
              ],
            },
            {
              // Open, because this is where an adopter leaves the mock source
              // behind and points the deployment at their own institution. The
              // source-product examples stay collapsed inside it: they show one
              // way to do what the two pages above them describe generally.
              label: 'Connect your own source',
              items: [
                { label: 'Create a source from OpenAPI', slug: 'tutorials/connect-an-institution-source' },
                { label: 'Connect a SQLite extract', slug: 'tutorials/connect-a-sqlite-extract' },
                { label: 'Advanced source patterns', slug: 'explanation/integration-patterns' },
                {
                  label: 'Worked examples',
                  collapsed: true,
                  items: [
                    { label: 'OpenCRVS: registered parent', slug: 'tutorials/verify-a-registered-parent-with-opencrvs' },
                    { label: 'OpenCRVS: birth certificate SD-JWT VC', slug: 'tutorials/issue-a-birth-certificate-vc-from-opencrvs' },
                    { label: 'DHIS2: immunization summary', slug: 'tutorials/issue-immunization-evidence-from-dhis2' },
                    { label: 'FHIR R4: patient coverage SD-JWT VC', slug: 'tutorials/issue-fhir-evidence-as-vcs' },
                  ],
                },
              ],
            },
            {
              label: 'Prepare and deploy',
              collapsed: true,
              items: [
                { label: 'Test with fixtures', slug: 'tutorials/prove-an-evidence-project' },
                { label: 'Configure Evidence Gateway', slug: 'configure/evidence' },
                { label: 'Build a production candidate', slug: 'tutorials/build-and-deploy-evidence-project' },
                { label: 'Configure Transit signing', slug: 'tutorials/move-evidence-to-production-signing' },
                { label: 'Deploy with Docker Compose', slug: 'tutorials/integrate-evidence-candidate-with-docker-compose' },
              ],
            },
            {
              label: 'Deliver to wallets',
              collapsed: true,
              items: [
                { label: 'Enable SD-JWT VC in a deployment', slug: 'configure/enable-sd-jwt-vc' },
                { label: 'Configure OID4VCI wallet delivery', slug: 'configure/evidence-oid4vci' },
                { label: 'Run OID4VCI interoperability checks', slug: 'tutorials/run-oid4vci-interoperability-checks' },
              ],
            },
            // Reference material a reader needs while the deployment is in
            // front of them, so it stays in this section rather than in
            // Reference, where it answered questions nobody was asking yet.
            { label: 'Configuration reference', slug: 'reference/evidence-configuration' },
            { label: 'Problems and error codes', slug: 'reference/evidence-problems' },
            {
              label: 'HTTP API',
              collapsed: true,
              items: [
                { label: 'Evidence Gateway (narrative)', slug: 'reference/apis/registry-evidence' },
                // Generated operation pages for each schema (theme-aware, searchable).
                ...openAPISidebarGroups,
              ],
            },
            // Product-scoped, so it sits with the product rather than in the
            // cross-product security group under Operate and secure.
            { label: 'Security model', slug: 'security/evidence' },
          ],
        },
        {
          // Relay V2 is the shipped runtime, so its pages are the section
          // itself rather than a collapsed preview inside it. The section
          // follows the same shape as Evidence Gateway above: overview, first
          // tutorial, then the later phases collapsed behind the phase they
          // belong to.
          label: 'Connect an existing registry',
          items: [
            { label: 'Overview', slug: 'configure' },
            { label: 'How governed publication works', slug: 'explanation/governed-registry-publication' },
            { label: 'Publish a SQLite registry', slug: 'tutorials/publish-governed-sqlite-registry' },
            {
              label: 'Author a project',
              collapsed: true,
              items: [
                { label: 'Author a Relay project', slug: 'configure/relay' },
                { label: 'Semantics and disclosure', slug: 'explanation/relay-semantics-and-disclosure' },
                { label: 'Validate a project', slug: 'verify' },
              ],
            },
            {
              // The caller's half of Relay, which the authoring and operating
              // pages never address. Open rather than collapsed, because a
              // consumer arrives without knowing Relay has a client at all, so
              // the tutorial that shows one has to be visible from the section
              // rather than behind a disclosure.
              label: 'Call a Relay API',
              items: [
                { label: 'Query a Relay with Python', slug: 'tutorials/query-relay-client' },
                { label: 'Relay client APIs', slug: 'reference/relay-client-api' },
              ],
            },
            { label: 'Run a Relay deployment', slug: 'operate/relay' },
            { label: 'relayctl workflows', slug: 'reference/relayctl' },
            { label: 'Operational posture (spec)', slug: 'spec/rs-op-posture' },
          ],
        },
        {
          label: 'Build a registry',
          items: [
            { label: 'Registry Server overview', slug: 'explanation/configuration-defined-registry' },
            { label: 'Modeling patterns', slug: 'explanation/registry-modeling-patterns' },
            { label: 'Create and query your first registry', slug: 'tutorials/first-registry-server' },
            { label: 'Review changes before updating a registry', slug: 'tutorials/review-registry-changes' },
            { label: 'Map a registry in QGIS', slug: 'tutorials/query-a-spatial-registry-from-qgis' },
            { label: 'Configure your registry', slug: 'configure/registry-server' },
            { label: 'Configure webhooks', slug: 'configure/registry-server-webhooks' },
            { label: 'Configuration reference', slug: 'reference/registry-server-configuration' },
            { label: 'History reference', slug: 'reference/registry-server-history' },
            { label: 'Events and webhooks reference', slug: 'reference/registry-server-events' },
          ],
        },
        {
          // Two audiences used to share one Evidence Gateway group: a relying
          // party calling the HTTP contract, and a deployment delivering the
          // same assertion to a wallet. A relying party runs neither runtime,
          // so its path is a section of its own and wallet delivery stays with
          // the deployment that does the delivering.
          label: 'Consume and verify assertions',
          items: [
            { label: 'Request from an application', slug: 'tutorials/request-evidence-from-an-application' },
            { label: 'Verify and retain an assertion', slug: 'tutorials/verify-an-assertion-as-a-consumer' },
            { label: 'Manage verifier trust', slug: 'tutorials/manage-evidence-verifier-trust' },
          ],
        },
        {
          // Registry Mint issues the access tokens a resource server verifies,
          // so it is a step in both adoption paths and belongs to neither.
          label: 'Authenticate callers',
          collapsed: true,
          items: [
            { label: 'Configure Registry Mint', slug: 'configure/mint' },
            { label: 'Add Mint to Evidence Gateway', slug: 'tutorials/issue-evidence-access-tokens-with-registry-mint' },
            { label: 'Call Mint from application code', slug: 'configure/request-an-access-token' },
            { label: 'Use Mint with QGIS', slug: 'configure/use-mint-with-qgis-and-standard-oauth-clients' },
            { label: 'Mint reference', slug: 'reference/mint' },
          ],
        },
        {
          // One index, one section. The concept, the tutorial, and the build
          // page had been split across three unrelated parents.
          label: 'Publish a Discovery index',
          collapsed: true,
          items: [
            { label: 'Registry Discovery is an index', slug: 'explanation/discovery-as-an-index' },
            { label: 'Publish and consume an index', slug: 'tutorials/publish-and-consume-discovery-index' },
            { label: 'Build and run an index', slug: 'configure/discovery' },
          ],
        },
        {
          // What an operator does once a deployment is running, and the
          // security material that operator is expected to have read. Pages
          // that name one runtime are allowed here when the reader is the
          // operator rather than the adopter who authored the project.
          label: 'Operate and secure',
          items: [
            { label: 'Overview', slug: 'operate/advanced' },
            { label: 'Prepare the operator handoff', slug: 'operate' },
            { label: 'Verify the Evidence audit chain', slug: 'operate/evidence-audit' },
            { label: 'Rotate Evidence signing keys', slug: 'tutorials/rotate-evidence-signing-keys' },
            { label: 'Rotate credentials and trust', slug: 'operate/advanced/rotate-credentials-and-trust' },
            { label: 'Inspect and diagnose', slug: 'operate/advanced/inspect-and-diagnose' },
            { label: 'Retention and persistent state', slug: 'operate/retention-and-persistent-state' },
            { label: 'Generated files and ownership', slug: 'generated-artifacts' },
            { label: 'Harden a production deployment', slug: 'security/hardening-checklist' },
            {
              label: 'Security and disclosure',
              collapsed: true,
              items: [
                { label: 'Overview', slug: 'security' },
                { label: 'Threat model', slug: 'explanation/threat-model' },
                { label: 'Known limitations', slug: 'explanation/known-limitations' },
                { label: 'Report a vulnerability', slug: 'security/report-a-vulnerability' },
                { label: 'Security support window', slug: 'security/support-window' },
                { label: 'Security self-assessment', slug: 'security/self-assessment' },
                { label: 'Release trust', slug: 'security/openssf-evidence' },
              ],
            },
          ],
        },
        {
          // Promoted out of Reference. A reader who wants the model behind the
          // products is not looking up a contract, and burying these pages two
          // levels inside Reference meant the decision records had no seat at
          // all.
          label: 'Understand the design',
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
              // Newest first. The records have no index page of their own, so
              // this group is the only navigation into them.
              label: 'Decisions',
              collapsed: true,
              items: [
                { label: 'Relay V1 and registryctl retirement', slug: 'decisions/relay-v1-and-registryctl-retirement-2026-08-11' },
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
              label: 'Compatibility and support',
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
                { label: 'RS-DOC · Documentation framework', slug: 'spec/rs-doc' },
                { label: 'RS-TERMS · Terms', slug: 'spec/rs-terms' },
                { label: 'RS-ARC-G · Architecture', slug: 'spec/rs-arc-g' },
                { label: 'RS-PR-EVIDENCE · Evidence Gateway protocol', slug: 'spec/rs-pr-evidence' },
                { label: 'RS-PR-RELAYCTL · relayctl contract', slug: 'spec/rs-pr-relayctl' },
                { label: 'RS-PR-RELAY · Relay protocol', slug: 'spec/rs-pr-relay' },
                { label: 'RS-SEC-G · Security model', slug: 'spec/rs-sec-g' },
                { label: 'RS-DM-MANIFEST · Portable metadata model', slug: 'spec/rs-dm-manifest' },
              ],
            },
            {
              label: 'Product documentation',
              collapsed: true,
              items: [
                {
                  label: 'Registry Relay',
                  collapsed: true,
                  items: generatedProduct('Relay').items,
                },
                {
                  label: 'Registry Manifest',
                  collapsed: true,
                  items: generatedProduct('Manifest').items,
                },
                // Evidence Gateway entered the product docset after every archived
                // docset was sealed, so its group is optional: absent when an
                // archived docset's generated sidebar has no Evidence Gateway product.
                // generate-sidebar.test.mjs pins its presence for the current
                // docset, keeping the loud-failure property there.
                ...(optionalGeneratedProduct('Evidence Gateway')
                  ? [
                      {
                        label: 'Evidence Gateway',
                        collapsed: true,
                        items: generatedProduct('Evidence Gateway').items,
                      },
                    ]
                  : []),
              ],
            },
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
