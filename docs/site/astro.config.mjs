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
import { DISCOVERY_HEADER } from './src/lib/page-markdown.ts';
import { buildNotaryRetirementRedirects } from './src/lib/notary-retirement-redirects.mjs';

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
    '/start/': internalRedirect('/'),
    '/start/see-it-live/': internalRedirect('/start/quickstart/'),
    '/explanation/trust-posture-and-security-guarantees/': internalRedirect('/security/'),
    '/reference/security-self-assessment/': internalRedirect('/security/self-assessment/'),
    '/reference/openssf-evidence/': internalRedirect('/security/openssf-evidence/'),
    // Retired pages keep old links useful by sending readers to a supported
    // task or reference page.
    '/journeys/': internalRedirect('/'),
    '/journeys/spreadsheet-protected-api/': internalRedirect('/tutorials/publish-spreadsheet-secured-registry-api/'),
    '/journeys/instance-openapi/': internalRedirect('/reference/apis/'),
    '/journeys/bounded-http/': internalRedirect('/tutorials/author-registry-project/'),
    '/journeys/bounded-multi-call-script/': internalRedirect('/tutorials/configure-project-script-adapter/'),
    '/journeys/exact-snapshot/': internalRedirect('/configure/'),
    '/journeys/product-input-lifecycle/': internalRedirect('/generated-artifacts/'),
    // Retired first-call and source-review routes enter the supported local path.
    '/start/your-first-call/': internalRedirect('/tutorials/publish-spreadsheet-secured-registry-api/'),
    '/start/test-current-source-revision/': internalRedirect('/start/quickstart/'),
    // The retired hosted lab tutorial lands on a chooser that distinguishes
    // that flow from the supported local beginner path. Solmara Lab keeps its
    // own route: it is where the two doors are shown working together.
    '/tutorials/first-run-with-registry-lab/': internalRedirect('/start/quickstart/'),
    // Retired monorepo lab tutorials redirect to the current integration guidance.
    // Retired advanced tutorials land on current task, explanation, or
    // reference entry points.
    '/tutorials/configure-project-api-key-authentication/': internalRedirect('/configure/'),
    '/tutorials/configure-project-fhir-r4/': internalRedirect('/explanation/integration-patterns/'),
    '/tutorials/configure-project-snapshot-materialization/': internalRedirect('/configure/'),
    '/tutorials/deploy-standalone-with-own-data/': internalRedirect('/operate/'),
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
    '/projects/registry-relay/authorize-callers/': internalRedirect('/products/registry-relay/client-integration/'),
    '/projects/registry-relay/reference/': internalRedirect('/products/registry-relay/configuration/'),
    // Retired project routes redirect only when a current replacement exists.
    // Solmara Lab is an external adopter, not a Registry Stack product.
    '/projects/registry-lab/demo-flow/': internalRedirect('/start/quickstart/'),
    // The API reference moved from static Redoc HTML to native, theme-aware,
    // searchable pages. Keep the old shareable links working.
    '/api/registry-relay.html': internalRedirect('/reference/apis/relay/'),
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
      description: 'Documentation for Registry Stack: Registry Relay and Evidence, the runtime services that publish protected registry data and answer bounded questions with signed, minimum-disclosure assertions.',
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
          description: 'Documentation for Registry Stack: tutorials, product docs, explanation, and API reference for Registry Relay and Evidence.',
          details: DISCOVERY_HEADER,
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
        // into them; old /api/*.html links are preserved by redirects below.
        starlightOpenAPI([
          {
            base: 'reference/apis/relay',
            schema: './openapi/registry-relay.openapi.json',
            sidebar: { label: 'Relay API operations', collapsed: true },
          },
          {
            base: 'reference/apis/evidence',
            schema: './openapi/registry-evidence.openapi.json',
            sidebar: { label: 'Evidence API operations', collapsed: true },
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
      // Keep the first screen focused on adopter outcomes. Detailed product,
      // generated-file, and contract material remains available under
      // collapsed reference sections.
      sidebar: [
        {
          label: 'Start',
          items: [
            { label: 'Overview', link: '/' },
            { label: 'Start a spreadsheet registry', slug: 'tutorials/publish-spreadsheet-secured-registry-api' },
            { label: 'Use your own spreadsheet', slug: 'tutorials/use-your-spreadsheet' },
            { label: 'When Registry Stack fits', slug: 'start/when-to-use' },
            { label: 'Evaluate Evidence', slug: 'start/evaluate-evidence' },
            { label: 'Pre-1.0 cutover', slug: 'start/pre-1.0-cutover' },
          ],
        },
        {
          label: 'Connect an existing registry',
          items: [
            { label: 'Overview', slug: 'configure' },
            { label: 'Connect an HTTP registry', slug: 'tutorials/author-registry-project' },
            { label: 'Configure OAuth client credentials', slug: 'configure/oauth-client-credentials' },
            { label: 'Add OAuth-backed Rhai', slug: 'tutorials/configure-project-script-adapter' },
            { label: 'OpenCRVS Events API case study', slug: 'tutorials/verify-opencrvs-claims' },
            { label: 'Advanced source patterns', slug: 'explanation/integration-patterns' },
            { label: 'Configuration fields', slug: 'reference/project-configuration' },
          ],
        },
        {
          label: 'Answer with Evidence',
          items: [
            { label: 'Overview', slug: 'start/evidence-quickstart' },
            { label: 'Get your first assertion', slug: 'tutorials/first-evidence-assertion' },
            { label: 'Return an age bracket', slug: 'tutorials/return-a-governed-value' },
            { label: 'See safe refusals', slug: 'tutorials/refuse-unsafe-evidence-requests' },
            { label: 'Configure Evidence', slug: 'configure/evidence' },
            { label: 'Configure Registry Mint', slug: 'configure/mint' },
            { label: 'Request a token from your own code', slug: 'configure/request-an-access-token' },
            { label: 'Move to production signing', slug: 'tutorials/move-evidence-to-production-signing' },
            { label: 'See it over a Relay API', slug: 'tutorials/first-run-with-solmara-lab' },
          ],
        },
        {
          label: 'Operate',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'operate' },
            { label: 'Approve the initial baseline', slug: 'operate/approve-initial-baseline' },
            { label: 'Run generated Compose', slug: 'operate/single-node-compose-behind-proxy' },
            {
              label: 'Advanced',
              collapsed: true,
              items: [
                { label: 'Approve a source change', slug: 'operate/advanced/compare-and-reapprove-source-change' },
              ],
            },
          ],
        },
        {
          label: 'Security',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'security' },
            { label: 'Evidence security model', slug: 'security/evidence' },
            { label: 'Report a vulnerability', slug: 'security/report-a-vulnerability' },
            { label: 'Security support window', slug: 'security/support-window' },
            { label: 'Release trust', slug: 'security/openssf-evidence' },
          ],
        },
        {
          label: 'Reference',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'reference' },
            { label: 'Validate a project', slug: 'verify' },
            { label: 'Generated files and ownership', slug: 'generated-artifacts' },
            { label: 'Project configuration', slug: 'reference/project-configuration' },
            { label: 'registryctl CLI', slug: 'reference/registryctl' },
            {
              label: 'API reference',
              collapsed: true,
              items: [
                { label: 'Overview', slug: 'reference/apis' },
                { label: 'Relay (narrative)', slug: 'reference/apis/registry-relay' },
                { label: 'Evidence (narrative)', slug: 'reference/apis/registry-evidence' },
                // Generated operation pages for each schema (theme-aware, searchable).
                ...openAPISidebarGroups,
              ],
            },
            { label: 'Errors and status codes', slug: 'reference/errors' },
            { label: 'Evidence problems', slug: 'reference/evidence-problems' },
            { label: 'Registry Mint', slug: 'reference/mint' },
            {
              label: 'Diagnostic catalogs',
              collapsed: true,
              items: [
                { label: 'Authoring diagnostics', slug: 'reference/diagnostics/authoring' },
                { label: 'Fixture diagnostics', slug: 'reference/diagnostics/fixture' },
                { label: 'Operator diagnostics', slug: 'reference/diagnostics/operator' },
              ],
            },
            { label: 'Environment variables', slug: 'reference/environment-variables' },
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
                // Evidence entered the product docset after every archived
                // docset was sealed, so its group is optional: absent when an
                // archived docset's generated sidebar has no Evidence product.
                // generate-sidebar.test.mjs pins its presence for the current
                // docset, keeping the loud-failure property there.
                ...(optionalGeneratedProduct('Evidence')
                  ? [
                      {
                        label: 'Registry Evidence',
                        collapsed: true,
                        items: generatedProduct('Evidence').items,
                      },
                    ]
                  : []),
              ],
            },
            { label: 'Contracts', slug: 'reference/contracts' },
            { label: 'API stability and versioning', slug: 'reference/api-stability' },
            { label: 'Deprecation policy', slug: 'reference/deprecation-policy' },
            { label: 'Standards', slug: 'reference/standards' },
            { label: 'ITB and SEMIC evidence', slug: 'reference/itb-semic-evidence' },
            { label: 'Glossary', slug: 'reference/glossary' },
            {
              label: 'Concepts',
              collapsed: true,
              items: [
                { label: 'Architecture', slug: 'explanation/architecture' },
                { label: 'Boundaries and map', slug: 'map/boundaries-and-map' },
                { label: 'Records stay home', slug: 'explanation/records-stay-home' },
                { label: 'Relay protected read flow', slug: 'explanation/consultation-flow' },
                { label: 'Disclosure modes', slug: 'explanation/disclosure-modes-and-computed-answers' },
                { label: 'Data minimization', slug: 'explanation/data-minimization-and-purpose-limitation' },
                { label: 'Trusted context', slug: 'explanation/trusted-context-constraints' },
                { label: 'Integration patterns', slug: 'explanation/integration-patterns' },
                { label: 'DPI safeguards', slug: 'explanation/dpi-safeguards-alignment' },
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
                { label: 'RS-PR-EVIDENCE · Evidence protocol', slug: 'spec/rs-pr-evidence' },
                { label: 'RS-PR-REGISTRYCTL · registryctl contract', slug: 'spec/rs-pr-registryctl' },
                { label: 'RS-PR-RELAY · Relay protocol', slug: 'spec/rs-pr-relay' },
                { label: 'RS-SEC-G · Security model', slug: 'spec/rs-sec-g' },
                { label: 'RS-DM-MANIFEST · Portable metadata model', slug: 'spec/rs-dm-manifest' },
              ],
            },
            { label: 'Changelog', slug: 'changelog' },
          ],
        },
      ],
    }),
    ...(isSearchExcludedBuild ? [disabledSitemap] : [sitemap()]),
  ],
});
