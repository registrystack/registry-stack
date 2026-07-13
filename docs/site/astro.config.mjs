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
 * @param {{ current: string, docsets: Array<{ id: string, status: string }> }} docsets
 * @param {NodeJS.ProcessEnv} env
 */
export function resolveDocsetBuildContext(docsets, env = process.env) {
  const selectedId = env.DOCS_DOCSET || docsets.current;
  const selectedDocset = docsets.docsets.find((entry) => entry.id === selectedId);
  if (!selectedDocset) throw new Error(`selected docs docset "${selectedId}" not found`);

  const base = env.DOCS_BASE || undefined;
  const basePath = base?.replace(/\/$/, '');
  const isArchivedBuild = selectedDocset.status === 'archived';
  /** @param {string} path */
  const internalRedirect = (path) => basePath ? `${basePath}${path}` : path;
  /** @param {string} path */
  const currentDocsetRedirect = (path) =>
    isArchivedBuild ? `https://docs.registrystack.org${path}` : internalRedirect(path);

  return {
    base,
    basePath,
    isArchivedBuild,
    internalRedirect,
    currentDocsetRedirect,
  };
}

const docsetsManifest = loadDocsetsManifest();
const {
  base,
  isArchivedBuild,
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
    '/start/': internalRedirect('/'),
    '/start/see-it-live/': internalRedirect('/tutorials/publish-spreadsheet-secured-registry-api/'),
    '/explanation/trust-posture-and-security-guarantees/': internalRedirect('/security/'),
    '/reference/security-self-assessment/': internalRedirect('/security/self-assessment/'),
    '/reference/openssf-evidence/': internalRedirect('/security/openssf-evidence/'),
    // quickstart's "Choose by question" router merged into the homepage (2026-06).
    '/start/your-first-call/': internalRedirect('/tutorials/first-run-with-solmara-lab/'),
    // The monorepo lab tutorial was replaced by the standalone Solmara Lab (2026-07).
    '/tutorials/first-run-with-registry-lab/': internalRedirect('/tutorials/first-run-with-solmara-lab/'),
    // Retired monorepo lab tutorials redirect to the current integration guidance.
    '/tutorials/configure-dhis2-claim-checks/': internalRedirect('/explanation/integration-patterns/'),
    '/tutorials/getting-started-fhir-evidence/': internalRedirect('/explanation/integration-patterns/'),
    // verify-claim-own-api moved into the Apply to your stack path (2026-06).
    '/tutorials/verify-claim-own-api/': internalRedirect('/tutorials/run-notary-standalone-for-api/'),
    '/tutorials/verify-opencrvs-dci-claims/': internalRedirect('/tutorials/verify-opencrvs-claims/'),
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
    '/projects/registry-notary/': internalRedirect('/products/registry-notary/'),
    '/projects/registry-notary/run-locally/': internalRedirect('/products/registry-notary/'),
    '/projects/registry-notary/configure-a-claim/': internalRedirect('/products/registry-notary/source-claim-modeling-guide/'),
    '/projects/registry-notary/reference/': internalRedirect('/products/registry-notary/operator-config-reference/'),
    // The target exists only in the current docset; archives redirect to the latest page.
    '/products/registry-notary/opencrvs-dci-onboarding/': currentDocsetRedirect('/products/registry-notary/opencrvs-onboarding/'),
    // registry-manifest, registry-atlas, registry-platform, registry-lab projects/*
    // redirects removed: targets are deferred from the MVP docs cut.
    '/projects/registry-lab/demo-flow/': internalRedirect('/tutorials/first-run-with-solmara-lab/'),
    // The API reference moved from static Redoc HTML to native, theme-aware,
    // searchable pages. Keep the old shareable links working.
    '/api/registry-relay.html': internalRedirect('/reference/apis/relay/'),
    '/api/registry-notary.html': internalRedirect('/reference/apis/notary/'),
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
      description: 'Documentation for Registry Stack: Registry Relay and Registry Notary, the runtime services that publish registry metadata, serve protected registry data, and issue evidence credentials.',
      plugins: [
        // Generates /llms.txt, /llms-full.txt, and /llms-small.txt for
        // machine consumption. The `details` field carries the discovery
        // pointer so LLM clients know where to find both corpus files.
        // API reference pages (reference/apis/*) are Redoc HTML embeds with
        // minimal prose; they are excluded from llms-small.txt to keep the
        // compact version useful, but remain in llms-full.txt.
        // Only registered for current builds. Archived docsets do not publish
        // a separate machine-readable corpus; preview bases remain current.
        ...(isArchivedBuild ? [] : [starlightLlmsTxt({
          description: 'Documentation for Registry Stack: tutorials, product docs, explanation, and API reference for Registry Relay and Registry Notary.',
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
            base: 'reference/apis/notary',
            schema: './openapi/registry-notary.openapi.json',
            sidebar: { label: 'Notary API operations', collapsed: true },
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
      // Diataxis IA: Get started, Tutorials, Products, Explanation, Reference.
      // The per-product groups are generated from src/data/repo-docs.yaml by
      // scripts/generate-sidebar.mjs (the productSidebar array), so each
      // product menu follows its doc_type/nav_order and never drifts from the
      // manifest. Within a product, pages are sub-grouped by Diataxis type
      // once the product grows past a threshold; smaller products stay flat.
      // generatedProduct() lifts each group into its own top-level product
      // section; hand-authored operator tutorials append after the generated
      // items.
      //
      // "Get started" leads with the promoted local first-run journey. The
      // hosted pages remain visible but held until their fresh-reader gates
      // pass. Named source-system paths live under Integrations.
      sidebar: [
        {
          label: 'Get started',
          items: [
            // Short nav labels to avoid wrapping in the narrow sidebar; page
            // titles keep the full wording.
            { label: 'Overview', link: '/' },
            { label: 'Your first registry API', slug: 'tutorials/publish-spreadsheet-secured-registry-api' },
            { label: 'Your first claim check', slug: 'tutorials/verify-claim-registry-api' },
            { label: 'When to use', slug: 'start/when-to-use' },
            { label: 'Run Solmara Lab', slug: 'tutorials/first-run-with-solmara-lab' },
            { label: 'Hosted Relay demo (held)', slug: 'start/quickstart' },
            { label: 'Hosted credential tour (held)', slug: 'start/credential-tour' },
          ],
        },
        {
          label: 'Registry Relay',
          collapsed: true,
          items: [
            ...generatedProduct('Relay').items,
            { label: 'Deploy with own data', slug: 'tutorials/deploy-standalone-with-own-data' },
          ],
        },
        {
          label: 'Registry Notary',
          collapsed: true,
          items: [
            ...generatedProduct('Notary').items,
            { label: 'Notary for a Registry Data API', slug: 'tutorials/run-notary-standalone-for-api' },
            { label: 'Production signing', slug: 'tutorials/move-notary-to-production-signing' },
          ],
        },
        {
          label: 'Registry Manifest',
          collapsed: true,
          items: generatedProduct('Manifest').items,
        },
        {
          label: 'Integrations',
          items: [
            { label: 'Bounded HTTP country integration', slug: 'tutorials/author-country-integration' },
            { label: 'API-key source authentication', slug: 'tutorials/configure-country-api-key-authentication' },
            { label: 'FHIR R4 country integration', slug: 'tutorials/configure-country-fhir-r4' },
            { label: 'Snapshot materialization', slug: 'tutorials/configure-country-snapshot-materialization' },
            { label: 'Sandboxed Rhai orchestration', slug: 'tutorials/configure-country-sandboxed-rhai' },
            { label: 'OpenCRVS claims', slug: 'tutorials/verify-opencrvs-claims' },
          ],
        },
        {
          label: 'Concepts',
          collapsed: true,
          items: [
            { label: 'Architecture', slug: 'explanation/architecture' },
            { label: 'Records stay home', slug: 'explanation/records-stay-home' },
            { label: 'Boundaries and map', slug: 'map/boundaries-and-map' },
            { label: 'Consultation flow', slug: 'explanation/consultation-flow' },
            { label: 'Evidence issuance', slug: 'explanation/evidence-issuance' },
            { label: 'Disclosure modes', slug: 'explanation/disclosure-modes-and-computed-answers' },
            { label: 'Data minimization', slug: 'explanation/data-minimization-and-purpose-limitation' },
            { label: 'Trusted context', slug: 'explanation/trusted-context-constraints' },
            { label: 'Integration patterns', slug: 'explanation/integration-patterns' },
            { label: 'DPI safeguards', slug: 'explanation/dpi-safeguards-alignment' },
          ],
        },
        {
          // The reviewer/auditor-facing rail: the enforced model, the threat
          // model, the canonical limits hub, and the public evidence a
          // security reviewer can check.
          label: 'Security',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'security' },
            { label: 'Threat model', slug: 'explanation/threat-model' },
            { label: 'Known limitations', slug: 'explanation/known-limitations' },
            { label: 'Harden a deployment', slug: 'security/hardening-checklist' },
            { label: 'Report a vulnerability', slug: 'security/report-a-vulnerability' },
            { label: 'Security support window', slug: 'security/support-window' },
            { label: 'Self-assessment', slug: 'security/self-assessment' },
            { label: 'OpenSSF evidence', slug: 'security/openssf-evidence' },
          ],
        },
        {
          // Stack-wide operator procedures that span both products. Product-
          // specific ops pages stay inside each product's generated group.
          label: 'Operate',
          collapsed: true,
          items: [
            { label: 'Single-node Compose', slug: 'operate/single-node-compose-behind-proxy' },
            { label: 'Backup and restore', slug: 'operate/backup-and-restore' },
            { label: 'Retention and state', slug: 'operate/retention-and-persistent-state' },
            { label: 'Upgrade and roll back', slug: 'operate/upgrade-and-rollback' },
          ],
        },
        {
          label: 'Reference',
          collapsed: true,
          items: [
            {
              label: 'API reference',
              collapsed: true,
              items: [
                { label: 'Overview', slug: 'reference/apis' },
                { label: 'Relay (narrative)', slug: 'reference/apis/registry-relay' },
                { label: 'Notary (narrative)', slug: 'reference/apis/registry-notary' },
                // Generated operation pages for each schema (theme-aware, searchable).
                ...openAPISidebarGroups,
              ],
            },
            { label: 'registryctl CLI', slug: 'reference/registryctl' },
            { label: 'Errors and status codes', slug: 'reference/errors' },
            { label: 'Environment variables', slug: 'reference/environment-variables' },
            { label: 'Contracts', slug: 'reference/contracts' },
            { label: 'API stability and versioning', slug: 'reference/api-stability' },
            { label: 'Deprecation policy', slug: 'reference/deprecation-policy' },
            { label: 'Standards', slug: 'reference/standards' },
            { label: 'ITB and SEMIC evidence', slug: 'reference/itb-semic-evidence' },
            { label: 'Glossary', slug: 'reference/glossary' },
          ],
        },
        {
          // The formal layer: independently identified, versioned, normative
          // specifications. Hand-authored (not generated from repo-docs.yaml)
          // because these are distilled public contracts, not pulled product
          // docs. The register page lists every spec from its own frontmatter.
          label: 'Specifications',
          collapsed: true,
          items: [
            { label: 'Register', slug: 'spec' },
            { label: 'RS-DOC · Documentation framework', slug: 'spec/rs-doc' },
            { label: 'RS-TERMS · Terms', slug: 'spec/rs-terms' },
            { label: 'RS-ARC-G · Architecture', slug: 'spec/rs-arc-g' },
            { label: 'RS-PR-NOTARY · Notary protocol', slug: 'spec/rs-pr-notary' },
            { label: 'RS-PR-RELAY · Relay protocol', slug: 'spec/rs-pr-relay' },
            { label: 'RS-SEC-G · Security model', slug: 'spec/rs-sec-g' },
            { label: 'RS-DM-CLAIM · Claim definition model', slug: 'spec/rs-dm-claim' },
            { label: 'RS-DM-MANIFEST · Portable metadata model', slug: 'spec/rs-dm-manifest' },
          ],
        },
        { label: 'Changelog', slug: 'changelog' },
      ],
    }),
    ...(isArchivedBuild ? [disabledSitemap] : [sitemap()]),
  ],
});
