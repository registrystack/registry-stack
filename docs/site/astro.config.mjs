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

const base = process.env.DOCS_BASE || undefined;
const basePath = base?.replace(/\/$/, '');
const isArchivedBuild = Boolean(basePath);
const productSidebar = loadProductSidebar();
const disabledSitemap = {
  name: '@astrojs/sitemap',
  hooks: {},
};

/** @param {string} path */
function internalRedirect(path) {
  return basePath ? `${basePath}${path}` : path;
}

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
    // quickstart's "Choose by question" router merged into the homepage (2026-06).
    '/start/quickstart/': internalRedirect('/'),
    '/start/your-first-call/': internalRedirect('/tutorials/first-run-with-registry-lab/'),
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
    '/products/registry-notary/opencrvs-dci-onboarding/': 'https://docs.registrystack.org/products/registry-notary/opencrvs-onboarding/',
    // registry-manifest, registry-atlas, registry-platform, registry-lab projects/*
    // redirects removed: targets are deferred from the MVP docs cut.
    '/projects/registry-lab/demo-flow/': internalRedirect('/start/see-it-live/'),
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
        // Only registered for non-archived builds: base-path builds do not
        // have a stable canonical site URL, and the plugin requires `site`.
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
      // The per-product groups inside Products are generated from
      // src/data/repo-docs.yaml by scripts/generate-sidebar.mjs (the
      // productSidebar array), so the menu follows each product's
      // doc_type/nav_order and never drifts from the manifest. Within a
      // product, pages are sub-grouped by Diataxis type once the product grows
      // past a threshold; smaller products stay flat. Product labels drop the
      // shared "Registry" prefix (Relay, Notary, ...) since the site title and
      // the Products group already supply that context.
      //
      // "Get started" is orientation only: Overview (which carries the
      // "Choose by question" router), the zero-install demo, and the
      // evaluation page. The core Tutorials path stays on one generated local
      // project; operator paths live under Apply to your stack, and named
      // source-system paths live under Integrate existing systems.
      sidebar: [
        {
          label: 'Get started',
          items: [
            // Short nav labels to avoid wrapping in the narrow sidebar; page
            // titles keep the full wording.
            { label: 'Overview', link: '/' },
            { label: 'See it live', slug: 'start/see-it-live' },
            { label: 'When to use', slug: 'start/when-to-use' },
          ],
        },
        {
          label: 'Tutorials',
          items: [
            { label: 'Run a protected API', slug: 'tutorials/publish-spreadsheet-secured-registry-api' },
            { label: 'Evaluate a claim', slug: 'tutorials/verify-claim-registry-api' },
          ],
        },
        {
          label: 'Apply to your stack',
          items: [
            { label: 'Notary for a Registry Data API', slug: 'tutorials/run-notary-standalone-for-api' },
            { label: 'Deploy with own data', slug: 'tutorials/deploy-standalone-with-own-data' },
            { label: 'Run the lab', slug: 'tutorials/first-run-with-registry-lab' },
          ],
        },
        {
          label: 'Integrate existing systems',
          items: [
            { label: 'OpenCRVS claims', slug: 'tutorials/verify-opencrvs-claims' },
            { label: 'DHIS2 claim checks', slug: 'tutorials/configure-dhis2-claim-checks' },
            { label: 'FHIR evidence', slug: 'tutorials/getting-started-fhir-evidence' },
          ],
        },
        {
          label: 'Products',
          items: productSidebar,
        },
        {
          label: 'Explanation',
          collapsed: true,
          items: [
            { label: 'Architecture', slug: 'explanation/architecture' },
            { label: 'Records stay home', slug: 'explanation/records-stay-home' },
            { label: 'Boundaries and map', slug: 'map/boundaries-and-map' },
            { label: 'Consultation flow', slug: 'explanation/consultation-flow' },
            { label: 'Evidence issuance', slug: 'explanation/evidence-issuance' },
            { label: 'Disclosure modes', slug: 'explanation/disclosure-modes-and-computed-answers' },
            { label: 'Trusted context', slug: 'explanation/trusted-context-constraints' },
            { label: 'Integration patterns', slug: 'explanation/integration-patterns' },
            { label: 'DPI safeguards', slug: 'explanation/dpi-safeguards-alignment' },
          ],
        },
        {
          // Trust & Security rail (roadmap §6): the reviewer/auditor-facing
          // posture, threat model, privacy story, and the canonical limits hub.
          label: 'Trust & security',
          collapsed: true,
          items: [
            { label: 'Trust posture', slug: 'explanation/trust-posture-and-security-guarantees' },
            { label: 'Threat model', slug: 'explanation/threat-model' },
            { label: 'Data minimization', slug: 'explanation/data-minimization-and-purpose-limitation' },
            { label: 'Known limitations', slug: 'explanation/known-limitations' },
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
            { label: 'Standards', slug: 'reference/standards' },
            { label: 'OpenSSF evidence', slug: 'reference/openssf-evidence' },
            { label: 'Security self-assessment', slug: 'reference/security-self-assessment' },
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
