// @ts-check
import { readFileSync } from 'node:fs';
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import starlight from '@astrojs/starlight';
import mermaid from 'astro-mermaid';

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

const productSidebar = loadProductSidebar();

export default defineConfig({
  site: 'https://docs.registrystack.org',
  trailingSlash: 'always',
  // Redirects for content that moved in the docs/marketing split (Wave 4).
  // External redirects (to marketing) absorb the migrated persuasion pages;
  // internal redirects map the retired /projects/* and /capabilities/* routes
  // to their new homes so old links and search results keep resolving.
  redirects: {
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
    '/capabilities/': '/explanation/architecture/',
    '/capabilities/describe-registries/': '/explanation/architecture/',
    '/capabilities/expose-protected-apis/': '/explanation/architecture/',
    '/capabilities/certify-evidence/': '/explanation/architecture/',
    '/capabilities/audit-and-operate/': '/explanation/architecture/',
    '/capabilities/inspect-published-artifacts/': '/explanation/architecture/',
    // Hand-authored projects/* -> pulled products/* (internal)
    '/projects/registry-relay/': '/products/registry-relay/',
    '/projects/registry-relay/run-locally/': '/products/registry-relay/ops/',
    '/projects/registry-relay/authorize-callers/': '/products/registry-relay/client-integration/',
    '/projects/registry-relay/reference/': '/products/registry-relay/configuration/',
    '/projects/registry-notary/': '/products/registry-notary/',
    '/projects/registry-notary/run-locally/': '/products/registry-notary/',
    '/projects/registry-notary/configure-a-claim/': '/products/registry-notary/source-claim-modeling-guide/',
    '/projects/registry-notary/reference/': '/products/registry-notary/operator-config-reference/',
    '/projects/registry-manifest/': '/products/registry-manifest/',
    '/projects/registry-manifest/validate-and-render/': '/products/registry-manifest/validate-and-render/',
    '/projects/registry-manifest/profile-fixtures/': '/products/registry-manifest/profile-fixtures/',
    '/projects/registry-manifest/reference/': '/products/registry-manifest/reference/',
    '/projects/registry-atlas/': '/products/registry-atlas/',
    '/projects/registry-atlas/run-locally/': '/products/registry-atlas/run-locally/',
    '/projects/registry-atlas/inspect-a-registry/': '/products/registry-atlas/inspect-a-registry/',
    '/projects/registry-atlas/reference/': '/products/registry-atlas/reference/',
    '/projects/registry-platform/': '/products/registry-platform/',
    '/projects/registry-platform/reference/': '/products/registry-platform/versioning/',
    '/projects/registry-lab/': '/products/registry-lab/',
    '/projects/registry-lab/reference/': '/products/registry-lab/',
    '/projects/registry-lab/demo-flow/': '/tutorials/first-run-with-registry-lab/',
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
      description: 'Documentation website for the registry stack.',
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
        Header: './src/components/RegistryHeader.astro',
        PageSidebar: './src/components/RegistryPageSidebar.astro',
        PageTitle: './src/components/RegistryPageTitle.astro',
        Footer: './src/components/RegistryFooter.astro',
        MobileMenuFooter: './src/components/RegistryMobileMenuFooter.astro',
      },
      editLink: {
        baseUrl: 'https://github.com/jeremi/registry-docs/edit/main/',
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/jeremi/registry-docs',
        },
      ],
      // Diataxis IA, product-first (Wave 5): Get started, Products, Explanation,
      // Reference. The per-product groups inside Products are generated from
      // src/data/repo-docs.yaml by scripts/generate-sidebar.mjs (the
      // productSidebar array), so the menu follows each product's
      // doc_type/nav_order and never drifts from the manifest. Within a
      // product, pages are sub-grouped by Diataxis type once the product grows
      // past a threshold; smaller products stay flat. Product labels drop the
      // shared "Registry" prefix (Relay, Notary, ...) since the site title and
      // the Products group already supply that context.
      //
      // "Get started" is the newcomer funnel: orient (Overview, Where to
      // start, When to use), then act. The registryctl tutorials are the
      // first local adoption path. The Registry Lab pages remain the deeper
      // stack tour once a reader wants the full multi-service topology.
      sidebar: [
        {
          label: 'Get started',
          items: [
            // Short nav labels to avoid wrapping in the narrow sidebar; page
            // titles keep the full wording. Ordered as the newcomer funnel:
            // orient, then the minimal call, then the full tour.
            { label: 'Overview', link: '/' },
            { label: 'Where to start', slug: 'start/quickstart' },
            { label: 'When to use', slug: 'start/when-to-use' },
            { label: 'Spreadsheet API', slug: 'tutorials/publish-spreadsheet-secured-registry-api' },
            { label: 'Registry claim', slug: 'tutorials/verify-claim-registry-api' },
            { label: 'Own API claim', slug: 'tutorials/verify-claim-own-api' },
            { label: 'Your first call', slug: 'start/your-first-call' },
            { label: 'First run', slug: 'tutorials/first-run-with-registry-lab' },
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
            { label: 'DPI safeguards alignment', slug: 'explanation/dpi-safeguards-alignment' },
            { label: 'Consultation flow', slug: 'explanation/consultation-flow' },
            { label: 'Evidence issuance', slug: 'explanation/evidence-issuance' },
            { label: 'Publishing pipeline', slug: 'explanation/publishing-pipeline' },
            { label: 'Integration patterns', slug: 'explanation/integration-patterns' },
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
                { label: 'Relay', slug: 'reference/apis/registry-relay' },
                { label: 'Notary', slug: 'reference/apis/registry-notary' },
              ],
            },
            { label: 'Contracts', slug: 'reference/contracts' },
            { label: 'Standards register', slug: 'reference/standards' },
            { label: 'Glossary', slug: 'reference/glossary' },
            { label: 'Boundaries and map', slug: 'map/boundaries-and-map' },
            { label: 'Decisions', slug: 'decisions/rename-2026-05-23' },
          ],
        },
      ],
    }),
    sitemap(),
  ],
});
