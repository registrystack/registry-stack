// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import starlight from '@astrojs/starlight';
import mermaid from 'astro-mermaid';

// Marketing site that now owns the persuasion layer (the pitch). Old docs
// routes that migrated there redirect to these pages.
const marketing = 'https://registrystack.org';

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
      // Diataxis IA (Wave 4): Start, Tutorials, How-to, Products, Explanation,
      // Reference. Product pages are pulled at build time by
      // scripts/sync-repo-docs.mjs (manifest: src/data/repo-docs.yaml) and live
      // under the single Products section. The cross-product lab recipes are
      // also surfaced under How-to as the cross-product entry point.
      sidebar: [
        {
          label: 'Start',
          items: [
            { label: 'Overview', link: '/' },
            { label: 'Choose where to start', slug: 'start/quickstart' },
            { label: 'When to use Registry Stack', slug: 'start/when-to-use' },
          ],
        },
        {
          label: 'Tutorials',
          items: [
            { label: 'First run with Registry Lab', slug: 'tutorials/first-run-with-registry-lab' },
            { label: 'Your first call', slug: 'start/your-first-call' },
          ],
        },
        {
          label: 'How-to',
          collapsed: true,
          items: [
            { label: 'Citizen self-attestation with eSignet', slug: 'products/registry-lab/citizen-self-attestation-esignet' },
            { label: 'Wallet interop testing', slug: 'products/registry-lab/wallet-interop-testing' },
          ],
        },
        {
          label: 'Products',
          collapsed: true,
          items: [
            {
              label: 'Registry Relay',
              collapsed: true,
              items: [
                { label: 'Registry Relay', slug: 'products/registry-relay' },
                { label: 'API guide', slug: 'products/registry-relay/api' },
                { label: 'Client integration', slug: 'products/registry-relay/client-integration' },
                { label: 'Configuration', slug: 'products/registry-relay/configuration' },
                { label: 'Operations runbook', slug: 'products/registry-relay/ops' },
                { label: 'Deployment hardening', slug: 'products/registry-relay/deployment-hardening' },
                { label: 'Portable metadata', slug: 'products/registry-relay/metadata' },
                { label: 'Evidence verification', slug: 'products/registry-relay/evidence-verification' },
                {
                  label: 'Standards adapter operator guide',
                  slug: 'products/registry-relay/standards-adapter-operator-guide',
                },
                { label: 'Development', slug: 'products/registry-relay/development' },
                { label: 'Use cases', slug: 'products/registry-relay/use-cases' },
              ],
            },
            {
              label: 'Registry Notary',
              collapsed: true,
              items: [
                { label: 'Registry Notary', slug: 'products/registry-notary' },
                { label: 'Architecture overview', slug: 'products/registry-notary/architecture-overview' },
                { label: 'Capability matrix', slug: 'products/registry-notary/capability-matrix' },
                { label: 'API reference', slug: 'products/registry-notary/api-reference' },
                { label: 'Client SDK guide', slug: 'products/registry-notary/client-sdk-guide' },
                {
                  label: 'Identity and record matching',
                  slug: 'products/registry-notary/identity-and-record-matching',
                },
                {
                  label: 'Source and claim modeling',
                  slug: 'products/registry-notary/source-claim-modeling-guide',
                },
                {
                  label: 'Operator configuration reference',
                  slug: 'products/registry-notary/operator-config-reference',
                },
                {
                  label: 'Credential lifecycle and status',
                  slug: 'products/registry-notary/credential-lifecycle-status',
                },
                { label: 'Signing key provider', slug: 'products/registry-notary/signing-key-provider' },
                {
                  label: 'Self-attestation operator guide',
                  slug: 'products/registry-notary/self-attestation-operator-guide',
                },
                {
                  label: 'Federated evaluation operator guide',
                  slug: 'products/registry-notary/federated-evaluation-operator-guide',
                },
                { label: 'OID4VCI wallet interop', slug: 'products/registry-notary/oid4vci-wallet-interop' },
                {
                  label: 'SD-JWT VC conformance profile',
                  slug: 'products/registry-notary/sd-jwt-vc-conformance-profile',
                },
                { label: 'Scenario patterns', slug: 'products/registry-notary/scenario-patterns' },
                {
                  label: 'OpenCRVS DCI tutorial',
                  slug: 'products/registry-notary/opencrvs-dci-standalone-tutorial',
                },
                { label: 'OpenSPP disability DCI', slug: 'products/registry-notary/openspp-disability-dci' },
                {
                  label: 'Deployment hardening runbook',
                  slug: 'products/registry-notary/deployment-hardening-runbook',
                },
              ],
            },
            {
              label: 'Registry Manifest',
              collapsed: true,
              items: [
                { label: 'Registry Manifest', slug: 'products/registry-manifest' },
                { label: 'Validate and render a manifest', slug: 'products/registry-manifest/validate-and-render' },
                { label: 'Validate against profile fixtures', slug: 'products/registry-manifest/profile-fixtures' },
                { label: 'Reference', slug: 'products/registry-manifest/reference' },
              ],
            },
            {
              label: 'Registry Atlas',
              collapsed: true,
              items: [
                { label: 'Registry Atlas', slug: 'products/registry-atlas' },
                { label: 'Run Atlas locally', slug: 'products/registry-atlas/run-locally' },
                { label: 'Inspect a registry', slug: 'products/registry-atlas/inspect-a-registry' },
                { label: 'Reference', slug: 'products/registry-atlas/reference' },
              ],
            },
            {
              label: 'Registry Platform',
              collapsed: true,
              items: [
                { label: 'Security principles', slug: 'products/registry-platform' },
                { label: 'Versioning', slug: 'products/registry-platform/versioning' },
                { label: 'Audit reference hashing', slug: 'products/registry-platform/audit-reference-hashing' },
              ],
            },
            {
              label: 'Registry Lab',
              collapsed: true,
              items: [
                { label: 'Registry Lab', slug: 'products/registry-lab' },
                { label: 'OpenCRVS DCI tutorial', slug: 'products/registry-lab/opencrvs-dci-notary-tutorial' },
                { label: 'DHIS2 OpenFn tutorial', slug: 'products/registry-lab/dhis2-openfn-notary-tutorial' },
                { label: 'OpenFn sidecar tutorial', slug: 'products/registry-lab/openfn-sidecar-notary-tutorial' },
                { label: 'Citizen self-attestation with eSignet', slug: 'products/registry-lab/citizen-self-attestation-esignet' },
                { label: 'Wallet interop testing', slug: 'products/registry-lab/wallet-interop-testing' },
                { label: 'Service-first discovery', slug: 'products/registry-lab/service-first-discovery' },
              ],
            },
          ],
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
                { label: 'Registry Relay', slug: 'reference/apis/registry-relay' },
                { label: 'Registry Notary', slug: 'reference/apis/registry-notary' },
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
