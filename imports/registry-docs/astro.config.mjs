// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://jeremi.github.io/registry-legend',
  base: '/registry-legend',
  trailingSlash: 'always',
  integrations: [
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
        baseUrl: 'https://github.com/jeremi/registry-legend/edit/main/',
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/jeremi/registry-legend',
        },
      ],
      sidebar: [
        {
          label: 'Start',
          items: [
            { label: 'Choose where to start', slug: 'start/quickstart' },
            { label: 'Why safer registry surfaces matter now', slug: 'start/safer-registry-surfaces' },
            { label: 'Your first call', slug: 'start/your-first-call' },
          ],
        },
        {
          label: 'Problems',
          items: [
            { label: 'Existing data is not service-ready', slug: 'problems/existing-data-not-service-ready' },
            { label: 'Registry capabilities are hard to discover', slug: 'problems/registry-capabilities-hard-to-discover' },
            { label: 'Entity identity and matching are unclear', slug: 'problems/entity-identity-and-matching' },
            { label: 'Integrations become one-off', slug: 'problems/one-off-integrations' },
            { label: 'APIs over-share records', slug: 'problems/apis-over-share-records' },
            { label: 'Semantics do not line up', slug: 'problems/semantics-do-not-line-up' },
            { label: 'Safeguards need technical enforcement', slug: 'problems/safeguards-need-technical-enforcement' },
            { label: 'AI and automation increase urgency', slug: 'problems/ai-and-automation-increase-urgency' },
          ],
        },
        {
          label: 'Use cases',
          items: [
            { label: 'Legacy registry API', slug: 'use-cases/legacy-registry-api' },
            { label: 'Publish registry metadata', slug: 'use-cases/publish-registry-metadata' },
            { label: 'Business registry status', slug: 'use-cases/business-registry-status' },
            { label: 'Eligibility or entitlement evidence', slug: 'use-cases/eligibility-or-entitlement-evidence' },
            { label: 'Workflow tool and governed services', slug: 'use-cases/workflow-tool-governed-services' },
            { label: 'Inspect before integrating', slug: 'use-cases/inspect-before-integrating' },
            { label: 'Prepare for a future registry platform', slug: 'use-cases/prepare-for-future-registry-platform' },
          ],
        },
        {
          label: 'Capabilities',
          items: [
            { label: 'Overview', slug: 'capabilities' },
            { label: 'Describe registries', slug: 'capabilities/describe-registries' },
            { label: 'Expose protected APIs', slug: 'capabilities/expose-protected-apis' },
            { label: 'Certify evidence', slug: 'capabilities/certify-evidence' },
            { label: 'Inspect published artifacts', slug: 'capabilities/inspect-published-artifacts' },
            { label: 'Audit and operate', slug: 'capabilities/audit-and-operate' },
          ],
        },
        {
          label: 'Ecosystem',
          items: [
            { label: 'Public service platforms', slug: 'ecosystem/public-service-platforms' },
            { label: 'Workflow engines', slug: 'ecosystem/workflow-engines' },
            { label: 'Exchange layers', slug: 'ecosystem/exchange-layers' },
            { label: 'Wallets', slug: 'ecosystem/wallets' },
            { label: 'Semantic standards', slug: 'ecosystem/semantic-standards' },
            { label: 'Sector API standards', slug: 'ecosystem/sector-api-standards' },
            { label: 'AI-assisted interoperability', slug: 'ecosystem/ai-assisted-interoperability' },
          ],
        },
        {
          label: 'How it works',
          items: [
            { label: 'Architecture', slug: 'explanation/architecture' },
            { label: 'Publishing pipeline', slug: 'explanation/publishing-pipeline' },
            { label: 'Consultation flow', slug: 'explanation/consultation-flow' },
            { label: 'Evidence issuance', slug: 'explanation/evidence-issuance' },
            { label: 'Standards positioning', slug: 'explanation/standards-positioning' },
            { label: 'DPI safeguards alignment', slug: 'explanation/dpi-safeguards-alignment' },
            {
              label: 'Projects',
              items: [
                { label: 'Registry Manifest', slug: 'projects/registry-manifest' },
                { label: 'Registry Relay', slug: 'projects/registry-relay' },
                { label: 'Registry Witness', slug: 'projects/registry-witness' },
                { label: 'Registry Atlas', slug: 'projects/registry-atlas' },
                { label: 'Registry Platform', slug: 'projects/registry-platform' },
                { label: 'Registry Lab', slug: 'projects/registry-lab' },
              ],
            },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Standards register', slug: 'reference/standards' },
            { label: 'Contracts', slug: 'reference/contracts' },
            {
              label: 'API reference',
              items: [
                { label: 'Overview', slug: 'reference/apis' },
                { label: 'Registry Relay', slug: 'reference/apis/registry-relay' },
                { label: 'Registry Witness', slug: 'reference/apis/registry-witness' },
              ],
            },
            { label: 'Glossary', slug: 'reference/glossary' },
            { label: 'Boundaries and map', slug: 'map/boundaries-and-map' },
            { label: 'Rename: evidence-server → Witness', slug: 'decisions/rename-2026-05-23' },
            { label: 'Historical docs index', slug: 'decisions/historical-docs-index' },
            { label: 'First run with Registry Lab', slug: 'tutorials/first-run-with-registry-lab' },
          ],
        },
      ],
    }),
    sitemap(),
  ],
});
