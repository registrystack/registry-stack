// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://jeremi.github.io/registry-docs',
  base: '/registry-docs',
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
        baseUrl: 'https://github.com/jeremi/registry-docs/edit/main/',
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/jeremi/registry-docs',
        },
      ],
      sidebar: [
        {
          label: 'Start',
          items: [
            { label: 'Overview', link: '/' },
            { label: 'Choose path', slug: 'start/quickstart' },
            { label: 'Why now', slug: 'start/safer-registry-surfaces' },
            { label: 'First call', slug: 'start/your-first-call' },
          ],
        },
        {
          label: 'Problem',
          items: [
            { label: 'Overview', slug: 'problems' },
            { label: 'Data readiness', slug: 'problems/existing-data-not-service-ready' },
            { label: 'Over-sharing APIs', slug: 'problems/apis-over-share-records' },
            { label: 'Policy enforcement', slug: 'problems/safeguards-need-technical-enforcement' },
            { label: 'One-off integrations', slug: 'problems/one-off-integrations' },
            { label: 'Capabilities discoverability', slug: 'problems/registry-capabilities-hard-to-discover' },
            { label: 'Shared meaning', slug: 'problems/semantics-do-not-line-up' },
            { label: 'Entity matching', slug: 'problems/entity-identity-and-matching' },
          ],
        },
        {
          label: 'Use cases',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'use-cases' },
            { label: 'Legacy API', slug: 'use-cases/legacy-registry-api' },
            { label: 'Status fact', slug: 'use-cases/business-registry-status' },
            { label: 'Eligibility evidence', slug: 'use-cases/eligibility-or-entitlement-evidence' },
            { label: 'Publish metadata', slug: 'use-cases/publish-registry-metadata' },
            { label: 'Inspect before integrating', slug: 'use-cases/inspect-before-integrating' },
          ],
        },
        {
          label: 'How it works',
          collapsed: true,
          items: [
            { label: 'Overview', slug: 'capabilities' },
            {
              label: 'Describe',
              collapsed: true,
              items: [
                { label: 'Overview', slug: 'capabilities/describe-registries' },
                { label: 'Publishing pipeline', slug: 'explanation/publishing-pipeline' },
              ],
            },
            {
              label: 'Expose',
              collapsed: true,
              items: [
                { label: 'Overview', slug: 'capabilities/expose-protected-apis' },
                { label: 'Consultation flow', slug: 'explanation/consultation-flow' },
              ],
            },
            {
              label: 'Certify',
              collapsed: true,
              items: [
                { label: 'Overview', slug: 'capabilities/certify-evidence' },
                { label: 'Evidence issuance', slug: 'explanation/evidence-issuance' },
              ],
            },
            { label: 'Audit & operate', slug: 'capabilities/audit-and-operate' },
            { label: 'Inspect artifacts', slug: 'capabilities/inspect-published-artifacts' },
            { label: 'Architecture', slug: 'explanation/architecture' },
            { label: 'Safeguards', slug: 'explanation/dpi-safeguards-alignment' },
            { label: 'Ecosystem', slug: 'ecosystem' },
          ],
        },
        {
          label: 'Products',
          collapsed: true,
          items: [
            { label: 'Registry Relay', slug: 'projects/registry-relay' },
            { label: 'Registry Notary', slug: 'projects/registry-notary' },
            { label: 'Registry metadata', slug: 'projects/registry-manifest' },
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
          ],
        },
      ],
    }),
    sitemap(),
  ],
});
