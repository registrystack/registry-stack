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
            { label: 'Three capabilities', slug: 'start/what-we-built' },
            { label: 'Quickstart', slug: 'start/quickstart' },
            { label: 'Your first call', slug: 'start/your-first-call' },
          ],
        },
        {
          label: 'Publish',
          items: [
            { label: 'Publishing pipeline', slug: 'explanation/publishing-pipeline' },
            {
              label: 'Registry Manifest',
              items: [
                { label: 'Overview', slug: 'projects/registry-manifest' },
                { label: 'Validate and render', slug: 'projects/registry-manifest/validate-and-render' },
                { label: 'Profile fixtures', slug: 'projects/registry-manifest/profile-fixtures' },
                { label: 'Reference', slug: 'projects/registry-manifest/reference' },
              ],
            },
            {
              label: 'Registry Atlas',
              items: [
                { label: 'Overview', slug: 'projects/registry-atlas' },
                { label: 'Run locally', slug: 'projects/registry-atlas/run-locally' },
                { label: 'Inspect a registry', slug: 'projects/registry-atlas/inspect-a-registry' },
                { label: 'Reference', slug: 'projects/registry-atlas/reference' },
              ],
            },
          ],
        },
        {
          label: 'Consult',
          items: [
            { label: 'Consultation flow', slug: 'explanation/consultation-flow' },
            {
              label: 'Registry Relay',
              items: [
                { label: 'Overview', slug: 'projects/registry-relay' },
                { label: 'Run locally', slug: 'projects/registry-relay/run-locally' },
                { label: 'Authorize callers', slug: 'projects/registry-relay/authorize-callers' },
                { label: 'Reference', slug: 'projects/registry-relay/reference' },
              ],
            },
          ],
        },
        {
          label: 'Prove',
          items: [
            { label: 'Evidence issuance', slug: 'explanation/evidence-issuance' },
            {
              label: 'Registry Witness',
              items: [
                { label: 'Overview', slug: 'projects/registry-witness' },
                { label: 'Run locally', slug: 'projects/registry-witness/run-locally' },
                { label: 'Configure a claim', slug: 'projects/registry-witness/configure-a-claim' },
                { label: 'Reference', slug: 'projects/registry-witness/reference' },
              ],
            },
          ],
        },
        {
          label: 'Infrastructure',
          items: [
            {
              label: 'Registry Platform',
              items: [
                { label: 'Overview', slug: 'projects/registry-platform' },
                { label: 'Reference', slug: 'projects/registry-platform/reference' },
              ],
            },
          ],
        },
        {
          label: 'Demo',
          items: [
            {
              label: 'Registry Lab',
              items: [
                { label: 'Overview', slug: 'projects/registry-lab' },
                { label: 'Demo flow', slug: 'projects/registry-lab/demo-flow' },
                { label: 'Reference', slug: 'projects/registry-lab/reference' },
              ],
            },
            { label: 'First run with Registry Lab', slug: 'tutorials/first-run-with-registry-lab' },
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
          ],
        },
        {
          label: 'Context & decisions',
          items: [
            { label: 'Boundaries and map', slug: 'map/boundaries-and-map' },
            { label: 'Architecture', slug: 'explanation/architecture' },
            { label: 'Standards positioning', slug: 'explanation/standards-positioning' },
            { label: 'DPI safeguards alignment', slug: 'explanation/dpi-safeguards-alignment' },
            { label: 'Rename: evidence-server → Witness', slug: 'decisions/rename-2026-05-23' },
            { label: 'Historical docs index', slug: 'decisions/historical-docs-index' },
          ],
        },
      ],
    }),
    sitemap(),
  ],
});
