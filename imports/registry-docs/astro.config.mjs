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
      title: 'Registry Legend',
      description: 'Documentation website for the registry project family.',
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
            { label: 'What is the registry family', slug: 'start/what-is-the-registry-family' },
            { label: 'Quickstart', slug: 'start/quickstart' },
          ],
        },
        {
          label: 'Projects',
          items: [
            { label: 'Project map', slug: 'map' },
            { label: 'Ownership & boundaries', slug: 'map/ownership-boundaries' },
            { label: 'All projects', slug: 'projects' },
            {
              label: 'Registry Platform',
              items: [
                { label: 'Overview', slug: 'projects/registry-platform' },
                { label: 'Reference', slug: 'projects/registry-platform/reference' },
              ],
            },
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
              label: 'Registry Relay',
              items: [
                { label: 'Overview', slug: 'projects/registry-relay' },
                { label: 'Run locally', slug: 'projects/registry-relay/run-locally' },
                { label: 'Authorize callers', slug: 'projects/registry-relay/authorize-callers' },
                { label: 'Reference', slug: 'projects/registry-relay/reference' },
              ],
            },
            {
              label: 'Registry Witness',
              items: [
                { label: 'Overview', slug: 'projects/registry-witness' },
                { label: 'Run locally', slug: 'projects/registry-witness/run-locally' },
                { label: 'Configure a claim', slug: 'projects/registry-witness/configure-a-claim' },
                { label: 'Reference', slug: 'projects/registry-witness/reference' },
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
            {
              label: 'Registry Lab',
              items: [
                { label: 'Overview', slug: 'projects/registry-lab' },
                { label: 'Demo flow', slug: 'projects/registry-lab/demo-flow' },
                { label: 'Reference', slug: 'projects/registry-lab/reference' },
              ],
            },
          ],
        },
        {
          label: 'Explanation',
          items: [
            { label: 'Architecture', slug: 'explanation/architecture' },
            { label: 'Standards positioning', slug: 'explanation/standards-positioning' },
            { label: 'DPI safeguards alignment', slug: 'explanation/dpi-safeguards-alignment' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Contracts', slug: 'reference/contracts' },
            { label: 'Standards register', slug: 'reference/standards' },
            { label: 'API reference', slug: 'reference/apis' },
            { label: 'Glossary', slug: 'reference/glossary' },
          ],
        },
        {
          label: 'Tutorials',
          items: [
            { label: 'First run with Registry Lab', slug: 'tutorials/first-run-with-registry-lab' },
          ],
        },
      ],
    }),
    sitemap(),
  ],
});
