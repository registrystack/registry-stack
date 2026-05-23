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
            { label: 'Introduction', slug: 'start' },
            { label: 'What is the registry family', slug: 'start/what-is-the-registry-family' },
            { label: 'Quickstart', slug: 'start/quickstart' },
          ],
        },
        {
          label: 'Map',
          items: [
            { label: 'Overview', slug: 'map' },
            { label: 'Ownership & boundaries', slug: 'map/ownership-boundaries' },
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
