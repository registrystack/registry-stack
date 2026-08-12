import { existsSync } from 'node:fs';

const generatedIndex = new URL('../content/docs/reference/cli/index.mdx', import.meta.url);

/**
 * Return CLI navigation only when the selected docset contains its generated index.
 * Archived builds stage this file from their pinned source before Astro loads.
 *
 * @param {string | URL} indexPath
 */
export function cliReferenceSidebar(indexPath = generatedIndex) {
  if (!existsSync(indexPath)) return [];
  return [
    {
      label: 'Command-line interfaces',
      collapsed: true,
      items: [
        { label: 'Overview', slug: 'reference/cli' },
        { label: 'relay', slug: 'reference/cli/relay' },
        { label: 'relayctl', slug: 'reference/cli/relayctl' },
        { label: 'evidence', slug: 'reference/cli/evidence' },
        { label: 'evidencectl', slug: 'reference/cli/evidencectl' },
        { label: 'mint', slug: 'reference/cli/mint' },
        { label: 'evidence-oid4vci', slug: 'reference/cli/evidence-oid4vci' },
      ],
    },
  ];
}
