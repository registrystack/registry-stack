import { existsSync, readFileSync } from 'node:fs';

const generatedIndex = new URL('../content/docs/reference/cli/index.mdx', import.meta.url);

/**
 * Return CLI navigation only when the selected docset contains a publishable
 * generated index. Archived builds stage this file from their pinned source
 * before Astro loads, so the index frontmatter is the publication authority.
 *
 * @param {string | URL} indexPath
 */
export function cliReferenceSidebar(indexPath = generatedIndex) {
  if (!existsSync(indexPath)) return [];
  const index = readFileSync(indexPath, 'utf8');
  const frontmatterEnd = index.indexOf('\n---\n', 4);
  const frontmatter = frontmatterEnd === -1 ? '' : index.slice(4, frontmatterEnd);
  if (/^draft:\s*true\s*$/mu.test(frontmatter)) return [];
  return [
    {
      label: 'Command-line interfaces',
      collapsed: true,
      items: [
        { label: 'Overview', slug: 'reference/cli' },
        // Older pinned catalogs predate Server and contain no Server pages.
        ...['registry-server', 'registry-serverctl']
          .filter((name) => index.includes(`](./${name}/)`))
          .map((name) => ({ label: name, slug: `reference/cli/${name}` })),
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
