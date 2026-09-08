import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const generatedIndex = new URL('../content/docs/reference/cli/index.mdx', import.meta.url);

// The generated binaries in the order the reference presents them. A pinned
// docset built from an older catalog contains no pages for a binary that
// catalog predates, and pages that do not exist receive no seat.
const binaries = [
  'breg',
  'bregctl',
  'relay',
  'relayctl',
  'evidence',
  'evidencectl',
  'mint',
  'evidence-oid4vci',
];

/** @param {string} path */
function isDraft(path) {
  const source = readFileSync(path, 'utf8');
  const frontmatterEnd = source.indexOf('\n---\n', 4);
  const frontmatter = frontmatterEnd === -1 ? '' : source.slice(4, frontmatterEnd);
  return /^draft:\s*true\s*$/mu.test(frontmatter);
}

/**
 * Seat one command page, then the pages of the subcommands under it, so the
 * navigation carries the command tree in the order a reader reads it.
 *
 * @param {string} directory Directory holding the page and its subcommands.
 * @param {string} name Command segment addressed by `${name}.mdx`.
 * @param {string} command Full command the page documents.
 * @param {string} slug Site slug of the page.
 */
function commandSeats(directory, name, command, slug) {
  const page = join(directory, `${name}.mdx`);
  if (!existsSync(page) || isDraft(page)) return [];
  const seats = [{ label: command, slug }];
  const children = join(directory, name);
  if (!existsSync(children)) return seats;
  const entries = readdirSync(children, { withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith('.mdx'))
    .map((entry) => entry.name.slice(0, -'.mdx'.length))
    .sort((left, right) => left.localeCompare(right));
  for (const child of entries) {
    seats.push(...commandSeats(children, child, `${command} ${child}`, `${slug}/${child}`));
  }
  return seats;
}

/**
 * Return CLI navigation only when the selected docset contains a publishable
 * generated index. Archived builds stage this file from their pinned source
 * before Astro loads, so the index frontmatter is the publication authority.
 *
 * Every generated page the docset publishes takes a seat, because the sidebar
 * is the whole of this site's navigation and the subcommand pages carry the
 * exact syntax the guides send readers to.
 *
 * @param {string | URL} indexPath
 */
export function cliReferenceSidebar(indexPath = generatedIndex) {
  if (!existsSync(indexPath)) return [];
  const index = indexPath instanceof URL ? fileURLToPath(indexPath) : String(indexPath);
  if (isDraft(index)) return [];
  const root = dirname(index);
  return [
    {
      label: 'CLI commands',
      collapsed: true,
      items: [
        { label: 'Overview', slug: 'reference/cli' },
        ...binaries.flatMap((binary) => commandSeats(root, binary, binary, `reference/cli/${binary}`)),
      ],
    },
  ];
}
