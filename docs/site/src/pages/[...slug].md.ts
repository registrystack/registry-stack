// Per-page machine-readable Markdown endpoint.
//
// URL scheme (contract shared with the UI agent):
//   Page pathname with trailing slash removed, then ".md"
//   /explanation/architecture/ -> /explanation/architecture.md
//   /                          -> /index.md
//   /products/registry-relay/  -> /products/registry-relay.md
//
// Routes ending in a file extension (.md) are exempt from Astro's
// trailingSlash enforcement, so this coexists with `trailingSlash: 'always'`.
import { getCollection } from 'astro:content';
import type { GetStaticPathsResult } from 'astro';
import { buildPageMarkdown, entrySlugToOutputPath } from '../lib/page-markdown';

export const prerender = true;

export async function getStaticPaths(): Promise<GetStaticPathsResult> {
  const entries = await getCollection('docs');
  return entries.map((entry) => ({
    params: { slug: entrySlugToOutputPath(entry.id) },
    props: { entry },
  }));
}

export async function GET({ props }: { props: { entry: Awaited<ReturnType<typeof getCollection<'docs'>>>[number] } }) {
  const { entry } = props;
  const body = buildPageMarkdown(
    entry.data.title,
    entry.data.description,
    entry.body ?? '',
  );
  return new Response(body, {
    headers: { 'content-type': 'text/markdown; charset=utf-8' },
  });
}
