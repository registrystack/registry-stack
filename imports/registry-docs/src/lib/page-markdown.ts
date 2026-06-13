// Pure helpers for the per-page .md endpoint (src/pages/[...slug].md.ts).
// Kept in a separate module so the logic is unit-testable without Astro.

// Discovery header prepended to every per-page .md response AND to
// llms-full.txt (contract shared with the UI agent — do not modify).
export const DISCOVERY_HEADER = `Registry stack documentation: machine-readable Markdown.
Index of all pages: https://docs.registrystack.org/llms.txt
Full corpus: https://docs.registrystack.org/llms-full.txt`;

/**
 * Map a docs collection entry slug to the output path param used in
 * src/pages/[...slug].md.ts so the generated file URL matches the page URL.
 *
 * The docs collection uses `docsLoader()`, which sets `entry.id` to the
 * path relative to src/content/docs/ without extension:
 *   "index"                                    -> "index"
 *   "explanation/architecture"                 -> "explanation/architecture"
 *   "products/registry-relay/index"            -> "products/registry-relay"
 *   "products/registry-relay/configuration"    -> "products/registry-relay/configuration"
 *
 * Astro trims a trailing "/index" to match the URL; we mirror that here.
 * The caller uses the returned value as the `slug` route param, producing
 * /explanation/architecture.md, /index.md, etc.
 */
export function entrySlugToOutputPath(entryId: string): string {
  // A bare "index" becomes the site root -> maps to "index" (-> /index.md)
  if (entryId === 'index') return 'index';
  // A product (or any) sub-index: strip the trailing /index segment so the
  // output path aligns with the canonical page URL.
  if (entryId.endsWith('/index')) return entryId.slice(0, -'/index'.length);
  return entryId;
}

/**
 * Build the Markdown body for a single docs page.
 *
 * @param title - Page title from frontmatter.
 * @param description - Optional description from frontmatter.
 * @param body - Raw Markdown body (entry.body from the content collection,
 *               which excludes frontmatter). MDX component tags are left as-is.
 */
export function buildPageMarkdown(title: string, description: string | undefined, body: string): string {
  const parts: string[] = [DISCOVERY_HEADER, '', `# ${title}`];
  if (description) {
    parts.push('', `> ${description}`);
  }
  parts.push('', body);
  return parts.join('\n');
}
