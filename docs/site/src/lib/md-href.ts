/**
 * Compute the root-relative URL of the Markdown source for a given page pathname.
 *
 * Contract:
 *   - Trailing slash is stripped, then ".md" is appended.
 *   - The root path "/" maps to "/index.md".
 *   - BASE_URL is stripped from the front of the pathname before computing
 *     the Markdown path, then prepended back so the result is still rooted
 *     correctly under the base.
 *
 * Examples (base = "/"):
 *   /                                         -> /index.md
 *   /explanation/architecture/                -> /explanation/architecture.md
 *   /products/registry-relay/configuration/  -> /products/registry-relay/configuration.md
 *
 * Examples (base = "/docs/"):
 *   /docs/                                    -> /docs/index.md
 *   /docs/explanation/architecture/           -> /docs/explanation/architecture.md
 */
export function mdHrefForPath(pathname: string, base: string = '/'): string {
  // Normalise base: ensure it ends with "/" so prefix stripping is reliable.
  const normBase = base.endsWith('/') ? base : base + '/';

  // Strip the base prefix to get the page-local path.
  let local = pathname.startsWith(normBase)
    ? pathname.slice(normBase.length - 1) // keep the leading "/"
    : pathname;

  // Ensure local starts with "/".
  if (!local.startsWith('/')) local = '/' + local;

  // Strip trailing slash.
  const stripped = local.endsWith('/') ? local.slice(0, -1) : local;

  // Root maps to /index.md; everything else gets .md appended.
  const localMd = stripped === '' ? '/index.md' : stripped + '.md';

  // Reattach the base prefix (minus its trailing slash to avoid duplication).
  const basePrefix = normBase === '/' ? '' : normBase.slice(0, -1);
  return basePrefix + localMd;
}
