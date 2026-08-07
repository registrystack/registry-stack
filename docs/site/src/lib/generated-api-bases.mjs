/**
 * The site bases starlight-openapi owns.
 *
 * Pages under these bases are virtual routes rather than docs content-collection
 * entries, so they have no per-page Markdown twin: they must not advertise a
 * Markdown alternate, must not offer the Copy or View as Markdown affordances,
 * and are excluded from the exhaustive .md coverage check. Every consumer reads
 * this list, so registering a new API reference in astro.config.mjs is the only
 * place that has to learn about it.
 *
 * These are the generated bases, not the hand-authored narrative pages
 * reference/apis/registry-relay and registry-evidence, which keep their .md.
 */
export const GENERATED_API_BASES = [
  'reference/apis/relay',
  'reference/apis/evidence',
];

/** True when a dist-relative page directory is a generated API route. */
export function isGeneratedApiDir(dir) {
  return GENERATED_API_BASES.some((base) => dir === base || dir.startsWith(`${base}/`));
}

/** True when a root-relative pathname is a generated API route. */
export function isGeneratedApiPath(pathname) {
  return GENERATED_API_BASES.some((base) => pathname.startsWith(`/${base}/`));
}
