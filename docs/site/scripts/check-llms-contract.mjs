import { stat } from 'node:fs/promises';

const productCorpusRequirements = Object.freeze({
  'registry-manifest': Object.freeze({
    label: 'Registry Manifest',
    pattern: /Registry Manifest/i,
  }),
  'registry-evidence': Object.freeze({
    label: 'Evidence Gateway',
    pattern: /Evidence Gateway/i,
  }),
  'registry-relay': Object.freeze({
    label: 'Registry Relay',
    pattern: /registry.relay/i,
  }),
  'registry-notary': Object.freeze({
    label: 'Registry Notary',
    pattern: /registry.notary/i,
  }),
});

/**
 * Resolve the docset represented by a built tree. DOCS_DOCSET is authoritative
 * for archive builds; otherwise the public base identifies mounted builds such
 * as /dev/. A root build without either selector is the current source tree.
 *
 * @param {{ current: string, docsets: Array<{ id: string, path: string }> }} manifest
 * @param {{ DOCS_DOCSET?: string, DOCS_PUBLIC_BASE?: string }} env
 */
export function checkedDocset(manifest, env = process.env) {
  if (env.DOCS_DOCSET) {
    const explicit = manifest.docsets.find(({ id }) => id === env.DOCS_DOCSET);
    if (!explicit) throw new Error(`selected docs docset "${env.DOCS_DOCSET}" not found`);
    return explicit;
  }

  const publicBase = `/${String(env.DOCS_PUBLIC_BASE || '/')
    .replace(/^\/+|\/+$/g, '')}/`.replace(/^\/\/$/, '/');
  return manifest.docsets.find(({ path }) => path === publicBase)
    ?? manifest.docsets.find(({ id }) => id === manifest.current)
    ?? (() => { throw new Error(`current docs docset "${manifest.current}" not found`); })();
}

/** @param {{ products?: Record<string, unknown> }} docset */
export function corpusRequirements(docset) {
  return Object.entries(productCorpusRequirements)
    .filter(([product]) => Boolean(docset.products?.[product]))
    .map(([, requirement]) => requirement);
}

/**
 * Representative Markdown endpoints for the selected docset. Current builds
 * sample retained products. Historical builds that declare Relay keep checking
 * the original Relay product and tutorial endpoints from that archive source.
 *
 * @param {{ status: string, products?: Record<string, unknown> }} docset
 */
export function sampleMarkdownFiles(docset) {
  const files = ['explanation/architecture.md', 'index.md'];
  if (docset.products?.['registry-manifest']) files.push('products/registry-manifest.md');
  if (docset.products?.['registry-evidence']) files.push('products/registry-evidence.md');
  if (docset.products?.['registry-relay']) {
    files.push('products/registry-relay.md');
    files.push('tutorials/publish-governed-sqlite-registry.md');
  } else if (docset.status === 'current') {
    files.push('tutorials/first-breg.md');
  }
  return files;
}

/** @param {string} path */
export async function isRegularFile(path) {
  try {
    return (await stat(path)).isFile();
  } catch (error) {
    if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') return false;
    throw error;
  }
}
