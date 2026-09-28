// Docset product gates shared by the Astro config, the docs content loader,
// the CLI navigation, the per-page Markdown endpoint, and the <DocsetProduct>
// regions of shared MDX pages.
//
// A docset publishes a product only when its `products` map in
// src/data/docsets.yaml names it. Pages and generated CLI references that
// belong to a gated product are dropped from the docs collection of every
// docset that does not name the product, so no HTML page, per-page Markdown
// twin, llms corpus entry, search record, or sitemap entry exists for them.
// Joining a docset is the one-line product entry in docsets.yaml.

/**
 * Hand-authored content entries (docs collection ids) each gated product owns.
 * @type {Readonly<Record<string, readonly string[]>>}
 */
export const PRODUCT_PAGES = Object.freeze({
  'registry-messaging': Object.freeze([
    'start/messaging',
    'tutorials/first-messaging',
    'configure/messaging',
    'operate/messaging',
    'reference/apis/registry-messaging',
  ]),
});

/**
 * Generated CLI reference binaries each gated product owns. Every page under
 * reference/cli/<binary> belongs to the product.
 * @type {Readonly<Record<string, readonly string[]>>}
 */
export const PRODUCT_CLI_BINARIES = Object.freeze({
  'registry-messaging': Object.freeze(['messaging', 'messagingctl']),
});

/**
 * The docset this build publishes: DOCS_DOCSET, else the manifest's current
 * docset. Mirrors resolveDocsetBuildContext in astro.config.mjs.
 *
 * @param {{ current: string, docsets: Array<{ id: string, products?: Record<string, unknown> }> }} manifest
 * @param {Record<string, string | undefined>} env
 */
export function selectedDocset(manifest, env = process.env) {
  const id = env.DOCS_DOCSET || manifest.current;
  const docset = manifest.docsets.find((entry) => entry.id === id);
  if (!docset) throw new Error(`selected docs docset "${id}" not found`);
  return docset;
}

/**
 * @param {{ products?: Record<string, unknown> }} docset
 * @param {string} product
 */
export function docsetHasProduct(docset, product) {
  return Boolean(docset.products?.[product]);
}

/**
 * Site routes of a gated product's hand-authored pages, with trailing slash.
 * @param {string} product
 */
export function productRoutes(product) {
  return (PRODUCT_PAGES[product] ?? []).map((id) => `/${id}/`);
}

/**
 * CLI binaries whose generated reference this docset does not publish.
 * @param {{ products?: Record<string, unknown> }} docset
 */
export function omittedCliBinaries(docset) {
  return Object.entries(PRODUCT_CLI_BINARIES)
    .filter(([product]) => !docsetHasProduct(docset, product))
    .flatMap(([, binaries]) => binaries);
}

/**
 * True when a docs collection entry belongs to a product this docset does not
 * publish.
 *
 * @param {string} entryId
 * @param {{ products?: Record<string, unknown> }} docset
 */
export function isEntryGatedOut(entryId, docset) {
  for (const [product, pages] of Object.entries(PRODUCT_PAGES)) {
    if (!docsetHasProduct(docset, product) && pages.includes(entryId)) return true;
  }
  for (const binary of omittedCliBinaries(docset)) {
    const root = `reference/cli/${binary}`;
    if (entryId === root || entryId.startsWith(`${root}/`)) return true;
  }
  return false;
}

const regionName = 'DocsetProduct';

/**
 * @param {{ attributes?: Array<{ type: string, name?: string, value?: unknown }> }} node
 * @param {{ products?: Record<string, unknown> }} docset
 */
function regionShown(node, docset) {
  const attributes = node.attributes ?? [];
  for (const attribute of attributes) {
    if (attribute.type !== 'mdxJsxAttribute' || !['product', 'absent'].includes(attribute.name ?? '')) {
      throw new Error(`<${regionName}> accepts only product and absent attributes`);
    }
  }
  const product = attributes.find((attribute) => attribute.name === 'product')?.value;
  if (typeof product !== 'string' || product === '') {
    throw new Error(`<${regionName}> needs a literal product attribute`);
  }
  const absent = attributes.some((attribute) => attribute.name === 'absent');
  return docsetHasProduct(docset, product) !== absent;
}

/**
 * Remark plugin for MDX pages. A <DocsetProduct product="..."> region keeps
 * its content when the docset carries the product and is removed otherwise;
 * with `absent` the rule is reversed. It works on the Markdown tree, before
 * headings are collected, so a removed region leaves nothing behind: no text,
 * no table-of-contents entry, and no search or llms corpus record. Use it in
 * .mdx pages only; plain Markdown has no JSX.
 *
 * @param {{ products?: Record<string, unknown> }} docset
 */
export function remarkDocsetProducts(docset) {
  /** @param {{ children?: any[] }} parent */
  const visit = (parent) => {
    if (!Array.isArray(parent.children)) return;
    for (let index = 0; index < parent.children.length; index += 1) {
      const node = parent.children[index];
      const isRegion =
        (node.type === 'mdxJsxFlowElement' || node.type === 'mdxJsxTextElement') &&
        node.name === regionName;
      if (!isRegion) {
        visit(node);
        continue;
      }
      const kept = regionShown(node, docset) ? node.children ?? [] : [];
      parent.children.splice(index, 1, ...kept);
      // Revisit the spliced content in place: it may hold further regions.
      index -= 1;
    }
  };
  return () => visit;
}

const gateBlock = /<DocsetProduct\s+product="([^"]+)"(\s+absent)?\s*>([\s\S]*?)<\/DocsetProduct>/g;

/**
 * Resolve <DocsetProduct> regions in a raw MDX body for the per-page Markdown
 * endpoint, which serves entry.body rather than the compiled page. A region is
 * kept when its product is in the docset (or, with `absent`, when it is not)
 * and dropped otherwise, matching remarkDocsetProducts. Regions do not nest.
 *
 * @param {string} body
 * @param {{ products?: Record<string, unknown> }} docset
 */
export function resolveDocsetProductRegions(body, docset) {
  return body.replace(gateBlock, (_match, product, absent, inner) => {
    const shown = docsetHasProduct(docset, product) !== Boolean(absent);
    return shown ? inner : '';
  });
}
