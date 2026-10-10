// The configuration formats an adopter writes come from the platform format
// registry, which products/platform/scripts/check-config-conventions.py holds
// to the code. Generated formats are left out: no adopter writes them.
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

import { publishJson } from './configuration-reference.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultDocsRoot = resolve(scriptDir, '..');
const defaultRepoRoot = resolve(defaultDocsRoot, '../..');

export const SOURCE = 'products/platform/config-formats.yaml';
export const FORMAT_VERSION = 1;
export const AUDIENCES = ['authored', 'operator'];
export const STABILITIES = ['promised', 'experimental', 'unpromised'];

// Products in sidebar order. `docsetProduct` names the docsets.yaml product key
// a docset must carry to publish the product's formats, or null when every
// docset publishes them. `references` are the docs pages that explain the
// product's files, as content entry ids.
export const PRODUCTS = [
  {
    id: 'evidence',
    title: 'Evidence Gateway',
    docsetProduct: 'registry-evidence',
    checkPage: 'reference/evidence-configuration',
    references: [
      { label: 'Evidence Gateway configuration reference', page: 'reference/evidence-configuration' },
    ],
  },
  {
    id: 'breg',
    title: 'Base Registry Engine',
    docsetProduct: null,
    checkPage: 'reference/breg-configuration',
    references: [
      { label: 'Base Registry Engine configuration reference', page: 'reference/breg-configuration' },
    ],
  },
  {
    id: 'casework',
    title: 'Registry Casework',
    docsetProduct: 'registry-casework',
    checkPage: 'configure/casework',
    references: [
      { label: 'Author a Casework policy', page: 'configure/casework' },
      { label: 'Deploy Registry Casework', page: 'operate/casework' },
    ],
  },
  {
    id: 'scheduling',
    title: 'Registry Scheduling',
    docsetProduct: 'registry-scheduling',
    checkPage: 'reference/scheduling-configuration',
    references: [
      { label: 'Registry Scheduling configuration reference', page: 'reference/scheduling-configuration' },
      { label: 'Registry Scheduling API', page: 'reference/apis/registry-scheduling' },
    ],
  },
  {
    id: 'render',
    title: 'Registry Render',
    docsetProduct: 'registry-render',
    checkPage: 'operate/registry-render',
    references: [
      { label: 'Render your first document', page: 'tutorials/first-render-document' },
      { label: 'Run Registry Render in serve mode', page: 'operate/registry-render' },
    ],
  },
  {
    id: 'messaging',
    title: 'Registry Messaging',
    docsetProduct: 'registry-messaging',
    checkPage: 'configure/messaging',
    references: [
      { label: 'Author a Messaging package', page: 'configure/messaging' },
      { label: 'Deploy Registry Messaging', page: 'operate/messaging' },
    ],
  },
  {
    id: 'discovery',
    title: 'Registry Discovery',
    docsetProduct: null,
    checkPage: 'configure/discovery',
    references: [
      { label: 'Package and run a Registry Discovery index', page: 'configure/discovery' },
    ],
  },
  {
    id: 'manifest',
    title: 'Registry Manifest',
    docsetProduct: 'registry-manifest',
    checkPage: 'products/registry-manifest/validate-and-render',
    references: [
      { label: 'Registry Manifest portable metadata data model', page: 'spec/rs-dm-manifest' },
    ],
  },
  {
    id: 'platform',
    title: 'Registry Platform',
    docsetProduct: null,
    checkPage: 'reference/cli/evidencectl',
    references: [],
  },
];

// Formats a docset publishes apart from the rest of their product.
export const FORMAT_DOCSET_PRODUCTS = {
  'breg/mcp-runtime': 'registry-breg-services',
  'breg/review-runtime': 'registry-breg-services',
};

// The registry writes `none` where a format has no value yet.
function named(value) {
  if (value === undefined || value === null || value === 'none') return null;
  if (typeof value !== 'string' || value === '') {
    throw new Error(`expected a string or none, found ${JSON.stringify(value)}`);
  }
  return value;
}

// A check command names its arguments as {project}; the site writes a value the
// reader replaces as <project>.
function placeholders(command) {
  return command.replace(/\{([a-z]+)\}/g, '<$1>');
}

function formatRow(entry) {
  const where = `${SOURCE} format ${entry.id}`;
  if (!STABILITIES.includes(entry.stability)) {
    throw new Error(`${where} has stability ${entry.stability}; expected one of ${STABILITIES.join(', ')}`);
  }
  if (!Array.isArray(entry.files) || entry.files.length === 0) {
    throw new Error(`${where} names no files`);
  }
  const current = entry.current === 'none' ? {} : entry.current;
  if (current === null || typeof current !== 'object') {
    throw new Error(`${where} has no current header record`);
  }
  const schema = entry.schema === 'none' || entry.schema === undefined ? {} : entry.schema;
  const check = named(entry.check);
  if (check !== null && /[{}]/.test(placeholders(check))) {
    throw new Error(`${where} has a check command with an unreadable placeholder: ${check}`);
  }
  return {
    id: entry.id,
    title: entry.title,
    audience: entry.audience,
    files: entry.files,
    syntax: entry.syntax,
    apiVersion: named(current.apiVersion),
    kind: named(current.kind),
    exceptionClass: entry.exceptionClass ?? null,
    schemaId: named(schema.id),
    schemaPath: named(schema.path),
    check: check === null ? null : placeholders(check),
    stability: entry.stability,
    docsetProduct: FORMAT_DOCSET_PRODUCTS[entry.id] ?? null,
  };
}

export async function buildConfigurationFormats(repoRoot = defaultRepoRoot) {
  const registry = parse(await readFile(resolve(repoRoot, SOURCE), 'utf8'));
  if (!Array.isArray(registry?.formats) || registry.formats.length === 0) {
    throw new Error(`${SOURCE} lists no formats`);
  }
  const known = new Set(PRODUCTS.map((product) => product.id));
  for (const entry of registry.formats) {
    if (!known.has(entry.product)) {
      throw new Error(`${SOURCE} format ${entry.id} belongs to ${entry.product}, which the docs site does not name; add it to PRODUCTS`);
    }
    if (![...AUDIENCES, 'generated'].includes(entry.audience)) {
      throw new Error(`${SOURCE} format ${entry.id} has audience ${entry.audience}`);
    }
  }
  for (const id of Object.keys(FORMAT_DOCSET_PRODUCTS)) {
    if (!registry.formats.some((entry) => entry.id === id)) {
      throw new Error(`FORMAT_DOCSET_PRODUCTS names ${id}, which ${SOURCE} does not list`);
    }
  }
  const products = PRODUCTS.map((product) => ({
    ...product,
    formats: registry.formats
      .filter((entry) => entry.product === product.id && AUDIENCES.includes(entry.audience))
      .map(formatRow),
  })).filter((product) => product.formats.length > 0);
  return {
    format_version: FORMAT_VERSION,
    generator: 'docs/site/scripts/generate-configuration-formats.mjs',
    source: SOURCE,
    products,
  };
}

export async function generateConfigurationFormats(
  docsRoot = defaultDocsRoot,
  repoRoot = defaultRepoRoot,
) {
  const document = await buildConfigurationFormats(repoRoot);
  await publishJson(resolve(docsRoot, 'src/data/generated/configuration-formats.json'), document);
  const total = document.products.reduce((sum, product) => sum + product.formats.length, 0);
  console.log(`Generated the configuration format table for ${total} formats across ${document.products.length} products.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await generateConfigurationFormats();
}
