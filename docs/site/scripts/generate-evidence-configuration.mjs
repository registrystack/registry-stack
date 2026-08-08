// Render the frozen Evidence configuration grammar as docs data.
//
// `products/evidence/contracts/{bundle,runtime}.schema.yaml` are the normative
// Version 1 grammar. They carry types, fixed values, and bounds, but almost no
// prose: the explanations live in the product's CONFIG.md. So this generator
// publishes exactly what the contracts can prove, and the page sends readers to
// CONFIG.md for intent.
//
// The key-path notation is the one
// `products/evidence/scripts/check-config-key-paths.sh` owns, and this
// generator's test compares against the blocks that check maintains, so the two
// walks cannot drift apart quietly.
import { readFile, mkdir, rename, unlink, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parse as parseYaml } from 'yaml';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultDocsRoot = resolve(scriptDir, '..');
const defaultRepoRoot = resolve(defaultDocsRoot, '../..');

export const FORMAT_VERSION = '1.0';

export const CONTRACTS = [
  {
    id: 'bundle',
    file: 'products/evidence/contracts/bundle.schema.yaml',
    title: 'bundle/evidence.yaml',
    marker: 'evidence-bundle-key-paths',
  },
  {
    id: 'runtime',
    file: 'products/evidence/contracts/runtime.schema.yaml',
    title: 'runtime.yaml',
    marker: 'evidence-runtime-key-paths',
  },
];

// Validation keywords worth showing beside a field. `required`, `const`, and
// `enum` are reported separately, and the structural keywords drive the walk.
const CONSTRAINT_KEYWORDS = [
  'exclusiveMaximum',
  'exclusiveMinimum',
  'format',
  'maxItems',
  'maxLength',
  'maxProperties',
  'maximum',
  'minItems',
  'minLength',
  'minProperties',
  'minimum',
  'multipleOf',
  'pattern',
  'uniqueItems',
];

function resolveReference(document, reference) {
  if (!reference.startsWith('#/')) {
    throw new Error(`only local schema references are supported: ${reference}`);
  }
  let node = document;
  for (const part of reference.slice(2).split('/')) {
    if (node === null || typeof node !== 'object' || !Object.hasOwn(node, part)) {
      throw new Error(`unresolved schema reference ${reference}`);
    }
    node = node[part];
  }
  return node;
}

function describeValue(value) {
  return typeof value === 'string' ? value : JSON.stringify(value);
}

function occurrenceOf(schema, keyPath, kind, required) {
  const values = [];
  if (Object.hasOwn(schema, 'const')) {
    values.push(describeValue(schema.const));
  }
  if (Array.isArray(schema.enum)) {
    values.push(...schema.enum.map(describeValue));
  }
  const constraints = CONSTRAINT_KEYWORDS.filter((keyword) => Object.hasOwn(schema, keyword)).map(
    (keyword) => `${keyword}: ${describeValue(schema[keyword])}`,
  );
  const types = Array.isArray(schema.type)
    ? schema.type
    : typeof schema.type === 'string'
      ? [schema.type]
      : [];
  return {
    key_path: keyPath,
    kind,
    types,
    required,
    values,
    constraints,
    description: typeof schema.description === 'string' ? schema.description : null,
    runtime_validation:
      typeof schema['x-runtime-validation'] === 'string' ? schema['x-runtime-validation'] : null,
  };
}

// Each node records what it knows about the path it sits on, so a property
// written as a `$ref` still reports the definition's type, values, and bounds,
// and a path reached through several combinator branches reports all of them.
function walk(document, schema, prefix, kind, required, occurrences, referenceStack) {
  if (schema === null || typeof schema !== 'object' || Array.isArray(schema)) {
    return;
  }

  if (prefix !== '') {
    occurrences.push(occurrenceOf(schema, prefix, kind, required));
  }

  if (Object.hasOwn(schema, '$ref')) {
    const reference = schema.$ref;
    // A recursive definition contributes its shape once. Re-entering it would
    // not terminate and shows the reader no key they have not already seen.
    if (referenceStack.has(reference)) {
      return;
    }
    walk(
      document,
      resolveReference(document, reference),
      prefix,
      kind,
      required,
      occurrences,
      new Set([...referenceStack, reference]),
    );
    return;
  }

  for (const combinator of ['allOf', 'anyOf', 'oneOf']) {
    if (Array.isArray(schema[combinator])) {
      for (const branch of schema[combinator]) {
        walk(document, branch, prefix, kind, required, occurrences, referenceStack);
      }
    }
  }

  if (schema.properties !== null && typeof schema.properties === 'object') {
    const requiredNames = new Set(Array.isArray(schema.required) ? schema.required : []);
    for (const [name, child] of Object.entries(schema.properties)) {
      const childPath = prefix ? `${prefix}.${name}` : name;
      walk(
        document,
        child ?? {},
        childPath,
        'property',
        requiredNames.has(name),
        occurrences,
        referenceStack,
      );
    }
  }

  if (schema.items !== null && typeof schema.items === 'object' && !Array.isArray(schema.items)) {
    walk(document, schema.items, `${prefix}[]`, 'array_item', false, occurrences, referenceStack);
  }

  const additional = schema.additionalProperties;
  if (additional !== null && typeof additional === 'object' && !Array.isArray(additional)) {
    const valuePath = prefix ? `${prefix}.*` : '*';
    walk(document, additional, valuePath, 'map_value', false, occurrences, referenceStack);
  }
}

const uniqueSorted = (values) => [...new Set(values)].sort();

function merge(occurrences) {
  // One entry per key path. A path reached through several combinator branches
  // shows the union of what those branches allow, and stays required only when
  // every branch requires it.
  const first = occurrences[0];
  return {
    key_path: first.key_path,
    kind: first.kind,
    type: uniqueSorted(occurrences.flatMap((occurrence) => occurrence.types)).join(' | ') || null,
    required: occurrences.every((occurrence) => occurrence.required),
    values: uniqueSorted(occurrences.flatMap((occurrence) => occurrence.values)),
    constraints: uniqueSorted(occurrences.flatMap((occurrence) => occurrence.constraints)),
    description: occurrences.find((occurrence) => occurrence.description)?.description ?? null,
    runtime_validation:
      occurrences.find((occurrence) => occurrence.runtime_validation)?.runtime_validation ?? null,
  };
}

/** Every key path a deployment may write, in `name`, `name[]`, `name.*` notation. */
export function collectFields(document) {
  if (document === null || typeof document !== 'object') {
    throw new Error('a contract must be a mapping');
  }
  const occurrences = [];
  walk(document, document, '', null, false, occurrences, new Set());

  const grouped = new Map();
  for (const occurrence of occurrences) {
    const existing = grouped.get(occurrence.key_path);
    if (existing) {
      existing.push(occurrence);
    } else {
      grouped.set(occurrence.key_path, [occurrence]);
    }
  }
  return [...grouped.keys()]
    .sort()
    .map((keyPath) => merge(grouped.get(keyPath)))
    .map((field) => ({ ...field, values: field.values.length > 0 ? field.values : null }));
}

export function validateEvidenceConfiguration(document) {
  if (document?.format_version !== FORMAT_VERSION) {
    throw new Error('evidence configuration reference uses an unsupported format_version');
  }
  if (!Array.isArray(document.contracts) || document.contracts.length !== CONTRACTS.length) {
    throw new Error('evidence configuration reference must cover every frozen contract');
  }
  for (const contract of document.contracts) {
    if (!Array.isArray(contract.fields) || contract.fields.length === 0) {
      throw new Error(`${contract.id} must document at least one key path`);
    }
    if (contract.field_count !== contract.fields.length) {
      throw new Error(`${contract.id} field_count does not match the entries it carries`);
    }
    const seen = new Set();
    for (const field of contract.fields) {
      if (typeof field.key_path !== 'string' || field.key_path.length === 0) {
        throw new Error(`${contract.id} has an entry without a key path`);
      }
      if (seen.has(field.key_path)) {
        throw new Error(`${contract.id} repeats ${field.key_path}`);
      }
      seen.add(field.key_path);
    }
  }
}

export async function buildEvidenceConfiguration(repoRoot = defaultRepoRoot) {
  const contracts = await Promise.all(
    CONTRACTS.map(async (contract) => {
      const schema = parseYaml(await readFile(resolve(repoRoot, contract.file), 'utf8'));
      const fields = collectFields(schema);
      return { ...contract, field_count: fields.length, fields };
    }),
  );
  return {
    format_version: FORMAT_VERSION,
    generator: 'docs/site/scripts/generate-evidence-configuration.mjs',
    contracts,
  };
}

async function publishJson(path, document) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${process.pid}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(document, null, 2)}\n`, {
      encoding: 'utf8',
      flag: 'wx',
    });
    await rename(temporary, path);
  } catch (error) {
    await unlink(temporary).catch(() => {});
    throw error;
  }
}

export async function generateEvidenceConfiguration(
  docsRoot = defaultDocsRoot,
  repoRoot = defaultRepoRoot,
) {
  const document = await buildEvidenceConfiguration(repoRoot);
  validateEvidenceConfiguration(document);
  await publishJson(resolve(docsRoot, 'src/data/generated/evidence-configuration.json'), document);
  const total = document.contracts.reduce((sum, contract) => sum + contract.field_count, 0);
  console.log(
    `Generated Evidence configuration reference for ${total} key paths across ${document.contracts.length} contracts.`,
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await generateEvidenceConfiguration();
}
