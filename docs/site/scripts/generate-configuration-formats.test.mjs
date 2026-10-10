import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { parse } from 'yaml';

import {
  buildConfigurationFormats,
  generateConfigurationFormats,
  PRODUCTS,
  SOURCE,
} from './generate-configuration-formats.mjs';

const repoRoot = new URL('../../../', import.meta.url);
const contentRoot = new URL('../src/content/docs/', import.meta.url);

async function registry() {
  return parse(await readFile(new URL(SOURCE, repoRoot), 'utf8'));
}

function rows(document) {
  return new Map(document.products.flatMap((product) => product.formats.map((format) => [format.id, format])));
}

test('publishes every authored and operator format and no generated one', async () => {
  const { formats } = await registry();
  const document = await buildConfigurationFormats();
  const expected = formats
    .filter((entry) => entry.audience === 'authored' || entry.audience === 'operator')
    .map((entry) => entry.id)
    .sort();
  assert.deepEqual([...rows(document).keys()].sort(), expected);
  assert.ok(formats.some((entry) => entry.audience === 'generated'), 'the registry lists generated formats');
  for (const product of document.products) {
    assert.ok(product.formats.length > 0, product.id);
    for (const format of product.formats) {
      assert.ok(format.id.startsWith(`${product.id}/`), format.id);
    }
  }
});

test('states each header, schema, check, and stability as the registry records it', async () => {
  const formats = rows(await buildConfigurationFormats());
  assert.deepEqual(formats.get('breg/project'), {
    id: 'breg/project',
    title: 'Registry project',
    audience: 'authored',
    files: ['registry.yaml'],
    syntax: 'yaml',
    apiVersion: 'id.registrystack.org/formats/breg/project/v1alpha1',
    kind: 'BRegProject',
    exceptionClass: null,
    schemaId: 'https://id.registrystack.org/schemas/breg/project/project.v1alpha1.schema.json',
    schemaPath: 'products/breg/generated/authoring/registry-project.schema.json',
    check: 'bregctl check <project>',
    stability: 'promised',
    docsetProduct: null,
  });
  const module = formats.get('breg/module');
  assert.equal(module.apiVersion, 'id.registrystack.org/formats/breg/module/v1alpha1');
  assert.equal(module.kind, 'BRegModule');
  const journeys = formats.get('breg/journeys');
  assert.equal(journeys.apiVersion, 'id.registrystack.org/formats/breg/journeys/v1');
  assert.equal(journeys.kind, 'BRegJourneys');
  assert.equal(formats.get('breg/linkml-schema').exceptionClass, 'external-format');
  assert.equal(formats.get('manifest/metadata').exceptionClass, 'exchange-model');
  const discovery = formats.get('discovery/runtime');
  assert.equal(discovery.check, 'discoveryctl check --runtime-config <file>');
  assert.equal(discovery.kind, 'DiscoveryRuntimeConfig');
  assert.equal(
    formats.get('casework/project').schemaId,
    'https://id.registrystack.org/schemas/casework/project/project.v1alpha1.schema.json',
  );
  assert.equal(
    formats.get('casework/project').schemaPath,
    'products/casework/generated/project/project.schema.json',
  );
  assert.equal(
    formats.get('messaging/runtime').check,
    'messagingctl check --project <project> --runtime-config <file>',
  );
  for (const format of formats.values()) {
    assert.ok(['promised', 'experimental', 'unpromised'].includes(format.stability), format.id);
    assert.doesNotMatch(format.check ?? '', /[{}]/, format.id);
  }
});

test('gates formats by the docset product that publishes them', async () => {
  const document = await buildConfigurationFormats();
  const product = (id) => document.products.find((entry) => entry.id === id);
  assert.equal(product('messaging').docsetProduct, 'registry-messaging');
  assert.equal(product('breg').docsetProduct, null);
  const formats = rows(document);
  assert.equal(formats.get('breg/mcp-runtime').docsetProduct, 'registry-breg-services');
  assert.equal(formats.get('breg/review-runtime').docsetProduct, 'registry-breg-services');
  assert.equal(formats.get('breg/runtime').docsetProduct, null);
  const docsets = parse(await readFile(new URL('../src/data/docsets.yaml', import.meta.url), 'utf8'));
  const latest = docsets.docsets.find((entry) => entry.id === docsets.current);
  for (const gate of [
    ...document.products.map((entry) => entry.docsetProduct),
    ...[...formats.values()].map((format) => format.docsetProduct),
  ].filter(Boolean)) {
    assert.ok(latest.products[gate], `${gate} is not a docsets.yaml product key`);
  }
});

test('links each product to pages that exist', () => {
  for (const product of PRODUCTS) {
    for (const reference of product.references) {
      const candidates = [`${reference.page}.mdx`, `${reference.page}.md`, `${reference.page}/index.mdx`];
      assert.ok(
        candidates.some((candidate) => existsSync(new URL(candidate, contentRoot))),
        `${product.id} links ${reference.page}, which has no page`,
      );
    }
  }
});

test('names a check page for every product, and the page exists', () => {
  for (const product of PRODUCTS) {
    assert.ok(product.checkPage, `${product.id} names no check page`);
    // Product pages under products/ are copied from the product source by npm run generate.
    if (product.checkPage.startsWith('products/') || product.checkPage.startsWith('reference/cli/')) continue;
    const candidates = [`${product.checkPage}.mdx`, `${product.checkPage}.md`];
    assert.ok(
      candidates.some((candidate) => existsSync(new URL(candidate, contentRoot))),
      `${product.id} names check page ${product.checkPage}, which has no page`,
    );
  }
});

test('lists the check command of every authored and operator format on its check page', async () => {
  const document = await buildConfigurationFormats();
  for (const product of document.products) {
    const page = product.checkPage;
    if (page.startsWith('products/') || page.startsWith('reference/cli/')) continue;
    const text = readFileSync(new URL(`${page}.mdx`, contentRoot), 'utf8');
    assert.match(
      text,
      new RegExp(`<ConfigurationFormatChecks[^>]*product="${product.id}"`, 'u'),
      `${page} does not render the check commands of ${product.id}`,
    );
  }
});

async function withRegistry(text, action) {
  const scratch = await mkdtemp(join(tmpdir(), 'configuration-formats-'));
  try {
    await mkdir(join(scratch, 'products/platform'), { recursive: true });
    await writeFile(join(scratch, SOURCE), text);
    return await action(scratch);
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
}

const entry = (fields) => [
  'formats:',
  '  - id: breg/mcp-runtime',
  '    product: breg',
  '    title: Gateway runtime',
  '    files: [runtime.yaml]',
  '    syntax: yaml',
  '    audience: operator',
  '    stability: experimental',
  '    current: none',
  '    schema: none',
  '    check: none',
  '  - id: breg/review-runtime',
  '    product: breg',
  '    title: Review runtime',
  '    files: [runtime.yaml]',
  '    syntax: yaml',
  '    audience: operator',
  '    stability: experimental',
  '    current: none',
  '    schema: none',
  '    check: none',
  '  - id: example/format',
  '    title: Example',
  '    files: [example.yaml]',
  '    syntax: yaml',
  '    current: none',
  '    schema: none',
  '    check: none',
  ...fields.map((field) => `    ${field}`),
  '',
].join('\n');

test('reads a registry entry that records none for its header and schema', async () => {
  const document = await withRegistry(
    entry(['product: platform', 'audience: authored', 'stability: unpromised']),
    (root) => buildConfigurationFormats(root),
  );
  const format = rows(document).get('example/format');
  assert.equal(format.apiVersion, null);
  assert.equal(format.kind, null);
  assert.equal(format.schemaId, null);
  assert.equal(format.schemaPath, null);
  assert.equal(format.check, null);
});

test('refuses a format of a product the site does not name', async () => {
  await withRegistry(
    entry(['product: unnamed', 'audience: authored', 'stability: promised']),
    (root) => assert.rejects(buildConfigurationFormats(root), /belongs to unnamed.*add it to PRODUCTS/),
  );
});

test('refuses an unknown stability or audience', async () => {
  await withRegistry(
    entry(['product: platform', 'audience: authored', 'stability: stable']),
    (root) => assert.rejects(buildConfigurationFormats(root), /stability stable/),
  );
  await withRegistry(
    entry(['product: platform', 'audience: reader', 'stability: promised']),
    (root) => assert.rejects(buildConfigurationFormats(root), /audience reader/),
  );
});

test('configuration format generation is deterministic and matches the generated data', async () => {
  const scratch = await mkdtemp(join(tmpdir(), 'configuration-formats-'));
  try {
    await generateConfigurationFormats(scratch);
    const path = join(scratch, 'src/data/generated/configuration-formats.json');
    const first = await readFile(path, 'utf8');
    await generateConfigurationFormats(scratch);
    assert.equal(first, await readFile(path, 'utf8'));
    assert.equal(
      first,
      await readFile(new URL('../src/data/generated/configuration-formats.json', import.meta.url), 'utf8'),
    );
  } finally {
    await rm(scratch, { recursive: true, force: true });
  }
});
