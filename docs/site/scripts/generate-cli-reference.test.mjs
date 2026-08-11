import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  expectedBinaries,
  generateCliReference,
  renderCatalog,
  schemaVersion,
  validateCatalog,
} from './generate-cli-reference.mjs';

function argument(display) {
  return {
    display,
    description: 'Static option description.',
    required: false,
    default_values: [],
    possible_values: [],
    environment: null,
  };
}

function command(name, parent = null, subcommands = []) {
  const invocation = parent === null ? name : `${parent} ${name}`;
  return {
    name,
    invocation,
    about: `Reference for ${invocation}`,
    long_about: null,
    usage: `${invocation} [OPTIONS]`,
    arguments: [],
    options: [argument('-h, --help')],
    subcommands,
  };
}

function fixtureCatalog() {
  const binaries = expectedBinaries.map((name) => command(name));
  const relayctl = binaries.find((binary) => binary.name === 'relayctl');
  const tooling = command('tooling', 'relayctl');
  tooling.subcommands.push(command('editor', 'relayctl tooling'));
  relayctl.subcommands.push(tooling);
  return { schema_version: schemaVersion, binaries };
}

test('renders one linked page for every nested public command', () => {
  const pages = renderCatalog(fixtureCatalog());
  assert.ok(pages.has('index.mdx'));
  assert.ok(pages.has('relayctl.mdx'));
  assert.ok(pages.has('relayctl/tooling.mdx'));
  assert.ok(pages.has('relayctl/tooling/editor.mdx'));
  assert.match(pages.get('index.mdx'), /\.\/relayctl\//u);
  assert.match(pages.get('relayctl.mdx'), /\.\/tooling\//u);
  assert.match(pages.get('relayctl/tooling.mdx'), /\.\/editor\//u);
  assert.match(pages.get('relayctl/tooling/editor.mdx'), /\| `-h, --help` \|/u);
  assert.match(pages.get('relayctl.mdx'), /\{\/\* Generated from Clap/u);
  assert.doesNotMatch(pages.get('relayctl.mdx'), /<!--/u);
});

test('rejects a hidden command even if a collector emits it', () => {
  const catalog = fixtureCatalog();
  catalog.binaries[0].subcommands.push(command('bundle-check', 'evidence'));
  assert.throws(() => validateCatalog(catalog), /publishes hidden command/u);
});

test('writes deterministic pages and detects tracked drift', async () => {
  const root = await mkdtemp(join(tmpdir(), 'registry-cli-reference-'));
  const docsRoot = join(root, 'docs', 'site');
  const output = `${JSON.stringify(fixtureCatalog(), null, 2)}\n`;
  const execute = async () => output;
  try {
    await generateCliReference(docsRoot, root, { execute });
    await generateCliReference(docsRoot, root, { check: true, execute });
    const relayctl = join(
      docsRoot,
      'src/content/docs/reference/cli/relayctl.mdx',
    );
    await writeFile(relayctl, 'stale\n', 'utf8');
    await assert.rejects(
      generateCliReference(docsRoot, root, { check: true, execute }),
      /is stale/u,
    );
    assert.match(await readFile(relayctl, 'utf8'), /stale/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
