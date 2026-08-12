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
    always_required: false,
    repeatable: false,
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
    constraints: [],
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

test('renders required groups and conditional requirements', () => {
  const catalog = fixtureCatalog();
  const relayctl = catalog.binaries.find((binary) => binary.name === 'relayctl');
  relayctl.constraints.push(
    {
      kind: 'required_exactly_one',
      when: null,
      arguments: ['--left', '--right'],
    },
    {
      kind: 'requires_all',
      when: '--right',
      arguments: ['--detail'],
    },
    {
      kind: 'required_one_or_more',
      when: null,
      arguments: ['--scope', '--role'],
    },
  );
  const page = renderCatalog(catalog).get('relayctl.mdx');
  assert.match(page, /Exactly one of `--left`, `--right` is required\./u);
  assert.match(page, /One or more of `--scope`, `--role` are required\./u);
  assert.match(page, /`--right` is present \| `--detail` is required\./u);
  assert.match(page, /Always required/u);
  assert.doesNotMatch(page, /Repeatable/u);
});

test('renders repeatable option cardinality', () => {
  const catalog = fixtureCatalog();
  const relayctl = catalog.binaries.find((binary) => binary.name === 'relayctl');
  relayctl.options.push({
    ...argument('--attribute-column <COLUMN>'),
    repeatable: true,
  });

  const page = renderCatalog(catalog).get('relayctl.mdx');
  assert.match(page, /\| `--attribute-column <COLUMN>` \| No \| Yes \|/u);
  assert.match(page, /\| Option \| Always required \| Repeatable \|/u);
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

test('the docs check detects CLI drift before generation', async () => {
  const packageJson = JSON.parse(
    await readFile(new URL('../package.json', import.meta.url), 'utf8'),
  );
  const checkSteps = packageJson.scripts.check.split(' && ');
  const sourceSteps = packageJson.scripts['check:source'].split(' && ');

  assert.equal(checkSteps[0], 'npm run check:source');
  assert.equal(sourceSteps[0], 'npm run check:cli-reference');
  assert.ok(
    sourceSteps.indexOf('npm run check:cli-reference') < sourceSteps.indexOf('npm run generate'),
  );
});
