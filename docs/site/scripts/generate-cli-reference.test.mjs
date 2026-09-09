import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  catalogDigest,
  contentDigest,
  legacyReviewSchemaVersion,
  expectedBinaries,
  generateCliReference,
  renderCatalog,
  reviewSchemaVersion,
  schemaVersion,
  validateCatalog,
  validateReviewMetadata,
} from './generate-cli-reference.mjs';
import { cliReferenceDigest, migrateCliReferenceReview } from './cli-reference-digest.mjs';

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
  return {
    schema_version: schemaVersion,
    source_version: '0.21.0',
    binaries,
  };
}

function fixtureReviewMetadata(overrides = {}) {
  return {
    schema_version: reviewSchemaVersion,
    status: 'draft',
    last_reviewed: 'unreviewed',
    reviewed_source_version: null,
    reviewed_catalog_sha256: null,
    reviewed_content_sha256: null,
    ...overrides,
  };
}

test('renders one linked page for every nested public command', () => {
  const pages = renderCatalog(fixtureCatalog(), fixtureReviewMetadata());
  assert.ok(pages.has('index.mdx'));
  assert.ok(pages.has('breg.mdx'));
  assert.ok(pages.has('bregctl.mdx'));
  assert.match(pages.get('index.mdx'), /Base Registry Engine/u);
  assert.ok(pages.has('relayctl.mdx'));
  assert.ok(pages.has('relayctl/tooling.mdx'));
  assert.ok(pages.has('relayctl/tooling/editor.mdx'));
  assert.match(pages.get('index.mdx'), /\.\/relayctl\//u);
  assert.match(pages.get('relayctl.mdx'), /\.\/tooling\//u);
  assert.match(pages.get('relayctl/tooling.mdx'), /\.\/editor\//u);
  assert.match(pages.get('relayctl/tooling/editor.mdx'), /\| `-h, --help` \|/u);
  assert.match(pages.get('relayctl.mdx'), /\{\/\* Generated from Clap/u);
  assert.match(pages.get('relayctl.mdx'), /status: draft\ndraft: true/u);
  assert.match(pages.get('relayctl.mdx'), /last_reviewed: "unreviewed"/u);
  assert.match(pages.get('relayctl.mdx'), /source version `0\.21\.0`/u);
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
    {
      kind: 'mutually_exclusive',
      when: null,
      arguments: ['--left', '--right'],
    },
  );
  const page = renderCatalog(catalog, fixtureReviewMetadata()).get('relayctl.mdx');
  assert.match(page, /Exactly one of `--left`, `--right` is required\./u);
  assert.match(page, /One or more of `--scope`, `--role` are required\./u);
  assert.match(page, /`--right` is present \| `--detail` is required\./u);
  assert.match(page, /`--left` and `--right` cannot be used together\./u);
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

  const page = renderCatalog(catalog, fixtureReviewMetadata()).get('relayctl.mdx');
  assert.match(page, /\| `--attribute-column <COLUMN>` \| No \| Yes \|/u);
  assert.match(page, /\| Option \| Always required \| Repeatable \|/u);
});

test('rejects a hidden command even if a collector emits it', () => {
  const catalog = fixtureCatalog();
  catalog.binaries[0].subcommands.push(command('bundle-check', 'evidence'));
  assert.throws(() => validateCatalog(catalog), /publishes hidden command/u);
});

test('rejects empty public help and unstable conflict pairs', () => {
  const emptyHelp = fixtureCatalog();
  emptyHelp.binaries[0].options[0].description = '';
  assert.throws(() => validateCatalog(emptyHelp), /description must be a non-empty string/u);

  const unsortedConflict = fixtureCatalog();
  unsortedConflict.binaries[0].constraints.push({
    kind: 'mutually_exclusive',
    when: null,
    arguments: ['--right', '--left'],
  });
  assert.throws(() => validateCatalog(unsortedConflict), /distinct and sorted/u);
});

test('requires human review of content while retaining its original source provenance', () => {
  const catalog = fixtureCatalog();
  assert.throws(
    () => validateReviewMetadata(fixtureReviewMetadata({ status: 'current' }), catalog),
    /unreviewed CLI reference metadata must be draft/u,
  );
  const reviewed = fixtureReviewMetadata({
    status: 'current',
    last_reviewed: '2026-08-13',
    reviewed_source_version: catalog.source_version,
    reviewed_catalog_sha256: catalogDigest(catalog),
    reviewed_content_sha256: contentDigest(catalog),
  });
  assert.equal(validateReviewMetadata(reviewed, catalog), reviewed);
  assert.throws(
    () => validateReviewMetadata({ ...reviewed, last_reviewed: '2026-02-30' }, catalog),
    /unreviewed or YYYY-MM-DD/u,
  );
  const bumped = { ...catalog, source_version: '0.22.0' };
  assert.notEqual(catalogDigest(bumped), catalogDigest(catalog));
  assert.equal(contentDigest(bumped), contentDigest(catalog));
  assert.equal(validateReviewMetadata(reviewed, bumped), reviewed);
  assert.throws(
    () => validateReviewMetadata({ ...reviewed, reviewed_catalog_sha256: 'a'.repeat(64) }, bumped),
    /does not cover the current command catalog digest/u,
  );
  const page = renderCatalog(bumped, reviewed).get('relayctl.mdx');
  assert.match(page, /status: current/u);
  assert.match(page, /last_reviewed: "2026-08-13"/u);
  assert.match(page, /source version `0\.22\.0`/u);
  assert.ok(page.includes(catalogDigest(bumped)));
  assert.doesNotMatch(page, /^draft: true$/mu);
  assert.match(renderCatalog(bumped, { ...reviewed, status: 'draft' }).get('relayctl.mdx'), /^draft: true$/mu);
});

test('every public catalog content change invalidates review, including version-like help', () => {
  const catalog = fixtureCatalog();
  const metadata = fixtureReviewMetadata({
    status: 'current',
    last_reviewed: '2026-08-13',
    reviewed_source_version: catalog.source_version,
    reviewed_catalog_sha256: catalogDigest(catalog),
    reviewed_content_sha256: contentDigest(catalog),
  });
  const mutations = [
    binary => { binary.about = 'Version 0.22.0 details'; },
    binary => { binary.long_about = 'Detailed help'; },
    binary => { binary.usage += ' <FILE>'; },
    binary => { binary.options[0].description = 'Different help'; },
    binary => { binary.options[0].display = '--other'; },
    binary => { binary.options[0].default_values = ['0.22.0']; },
    binary => { binary.options[0].possible_values = ['left']; },
    binary => { binary.options[0].environment = 'CONFIG_PATH'; },
    binary => { binary.options[0].repeatable = true; },
    binary => { binary.options[0].always_required = true; },
    binary => { binary.arguments.push(argument('<FILE>')); },
    binary => { binary.constraints.push({ kind: 'required_exactly_one', when: null, arguments: ['--left', '--right'] }); },
    binary => { binary.subcommands[0].subcommands[0].about = 'Nested help'; },
    binary => { binary.subcommands.push(command('extra', 'relayctl')); },
  ];
  for (const mutate of mutations) {
    const changed = structuredClone(catalog);
    mutate(changed.binaries.find(binary => binary.name === 'relayctl'));
    assert.notEqual(contentDigest(changed), contentDigest(catalog));
    assert.throws(() => validateReviewMetadata(metadata, changed), /current command content/u);
  }
});

test('legacy v2 reviews retain exact version and catalog checks', () => {
  const catalog = fixtureCatalog();
  const legacy = {
    schema_version: legacyReviewSchemaVersion,
    status: 'current',
    last_reviewed: '2026-08-13',
    reviewed_source_version: catalog.source_version,
    reviewed_catalog_sha256: catalogDigest(catalog),
  };
  assert.equal(validateReviewMetadata(legacy, catalog), legacy);
  assert.throws(
    () => validateReviewMetadata(legacy, { ...catalog, source_version: '0.22.0' }),
    /covers 0\.21\.0, not 0\.22\.0/u,
  );
  const changed = structuredClone(catalog);
  changed.binaries[0].about = 'Changed help';
  assert.throws(() => validateReviewMetadata(legacy, changed), /current command catalog digest/u);
});

test('writes deterministic pages and detects local output drift', async () => {
  const root = await mkdtemp(join(tmpdir(), 'registry-cli-reference-'));
  const docsRoot = join(root, 'docs', 'site');
  const output = `${JSON.stringify(fixtureCatalog(), null, 2)}\n`;
  const execute = async () => output;
  try {
    await mkdir(join(docsRoot, 'src/data'), { recursive: true });
    await writeFile(
      join(docsRoot, 'src/data/cli-reference.yaml'),
      [
        `schema_version: ${reviewSchemaVersion}`,
        'status: draft',
        'last_reviewed: unreviewed',
        'reviewed_source_version: null',
        'reviewed_catalog_sha256: null',
        'reviewed_content_sha256: null',
        '',
      ].join('\n'),
      'utf8',
    );
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

test('the docs check generates missing outputs before validating CLI parity', async () => {
  const packageJson = JSON.parse(
    await readFile(new URL('../package.json', import.meta.url), 'utf8'),
  );
  const checkSteps = packageJson.scripts.check.split(' && ');
  const sourceSteps = packageJson.scripts['check:source'].split(' && ');

  assert.equal(packageJson.scripts.pretest, 'npm run generate');
  assert.equal(checkSteps[0], 'npm run check:source');
  assert.equal(sourceSteps[0], 'npm run generate');
  assert.ok(
    sourceSteps.indexOf('npm run generate') < sourceSteps.indexOf('npm run check:cli-reference'),
  );
});

test('the digest helper reports the values the review record must carry', async () => {
  const catalog = fixtureCatalog();
  const execute = async () => `${JSON.stringify(catalog, null, 2)}\n`;
  const digest = await cliReferenceDigest('/unused', { execute });
  assert.deepEqual(digest, {
    reviewed_source_version: '0.21.0',
    reviewed_catalog_sha256: catalogDigest(catalog),
    reviewed_content_sha256: contentDigest(catalog),
  });
  const malformed = async () => 'not json';
  await assert.rejects(cliReferenceDigest('/unused', { execute: malformed }), /did not emit JSON/u);
});

test('the digest helper is published as an npm script', async () => {
  const packageJson = JSON.parse(
    await readFile(new URL('../package.json', import.meta.url), 'utf8'),
  );
  assert.equal(
    packageJson.scripts['cli-reference:digest'],
    'node scripts/cli-reference-digest.mjs',
  );
});

test('migration proves legacy review after a version bump and preserves human provenance', async () => {
  const root = await mkdtemp(join(tmpdir(), 'registry-cli-migrate-'));
  const directory = join(root, 'docs/site/src/data');
  const path = join(directory, 'cli-reference.yaml');
  const catalog = fixtureCatalog();
  const original = [
    '# Existing human review',
    `schema_version: ${legacyReviewSchemaVersion}`,
    'status: current',
    'last_reviewed: 2026-08-13',
    'reviewed_source_version: "0.21.0"',
    `reviewed_catalog_sha256: ${catalogDigest(catalog)}`,
    '',
  ].join('\n');
  const bumped = { ...catalog, source_version: '0.22.0' };
  const execute = async () => JSON.stringify(bumped);
  try {
    await mkdir(directory, { recursive: true });
    await writeFile(path, original);
    const result = await migrateCliReferenceReview(root, { execute });
    assert.equal(result.migrated, true);
    assert.equal(result.metadata.last_reviewed, '2026-08-13');
    assert.equal(result.metadata.reviewed_source_version, '0.21.0');
    assert.equal(result.metadata.reviewed_catalog_sha256, catalogDigest(catalog));
    assert.equal(result.metadata.reviewed_content_sha256, contentDigest(catalog));
    const migrated = await readFile(path, 'utf8');
    assert.match(migrated, /^# Existing human review/u);
    assert.equal((await migrateCliReferenceReview(root, { execute })).migrated, false);
    assert.equal(await readFile(path, 'utf8'), migrated);
    await generateCliReference(join(root, 'docs/site'), root, { execute });
    await generateCliReference(join(root, 'docs/site'), root, { execute, check: true });

    await writeFile(path, original);
    const changed = structuredClone(bumped);
    changed.binaries[0].about = 'Changed reference';
    await assert.rejects(
      migrateCliReferenceReview(root, { execute: async () => JSON.stringify(changed) }),
      /current command catalog digest/u,
    );
    assert.equal(await readFile(path, 'utf8'), original);

    const draft = original.replace('status: current', 'status: draft')
      .replace('last_reviewed: 2026-08-13', 'last_reviewed: unreviewed')
      .replace('reviewed_source_version: "0.21.0"', 'reviewed_source_version: null')
      .replace(`reviewed_catalog_sha256: ${catalogDigest(catalog)}`, 'reviewed_catalog_sha256: null');
    await writeFile(path, draft);
    const draftResult = await migrateCliReferenceReview(root, { execute });
    assert.equal(draftResult.metadata.last_reviewed, 'unreviewed');
    assert.equal(draftResult.metadata.reviewed_content_sha256, null);
    assert.equal(draftResult.metadata.status, 'draft');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('migration preserves author edits made while the collector runs', async () => {
  const root = await mkdtemp(join(tmpdir(), 'registry-cli-migrate-edit-'));
  const directory = join(root, 'docs/site/src/data');
  const path = join(directory, 'cli-reference.yaml');
  const catalog = fixtureCatalog();
  const metadata = {
    schema_version: legacyReviewSchemaVersion,
    status: 'current',
    last_reviewed: '2026-08-13',
    reviewed_source_version: catalog.source_version,
    reviewed_catalog_sha256: catalogDigest(catalog),
  };
  const original = JSON.stringify(metadata);
  const edited = JSON.stringify({ ...metadata, status: 'draft' });
  try {
    await mkdir(directory, { recursive: true });
    await writeFile(path, original);
    await assert.rejects(migrateCliReferenceReview(root, {
      execute: async () => {
        await writeFile(path, edited);
        return JSON.stringify(catalog);
      },
    }), /metadata changed during migration/u);
    assert.equal(await readFile(path, 'utf8'), edited);
    await assert.rejects(readFile(`${path}.tmp-${process.pid}`), { code: 'ENOENT' });

    // A retry can migrate the author's record, preserving its chosen draft status.
    const retry = await migrateCliReferenceReview(root, {
      execute: async () => JSON.stringify(catalog),
    });
    assert.equal(retry.migrated, true);
    assert.equal(retry.metadata.status, 'draft');
    assert.equal(retry.metadata.last_reviewed, metadata.last_reviewed);

    await writeFile(path, original);
    const temporary = `${path}.tmp-${process.pid}`;
    await writeFile(temporary, 'Existing temporary file owned by another operation');
    await assert.rejects(migrateCliReferenceReview(root, {
      execute: async () => JSON.stringify(catalog),
    }), { code: 'EEXIST' });
    assert.equal(await readFile(path, 'utf8'), original);
    assert.equal(await readFile(temporary, 'utf8'), 'Existing temporary file owned by another operation');
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
