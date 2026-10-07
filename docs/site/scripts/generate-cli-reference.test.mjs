import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';

import {
  catalogDigest,
  catalogSnapshot,
  expectedBinaries,
  generateCliReference,
  loadCatalog,
  renderCatalog,
  schemaVersion,
  validateCatalog,
  validateReviewMetadata,
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
  const evidencectl = binaries.find((binary) => binary.name === 'evidencectl');
  const tooling = command('tooling', 'evidencectl');
  tooling.subcommands.push(command('editor', 'evidencectl tooling'));
  evidencectl.subcommands.push(tooling);
  return {
    schema_version: schemaVersion,
    source_version: '0.21.0',
    binaries,
  };
}

function fixtureReviewMetadata(overrides = {}) {
  return {
    status: 'draft',
    last_reviewed: 'unreviewed',
    ...overrides,
  };
}

// A repository holding the committed snapshot and the workspace manifest the
// generator reads.
async function fixtureRepository(catalog, version = catalog.source_version) {
  const root = await mkdtemp(join(tmpdir(), 'registry-cli-reference-'));
  const snapshot = join(root, catalogSnapshot);
  await mkdir(join(snapshot, '..'), { recursive: true });
  await writeFile(
    snapshot,
    `${JSON.stringify({ schema_version: catalog.schema_version, binaries: catalog.binaries }, null, 2)}\n`,
  );
  await writeFile(
    join(root, 'Cargo.toml'),
    `[workspace]\nmembers = []\n\n[workspace.package]\nversion = "${version}"\n`,
  );
  return root;
}

test('renders one linked page for every nested public command', () => {
  const pages = renderCatalog(fixtureCatalog(), fixtureReviewMetadata());
  assert.ok(pages.has('index.mdx'));
  assert.ok(pages.has('breg.mdx'));
  assert.ok(pages.has('bregctl.mdx'));
  assert.match(pages.get('index.mdx'), /Base Registry Engine/u);
  assert.ok(pages.has('evidencectl.mdx'));
  assert.ok(pages.has('evidencectl/tooling.mdx'));
  assert.ok(pages.has('evidencectl/tooling/editor.mdx'));
  assert.match(pages.get('index.mdx'), /\.\/evidencectl\//u);
  assert.match(pages.get('evidencectl.mdx'), /\.\/tooling\//u);
  assert.match(pages.get('evidencectl/tooling.mdx'), /\.\/editor\//u);
  assert.match(pages.get('evidencectl/tooling/editor.mdx'), /\| `-h, --help` \|/u);
  assert.match(
    pages.get('evidencectl.mdx'),
    /\{\/\* Generated from crates\/registry-cli-docs\/catalog\.json and the workspace version in Cargo\.toml /u,
  );
  // A command change reaches the pages through the committed catalog, so each
  // generation contract names the catalog regeneration before the docs one.
  for (const name of ['index.mdx', 'evidencectl.mdx']) {
    assert.match(
      pages.get(name),
      /run `cargo run --locked -p registry-cli-docs -- --write`, commit `crates\/registry-cli-docs\/catalog\.json`, then run `npm run generate` from `docs\/site`\./u,
    );
  }
  assert.match(
    pages.get('index.mdx'),
    /The `registry-cli-docs` snapshot test holds that catalog to the Clap definitions, and the docs check holds these pages to the catalog\./u,
  );
  assert.match(pages.get('evidencectl.mdx'), /status: draft\ndraft: true/u);
  assert.match(pages.get('evidencectl.mdx'), /last_reviewed: "unreviewed"/u);
  assert.match(pages.get('evidencectl.mdx'), /source version `0\.21\.0`/u);
  assert.doesNotMatch(pages.get('evidencectl.mdx'), /<!--/u);
});

test('wraps a docset-gated product group of the index in a DocsetProduct region', () => {
  const index = renderCatalog(fixtureCatalog(), fixtureReviewMetadata()).get('index.mdx');
  const region = index.match(
    /\n<DocsetProduct product="registry-messaging">\n([\s\S]*?)\n<\/DocsetProduct>\n/u,
  );
  assert.ok(region, 'the Registry Messaging group must sit in a DocsetProduct region');
  assert.match(region[1], /^## Registry Messaging$/mu);
  assert.match(region[1], /\(\.\/messaging\/\)/u);
  assert.match(region[1], /\(\.\/messagingctl\/\)/u);
  // Nothing else in the index names Messaging, so removing the region leaves
  // no trace of it in a docset that does not publish the product.
  assert.doesNotMatch(index.replace(region[0], '\n'), /messaging/iu);
  // Only gated groups are wrapped.
  assert.equal(index.match(/<DocsetProduct /gu).length, 2);
});

test('wraps the Base Registry Engine citizen gateway group of the index in a DocsetProduct region', () => {
  const index = renderCatalog(fixtureCatalog(), fixtureReviewMetadata()).get('index.mdx');
  const region = index.match(
    /\n<DocsetProduct product="registry-breg-services">\n([\s\S]*?)\n<\/DocsetProduct>\n/u,
  );
  assert.ok(region, 'the citizen gateway group must sit in a DocsetProduct region');
  assert.match(region[1], /^## Base Registry Engine citizen gateway$/mu);
  assert.match(region[1], /\(\.\/breg-mcp\/\)/u);
  assert.match(region[1], /\(\.\/breg-review\/\)/u);
  // The Base Registry Engine group itself stays published in every docset.
  const rest = index.replace(region[0], '\n');
  assert.match(rest, /^## Base Registry Engine$/mu);
  assert.doesNotMatch(rest, /breg-mcp|breg-review|citizen gateway/iu);
});

test('renders required groups and conditional requirements', () => {
  const catalog = fixtureCatalog();
  const evidencectl = catalog.binaries.find((binary) => binary.name === 'evidencectl');
  evidencectl.constraints.push(
    {
      kind: 'required-exactly-one',
      when: null,
      arguments: ['--left', '--right'],
    },
    {
      kind: 'requires-all',
      when: '--right',
      arguments: ['--detail'],
    },
    {
      kind: 'required-one-or-more',
      when: null,
      arguments: ['--scope', '--role'],
    },
    {
      kind: 'mutually-exclusive',
      when: null,
      arguments: ['--left', '--right'],
    },
  );
  const page = renderCatalog(catalog, fixtureReviewMetadata()).get('evidencectl.mdx');
  assert.match(page, /Exactly one of `--left`, `--right` is required\./u);
  assert.match(page, /One or more of `--scope`, `--role` are required\./u);
  assert.match(page, /`--right` is present \| `--detail` is required\./u);
  assert.match(page, /`--left` and `--right` cannot be used together\./u);
  assert.match(page, /Always required/u);
  assert.doesNotMatch(page, /Repeatable/u);
});

test('renders repeatable option cardinality', () => {
  const catalog = fixtureCatalog();
  const evidencectl = catalog.binaries.find((binary) => binary.name === 'evidencectl');
  evidencectl.options.push({
    ...argument('--attribute-column <COLUMN>'),
    repeatable: true,
  });

  const page = renderCatalog(catalog, fixtureReviewMetadata()).get('evidencectl.mdx');
  assert.match(page, /\| `--attribute-column <COLUMN>` \| No \| Yes \|/u);
  assert.match(page, /\| Option \| Always required \| Repeatable \|/u);
});

test('escapes MDX expression and JSX characters in help text outside code spans', () => {
  const catalog = fixtureCatalog();
  const evidencectl = catalog.binaries.find((binary) => binary.name === 'evidencectl');
  const tooling = evidencectl.subcommands.find((command) => command.name === 'tooling');
  evidencectl.about = 'Read {a} map before <b> applies';
  evidencectl.long_about = 'Fill ${NAME} values; a path\\{x} keeps its backslash';
  tooling.about = 'Write {x} and <y>';
  evidencectl.options.push({
    ...argument('--environment'),
    description: 'Fill ${NAME} values, written `${NAME}` or ``a `{b}` <c>``, unless a < b',
  });

  const pages = renderCatalog(catalog, fixtureReviewMetadata());
  const page = pages.get('evidencectl.mdx');
  assert.match(page, /^Read \\\{a\\\} map before \\<b> applies\.$/mu);
  assert.match(page, /^Fill \$\\\{NAME\\\} values; a path\\\\\\\{x\\\} keeps its backslash\.$/mu);
  assert.match(page, /\| \[`tooling`\]\(\.\/tooling\/\) \| Write \\\{x\\\} and \\<y> \|/u);
  assert.ok(
    page.includes(
      '| Fill $\\{NAME\\} values, written `${NAME}` or ``a `{b}` <c>``, unless a \\< b |',
    ),
    page,
  );
  assert.match(pages.get('index.mdx'), /\| \[`evidencectl`\]\(\.\/evidencectl\/\) \| Read \\\{a\\\} map before \\<b> applies \|/u);
  assert.match(pages.get('evidencectl/tooling.mdx'), /^Write \\\{x\\\} and \\<y>\.$/mu);
  // Every brace and angle bracket outside a code span carries its escape.
  for (const [name, contents] of pages) {
    const body = contents.split('\n---\n').slice(1).join('\n---\n');
    const prose = body
      .replace(/^\{\/\*.*\*\/\}$/gmu, '')
      .replace(/^<\/?DocsetProduct[^>]*>$/gmu, '')
      .replace(/```[\s\S]*?```/gu, '')
      .replace(/(`+)[\s\S]*?[^`]\1(?!`)/gu, '');
    assert.doesNotMatch(prose, /(?<!\\)[{}<]/u, name);
  }
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
    kind: 'mutually-exclusive',
    when: null,
    arguments: ['--right', '--left'],
  });
  assert.throws(() => validateCatalog(unsortedConflict), /distinct and sorted/u);
});

test('the review record controls publication without restating command content', () => {
  const catalog = fixtureCatalog();
  assert.throws(
    () => validateReviewMetadata(fixtureReviewMetadata({ status: 'current' })),
    /unreviewed CLI reference metadata must be draft/u,
  );
  const reviewed = fixtureReviewMetadata({ status: 'current', last_reviewed: '2026-08-13' });
  assert.equal(validateReviewMetadata(reviewed), reviewed);
  assert.throws(
    () => validateReviewMetadata({ ...reviewed, last_reviewed: '2026-02-30' }),
    /unreviewed or YYYY-MM-DD/u,
  );
  assert.throws(
    () => validateReviewMetadata({ ...reviewed, reviewed_catalog_sha256: 'a'.repeat(64) }),
    /must contain exactly last_reviewed, status/u,
  );
  const page = renderCatalog(catalog, reviewed).get('evidencectl.mdx');
  assert.match(page, /status: current/u);
  assert.match(page, /last_reviewed: "2026-08-13"/u);
  assert.match(page, /source version `0\.21\.0`/u);
  assert.ok(page.includes(catalogDigest(catalog)));
  assert.doesNotMatch(page, /^draft: true$/mu);
  assert.match(renderCatalog(catalog, { ...reviewed, status: 'draft' }).get('evidencectl.mdx'), /^draft: true$/mu);
});

test('the catalog joins the committed snapshot to the workspace version', async () => {
  const catalog = fixtureCatalog();
  const root = await fixtureRepository(catalog, '0.22.0');
  try {
    const loaded = await loadCatalog(root);
    assert.deepEqual(Object.keys(loaded), ['schema_version', 'source_version', 'binaries']);
    assert.equal(loaded.source_version, '0.22.0');
    assert.deepEqual(loaded.binaries, catalog.binaries);
    assert.equal(catalogDigest(loaded), catalogDigest({ ...catalog, source_version: '0.22.0' }));

    await writeFile(join(root, catalogSnapshot), JSON.stringify(catalog));
    await assert.rejects(loadCatalog(root), /snapshot must contain exactly binaries, schema_version/u);
    await rm(join(root, catalogSnapshot));
    await assert.rejects(loadCatalog(root), /registry-cli-docs\/catalog\.json could not be read/u);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('writes deterministic pages and detects local output drift', async () => {
  const root = await fixtureRepository(fixtureCatalog());
  const docsRoot = join(root, 'docs', 'site');
  try {
    await mkdir(join(docsRoot, 'src/data'), { recursive: true });
    await writeFile(
      join(docsRoot, 'src/data/cli-reference.yaml'),
      'status: draft\nlast_reviewed: unreviewed\n',
      'utf8',
    );
    await generateCliReference(docsRoot, root);
    await generateCliReference(docsRoot, root, { check: true });
    const evidencectl = join(
      docsRoot,
      'src/content/docs/reference/cli/evidencectl.mdx',
    );
    assert.match(await readFile(evidencectl, 'utf8'), /source version `0\.21\.0`/u);
    await writeFile(evidencectl, 'stale\n', 'utf8');
    await assert.rejects(
      generateCliReference(docsRoot, root, { check: true }),
      /is stale/u,
    );
    assert.match(await readFile(evidencectl, 'utf8'), /stale/u);

    // A version bump changes the stated version, not the reviewed snapshot.
    await generateCliReference(docsRoot, root);
    await writeFile(
      join(root, 'Cargo.toml'),
      '[workspace]\nmembers = []\n\n[workspace.package]\nversion = "0.22.0"\n',
    );
    await assert.rejects(
      generateCliReference(docsRoot, root, { check: true }),
      /is stale/u,
    );
    await generateCliReference(docsRoot, root);
    assert.match(await readFile(evidencectl, 'utf8'), /source version `0\.22\.0`/u);
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
