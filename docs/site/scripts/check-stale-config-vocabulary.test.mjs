import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);
const scriptDir = dirname(fileURLToPath(import.meta.url));
const gate = resolve(scriptDir, 'check-stale-config-vocabulary.sh');

async function runGate(root) {
  try {
    const { stdout, stderr } = await execFileAsync('bash', [gate], {
      env: { ...process.env, CONFIG_VOCABULARY_ROOT: root },
    });
    return { code: 0, output: `${stdout}${stderr}` };
  } catch (error) {
    return { code: error.code ?? 1, output: `${error.stdout}${error.stderr}` };
  }
}

// Build a minimal docs-site tree. `pages` maps a path relative to the tree
// root to its contents; `baseline` lists the pending-rewrite page paths.
async function withFixture({ pages = {}, baseline = [] }, check) {
  const root = await mkdtemp(join(tmpdir(), 'config-vocabulary-'));
  try {
    await mkdir(join(root, 'src/content/docs'), { recursive: true });
    await mkdir(join(root, 'src/data'), { recursive: true });
    await mkdir(join(root, 'scripts'), { recursive: true });
    await writeFile(join(root, 'README.md'), '# Fixture\n');
    await writeFile(
      join(root, 'scripts/check-stale-config-vocabulary.baseline'),
      `# fixture baseline\n${baseline.map((page) => `${page} # PR 2\n`).join('')}`,
    );
    for (const [page, text] of Object.entries(pages)) {
      await mkdir(dirname(join(root, page)), { recursive: true });
      await writeFile(join(root, page), text);
    }
    await check(root);
  } finally {
    await rm(root, { recursive: true });
  }
}

const bregPage = 'src/content/docs/configure/breg-access.mdx';

test('a clean tree passes', async () => {
  await withFixture({ pages: { [bregPage]: 'A profile grants a Record type.\n' } }, async (root) => {
    const result = await runGate(root);
    assert.equal(result.code, 0, result.output);
  });
});

test('a retired word on a BReg page outside the baseline fails', async () => {
  await withFixture(
    { pages: { [bregPage]: 'Intro.\nEach entity has fields.\n' } },
    async (root) => {
      const result = await runGate(root);
      assert.equal(result.code, 1, result.output);
      assert.match(result.output, /configure\/breg-access\.mdx:2: Each entity has fields\./u);
      assert.match(result.output, /retired vocabulary found outside the pending-rewrite baseline/u);
    },
  );
});

test('a retired spelling refused on every page fails on a non-BReg page', async () => {
  await withFixture(
    { pages: { 'src/content/docs/start/casework.mdx': 'Call `createChangeRequest` first.\n' } },
    async (root) => {
      const result = await runGate(root);
      assert.equal(result.code, 1, result.output);
      assert.match(result.output, /start\/casework\.mdx:1:/u);
    },
  );
});

test('a retired word on a baselined page passes with a reported count', async () => {
  await withFixture(
    {
      pages: { [bregPage]: 'Each entity has fields.\nA change request waits.\nClean line.\n' },
      baseline: [bregPage],
    },
    async (root) => {
      const result = await runGate(root);
      assert.equal(result.code, 0, result.output);
      assert.match(
        result.output,
        /pending rewrite: src\/content\/docs\/configure\/breg-access\.mdx: 2 line\(s\) with retired vocabulary/u,
      );
    },
  );
});

test('a clean baselined page is reported as removable and passes', async () => {
  await withFixture(
    { pages: { [bregPage]: 'A Record type has fields.\n' }, baseline: [bregPage] },
    async (root) => {
      const result = await runGate(root);
      assert.equal(result.code, 0, result.output);
      assert.match(result.output, /breg-access\.mdx: clean; remove it from the baseline/u);
    },
  );
});

test('allowances pass on BReg and cross-product pages', async () => {
  await withFixture(
    {
      pages: {
        'src/content/docs/reference/breg-api.mdx': [
          '| `meta.entityTypeIdentifier` | string | The Record type identifier. |',
          '`etag` is the strong entity tag a later patch must present.',
          'See [Actions and Proposals](../../configure/breg-change-control/).',
          '{/* Evidence: crates/registry-breg/src/compiler.rs, compile_entities() */}',
          'A DHIS2 `trackedEntity` and its `tracked_entity_id` selector.',
          '',
        ].join('\n'),
        'src/content/docs/tutorials/verify-a-registered-parent-with-opencrvs.mdx': [
          'OpenCRVS returns the registered entity and its `trackingId`.',
          '  --data-binary @.evidence/requests/opencrvs-parent/request.json \\',
          '',
        ].join('\n'),
        'src/content/docs/explanation/disclosure-modes-and-computed-answers.mdx':
          'The `audience-scoped-entity-reference` value form identifies a related entity.\n',
      },
    },
    async (root) => {
      const result = await runGate(root);
      assert.equal(result.code, 0, result.output);
    },
  );
});

test('retired type names in camel case fail on any page', async () => {
  for (const name of ['ChangeRequest', 'BRegLifecycleAction', 'BRegLifecycleAuthority']) {
    await withFixture(
      { pages: { 'src/content/docs/reference/client-api.mdx': `The \`${name}\` type.\n` } },
      async (root) => {
        const result = await runGate(root);
        assert.equal(result.code, 1, result.output);
        assert.match(result.output, new RegExp(name));
      },
    );
  }
});

test('retired Evidence and Casework spellings fail on any page', async () => {
  const lines = {
    'src/content/docs/start/evidence.mdx': 'Open the authoring workspace.\n',
    'src/content/docs/explanation/how-evidence-works.mdx': 'Each definition answers one bounded question.\n',
    'src/content/docs/explanation/how-casework-works.mdx': 'Casework owns the review round.\n',
  };
  for (const [page, text] of Object.entries(lines)) {
    await withFixture({ pages: { [page]: text } }, async (root) => {
      const result = await runGate(root);
      assert.equal(result.code, 1, result.output);
      assert.match(result.output, new RegExp(`${page.replace(/[./]/gu, '\\$&')}:1:`, 'u'));
    });
  }
});

test('an approved specification page keeps the words it was approved with', async () => {
  await withFixture(
    { pages: { 'src/content/docs/spec/rs-arc-g.mdx': 'Casework holds one review round.\n' } },
    async (root) => {
      const result = await runGate(root);
      assert.equal(result.code, 0, result.output);
    },
  );
});

test('the existing stale configuration patterns still fail', async () => {
  await withFixture(
    { pages: { 'src/content/docs/reference/evidence-configuration.mdx': 'Set `webhook.destinationId`.\n' } },
    async (root) => {
      const result = await runGate(root);
      assert.equal(result.code, 1, result.output);
      assert.match(result.output, /stale config vocabulary found/u);
    },
  );
});
