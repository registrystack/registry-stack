import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import * as tar from 'tar';
import {
  packageExamples,
  exampleFiles,
  packageSourceRecipes,
  sourceRecipeFiles,
} from './generate-evidence-examples.mjs';

test('examples archive is repeatable and contains only reviewed inputs', async () => {
  const root = await mkdtemp(join(tmpdir(), 'evidence-examples-archive-'));
  try {
    for (const path of exampleFiles) {
      await mkdir(dirname(join(root, path)), { recursive: true });
      await writeFile(join(root, path), `reviewed ${path}\n`);
    }
    await mkdir(join(root, 'standalone/.generated/secrets'), { recursive: true });
    await writeFile(join(root, 'standalone/.generated/secrets/signing-key'), 'MUST NOT BE PACKAGED');
    await mkdir(join(root, 'standalone/__pycache__'), { recursive: true });
    await writeFile(join(root, 'standalone/__pycache__/serve-source.cpython-311.pyc'), 'MUST NOT BE PACKAGED');
    await packageExamples(root, join(root, 'first.tar.gz'));
    await packageExamples(root, join(root, 'second.tar.gz'));
    assert.deepEqual(await readFile(join(root, 'first.tar.gz')), await readFile(join(root, 'second.tar.gz')));
    const entries = [];
    await tar.list({ file: join(root, 'first.tar.gz'), onReadEntry: entry => { entries.push(entry.path); entry.resume(); } });
    assert.deepEqual(entries, exampleFiles);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('the inventory names every file of the maintained example projects', async () => {
  const site = join(dirname(new URL(import.meta.url).pathname), '..');
  const examples = join(site, '../../products/evidence/examples');
  const { readdir } = await import('node:fs/promises');
  const found = [];
  for (const project of ['fhir', 'standalone']) {
    for (const entry of await readdir(join(examples, project), { recursive: true, withFileTypes: true })) {
      if (!entry.isFile()) continue;
      const relative = join(entry.parentPath, entry.name).slice(examples.length + 1);
      if (relative.includes('/.generated/') || relative.includes('/.evidence/') || relative.includes('/__pycache__/')) continue;
      found.push(relative);
    }
  }
  assert.deepEqual(found.sort(), exampleFiles);
});

test('source recipes archive is repeatable and excludes private local state', async () => {
  const root = await mkdtemp(join(tmpdir(), 'evidence-source-recipes-archive-'));
  try {
    for (const path of sourceRecipeFiles) {
      await mkdir(dirname(join(root, path)), { recursive: true });
      await writeFile(join(root, path), `reviewed ${path}\n`);
    }
    await mkdir(join(root, 'dhis2-tracker/fixture-validation/.evidence/source-imports'), { recursive: true });
    await writeFile(join(root, 'dhis2-tracker/fixture-validation/.evidence/source-imports/state.json'), 'MUST NOT BE PACKAGED');
    await mkdir(join(root, 'opencrvs-event-search/fixture-validation/.generated/secrets'), { recursive: true });
    await writeFile(join(root, 'opencrvs-event-search/fixture-validation/.generated/secrets/client-secret'), 'MUST NOT BE PACKAGED');

    await packageSourceRecipes(root, join(root, 'first.tar.gz'));
    await packageSourceRecipes(root, join(root, 'second.tar.gz'));
    assert.deepEqual(await readFile(join(root, 'first.tar.gz')), await readFile(join(root, 'second.tar.gz')));
    const entries = [];
    await tar.list({ file: join(root, 'first.tar.gz'), onReadEntry: entry => { entries.push(entry.path); entry.resume(); } });
    assert.deepEqual(entries, sourceRecipeFiles);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('the source recipe inventory names every maintained recipe file', async () => {
  const site = join(dirname(new URL(import.meta.url).pathname), '..');
  const recipes = join(site, '../../products/evidence/source-recipes');
  const { readdir } = await import('node:fs/promises');
  const found = [];
  for (const entry of await readdir(recipes, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const relative = join(entry.parentPath, entry.name).slice(recipes.length + 1);
    if (relative.includes('/.generated/') || relative.includes('/.evidence/') || relative.includes('/__pycache__/')) continue;
    found.push(relative);
  }
  assert.deepEqual(found.sort(), sourceRecipeFiles);
});

test('downloaded projects expose pack acquisition without retired source scripts', () => {
  const retiredExamples = [
    'standalone/functions/extract-licence.rhai',
    'standalone/functions/extract-parents.rhai',
    'standalone/functions/extract-person.rhai',
  ];
  const retiredRecipes = [
    'dhis2-tracker/adapters/dhis2-tracker-extract.rhai',
    'dhis2-tracker/adapters/dhis2-tracker-prepare.rhai',
    'dhis2-tracker/fixture-validation/functions/validation-seed-extract.rhai',
    'opencrvs-event-search/adapters/opencrvs-event-search-extract.rhai',
    'opencrvs-event-search/adapters/opencrvs-event-search-prepare.rhai',
    'opencrvs-event-search/fixture-validation/functions/validation-seed-extract.rhai',
  ];
  for (const file of retiredExamples) assert.ok(!exampleFiles.includes(file), file);
  for (const file of retiredRecipes) assert.ok(!sourceRecipeFiles.includes(file), file);
  assert.ok(exampleFiles.includes('standalone/adapter-packs/synthetic-register/scripts/lookup.rhai'));
  for (const recipe of ['dhis2-tracker', 'opencrvs-event-search']) {
    assert.ok(sourceRecipeFiles.includes(`${recipe}/adapter-packs/${recipe}/scripts/source-recipe.rhai`));
    assert.ok(sourceRecipeFiles.includes(`${recipe}/fixture-validation/adapter-packs/validation-seed/scripts/lookup.rhai`));
  }
});
