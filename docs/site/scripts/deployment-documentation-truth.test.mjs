import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { test } from 'node:test';

import YAML from 'yaml';

const siteRoot = resolve(import.meta.dirname, '..');
const repoRoot = resolve(siteRoot, '../..');

async function readRepo(relative) {
  return readFile(resolve(repoRoot, relative), 'utf8');
}

async function readYaml(relative) {
  return YAML.parse(await readRepo(relative));
}

test('current docs stay under /dev/ while v0.15.2 remains the released archive', async () => {
  const [docsets, repoDocs, generatedDocsets, readme] = await Promise.all([
    readYaml('docs/site/src/data/docsets.yaml'),
    readYaml('docs/site/src/data/repo-docs.yaml'),
    readRepo('docs/site/src/data/generated/docsets.json').then(JSON.parse),
    readRepo('README.md'),
  ]);
  assert.deepEqual(generatedDocsets, docsets, 'generated docset metadata must match its source');
  const current = docsets.docsets.find((docset) => docset.id === docsets.current);
  const released = docsets.docsets.find((docset) => docset.id === docsets.released);

  assert.equal(current.id, 'latest');
  assert.equal(docsets.released, 'v0.15.2');
  assert.equal(docsets.published_archive_limit, 3);
  assert.notEqual(docsets.current, docsets.released);
  assert.equal(current.label, 'Development (unreleased)');
  assert.equal(current.path, '/dev/');
  assert.equal(current.status, 'current');
  assert.equal(current.availability, 'unreleased');
  assert.equal(current.source, 'registry-stack-main');
  const readmeLines = new Set(readme.split(/\r?\n/));
  assert.equal(
    readmeLines.has(
      '| Serve a governed read-only API over a registry you hold | [Publish a governed SQLite registry](https://docs.registrystack.org/dev/tutorials/publish-governed-sqlite-registry/) |',
    ),
    true,
  );
  assert.equal(
    [...readmeLines].some((line) => line.includes('/start/pre-1.0-cutover/')),
    false,
  );
  assert.equal(
    current.description,
    'Unreleased Registry Stack documentation built from the main branch.',
  );
  for (const product of Object.values(current.products)) {
    assert.equal(product.ref, 'HEAD');
    assert.equal(product.version, 'main source (unreleased)');
    assert.doesNotMatch(product.version, /^v0\.15\.2$/);
  }

  for (const [repoId, repo] of Object.entries(repoDocs.repos)) {
    if (!Array.isArray(repo.docs) || repo.docs.length === 0) continue;
    assert.equal(repo.ref, 'HEAD', `${repoId} current docs must read main source`);
    assert.equal(
      repo.version,
      'main source (unreleased)',
      `${repoId} current docs must not inherit a crate release version`,
    );
  }

  assert.equal(released.path, '/v/0.15.2/');
  assert.equal(released.status, 'archived');
  assert.equal(released.availability, 'released');
  assert.equal(released.source, 'registry-stack-v0.15.2');
  assert.match(released.description, /^Released Registry Stack v0\.15\.2/);
  for (const [productId, product] of Object.entries(released.products)) {
    if (productId === 'crosswalk') continue;
    assert.equal(product.version, 'v0.15.2');
    assert.equal(
      product.ref,
      '5da961bf965cc9bb0e962db8bd3b6055459a0d97',
      `${productId} v0.15.2 docs must stay on the immutable prepared-source ref`,
    );
  }

  for (const docset of docsets.docsets) {
    if (docset.id === 'latest') continue;
    if (['v0.16.2', 'v0.16.1', 'v0.16.0'].includes(docset.id)) {
      assert.equal(docset.status, 'draft');
      assert.equal(docset.availability, 'failed');
      assert.match(docset.description, /failed-train record/);
      for (const [productId, product] of Object.entries(docset.products)) {
        if (productId === 'crosswalk') continue;
        assert.equal(product.ref, docset.id);
      }
      continue;
    }
    assert.equal(docset.status, 'archived', `${docset.id} must expose its release-train status`);
    const expectedAvailability =
      ['v0.23.0', 'v0.22.0', 'v0.21.0', 'v0.20.1', 'v0.20.0', 'v0.18.0', 'v0.17.0', 'v0.16.3', 'v0.15.1', 'v0.15.0'].includes(docset.id)
        ? 'candidate'
        : docset.id.startsWith('v')
          ? 'released'
          : 'candidate';
    assert.equal(
      docset.availability,
      expectedAvailability,
      `${docset.id} must expose release availability`,
    );
  }
});

test('current deployment recovery pages do not present draft procedures as supported paths', async () => {
  // Relay V2 retired the separate backup, restore, upgrade, and rollback pages,
  // so this guard no longer names them. Which operate pages claim current
  // status is the page owner's call; what must never happen is a page claiming
  // it while still carrying a draft disclaimer.
  const operateRoot = 'docs/site/src/content/docs/operate';
  const pages = (await readdir(resolve(repoRoot, operateRoot), { recursive: true }))
    .filter((name) => name.endsWith('.mdx'))
    .map((name) => `${operateRoot}/${name}`);

  assert.ok(pages.length > 0, `expected operate pages under ${operateRoot}`);
  for (const path of pages) {
    const source = await readRepo(path);
    if (!/^status: current$/m.test(source)) continue;
    assert.doesNotMatch(source, /This page is draft\./, path);
  }
});

test('glossary defers issue 361 without describing an implemented project-root bundle or coordinator', async () => {
  const glossary = await readRepo('docs/site/src/content/docs/reference/glossary.mdx');

  assert.match(
    glossary,
    /href="https:\/\/github\.com\/registrystack\/registry-stack\/issues\/361"/,
  );
  assert.match(glossary, /Current source does not generate, sign, verify, or activate a project-root bundle/);
  assert.match(glossary, /no Registry Stack coordinator binds or atomically activates them/);
  assert.match(glossary, /this is not atomic project activation/);
  assert.doesNotMatch(glossary, /root manifest binds compatible Relay and Notary/i);
  assert.doesNotMatch(glossary, /One activated deployment-bundle generation/i);
});
