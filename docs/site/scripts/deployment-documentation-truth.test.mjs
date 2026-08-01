import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
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

const currentActivationPages = [
  'products/notary/docs/configuration-trust-and-integrity.md',
  'products/notary/docs/operator-config-reference.md',
  'products/notary/docs/deployment-hardening-runbook.md',
];

test('current docs stay under /dev/ while v0.15.2 is the released archive', async () => {
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
  assert.notEqual(docsets.current, docsets.released);
  assert.equal(current.label, 'Development (unreleased)');
  assert.equal(current.path, '/dev/');
  assert.equal(current.status, 'current');
  assert.equal(current.availability, 'unreleased');
  assert.equal(current.source, 'registry-stack-main');
  const readmeLines = new Set(readme.split(/\r?\n/));
  assert.equal(
    readmeLines.has(
      '| Build and run the maintained HTTP project | [Registry Stack 1.0 first run](https://docs.registrystack.org/dev/tutorials/author-registry-project/) |',
    ),
    true,
  );
  assert.equal(
    readmeLines.has(
      '| Move a pre-1.0 project | [Pre-1.0 cutover](https://docs.registrystack.org/dev/start/pre-1.0-cutover/) |',
    ),
    true,
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
    assert.equal(docset.status, 'archived', `${docset.id} must expose its release-train status`);
    const expectedAvailability =
      ['v0.16.1', 'v0.16.0', 'v0.15.1', 'v0.15.0'].includes(docset.id)
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
  for (const path of [
    'docs/site/src/content/docs/operate/backup-and-restore.mdx',
    'docs/site/src/content/docs/operate/upgrade-and-rollback.mdx',
  ]) {
    const source = await readRepo(path);
    assert.match(source, /^status: current$/m, path);
    assert.doesNotMatch(source, /This page is draft\./, path);
  }
});

test('current combined-topology pages require separate product bundles and compatible staged admission', async () => {
  const pages = await Promise.all(
    currentActivationPages.map(async (path) => [path, await readRepo(path)]),
  );

  for (const [path, source] of pages) {
    assert.match(
      source,
      /(?:separate product bundles|product bundles separately|separately[\s\S]{0,100}product bundles)/i,
      path,
    );
    assert.match(source, /anti-rollback/i, path);
    assert.match(source, /not atomic project activation/i, path);
    assert.match(source, /Relay[\s\S]{0,160}without admitting\s+caller traffic/i, path);
    assert.match(source, /health[\s\S]{0,120}readiness[\s\S]{0,120}audit[\s\S]{0,120}posture/i, path);
    assert.match(source, /Notary[\s\S]{0,180}(?:Relay|consultation) contract/i, path);
    assert.match(source, /admit caller traffic only (?:after|when) both products are ready/i, path);
    assert.match(source, /contract mismatch[\s\S]{0,100}before source access/i, path);

    for (const staleClaim of [
      /combined generation must activate[\s\S]*atomically/i,
      /activate Relay and Notary as one compatible project generation/i,
      /stage a complete Relay and Notary generation/i,
      /activate one complete generation/i,
      /root manifest binds compatible Relay and Notary/i,
    ]) {
      assert.doesNotMatch(source, staleClaim, `${path} reintroduced ${staleClaim}`);
    }
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
