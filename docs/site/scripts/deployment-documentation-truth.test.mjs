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

// Release manifests keyed by their exact source tag.
async function readReleaseManifests() {
  const directory = 'release/manifests';
  const names = (await readdir(resolve(repoRoot, directory)))
    .filter((name) => /^registry-stack-.*\.yaml$/.test(name));
  const manifests = new Map();
  for (const name of names) {
    const manifest = await readYaml(`${directory}/${name}`);
    manifests.set(manifest.stack.source_tag, manifest);
  }
  return manifests;
}

function releaseVersion(id) {
  return /^v(\d+)\.(\d+)\.(\d+)$/.exec(id)?.slice(1).map(Number) ?? null;
}

function compareVersions(left, right) {
  for (let index = 0; index < left.length; index += 1) {
    if (left[index] !== right[index]) return left[index] - right[index];
  }
  return 0;
}

test('current docs stay under /dev/ while the newest published release is the released archive', async () => {
  const [docsets, repoDocs, generatedDocsets, readme, manifests] = await Promise.all([
    readYaml('docs/site/src/data/docsets.yaml'),
    readYaml('docs/site/src/data/repo-docs.yaml'),
    readRepo('docs/site/src/data/generated/docsets.json').then(JSON.parse),
    readRepo('README.md'),
    readReleaseManifests(),
  ]);
  assert.deepEqual(generatedDocsets, docsets, 'generated docset metadata must match its source');
  const current = docsets.docsets.find((docset) => docset.id === docsets.current);
  const released = docsets.docsets.find((docset) => docset.id === docsets.released);
  const superseded = docsets.docsets.find((docset) => docset.id === 'v0.25.0');

  assert.equal(current.id, 'latest');
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
      '| Serve governed record APIs from PostgreSQL | [Create and query your first registry](https://docs.registrystack.org/dev/tutorials/first-breg/) |',
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
    assert.doesNotMatch(product.version, /^v\d+\.\d+\.\d+$/);
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

  // The released selector names a published release: its manifest records
  // the release as published, and its docs stay on the immutable commit the
  // release tag dereferences to.
  const releasedVersion = releaseVersion(released.id);
  const releasedManifest = manifests.get(released.id);
  assert.ok(releasedVersion, `released selector ${released.id} must name a release tag`);
  assert.ok(releasedManifest, `released selector ${released.id} must have a release manifest`);
  assert.equal(releasedManifest.stack.status, 'released');
  assert.match(releasedManifest.stack.source_ref, /^[0-9a-f]{40}$/);
  assert.equal(released.path, `/v/${releasedVersion.join('.')}/`);
  assert.equal(released.status, 'archived');
  assert.equal(released.availability, 'released');
  assert.equal(released.source, `registry-stack-${released.id}`);
  assert.ok(
    released.description.startsWith(`Released Registry Stack ${released.id} `),
    `${released.id} description must say it is released`,
  );
  for (const [productId, product] of Object.entries(released.products)) {
    if (productId === 'crosswalk') continue;
    assert.equal(product.version, released.id);
    assert.equal(
      product.ref,
      releasedManifest.stack.source_ref,
      `${productId} ${released.id} docs must stay on the immutable prepared-source ref`,
    );
  }

  // The selector keeps up with publication. Release preparation adds one
  // candidate docset ahead of the selector and never moves the selector, so
  // at most that one prepared candidate may be newer than it. A second newer
  // docset means a published release was never promoted, and development
  // pages would name an old release as the supported one.
  const versioned = docsets.docsets
    .filter((docset) => releaseVersion(docset.id) && docset.availability !== 'failed')
    .sort((left, right) => compareVersions(releaseVersion(right.id), releaseVersion(left.id)));
  const ahead = versioned.filter(
    (docset) => compareVersions(releaseVersion(docset.id), releasedVersion) > 0,
  );
  assert.ok(
    ahead.length <= 1,
    `released selector ${released.id} is behind ${ahead.map((docset) => docset.id).reverse().join(', ')}; ` +
      'promote each published release (release/OPERATIONS.md, "Promote the published documentation")',
  );
  for (const docset of ahead) {
    assert.equal(docset.id, versioned[0].id, `${docset.id} must be the newest prepared docset`);
    assert.equal(docset.availability, 'candidate', `${docset.id} must still be a candidate`);
  }
  const newestReleasedManifest = versioned
    .filter((docset) => manifests.get(docset.id)?.stack.status === 'released')[0];
  assert.equal(
    docsets.released,
    newestReleasedManifest?.id,
    'released selector must name the newest release whose manifest records it as released',
  );

  // A superseded release keeps the archive it published. Promoting a newer
  // selector must not rewrite an older docset's tree.
  assert.equal(superseded.path, '/v/0.25.0/');
  assert.equal(superseded.status, 'archived');
  assert.equal(superseded.availability, 'released');
  assert.equal(superseded.source, 'registry-stack-v0.25.0');
  assert.match(superseded.description, /^Released Registry Stack v0\.25\.0/);
  for (const [productId, product] of Object.entries(superseded.products)) {
    if (productId === 'crosswalk') continue;
    assert.equal(product.version, 'v0.25.0');
    assert.equal(
      product.ref,
      '6e662d66ab1278b81396c0827538bc58b0abe224',
      `${productId} v0.25.0 docs must stay on the immutable prepared-source ref`,
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
    // A release manifest that records publication makes its docset released.
    // Older docsets whose manifests record no status keep the availability
    // they were archived with; pre-semantic-version docsets are candidates.
    if (!releaseVersion(docset.id)) {
      assert.equal(docset.availability, 'candidate', `${docset.id} must expose release availability`);
    } else if (manifests.get(docset.id)?.stack.status === 'released') {
      assert.equal(docset.availability, 'released', `${docset.id} must expose release availability`);
    } else {
      assert.ok(
        ['released', 'candidate'].includes(docset.availability),
        `${docset.id} must expose release availability`,
      );
    }
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
