// Guards product release-note pages and registryctl changelog sections from
// drifting behind the shipped release headings.

import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { test } from 'node:test';
import { parse } from 'yaml';

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(here, '../../..');

const productReleaseNotes = [
  {
    name: 'Registry Relay',
    changelog: 'crates/registry-relay/CHANGELOG.md',
    releaseNotes: 'crates/registry-relay/docs/release-notes.md',
  },
  {
    name: 'Registry Manifest',
    changelog: 'products/manifest/CHANGELOG.md',
    releaseNotes: 'products/manifest/docs/release-notes.md',
  },
  {
    name: 'Registry Notary',
    changelog: 'products/notary/CHANGELOG.md',
    releaseNotes: 'products/notary/docs/release-notes.md',
  },
];

function readRepoFile(path) {
  return readFileSync(resolve(repoRoot, path), 'utf8');
}

function headingVersions(markdown) {
  const versions = [];
  const heading = /^##\s+(?:\[)?v?([0-9]+\.[0-9]+\.[0-9]+)(?:\])?(?:\s|$)/gm;
  for (const match of markdown.matchAll(heading)) {
    versions.push(match[1]);
  }
  return versions;
}

function compareSemver(left, right) {
  const leftParts = left.split('.').map(Number);
  const rightParts = right.split('.').map(Number);
  for (let index = 0; index < 3; index += 1) {
    if (leftParts[index] !== rightParts[index]) {
      return leftParts[index] - rightParts[index];
    }
  }
  return 0;
}

function newestVersion(versions, label) {
  assert.ok(versions.length > 0, `${label} must contain at least one released version heading`);
  return versions.toSorted(compareSemver).at(-1);
}

function latestStackReleaseVersion() {
  const versions = readdirSync(resolve(repoRoot, 'release/notes'))
    .map((name) => /^v([0-9]+\.[0-9]+\.[0-9]+)[.]md$/.exec(name)?.[1])
    .filter(Boolean);
  return newestVersion(versions, 'release/notes');
}

function latestStackManifest() {
  const version = latestStackReleaseVersion();
  const manifests = readdirSync(resolve(repoRoot, 'release/manifests'))
    .filter((name) => /^registry-stack-.+[.]yaml$/.test(name))
    .map((name) => parse(readRepoFile(`release/manifests/${name}`)))
    .filter((manifest) => manifest?.stack?.version === version);

  assert.equal(manifests.length, 1, `expected one release manifest for ${version}`);
  return manifests[0];
}

test('product release notes track newest released changelog headings', () => {
  for (const product of productReleaseNotes) {
    const newestChangelog = newestVersion(
      headingVersions(readRepoFile(product.changelog)),
      `${product.name} changelog`,
    );
    const newestReleaseNotes = newestVersion(
      headingVersions(readRepoFile(product.releaseNotes)),
      `${product.name} release notes`,
    );

    assert.equal(
      newestReleaseNotes,
      newestChangelog,
      `${product.name} release notes must include changelog version ${newestChangelog}`,
    );
  }
});

test('registryctl changelog tracks the latest stack release', () => {
  const newestRegistryctl = newestVersion(
    headingVersions(readRepoFile('crates/registryctl/CHANGELOG.md')),
    'registryctl changelog',
  );

  assert.equal(
    newestRegistryctl,
    latestStackReleaseVersion(),
    'registryctl changelog must carry a section for the latest stack release',
  );
});

test('a hosted-held release does not claim completed current Solmara smoke evidence', () => {
  const manifest = latestStackManifest();
  const hostedHeld = manifest.warnings?.some(
    (warning) => warning.code === 'hosted-publication-held',
  );
  if (!hostedHeld) {
    return;
  }

  const publicEvidenceData = [
    readRepoFile('docs/site/src/data/contracts.yaml'),
    readRepoFile('docs/site/src/data/standards.yaml'),
  ].join('\n');

  assert.doesNotMatch(publicEvidenceData, /Solmara Lab checks the (?:current )?hosted/);
  assert.match(
    publicEvidenceData,
    /hosted evidence remains pending until the lab is[\s\S]*repinned to published v[0-9]+[.][0-9]+[.][0-9]+ digests/,
  );
});
