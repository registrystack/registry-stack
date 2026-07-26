import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { test } from 'node:test';
import { promisify } from 'node:util';

import {
  diagnosticCatalogs,
  validateDiagnosticReference,
} from './generate-diagnostic-references.mjs';

const siteRoot = resolve(import.meta.dirname, '..');
const repoRoot = resolve(siteRoot, '../..');
const execFileAsync = promisify(execFile);
const expectedCounts = {
  authoring: 17,
  fixture: 16,
  operator: 59,
};

async function artifactBytes(catalog) {
  const contract = diagnosticCatalogs[catalog];
  return Promise.all([
    readFile(resolve(siteRoot, contract.internal), 'utf8'),
    readFile(resolve(siteRoot, contract.public), 'utf8'),
    readFile(resolve(repoRoot, contract.fixture), 'utf8'),
  ]);
}

async function executableBytes(catalog) {
  const { stdout } = await execFileAsync(
    'cargo',
    [
      'run',
      '--locked',
      '--quiet',
      '-p',
      'registryctl',
      '--',
      'project',
      'diagnostics',
      '--catalog',
      catalog,
      '--format',
      'json',
    ],
    {
      cwd: repoRoot,
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
    },
  );
  return stdout;
}

test('committed diagnostic artifacts are strict and byte-identical at every publication point', async () => {
  for (const catalog of Object.keys(diagnosticCatalogs)) {
    const [internal, publicArtifact, registryctlFixture] = await artifactBytes(catalog);
    assert.equal(publicArtifact, internal);
    assert.equal(registryctlFixture, internal);

    const reference = JSON.parse(internal);
    validateDiagnosticReference(catalog, reference);
    assert.equal(reference.entries.length, expectedCounts[catalog]);
    assert.ok(
      reference.entries.every(
        (entry) => entry.lifecycle === 'unreleased' && entry.introduced_in === null,
      ),
      `${catalog} must not attribute newly introduced codes to an older release`,
    );
    if (catalog === 'operator') {
      assert.deepEqual(reference.omissions, []);
    }
  }
});

test('committed diagnostic artifacts are byte-exact to the registryctl executable', async () => {
  for (const catalog of Object.keys(diagnosticCatalogs)) {
    const first = await executableBytes(catalog);
    const second = await executableBytes(catalog);
    assert.equal(
      second,
      first,
      `${catalog} registryctl diagnostic output is not byte deterministic`,
    );
    const [internal, publicArtifact, registryctlFixture] = await artifactBytes(catalog);
    assert.equal(internal, first, `${catalog} internal reference drifted from registryctl`);
    assert.equal(publicArtifact, first, `${catalog} public reference drifted from registryctl`);
    assert.equal(
      registryctlFixture,
      first,
      `${catalog} registryctl fixture drifted from its executable`,
    );

    const reference = JSON.parse(first);
    validateDiagnosticReference(catalog, reference);
    assert.ok(
      reference.entries.every(
        (entry) => entry.lifecycle === 'unreleased' && entry.introduced_in === null,
      ),
      `${catalog} executable must not attribute unreleased codes to an older release`,
    );
  }
});

test('every machine docs anchor resolves to its catalog page and generated component id', async () => {
  const component = await readFile(
    resolve(siteRoot, 'src/components/DiagnosticReference.astro'),
    'utf8',
  );
  assert.match(
    component,
    /const anchorId = \(entry: Entry\) => entry\.docs_anchor\.split\('#', 2\)\[1\]/,
  );
  assert.match(component, /id=\{anchorId\(entry\)\}/);

  for (const catalog of Object.keys(diagnosticCatalogs)) {
    const [bytes] = await artifactBytes(catalog);
    const reference = JSON.parse(bytes);
    const pagePath = resolve(
      siteRoot,
      'src/content/docs/reference/diagnostics',
      `${catalog}.mdx`,
    );
    const page = await readFile(pagePath, 'utf8');
    assert.match(page, new RegExp(`catalog="${catalog}"`));
    for (const entry of reference.entries) {
      const [route, id] = entry.docs_anchor.split('#');
      assert.equal(route, `/reference/diagnostics/${catalog}/`);
      assert.match(id, new RegExp(`^${entry.product}--[a-z0-9._-]+$`));
    }
  }
});

test('published diagnostic pages state the pure CLI and evidence boundaries', async () => {
  const pages = await Promise.all(
    Object.keys(diagnosticCatalogs).map((catalog) =>
      readFile(
        resolve(
          siteRoot,
          'src/content/docs/reference/diagnostics',
          `${catalog}.mdx`,
        ),
        'utf8',
      ),
    ),
  );
  const source = pages.join('\n');
  assert.doesNotMatch(source, /\/reference\/registryctl\/(?:authoring-diagnostics|fixture-errors|preflight-errors)\//);
  assert.match(source, /registryctl project diagnostics --catalog authoring --format json/);
  assert.match(source, /registryctl project diagnostics --catalog fixture --format json/);
  assert.match(source, /registryctl project diagnostics --catalog operator --format json/);
  assert.match(source, /does not open a country project/);
  assert.match(source, /do not disclose the received configuration/);
  assert.doesNotMatch(
    source,
    /COUNTRY_(?:SECRET|VALUE)_SENTINEL|BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY/,
  );
});
