import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { test } from 'node:test';
import YAML from 'yaml';

import { docsetPublishesBregOpenApi, docsetPublishesEvidenceOid4vciOpenApi } from './fetch-openapi.mjs';

const run = promisify(execFile);
const fetchOpenapi = resolve(import.meta.dirname, 'fetch-openapi.mjs');
const caseworkPath = 'products/casework/generated/registry-casework.openapi.json';
const discoveryPath = 'crates/registry-discovery/openapi.json';
const evidencePath = 'products/evidence/generated/registry-evidence.openapi.json';
const oid4vciPath = 'products/evidence/generated/registry-evidence-oid4vci.openapi.json';
const bregPath = 'products/breg/generated/facility/generated/openapi.json';

function docset(id, availability, evidenceRef, caseworkRef) {
  const products = {
    'registry-evidence': { version: id === 'latest' ? 'main source' : id, ref: evidenceRef },
  };
  if (caseworkRef) {
    products['registry-casework'] = { version: id === 'latest' ? 'main source' : id, ref: caseworkRef };
  }
  return {
    id,
    label: id,
    path: id === 'latest' ? '/dev/' : `/v/${id.slice(1)}/`,
    status: id === 'latest' ? 'current' : 'archived',
    availability,
    source: id,
    published_at: '2026-09-12',
    description: id,
    ...(id === 'v0.30.0' && availability === 'candidate' ? { repo_docs_source: 'monorepo' } : {}),
    products,
  };
}

test('Discovery OpenAPI comes from the independently selected unit tag', async () => {
  const source = await mkdtemp(join(tmpdir(), 'discovery-openapi-source-'));
  const root = join(source, 'docs/site');
  const data = join(root, 'src/data');
  const output = join(root, 'openapi/registry-discovery.openapi.json');
  try {
    await mkdir(join(source, 'crates/registry-discovery'), { recursive: true });
    await mkdir(join(source, 'products/evidence/generated'), { recursive: true });
    await mkdir(join(source, 'products/breg/generated/facility/generated'), { recursive: true });
    await mkdir(data, { recursive: true });
    await run('git', ['init', '--quiet', source]);
    await writeFile(join(source, discoveryPath), '{"info":{"version":"selected"}}\n');
    await writeFile(join(source, evidencePath), '{"info":{"version":"evidence"}}\n');
    await writeFile(join(source, oid4vciPath), '{"info":{"version":"oid4vci"}}\n');
    await writeFile(join(source, bregPath), '{"info":{"version":"breg"}}\n');
    await run('git', ['-C', source, 'add', '.']);
    await run('git', ['-C', source, '-c', 'user.name=Docs Test',
      '-c', 'user.email=docs-test@example.invalid', 'commit', '--quiet', '-m', 'discovery release']);
    await run('git', ['-C', source, 'tag', 'discovery/v1.4.2']);
    const { stdout } = await run('git', ['-C', source, 'rev-parse', 'HEAD']);
    const releasedRef = stdout.trim();
    await writeFile(join(source, discoveryPath), '{"info":{"version":"ambient-stack"}}\n');

    await writeFile(join(data, 'repo-docs.yaml'), YAML.stringify({ repos: {
      'registry-discovery': {
        ref: 'HEAD', local: '../..', remote: source, openapi: discoveryPath,
      },
      'registry-evidence': {
        ref: 'HEAD', local: '../..', remote: source, openapi: evidencePath,
        docs: [{ src: 'README.md' }],
      },
    } }));
    const latest = docset('latest', 'unreleased', 'HEAD');
    const stackProduct = (version, ref) => ({ version, ref });
    await writeFile(join(data, 'docsets.yaml'), YAML.stringify({
      current: 'latest',
      released: 'v1.0.0',
      published_archive_limit: 3,
      docsets: [
        { ...latest, products: { ...latest.products,
          'registry-stack': stackProduct('main source', 'HEAD'),
          'registry-discovery': stackProduct('main source', 'HEAD') } },
        { ...docset('v1.0.0', 'released', releasedRef), products: {
          ...docset('v1.0.0', 'released', releasedRef).products,
          'registry-stack': stackProduct('v1.0.0', releasedRef) } },
        { ...docset('v2.0.0', 'candidate', 'v2.0.0'), repo_docs_source: 'monorepo',
          products: {
            ...docset('v2.0.0', 'candidate', 'v2.0.0').products,
            'registry-stack': stackProduct('v2.0.0', 'v2.0.0'),
            'registry-discovery': stackProduct('v1.4.2', 'discovery/v1.4.2') } },
      ],
    }));

    const { stdout: log } = await run(process.execPath, [fetchOpenapi], {
      cwd: root,
      env: { ...process.env, DOCS_DOCSET: 'v2.0.0' },
    });

    assert.equal(JSON.parse(await readFile(output, 'utf8')).info.version, 'selected');
    assert.equal(
      JSON.parse(await readFile(
        join(root, 'openapi/registry-discovery.render.openapi.json'),
        'utf8',
      )).info.version,
      'selected',
    );
    assert.match(log, /Fetched registry-discovery OpenAPI spec at discovery\/v1 \(clone\)/);
  } finally {
    await rm(source, { recursive: true, force: true });
  }
});

test('Casework OpenAPI follows current HEAD, excludes v0.29, and pins v0.30 archives', async () => {
  const root = await mkdtemp(join(tmpdir(), 'casework-openapi-refs-'));
  const source = join(root, 'source');
  const data = join(root, 'src/data');
  const output = join(root, 'openapi/registry-casework.openapi.json');
  const renderedOutput = join(root, 'openapi/registry-casework.render.openapi.json');
  const bregOutput = join(root, 'openapi/registry-breg.openapi.json');
  const bregRenderedOutput = join(root, 'openapi/registry-breg.render.openapi.json');
  try {
    await mkdir(join(source, 'products/casework/generated'), { recursive: true });
    await mkdir(join(source, 'products/breg/generated/facility/generated'), { recursive: true });
    await mkdir(join(source, 'products/evidence/generated'), { recursive: true });
    await mkdir(data, { recursive: true });
    await run('git', ['init', '--quiet', source]);
    await writeFile(join(source, caseworkPath), '{"info":{"version":"archived"}}\n');
    await writeFile(join(source, evidencePath), '{"info":{"version":"evidence"}}\n');
    await writeFile(join(source, oid4vciPath), '{"info":{"version":"oid4vci"}}\n');
    await writeFile(join(source, bregPath),
      '{"info":{"version":"breg"},"components":{"schemas":{"Row":{"properties":{"any":true}}}}}\n');
    await run('git', ['-C', source, 'add', '.']);
    await run('git', ['-C', source, '-c', 'user.name=Docs Test',
      '-c', 'user.email=docs-test@example.invalid', 'commit', '--quiet', '-m', 'archive']);
    const { stdout: archivedRef } = await run('git', ['-C', source, 'rev-parse', 'HEAD']);
    await writeFile(join(source, caseworkPath), '{"info":{"version":"current"}}\n');
    await run('git', ['-C', source, 'add', '.']);
    await run('git', ['-C', source, '-c', 'user.name=Docs Test',
      '-c', 'user.email=docs-test@example.invalid', 'commit', '--quiet', '-m', 'current']);

    await writeFile(join(data, 'repo-docs.yaml'), YAML.stringify({ repos: {
      'registry-casework': { ref: 'HEAD', local: 'source', remote: source, openapi: caseworkPath },
      'registry-evidence': { ref: 'HEAD', local: 'source', remote: source, openapi: evidencePath,
        docs: [{ src: 'README.md' }] },
      'registry-breg': { ref: 'HEAD', local: 'source', remote: source, openapi: bregPath },
    } }));

    async function fetch(selected, released, v030Availability) {
      const archived = archivedRef.trim();
      await writeFile(join(data, 'docsets.yaml'), YAML.stringify({
        current: 'latest',
        released,
        published_archive_limit: 3,
        docsets: [
          docset('latest', 'unreleased', 'HEAD', 'HEAD'),
          docset('v0.29.0', 'released', archived),
          docset('v0.30.0', v030Availability,
            v030Availability === 'candidate' ? 'v0.30.0' : archived,
            v030Availability === 'candidate' ? 'v0.30.0' : archived),
        ],
      }));
      await rm(output, { force: true });
      await rm(renderedOutput, { force: true });
      await rm(bregOutput, { force: true });
      await rm(bregRenderedOutput, { force: true });
      await run(process.execPath, [fetchOpenapi], {
        cwd: root,
        env: { ...process.env, DOCS_DOCSET: selected },
      });
    }

    await fetch('latest', 'v0.29.0', 'candidate');
    assert.equal(JSON.parse(await readFile(output, 'utf8')).info.version, 'current');
    // The current docset publishes the BReg facility document; v0.29 predates it.
    assert.equal(JSON.parse(await readFile(bregOutput, 'utf8')).info.version, 'breg');
    assert.deepEqual(JSON.parse(await readFile(bregRenderedOutput, 'utf8')).components.schemas.Row,
      { properties: { any: {} } });

    await fetch('v0.29.0', 'v0.29.0', 'candidate');
    await assert.rejects(readFile(output, 'utf8'), { code: 'ENOENT' });
    await assert.rejects(readFile(bregOutput, 'utf8'), { code: 'ENOENT' });

    await fetch('v0.30.0', 'v0.29.0', 'candidate');
    assert.equal(JSON.parse(await readFile(output, 'utf8')).info.version, 'current');

    await fetch('v0.30.0', 'v0.30.0', 'released');
    assert.equal(JSON.parse(await readFile(output, 'utf8')).info.version, 'archived');

    const booleanSpec = '{"info":{"version":"current"},"components":{"schemas":{"Payload":{"properties":{"body":true},"additionalProperties":false}}}}\n';
    await writeFile(join(source, caseworkPath), booleanSpec);
    await fetch('latest', 'v0.29.0', 'candidate');
    assert.equal(await readFile(output, 'utf8'), booleanSpec);
    assert.deepEqual(JSON.parse(await readFile(renderedOutput, 'utf8')).components.schemas.Payload,
      { properties: { body: {} }, additionalProperties: false });

    await writeFile(join(source, caseworkPath), '{"components":{"schemas":{"Forbidden":false}}}\n');
    await assert.rejects(fetch('latest', 'v0.29.0', 'candidate'),
      /false schema at #\/components\/schemas\/Forbidden/);
    await assert.rejects(readFile(output, 'utf8'), { code: 'ENOENT' });
    await assert.rejects(readFile(renderedOutput, 'utf8'), { code: 'ENOENT' });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('BReg OpenAPI defaults to the checked-out monorepo at the registry-stack ref', async () => {
  const source = await mkdtemp(join(tmpdir(), 'breg-openapi-source-'));
  const root = join(source, 'docs/site');
  const data = join(root, 'src/data');
  try {
    await mkdir(join(source, 'products/breg/generated/facility/generated'), { recursive: true });
    await mkdir(join(source, 'products/evidence/generated'), { recursive: true });
    await mkdir(data, { recursive: true });
    await writeFile(join(source, bregPath), '{"info":{"version":"facility"}}\n');
    await writeFile(join(source, evidencePath), '{"info":{"version":"evidence"}}\n');
    await writeFile(join(source, oid4vciPath), '{"info":{"version":"oid4vci"}}\n');
    await writeFile(join(data, 'repo-docs.yaml'), YAML.stringify({ repos: {
      'registry-evidence': { ref: 'HEAD', local: '../..', openapi: evidencePath, docs: [{ src: 'README.md' }] },
    } }));
    const latest = docset('latest', 'unreleased', 'HEAD');
    await writeFile(join(data, 'docsets.yaml'), YAML.stringify({
      current: 'latest',
      released: 'v0.29.0',
      published_archive_limit: 3,
      docsets: [{ ...latest, products: { ...latest.products,
        'registry-stack': { version: 'main source', ref: 'HEAD' } } },
      docset('v0.29.0', 'released', '0'.repeat(40))],
    }));
    await run(process.execPath, [fetchOpenapi], { cwd: root, env: { ...process.env, DOCS_DOCSET: 'latest' } });
    assert.equal(JSON.parse(await readFile(join(root, 'openapi/registry-breg.openapi.json'), 'utf8')).info.version,
      'facility');
    assert.ok(await readFile(join(root, 'openapi/registry-breg.render.openapi.json'), 'utf8'));
  } finally {
    await rm(source, { recursive: true, force: true });
  }
});

test('BReg OpenAPI is published by the current docset and by release docsets from v0.42.0', async () => {
  const source = await mkdtemp(join(tmpdir(), 'breg-openapi-floor-'));
  const root = join(source, 'docs/site');
  const data = join(root, 'src/data');
  const output = join(root, 'openapi/registry-breg.openapi.json');
  const renderedOutput = join(root, 'openapi/registry-breg.render.openapi.json');
  try {
    await mkdir(join(source, 'products/breg/generated/facility/generated'), { recursive: true });
    await mkdir(join(source, 'products/evidence/generated'), { recursive: true });
    await mkdir(data, { recursive: true });
    await run('git', ['init', '--quiet', source]);
    await writeFile(join(source, bregPath), '{"info":{"version":"released"}}\n');
    await writeFile(join(source, evidencePath), '{"info":{"version":"evidence"}}\n');
    await writeFile(join(source, oid4vciPath), '{"info":{"version":"oid4vci"}}\n');
    await run('git', ['-C', source, 'add', '.']);
    await run('git', ['-C', source, '-c', 'user.name=Docs Test',
      '-c', 'user.email=docs-test@example.invalid', 'commit', '--quiet', '-m', 'release']);
    const { stdout } = await run('git', ['-C', source, 'rev-parse', 'HEAD']);
    const releasedRef = stdout.trim();
    // The checked-out tree moves on from the released commit, so a docset that
    // pins the commit reads it while the current and candidate docsets read
    // the checkout.
    await writeFile(join(source, bregPath), '{"info":{"version":"checkout"}}\n');
    await writeFile(join(data, 'repo-docs.yaml'), YAML.stringify({ repos: {
      'registry-evidence': { ref: 'HEAD', local: '../..', remote: source, openapi: evidencePath,
        docs: [{ src: 'README.md' }] },
    } }));
    function withStack(entry, ref) {
      return { ...entry, products: { ...entry.products,
        'registry-stack': { version: entry.id === 'latest' ? 'main source' : entry.id, ref } } };
    }
    const candidate = withStack(docset('v0.43.0', 'candidate', 'v0.43.0'), 'v0.43.0');
    await writeFile(join(data, 'docsets.yaml'), YAML.stringify({
      current: 'latest',
      released: 'v0.42.0',
      published_archive_limit: 3,
      docsets: [
        withStack(docset('latest', 'unreleased', 'HEAD'), 'HEAD'),
        { ...candidate, repo_docs_source: 'monorepo' },
        withStack(docset('v0.42.0', 'released', releasedRef), releasedRef),
        withStack(docset('v0.41.0', 'released', releasedRef), releasedRef),
      ],
    }));

    async function fetch(selected) {
      await rm(output, { force: true });
      await rm(renderedOutput, { force: true });
      const { stdout: log } = await run(process.execPath, [fetchOpenapi], {
        cwd: root,
        env: { ...process.env, DOCS_DOCSET: selected },
      });
      return log;
    }

    await fetch('latest');
    assert.equal(JSON.parse(await readFile(output, 'utf8')).info.version, 'checkout');

    // A release candidate is built from its checked-out source before its tag exists.
    await fetch('v0.43.0');
    assert.equal(JSON.parse(await readFile(output, 'utf8')).info.version, 'checkout');
    assert.ok(await readFile(renderedOutput, 'utf8'));

    // An archived docset at the floor reads its pinned source.
    await fetch('v0.42.0');
    assert.equal(JSON.parse(await readFile(output, 'utf8')).info.version, 'released');
    assert.ok(await readFile(renderedOutput, 'utf8'));

    // A docset older than the floor does not publish the facility document.
    const log = await fetch('v0.41.0');
    assert.match(log, /Skipped registry-breg OpenAPI spec absent from docset v0\.41\.0\./);
    await assert.rejects(readFile(output, 'utf8'), { code: 'ENOENT' });
    await assert.rejects(readFile(renderedOutput, 'utf8'), { code: 'ENOENT' });
  } finally {
    await rm(source, { recursive: true, force: true });
  }
});

test('BReg OpenAPI is absent from the beta archives that predate release version ids', async () => {
  for (const id of ['beta-5', 'beta-3', 'beta-2026-06-12']) {
    assert.equal(docsetPublishesBregOpenApi({ id }, 'latest'), false, id);
    assert.equal(docsetPublishesEvidenceOid4vciOpenApi({ id }, 'latest'), false, id);
  }
  assert.throws(() => docsetPublishesBregOpenApi({ id: 'v0.42' }, 'latest'), /is not a release version/);

  // Every docset the site declares resolves, so any archive can be rebuilt.
  const declared = YAML.parse(await readFile(resolve(import.meta.dirname, '../src/data/docsets.yaml'), 'utf8'));
  for (const docset of declared.docsets) {
    assert.equal(typeof docsetPublishesBregOpenApi(docset, declared.current), 'boolean', docset.id);
  }
});

test('OID4VCI OpenAPI is published by the current docset and by release docsets from v0.20.0', async () => {
  const source = await mkdtemp(join(tmpdir(), 'oid4vci-openapi-floor-'));
  const root = join(source, 'docs/site');
  const data = join(root, 'src/data');
  const output = join(root, 'openapi/registry-evidence-oid4vci.openapi.json');
  const renderedOutput = join(root, 'openapi/registry-evidence-oid4vci.render.openapi.json');
  const evidenceOutput = join(root, 'openapi/registry-evidence.openapi.json');
  try {
    await mkdir(join(source, 'products/evidence/generated'), { recursive: true });
    await mkdir(data, { recursive: true });
    await run('git', ['init', '--quiet', source]);
    await writeFile(join(source, evidencePath), '{"info":{"version":"evidence"}}\n');
    await writeFile(join(source, oid4vciPath), '{"info":{"version":"released"}}\n');
    await run('git', ['-C', source, 'add', '.']);
    await run('git', ['-C', source, '-c', 'user.name=Docs Test',
      '-c', 'user.email=docs-test@example.invalid', 'commit', '--quiet', '-m', 'release']);
    const { stdout } = await run('git', ['-C', source, 'rev-parse', 'HEAD']);
    const releasedRef = stdout.trim();
    await writeFile(join(source, oid4vciPath), '{"info":{"version":"checkout"}}\n');
    // The document follows the registry-evidence entry's ref and source, not
    // its `openapi` path, which names the Registry Evidence document.
    await writeFile(join(data, 'repo-docs.yaml'), YAML.stringify({ repos: {
      'registry-evidence': { ref: 'HEAD', local: '../..', remote: source, openapi: evidencePath,
        docs: [{ src: 'README.md' }] },
    } }));
    const latest = docset('latest', 'unreleased', 'HEAD');
    await writeFile(join(data, 'docsets.yaml'), YAML.stringify({
      current: 'latest',
      released: 'v0.20.0',
      published_archive_limit: 3,
      docsets: [
        { ...latest, products: { ...latest.products,
          'registry-stack': { version: 'main source', ref: 'HEAD' } } },
        docset('v0.20.0', 'released', releasedRef),
        docset('v0.19.0', 'released', releasedRef),
      ],
    }));

    async function fetch(selected) {
      await rm(output, { force: true });
      await rm(renderedOutput, { force: true });
      const { stdout: log } = await run(process.execPath, [fetchOpenapi], {
        cwd: root,
        env: { ...process.env, DOCS_DOCSET: selected },
      });
      return log;
    }

    await fetch('latest');
    assert.equal(JSON.parse(await readFile(output, 'utf8')).info.version, 'checkout');
    assert.equal(JSON.parse(await readFile(evidenceOutput, 'utf8')).info.version, 'evidence');

    // An archived docset at the floor reads its pinned source.
    await fetch('v0.20.0');
    assert.equal(JSON.parse(await readFile(output, 'utf8')).info.version, 'released');
    assert.ok(await readFile(renderedOutput, 'utf8'));

    // A docset older than the floor still publishes the Registry Evidence
    // document and not the OID4VCI one.
    const log = await fetch('v0.19.0');
    assert.match(log, /Skipped registry-evidence-oid4vci OpenAPI spec absent from docset v0\.19\.0\./);
    assert.equal(JSON.parse(await readFile(evidenceOutput, 'utf8')).info.version, 'evidence');
    await assert.rejects(readFile(output, 'utf8'), { code: 'ENOENT' });
    await assert.rejects(readFile(renderedOutput, 'utf8'), { code: 'ENOENT' });
  } finally {
    await rm(source, { recursive: true, force: true });
  }
});
