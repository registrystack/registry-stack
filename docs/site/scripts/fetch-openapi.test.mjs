import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { test } from 'node:test';
import YAML from 'yaml';

const run = promisify(execFile);
const fetchOpenapi = resolve(import.meta.dirname, 'fetch-openapi.mjs');
const caseworkPath = 'products/casework/generated/registry-casework.openapi.json';
const evidencePath = 'products/evidence/generated/registry-evidence.openapi.json';
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
    // The BReg facility document is published by the current docset only.
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
