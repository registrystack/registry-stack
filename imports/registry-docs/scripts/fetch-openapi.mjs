// Build-time OpenAPI fetch-at-ref (Wave 4, Phase B).
//
// Sources each product's OpenAPI spec from the sibling repo at the pinned ref
// declared in src/data/repo-docs.yaml, instead of relying on a hand-copied
// snapshot. The fetched specs land in openapi/<id>.openapi.json, which is what
// redocly.yaml (and `npm run redoc` / `npm run check:openapi`) reads. The specs
// are a build artifact pinned to the same ref the docs pipeline uses, so the
// rendered API reference always matches the pulled product docs.
//
// Resolution mirrors scripts/sync-repo-docs.mjs: prefer the sibling checkout
// (extracting the spec at the pinned ref via `git show <ref>:<path>` so dev and
// CI builds are reproducible), otherwise shallow-clone the remote at the ref.
//
// No silent failures: a repo with no spec mapping is skipped explicitly with a
// warning; a missing ref, a missing spec at the ref, or invalid JSON fails the
// build loudly.

import { mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { access } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { join, relative, resolve } from 'node:path';
import { promisify } from 'node:util';
import YAML from 'yaml';
import { applyDocsetRefs, getDocset, loadDocsets, selectedDocsetId } from './docsets.mjs';

const run = promisify(execFile);

const root = process.cwd();
const dataDir = resolve(root, 'src/data');
const openapiDir = resolve(root, 'openapi');
const cacheRoot = resolve(root, '.repo-docs-cache');

// Repo id -> the spec path within the repo. Only repos listed here publish an
// aggregated API reference; others are skipped.
const SPEC_SOURCES = {
  'registry-relay': 'openapi/registry-relay.openapi.json',
  'registry-notary': 'openapi/registry-notary.openapi.json',
};

function fail(message) {
  console.error(`error: ${message}`);
  process.exitCode = 1;
  throw new Error(message);
}

async function isDir(path) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

// Read the spec at the pinned ref from a local checkout, or null if the ref or
// the spec is unavailable there (caller falls back to a clone).
async function specFromLocal(localPath, ref, specPath) {
  try {
    const { stdout } = await run('git', ['show', `${ref}:${specPath}`], {
      cwd: localPath,
      maxBuffer: 64 * 1024 * 1024,
    });
    return stdout;
  } catch {
    return null;
  }
}

// Shallow-clone a single pinned commit, then read the spec from the worktree.
async function specFromClone(repoId, remote, ref, specPath) {
  const dest = join(cacheRoot, `${repoId}-openapi`);
  await rm(dest, { recursive: true, force: true });
  await mkdir(dest, { recursive: true });
  try {
    await run('git', ['init', '--quiet'], { cwd: dest });
    await run('git', ['remote', 'add', 'origin', remote], { cwd: dest });
    await run('git', ['fetch', '--quiet', '--depth', '1', 'origin', ref], { cwd: dest });
    await run('git', ['checkout', '--quiet', 'FETCH_HEAD'], { cwd: dest });
  } catch (error) {
    fail(`${repoId}: failed to clone ${remote} at ${ref} for the OpenAPI spec: ${error.message}`);
  }
  return readFile(resolve(dest, specPath), 'utf8');
}

async function main() {
  const manifest = YAML.parse(await readFile(resolve(dataDir, 'repo-docs.yaml'), 'utf8'));
  if (!manifest || typeof manifest.repos !== 'object') {
    fail('repo-docs.yaml must contain a top-level `repos` map');
  }
  const docsets = await loadDocsets({ dataDir });
  const docset = getDocset(docsets, selectedDocsetId(docsets));
  if (docset.id !== docsets.current) {
    applyDocsetRefs(manifest, docset);
    console.log(`Using archived docset ${docset.id} for OpenAPI refs.`);
  }

  await mkdir(openapiDir, { recursive: true });

  let written = 0;
  for (const [repoId, specPath] of Object.entries(SPEC_SOURCES)) {
    const repo = manifest.repos[repoId];
    if (!repo) {
      fail(`${repoId}: no entry in repo-docs.yaml to source the OpenAPI spec ref from`);
    }
    if (!repo.ref) {
      fail(`${repoId}: no pinned ref in repo-docs.yaml for the OpenAPI spec`);
    }

    const localPath = repo.local ? resolve(root, repo.local) : null;
    let raw = null;
    let mode = null;
    if (localPath && (await isDir(localPath))) {
      raw = await specFromLocal(localPath, repo.ref, specPath);
      if (raw !== null) mode = 'local';
    }
    if (raw === null) {
      if (!repo.remote) {
        fail(`${repoId}: spec ${specPath} not found at ${repo.ref} locally and no remote to clone`);
      }
      raw = await specFromClone(repoId, repo.remote, repo.ref, specPath);
      mode = 'clone';
    }

    // Parse to fail loudly on malformed JSON and to emit a stable, formatted file.
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      fail(`${repoId}: spec at ${repo.ref}:${specPath} is not valid JSON: ${error.message}`);
    }

    const outFile = resolve(openapiDir, `${repoId}.openapi.json`);
    await writeFile(outFile, `${JSON.stringify(parsed, null, 2)}\n`);
    written += 1;
    console.log(
      `Fetched ${repoId} OpenAPI spec at ${repo.ref.slice(0, 12)} (${mode}) -> ${relative(root, outFile)}`,
    );
  }

  console.log(`Fetched ${written} OpenAPI spec(s) at pinned refs.`);
}

await main();
