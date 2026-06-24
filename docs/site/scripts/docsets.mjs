import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import YAML from 'yaml';

const docsetIdPattern = /^[a-z0-9][a-z0-9.-]*[a-z0-9]$/;
const shaPattern = /^[0-9a-f]{40}$/;

export async function loadYaml(path) {
  return YAML.parse(await readFile(path, 'utf8'));
}

export async function loadDocsets({ dataDir = resolve(process.cwd(), 'src/data') } = {}) {
  const manifest = await loadYaml(resolve(dataDir, 'docsets.yaml'));
  validateDocsets(manifest);
  return manifest;
}

export function selectedDocsetId(docsets, env = process.env) {
  return env.DOCS_DOCSET || docsets.current;
}

export function getDocset(docsets, id = selectedDocsetId(docsets)) {
  const docset = docsets.docsets.find((entry) => entry.id === id);
  if (!docset) {
    throw new Error(`Unknown docs docset "${id}"`);
  }
  return docset;
}

export function validateDocsets(manifest) {
  if (!manifest || typeof manifest !== 'object') {
    throw new Error('docsets.yaml must contain a top-level object');
  }
  if (!manifest.current || typeof manifest.current !== 'string') {
    throw new Error('docsets.yaml must declare current');
  }
  if (!Array.isArray(manifest.docsets) || manifest.docsets.length === 0) {
    throw new Error('docsets.yaml must contain a non-empty docsets list');
  }

  const ids = new Set();
  for (const [index, docset] of manifest.docsets.entries()) {
    const prefix = `docsets[${index}]`;
    for (const key of ['id', 'label', 'path', 'status', 'source', 'published_at', 'description', 'products']) {
      if (docset[key] === undefined || docset[key] === null || docset[key] === '') {
        throw new Error(`${prefix} is missing ${key}`);
      }
    }
    if (!docsetIdPattern.test(docset.id)) {
      throw new Error(`${prefix}.id must use lowercase letters, numbers, dots, or hyphens`);
    }
    if (ids.has(docset.id)) {
      throw new Error(`Duplicate docset id "${docset.id}"`);
    }
    ids.add(docset.id);
    if (!['current', 'archived', 'draft'].includes(docset.status)) {
      throw new Error(`${prefix}.status must be current, archived, or draft`);
    }
    if (!docset.path.startsWith('/') || !docset.path.endsWith('/')) {
      throw new Error(`${prefix}.path must be an absolute path with a trailing slash`);
    }
    if (typeof docset.products !== 'object' || Array.isArray(docset.products)) {
      throw new Error(`${prefix}.products must be a map`);
    }
    for (const [repoId, product] of Object.entries(docset.products)) {
      if (!product || typeof product !== 'object') {
        throw new Error(`${prefix}.products.${repoId} must be a map`);
      }
      if (!product.version || !product.ref) {
        throw new Error(`${prefix}.products.${repoId} must declare version and ref`);
      }
      const isCurrentHead = docset.id === manifest.current && product.ref === 'HEAD';
      if (!isCurrentHead && !shaPattern.test(product.ref)) {
        throw new Error(`${prefix}.products.${repoId}.ref must be a full 40-character SHA`);
      }
    }
  }

  if (!ids.has(manifest.current)) {
    throw new Error(`docsets.yaml current "${manifest.current}" does not match a docset id`);
  }
}

export function applyDocsetRefs(repoManifest, docset, { requireAllActive = true } = {}) {
  if (!repoManifest?.repos || typeof repoManifest.repos !== 'object') {
    throw new Error('repo-docs.yaml must contain a top-level repos map');
  }
  const activeRepos = Object.entries(repoManifest.repos).filter(([, repo]) => {
    return Array.isArray(repo.docs) && repo.docs.length > 0;
  });

  for (const [repoId, repo] of activeRepos) {
    const product = docset.products[repoId];
    if (!product) {
      if (requireAllActive) {
        throw new Error(`Docset "${docset.id}" has no product ref for active repo "${repoId}"`);
      }
      continue;
    }
    repo.ref = product.ref;
    repo.version = product.version;
    if (docset.status === 'archived') {
      if (repo.archive_remote) repo.remote = repo.archive_remote;
      if (Object.hasOwn(repo, 'archive_local')) {
        repo.local = repo.archive_local;
      } else if (repo.archive_remote) {
        delete repo.local;
      }
      if (repo.archive_openapi) repo.openapi = repo.archive_openapi;
      for (const entry of repo.docs ?? []) {
        if (entry.archive_src) entry.src = entry.archive_src;
      }
    }
  }
  return repoManifest;
}

export function docEntryAppliesToDocset(entry, docset) {
  const excluded = entry.exclude_docsets;
  if (excluded === undefined) return true;
  if (!Array.isArray(excluded)) {
    throw new Error(`${entry.src ?? 'repo doc entry'} exclude_docsets must be a list`);
  }
  return !excluded.includes(docset.id);
}

export function filterRepoDocsForDocset(repoManifest, docset) {
  if (!repoManifest?.repos || typeof repoManifest.repos !== 'object') {
    throw new Error('repo-docs.yaml must contain a top-level repos map');
  }
  for (const repo of Object.values(repoManifest.repos)) {
    if (!Array.isArray(repo.docs)) continue;
    repo.docs = repo.docs.filter((entry) => docEntryAppliesToDocset(entry, docset));
  }
  return repoManifest;
}

export function currentProductsMatchRepoManifest(repoManifest, docsets) {
  const current = getDocset(docsets, docsets.current);
  const errors = [];
  for (const [repoId, repo] of Object.entries(repoManifest.repos ?? {})) {
    if (!Array.isArray(repo.docs) || repo.docs.length === 0) continue;
    const product = current.products[repoId];
    if (!product) {
      errors.push(`current docset is missing active repo "${repoId}"`);
      continue;
    }
    if (repo.ref !== product.ref) {
      errors.push(`${repoId}: repo-docs ref ${repo.ref} does not match current docset ref ${product.ref}`);
    }
    if (repo.version && repo.version !== product.version) {
      errors.push(`${repoId}: repo-docs version ${repo.version} does not match current docset version ${product.version}`);
    }
  }
  return errors;
}
