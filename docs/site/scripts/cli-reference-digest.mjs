import { readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import YAML from 'yaml';

import {
  catalogDigest,
  contentDigest,
  executeCatalog,
  legacyReviewSchemaVersion,
  reviewSchemaVersion,
  validateReviewMetadata,
} from './generate-cli-reference.mjs';

const scriptPath = fileURLToPath(import.meta.url);
const defaultRepoRoot = resolve(dirname(scriptPath), '../../..');

async function collect(repoRoot, execute) {
  const output = await execute(repoRoot);
  try {
    return JSON.parse(output);
  } catch (error) {
    throw new Error(`CLI reference collector did not emit JSON: ${error.message}`);
  }
}

// These are the provenance and content values to record after an actual review.
// A release-version-only change does not require replacing a v3 review record.
export async function cliReferenceDigest(
  repoRoot = defaultRepoRoot,
  { execute = executeCatalog } = {},
) {
  const catalog = await collect(repoRoot, execute);
  return {
    reviewed_source_version: catalog.source_version,
    reviewed_catalog_sha256: catalogDigest(catalog),
    reviewed_content_sha256: contentDigest(catalog),
  };
}

export async function migrateCliReferenceReview(
  repoRoot = defaultRepoRoot,
  { execute = executeCatalog } = {},
) {
  const path = resolve(repoRoot, 'docs/site/src/data/cli-reference.yaml');
  const original = await readFile(path, 'utf8');
  const document = YAML.parseDocument(original);
  if (document.errors.length > 0) throw document.errors[0];
  const metadata = document.toJS();
  const catalog = await collect(repoRoot, execute);
  if (metadata?.schema_version !== legacyReviewSchemaVersion) {
    validateReviewMetadata(metadata, catalog);
    return { migrated: false, metadata };
  }

  // Prove the legacy digest covers these exact commands at its recorded version.
  // This also permits migration after a version-only bump, without inventing review.
  const reviewedCatalog = metadata.last_reviewed === 'unreviewed'
    ? catalog
    : { ...catalog, source_version: metadata.reviewed_source_version };
  validateReviewMetadata(metadata, reviewedCatalog);
  const migrated = {
    ...metadata,
    schema_version: reviewSchemaVersion,
    reviewed_content_sha256: metadata.last_reviewed === 'unreviewed'
      ? null
      : contentDigest(catalog),
  };
  validateReviewMetadata(migrated, catalog);
  document.set('schema_version', migrated.schema_version);
  document.set('reviewed_content_sha256', migrated.reviewed_content_sha256);
  const temporary = `${path}.tmp-${process.pid}`;
  try {
    await writeFile(temporary, String(document), 'utf8');
    await rename(temporary, path);
  } finally {
    await unlink(temporary).catch(() => {});
  }
  return { migrated: true, metadata: migrated };
}

if (process.argv[1] === scriptPath) {
  const arguments_ = process.argv.slice(2);
  if (arguments_.length > 1 || (arguments_.length === 1 && arguments_[0] !== '--migrate')) {
    throw new Error(`unknown argument ${arguments_[0]}`);
  }
  if (arguments_[0] === '--migrate') {
    const result = await migrateCliReferenceReview();
    process.stdout.write(result.migrated
      ? 'Migrated CLI review to v3; existing review date and source provenance preserved.\n'
      : 'CLI review already uses v3 and covers the current command content.\n');
  } else {
    const digest = await cliReferenceDigest();
    process.stdout.write(
      `reviewed_source_version: ${JSON.stringify(digest.reviewed_source_version)}\n`
      + `reviewed_catalog_sha256: ${digest.reviewed_catalog_sha256}\n`
      + `reviewed_content_sha256: ${digest.reviewed_content_sha256}\n`,
    );
  }
}
