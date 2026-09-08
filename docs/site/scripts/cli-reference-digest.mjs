import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { catalogDigest, executeCatalog } from './generate-cli-reference.mjs';

const scriptPath = fileURLToPath(import.meta.url);
const defaultRepoRoot = resolve(dirname(scriptPath), '../../..');

// Prints the two values `src/data/cli-reference.yaml` records when a reviewer
// publishes the generated CLI reference: the workspace version the collector
// reports and the digest of the command catalog it emitted. The generator
// refuses a build whose values differ from the record, so this is the command
// to run before re-stamping the record after a CLI or version change.
export async function cliReferenceDigest(
  repoRoot = defaultRepoRoot,
  { execute = executeCatalog } = {},
) {
  const output = await execute(repoRoot);
  let catalog;
  try {
    catalog = JSON.parse(output);
  } catch (error) {
    throw new Error(`CLI reference collector did not emit JSON: ${error.message}`);
  }
  return {
    reviewed_source_version: catalog.source_version,
    reviewed_catalog_sha256: catalogDigest(catalog),
  };
}

if (process.argv[1] === scriptPath) {
  if (process.argv.length > 2) {
    throw new Error(`unknown argument ${process.argv[2]}`);
  }
  const digest = await cliReferenceDigest();
  process.stdout.write(
    `reviewed_source_version: ${JSON.stringify(digest.reviewed_source_version)}\n`
    + `reviewed_catalog_sha256: ${digest.reviewed_catalog_sha256}\n`,
  );
}
