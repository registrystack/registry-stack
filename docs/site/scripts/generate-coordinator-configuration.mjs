// Registry Coordinator config shapes and its operation catalogue come from the
// committed Rust-generated schemas under products/coordinator/generated.
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

import { collectFields, FORMAT_VERSION, publishJson } from './configuration-reference.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultDocsRoot = resolve(scriptDir, '..');
const defaultRepoRoot = resolve(defaultDocsRoot, '../..');

const reference = 'docs/site/src/content/docs/reference/coordinator-configuration.mdx';

export const CONTRACTS = [
  { id: 'project', title: 'workflow.yaml', file: 'project/project.schema.json' },
  { id: 'scenarios', title: 'scenarios.yaml', file: 'scenarios/scenarios.schema.json' },
  { id: 'runtime', title: 'runtime.yaml', file: 'runtime/runtime.schema.json' },
].map((contract) => ({
  ...contract,
  file: `products/coordinator/generated/${contract.file}`,
  status: 'beta',
  reference,
}));

export const OPERATION_CATALOG = 'products/coordinator/generated/operations/catalog.json';

// One row per maintained operation, read from the host contract the runtime
// itself compiles against.
export function operationRows(catalog) {
  return Object.entries(catalog).map(([id, entry]) => {
    const { identity, limits, completionObservation } = entry.host;
    if (identity.id !== id) throw new Error(`${OPERATION_CATALOG}: ${id} names ${identity.id}`);
    return {
      id,
      product: identity.product,
      effect: identity.effect,
      recovery: identity.recovery,
      read_receipt: identity.readReceipt,
      key_requirement: identity.keyRequirement,
      authority: entry.host.authority,
      completion: completionObservation?.name ?? null,
      maximum_call_attempts: limits.maximumCallAttempts,
      attempt_timeout_seconds: limits.attemptTimeoutSeconds,
    };
  });
}

export async function buildCoordinatorConfiguration(repoRoot = defaultRepoRoot) {
  const contracts = await Promise.all(CONTRACTS.map(async (contract) => {
    const schema = parse(await readFile(resolve(repoRoot, contract.file), 'utf8'), {
      intAsBigInt: true,
    });
    const fields = collectFields(schema);
    if (fields.length === 0) throw new Error(`${contract.file} has no configuration fields`);
    return { ...contract, field_count: fields.length, fields };
  }));
  const catalog = JSON.parse(await readFile(resolve(repoRoot, OPERATION_CATALOG), 'utf8'));
  const operations = operationRows(catalog);
  if (operations.length === 0) throw new Error(`${OPERATION_CATALOG} has no operations`);
  return {
    format_version: FORMAT_VERSION,
    generator: 'docs/site/scripts/generate-coordinator-configuration.mjs',
    contracts,
    operations,
  };
}

export async function generateCoordinatorConfiguration(
  docsRoot = defaultDocsRoot,
  repoRoot = defaultRepoRoot,
) {
  const document = await buildCoordinatorConfiguration(repoRoot);
  await publishJson(resolve(docsRoot, 'src/data/generated/coordinator-configuration.json'), document);
  const total = document.contracts.reduce((sum, contract) => sum + contract.field_count, 0);
  console.log(`Generated Coordinator configuration reference for ${total} key paths across ${document.contracts.length} schemas and ${document.operations.length} operations.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await generateCoordinatorConfiguration();
}
