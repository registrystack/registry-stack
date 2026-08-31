// Registry Server config shapes come from the committed Rust-generated schemas.
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

import { collectFields, FORMAT_VERSION, publishJson } from './configuration-reference.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultDocsRoot = resolve(scriptDir, '..');
const defaultRepoRoot = resolve(defaultDocsRoot, '../..');

export const CONTRACTS = [
  { id: 'project', title: 'registry.yaml', file: 'authoring/registry-project.schema.json' },
  { id: 'module', title: 'modules/<name>/module.yaml', file: 'authoring/registry-module.schema.json' },
  { id: 'runtime', title: 'runtime.yaml', file: 'runtime/runtime.schema.json' },
].map((contract) => ({
  ...contract,
  file: `products/registry-server/generated/${contract.file}`,
  status: 'beta',
  reference: 'docs/site/src/content/docs/configure/registry-server.mdx',
}));

export async function buildServerConfiguration(repoRoot = defaultRepoRoot) {
  const contracts = await Promise.all(CONTRACTS.map(async (contract) => {
    const schema = parse(await readFile(resolve(repoRoot, contract.file), 'utf8'), {
      intAsBigInt: true,
    });
    const fields = collectFields(schema);
    if (fields.length === 0) throw new Error(`${contract.file} has no configuration fields`);
    return { ...contract, field_count: fields.length, fields };
  }));
  return {
    format_version: FORMAT_VERSION,
    generator: 'docs/site/scripts/generate-server-configuration.mjs',
    contracts,
  };
}

export async function generateServerConfiguration(
  docsRoot = defaultDocsRoot,
  repoRoot = defaultRepoRoot,
) {
  const document = await buildServerConfiguration(repoRoot);
  await publishJson(resolve(docsRoot, 'src/data/generated/server-configuration.json'), document);
  const total = document.contracts.reduce((sum, contract) => sum + contract.field_count, 0);
  console.log(`Generated Server configuration reference for ${total} key paths across ${document.contracts.length} schemas.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await generateServerConfiguration();
}
