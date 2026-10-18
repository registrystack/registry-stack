// Registry Render config shapes come from the committed Rust-generated schemas.
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

import { collectFields, FORMAT_VERSION, publishJson } from './configuration-reference.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultDocsRoot = resolve(scriptDir, '..');
const defaultRepoRoot = resolve(defaultDocsRoot, '../..');

export const CONTRACTS = [
  { id: 'bundle', title: 'manifest.yaml', file: 'bundle.schema.json' },
  { id: 'labels', title: 'labels/*.yaml', file: 'labels.schema.json' },
  { id: 'runtime', title: 'runtime.yaml', file: 'runtime.schema.json' },
].map((contract) => ({
  ...contract,
  file: `products/render/schemas/${contract.file}`,
  status: 'beta',
  reference: 'docs/site/src/content/docs/reference/render-configuration.mdx',
}));

export async function buildRenderConfiguration(repoRoot = defaultRepoRoot) {
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
    generator: 'docs/site/scripts/generate-render-configuration.mjs',
    contracts,
  };
}

export async function generateRenderConfiguration(
  docsRoot = defaultDocsRoot,
  repoRoot = defaultRepoRoot,
) {
  const document = await buildRenderConfiguration(repoRoot);
  await publishJson(resolve(docsRoot, 'src/data/generated/render-configuration.json'), document);
  const total = document.contracts.reduce((sum, contract) => sum + contract.field_count, 0);
  console.log(`Generated Render configuration reference for ${total} key paths across ${document.contracts.length} schemas.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await generateRenderConfiguration();
}
