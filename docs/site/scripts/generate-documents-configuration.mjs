// Document Store config shapes come from the committed Rust-generated schemas.
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

import { collectFields, FORMAT_VERSION, publishJson } from './configuration-reference.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultDocsRoot = resolve(scriptDir, '..');
const defaultRepoRoot = resolve(defaultDocsRoot, '../..');

export const CONTRACTS = [
  { id: 'project', title: 'documents.yaml', file: 'project/project.schema.json' },
  { id: 'runtime', title: 'runtime.yaml', file: 'runtime/runtime.schema.json' },
].map((contract) => ({
  ...contract,
  file: `products/documents/generated/${contract.file}`,
  status: 'beta',
  reference: 'docs/site/src/content/docs/reference/documents-configuration.mdx',
}));

export async function buildDocumentsConfiguration(repoRoot = defaultRepoRoot) {
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
    generator: 'docs/site/scripts/generate-documents-configuration.mjs',
    contracts,
  };
}

export async function generateDocumentsConfiguration(
  docsRoot = defaultDocsRoot,
  repoRoot = defaultRepoRoot,
) {
  const document = await buildDocumentsConfiguration(repoRoot);
  await publishJson(resolve(docsRoot, 'src/data/generated/documents-configuration.json'), document);
  const total = document.contracts.reduce((sum, contract) => sum + contract.field_count, 0);
  console.log(`Generated Document Store configuration reference for ${total} key paths across ${document.contracts.length} schemas.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await generateDocumentsConfiguration();
}
