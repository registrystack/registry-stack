// Registry Casework config shapes come from the committed Rust-generated schemas.
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

import { collectFields, FORMAT_VERSION, publishJson } from './configuration-reference.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultDocsRoot = resolve(scriptDir, '..');
const defaultRepoRoot = resolve(defaultDocsRoot, '../..');

const configureReference = 'docs/site/src/content/docs/configure/casework.mdx';
const operateReference = 'docs/site/src/content/docs/operate/casework.mdx';

export const CONTRACTS = [
  { id: 'project', title: 'casework.yaml', file: 'project/project.schema.json', reference: configureReference },
  { id: 'fixture', title: 'fixtures/*.yaml', file: 'fixture/fixture.schema.json', reference: configureReference },
  { id: 'dev-clients', title: 'dev-clients.yaml', file: 'dev-clients/dev-clients.schema.json', reference: configureReference },
  { id: 'holiday-set', title: 'holiday-sets/*.yaml', file: 'holiday-set/holiday-set.schema.json', reference: configureReference },
  { id: 'runtime', title: 'runtime.yaml', file: 'runtime/runtime.schema.json', reference: operateReference },
].map((contract) => ({
  ...contract,
  file: `products/casework/generated/${contract.file}`,
  status: 'beta',
}));

export async function buildCaseworkConfiguration(repoRoot = defaultRepoRoot) {
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
    generator: 'docs/site/scripts/generate-casework-configuration.mjs',
    contracts,
  };
}

export async function generateCaseworkConfiguration(
  docsRoot = defaultDocsRoot,
  repoRoot = defaultRepoRoot,
) {
  const document = await buildCaseworkConfiguration(repoRoot);
  await publishJson(resolve(docsRoot, 'src/data/generated/casework-configuration.json'), document);
  const total = document.contracts.reduce((sum, contract) => sum + contract.field_count, 0);
  console.log(`Generated Casework configuration reference for ${total} key paths across ${document.contracts.length} schemas.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await generateCaseworkConfiguration();
}
