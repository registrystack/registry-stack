// Registry Messaging config shapes come from the committed Rust-generated schemas.
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

import { collectFields, FORMAT_VERSION, publishJson } from './configuration-reference.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultDocsRoot = resolve(scriptDir, '..');
const defaultRepoRoot = resolve(defaultDocsRoot, '../..');

export const CONTRACTS = [
  { id: 'project', title: 'messaging.yaml', file: 'authoring/project.schema.json' },
  { id: 'template', title: 'templates/*/*/template.yaml', file: 'authoring/template.schema.json' },
  { id: 'provider', title: 'providers/*/provider.yaml', file: 'authoring/provider.schema.json' },
  { id: 'runtime', title: 'runtime.yaml', file: 'runtime/runtime.schema.json' },
].map((contract) => ({
  ...contract,
  file: `products/messaging/generated/${contract.file}`,
  status: 'beta',
  reference: 'docs/site/src/content/docs/reference/messaging-configuration.mdx',
}));

export async function buildMessagingConfiguration(repoRoot = defaultRepoRoot) {
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
    generator: 'docs/site/scripts/generate-messaging-configuration.mjs',
    contracts,
  };
}

export async function generateMessagingConfiguration(
  docsRoot = defaultDocsRoot,
  repoRoot = defaultRepoRoot,
) {
  const document = await buildMessagingConfiguration(repoRoot);
  await publishJson(resolve(docsRoot, 'src/data/generated/messaging-configuration.json'), document);
  const total = document.contracts.reduce((sum, contract) => sum + contract.field_count, 0);
  console.log(`Generated Messaging configuration reference for ${total} key paths across ${document.contracts.length} schemas.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await generateMessagingConfiguration();
}
