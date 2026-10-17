// Base Registry Engine config shapes come from the committed Rust-generated schemas.
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

import { collectFields, FORMAT_VERSION, publishJson } from './configuration-reference.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultDocsRoot = resolve(scriptDir, '..');
const defaultRepoRoot = resolve(defaultDocsRoot, '../..');

const contract = (status, reference) => (entry) => ({
  ...entry,
  file: `products/breg/generated/${entry.file}`,
  status,
  reference: `docs/site/src/content/docs/${reference ?? entry.reference}`,
});

export const CONTRACTS = [
  { id: 'project', title: 'registry.yaml', file: 'authoring/registry-project.schema.json' },
  { id: 'module', title: 'modules/<name>/module.yaml', file: 'authoring/registry-module.schema.json' },
  { id: 'runtime', title: 'runtime.yaml', file: 'runtime/runtime.schema.json' },
].map(contract('beta', 'configure/breg.mdx'));

// Files `bregctl` reads beside a project: adopter tooling, published by the
// `tool-schema` example under products/breg/generated/tools. Listed in the
// order an adopter meets them, which is the order the reference page shows.
export const TOOL_CONTRACTS = [
  {
    id: 'dev-clients',
    title: 'dev-clients.yaml',
    file: 'tools/dev-clients.v1alpha1.schema.json',
    reference: 'tutorials/first-breg.mdx',
  },
  {
    id: 'example-scenarios',
    title: 'examples/scenarios.json',
    file: 'tools/example-scenarios.v1alpha1.schema.json',
    reference: 'tutorials/first-breg.mdx',
  },
  {
    id: 'journeys',
    title: 'tests/journeys.yaml',
    file: 'tools/journeys.v1.schema.json',
    reference: 'configure/breg-journeys.mdx',
  },
  {
    id: 'schema-test-credentials',
    title: '--credentials <file>',
    file: 'tools/schema-test-credentials.v1.schema.json',
    reference: 'operate/breg.mdx',
  },
  {
    id: 'migration-descriptor',
    title: 'modules/<module-id>/migrations/<migration-id>/descriptor.json',
    file: 'tools/migration-descriptor.v1alpha1.schema.json',
    reference: 'operate/breg-changes.mdx',
  },
  {
    id: 'backup-binding',
    title: '--backup <backupBindingPath>=<binding file>',
    file: 'tools/backup-binding.v1alpha1.schema.json',
    reference: 'operate/breg-changes.mdx',
  },
  {
    id: 'model-selection',
    title: 'model/selection.yaml',
    file: 'tools/model-selection.v1alpha1.schema.json',
    reference: 'reference/bregctl-publicschema-wizard.mdx',
  },
].map(contract('tooling'));

// The runtime documents of the supporting services beside the engine.
export const SERVICE_CONTRACTS = [
  { id: 'mcp-runtime', title: 'breg-mcp runtime.yaml', file: 'mcp-runtime/mcp-runtime.schema.json' },
  { id: 'review-runtime', title: 'breg-review runtime.yaml', file: 'review-runtime/review-runtime.schema.json' },
].map(contract('beta', 'configure/breg-mcp.mdx'));

export const CLIENT_CAPABILITIES = 'products/breg/contracts/client-capabilities.json';
const PROPOSAL_QUERY_TYPE = 'BRegProposalQuery.';

async function readContracts(repoRoot, contracts) {
  return Promise.all(contracts.map(async (entry) => {
    const schema = parse(await readFile(resolve(repoRoot, entry.file), 'utf8'), {
      intAsBigInt: true,
    });
    const fields = collectFields(schema);
    if (fields.length === 0) throw new Error(`${entry.file} has no configuration fields`);
    return { ...entry, field_count: fields.length, fields };
  }));
}

// The Proposal list query keys the client capability inventory binds: every
// option whose Rust binding is a `BRegProposalQuery` member, in inventory order.
export function proposalQueryKeys(inventory) {
  const bindings = inventory.queryOptionBindings;
  if (bindings === null || typeof bindings !== 'object') {
    throw new Error(`${CLIENT_CAPABILITIES} has no queryOptionBindings`);
  }
  const keys = Object.entries(bindings)
    .filter(([, binding]) => binding.rust.every((name) => name.startsWith(PROPOSAL_QUERY_TYPE)))
    .map(([key, binding]) => ({
      key,
      rust: binding.rust,
      node: binding.node,
      python: binding.python,
    }));
  if (keys.length === 0) throw new Error(`${CLIENT_CAPABILITIES} binds no Proposal list query key`);
  return keys;
}

export async function buildBRegConfiguration(repoRoot = defaultRepoRoot) {
  const inventory = JSON.parse(await readFile(resolve(repoRoot, CLIENT_CAPABILITIES), 'utf8'));
  return {
    format_version: FORMAT_VERSION,
    generator: 'docs/site/scripts/generate-breg-configuration.mjs',
    contracts: await readContracts(repoRoot, CONTRACTS),
    tools: await readContracts(repoRoot, TOOL_CONTRACTS),
    services: await readContracts(repoRoot, SERVICE_CONTRACTS),
    client_proposal_query: { file: CLIENT_CAPABILITIES, keys: proposalQueryKeys(inventory) },
  };
}

export async function generateBRegConfiguration(
  docsRoot = defaultDocsRoot,
  repoRoot = defaultRepoRoot,
) {
  const document = await buildBRegConfiguration(repoRoot);
  await publishJson(resolve(docsRoot, 'src/data/generated/breg-configuration.json'), document);
  const schemas = [...document.contracts, ...document.tools, ...document.services];
  const total = schemas.reduce((sum, entry) => sum + entry.field_count, 0);
  console.log(`Generated BReg configuration reference for ${total} key paths across ${schemas.length} schemas.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await generateBRegConfiguration();
}
