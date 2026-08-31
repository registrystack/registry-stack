// Render the Evidence configuration grammar and the authoring form as docs data.
//
// Two kinds of schema are published here, and they are not the same promise.
// `products/evidence/contracts/{bundle,runtime}.schema.yaml` are the normative,
// frozen Version 1 grammar. `crates/registry-evidencectl/schemas/authoring/`
// holds schemas generated from the `registry-evidence-authoring` model, which
// are adopter tooling outside that frozen set and free to change with the tool
// that generates them. Every entry records which it is under `status`, and a
// generated document whose entry carries no known status is a failure rather
// than an unlabelled section, because a reader who mistakes one for the other
// has read the page wrongly.
//
// All of them carry types, fixed values, and bounds, but almost no prose: the
// explanations live in the product's CONFIG.md files. So this generator
// publishes exactly what a schema can prove, and each entry names the CONFIG.md
// a reader goes to for intent.
//
// The key-path notation is the one
// `products/evidence/scripts/check-config-key-paths.sh` owns, and this
// generator's test compares against the blocks that check maintains, so the two
// walks cannot drift apart quietly.
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { parse as parseYaml } from 'yaml';
import { collectFields, FORMAT_VERSION, publishJson } from './configuration-reference.mjs';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const defaultDocsRoot = resolve(scriptDir, '..');
const defaultRepoRoot = resolve(defaultDocsRoot, '../..');

export { FORMAT_VERSION } from './configuration-reference.mjs';

// What promise a published schema carries. `frozen` is the Version 1
// configuration contract. `tooling` is adopter tooling, held to the same
// key-path parity rule and free to change with the tool that generates it.
export const CONTRACT_STATUSES = ['frozen', 'tooling'];

const DEPLOYMENT_REFERENCE =
  'products/evidence/reference/request-adapter/deployment-projects/CONFIG.md';
const AUTHORING_REFERENCE = 'products/evidence/reference/authoring-projects/CONFIG.md';

export const CONTRACTS = [
  {
    id: 'bundle',
    file: 'products/evidence/contracts/bundle.schema.yaml',
    title: 'bundle/evidence.yaml',
    marker: 'evidence-bundle-key-paths',
    status: 'frozen',
    reference: DEPLOYMENT_REFERENCE,
  },
  {
    id: 'runtime',
    file: 'products/evidence/contracts/runtime.schema.yaml',
    title: 'runtime.yaml',
    marker: 'evidence-runtime-key-paths',
    status: 'frozen',
    reference: DEPLOYMENT_REFERENCE,
  },
  {
    id: 'authoring-question',
    file: 'crates/registry-evidencectl/schemas/authoring/question.schema.json',
    title: 'questions/<name>.yaml',
    marker: 'evidence-authoring-question-key-paths',
    status: 'tooling',
    reference: AUTHORING_REFERENCE,
  },
  {
    id: 'authoring-project-marker',
    file: 'crates/registry-evidencectl/schemas/authoring/project-marker.schema.json',
    title: 'evidence-project.yaml',
    marker: 'evidence-authoring-project-marker-key-paths',
    status: 'tooling',
    reference: AUTHORING_REFERENCE,
  },
];

export { collectFields } from './configuration-reference.mjs';

export function validateEvidenceConfiguration(document) {
  if (document?.format_version !== FORMAT_VERSION) {
    throw new Error('evidence configuration reference uses an unsupported format_version');
  }
  if (!Array.isArray(document.contracts)) {
    throw new Error('evidence configuration reference must carry a list of schemas');
  }
  const expected = CONTRACTS.map((contract) => contract.id).sort();
  const published = document.contracts.map((contract) => contract.id).sort();
  if (
    published.length !== expected.length ||
    published.some((id, index) => id !== expected[index])
  ) {
    throw new Error(
      'evidence configuration reference must cover exactly the schemas this generator knows',
    );
  }
  for (const contract of document.contracts) {
    // The page labels each section from this value. An entry carrying a status
    // the page cannot label would publish a tooling schema under no promise at
    // all, which reads as the frozen grammar beside it.
    if (!CONTRACT_STATUSES.includes(contract.status)) {
      throw new Error(`${contract.id} does not declare a known status`);
    }
    if (typeof contract.reference !== 'string' || contract.reference.length === 0) {
      throw new Error(`${contract.id} does not name the reference explaining it`);
    }
    if (!Array.isArray(contract.fields) || contract.fields.length === 0) {
      throw new Error(`${contract.id} must document at least one key path`);
    }
    if (contract.field_count !== contract.fields.length) {
      throw new Error(`${contract.id} field_count does not match the entries it carries`);
    }
    const seen = new Set();
    for (const field of contract.fields) {
      if (typeof field.key_path !== 'string' || field.key_path.length === 0) {
        throw new Error(`${contract.id} has an entry without a key path`);
      }
      if (seen.has(field.key_path)) {
        throw new Error(`${contract.id} repeats ${field.key_path}`);
      }
      seen.add(field.key_path);
    }
  }
}

export async function buildEvidenceConfiguration(repoRoot = defaultRepoRoot) {
  const contracts = await Promise.all(
    CONTRACTS.map(async (contract) => {
      const schema = parseYaml(await readFile(resolve(repoRoot, contract.file), 'utf8'), {
        intAsBigInt: true,
      });
      const fields = collectFields(schema);
      return { ...contract, field_count: fields.length, fields };
    }),
  );
  return {
    format_version: FORMAT_VERSION,
    generator: 'docs/site/scripts/generate-evidence-configuration.mjs',
    contracts,
  };
}


export async function generateEvidenceConfiguration(
  docsRoot = defaultDocsRoot,
  repoRoot = defaultRepoRoot,
) {
  const document = await buildEvidenceConfiguration(repoRoot);
  validateEvidenceConfiguration(document);
  await publishJson(resolve(docsRoot, 'src/data/generated/evidence-configuration.json'), document);
  const total = document.contracts.reduce((sum, contract) => sum + contract.field_count, 0);
  console.log(
    `Generated Evidence configuration reference for ${total} key paths across ${document.contracts.length} schemas.`,
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await generateEvidenceConfiguration();
}
