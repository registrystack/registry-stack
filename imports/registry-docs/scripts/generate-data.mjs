import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import YAML from 'yaml';

const root = process.cwd();
const dataDir = resolve(root, 'src/data');
const generatedDir = resolve(dataDir, 'generated');

const required = {
  projects: ['id', 'name', 'repo_path', 'role', 'owns', 'does_not_own', 'source_docs'],
  contracts: ['id', 'name', 'owner', 'status', 'surface', 'source_of_truth', 'consumer_note'],
  standards: [
    'id',
    'name',
    'standards_body',
    'official_url',
    'status',
    'claim_level',
    'adoption_mode',
    'used_by',
    'surfaces',
    'version_or_profile',
    'evidence_docs',
    'last_checked',
    'notes',
  ],
  'openapi-sources': ['id', 'name', 'owner', 'source', 'artifact', 'status', 'redoc_path'],
};

const generated = [];

async function loadYaml(name) {
  const file = resolve(dataDir, `${name}.yaml`);
  const text = await readFile(file, 'utf8');
  const parsed = YAML.parse(text);
  if (!Array.isArray(parsed)) {
    throw new Error(`${name}.yaml must contain a top-level list`);
  }
  for (const [index, item] of parsed.entries()) {
    for (const key of required[name]) {
      if (item[key] === undefined || item[key] === null || item[key] === '') {
        throw new Error(`${name}.yaml entry ${index + 1} is missing ${key}`);
      }
    }
  }
  return parsed;
}

await mkdir(generatedDir, { recursive: true });

for (const name of Object.keys(required)) {
  const data = await loadYaml(name);
  await writeFile(resolve(generatedDir, `${name}.json`), `${JSON.stringify(data, null, 2)}\n`);
  generated.push(name);
}

const docsets = YAML.parse(await readFile(resolve(dataDir, 'docsets.yaml'), 'utf8'));
await writeFile(resolve(generatedDir, 'docsets.json'), `${JSON.stringify(docsets, null, 2)}\n`);
generated.push('docsets');

console.log(`Generated ${generated.length} data files.`);
