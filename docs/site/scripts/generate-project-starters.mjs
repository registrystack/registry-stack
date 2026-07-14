import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import YAML from 'yaml';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const docsRoot = resolve(scriptDir, '..');
const defaultRepoRoot = resolve(docsRoot, '../..');

export const starterSources = [
  {
    starter: 'http',
    label: 'Custom HTTP',
    workspace: 'http-project',
    source: 'crates/registryctl/assets/project-starters/bounded-http',
    fixtureFile: 'active.yaml',
    summary: 'One fixed bounded HTTP request with a closed response projection.',
  },
  {
    starter: 'dhis2-tracker',
    label: 'DHIS2 Tracker',
    workspace: 'dhis2-project',
    source: 'crates/registryctl/tests/fixtures/project-authoring/dhis2-tracker',
    fixtureFile: 'match.yaml',
    summary:
      'A product-neutral script adapter applied to a bounded DHIS2 Tracker read journey.',
  },
  {
    starter: 'opencrvs-dci',
    label: 'OpenCRVS DCI',
    workspace: 'opencrvs-project',
    source: 'crates/registryctl/tests/fixtures/project-authoring/opencrvs',
    fixtureFile: 'match.yaml',
    summary:
      'A product-neutral script adapter with the signed DCI search verification profile.',
  },
  {
    starter: 'fhir-r4',
    label: 'FHIR R4',
    workspace: 'fhir-project',
    source: 'crates/registryctl/tests/fixtures/project-authoring/fhir-r4-coverage-active',
    fixtureFile: 'match.yaml',
    summary:
      'A product-neutral script adapter with bounded FHIR R4 search-set parsing.',
  },
  {
    starter: 'snapshot',
    label: 'Exact snapshot',
    workspace: 'snapshot-project',
    source: 'crates/registryctl/tests/fixtures/project-authoring/snapshot-exact',
    fixtureFile: 'match.yaml',
    summary: 'An exact lookup over one immutable local materialization.',
  },
];

async function readYaml(path) {
  return YAML.parse(await readFile(path, 'utf8'));
}

export async function buildProjectStarterMatrix(repoRoot = defaultRepoRoot) {
  const starters = [];

  for (const source of starterSources) {
    const projectRoot = resolve(repoRoot, source.source);
    const project = await readYaml(join(projectRoot, 'registry-stack.yaml'));
    const integrations = Object.keys(project.integrations ?? {});
    if (integrations.length !== 1) {
      throw new Error(`${source.source} must contain exactly one starter integration`);
    }

    const integration = integrations[0];
    const fixtureDir = join(projectRoot, 'integrations', integration, 'fixtures');
    const fixtureFiles = (await readdir(fixtureDir)).filter((name) => name.endsWith('.yaml'));
    if (!fixtureFiles.includes(source.fixtureFile)) {
      throw new Error(`${source.source} is missing focused fixture ${source.fixtureFile}`);
    }

    const fixture = await readYaml(join(fixtureDir, source.fixtureFile));
    if (fixture.expect?.outcome !== 'match' || typeof fixture.name !== 'string') {
      throw new Error(`${source.source}/${source.fixtureFile} must be a named match fixture`);
    }

    const projectDir = source.workspace;
    const selection = `--integration ${integration} --fixture ${fixture.name}`;
    starters.push({
      starter: source.starter,
      label: source.label,
      summary: source.summary,
      source: source.source,
      integration,
      fixture: fixture.name,
      commands: [
        `registryctl init --from ${source.starter} --project-dir ${projectDir}`,
        `registryctl test --project-dir ${projectDir} ${selection} --trace`,
        `registryctl test --project-dir ${projectDir} ${selection} --watch`,
        `registryctl test --project-dir ${projectDir}`,
        `registryctl check --project-dir ${projectDir} --environment local --explain`,
        `registryctl build --project-dir ${projectDir} --environment local`,
      ],
    });
  }

  return starters;
}

export async function generateProjectStarterMatrix(repoRoot = defaultRepoRoot) {
  const outputDir = resolve(docsRoot, 'src/data/generated');
  await mkdir(outputDir, { recursive: true });
  const starters = await buildProjectStarterMatrix(repoRoot);
  await writeFile(
    resolve(outputDir, 'project-starters.json'),
    `${JSON.stringify(starters, null, 2)}\n`,
  );
  console.log(`Generated project starter command matrix for ${starters.length} starters.`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await generateProjectStarterMatrix();
}
