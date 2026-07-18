import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import YAML from 'yaml';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const docsRoot = resolve(scriptDir, '..');
const defaultRepoRoot = resolve(docsRoot, '../..');
const catalogRelative = 'crates/registryctl/tests/fixtures/project-authoring-journeys.yaml';
const goldenPrefix = 'crates/registryctl/tests/fixtures/project-authoring/';
const supportedSteps = ['init', 'editor', 'trace', 'watch', 'test', 'check', 'build'];
const starterSteps = supportedSteps;
const publicStarterOrder = ['http', 'dhis2-tracker', 'opencrvs-dci', 'fhir-r4', 'snapshot'];
const safeCliTokenPattern = /^[A-Za-z0-9][A-Za-z0-9._-]*$/u;

async function readYaml(path) {
  return YAML.parse(await readFile(path, 'utf8'));
}

function equalValues(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function requireSafeCliToken(value, field) {
  if (typeof value !== 'string' || !safeCliTokenPattern.test(value)) {
    throw new Error(`${field} must be a safe CLI token`);
  }
}

function requireSafeProjectPath(value, field) {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.startsWith('-') ||
    !value.split('/').every((segment) => safeCliTokenPattern.test(segment))
  ) {
    throw new Error(`${field} must be a safe relative project path`);
  }
}

function validateCatalogCommandArguments(workspace) {
  requireSafeProjectPath(workspace.project_dir, `${workspace.id} project_dir`);
  requireSafeCliToken(workspace.environment, `${workspace.id} environment`);
  if (workspace.starter !== undefined) {
    requireSafeCliToken(workspace.starter, `${workspace.id} starter`);
  }
}

function deriveTopology(project, source) {
  const services = Object.values(project.services ?? {});
  const hasRelay =
    Object.keys(project.integrations ?? {}).length > 0 ||
    Object.keys(project.entities ?? {}).length > 0 ||
    services.some((service) => service.kind === 'records_api');
  const hasNotary = services.some((service) => service.kind === 'evidence');
  if (hasRelay && hasNotary) return 'combined';
  if (hasRelay) return 'relay-only';
  if (hasNotary) return 'notary-only';
  throw new Error(`${source} does not select a Registry Stack product`);
}

async function deriveFocusedSelection(projectRoot, project, workspace) {
  const integrations = Object.entries(project.integrations ?? {});
  if (integrations.length !== 1) {
    throw new Error(`${workspace.source} must contain exactly one focused integration`);
  }
  const [integration, reference] = integrations[0];
  requireSafeCliToken(integration, `${workspace.id} integration id`);
  const fixtureDir = join(projectRoot, dirname(reference.file), 'fixtures');
  const fixtureFiles = (await readdir(fixtureDir)).filter((name) => name.endsWith('.yaml'));
  if (!fixtureFiles.includes(workspace.focused_fixture_file)) {
    throw new Error(
      `${workspace.source} is missing focused fixture ${workspace.focused_fixture_file}`,
    );
  }
  const fixture = await readYaml(join(fixtureDir, workspace.focused_fixture_file));
  if (typeof fixture.name !== 'string' || fixture.name.length === 0) {
    throw new Error(`${workspace.source}/${workspace.focused_fixture_file} must be a named fixture`);
  }
  requireSafeCliToken(fixture.name, `${workspace.id} fixture name`);
  if (workspace.starter && fixture.expect?.outcome !== 'match') {
    throw new Error(`${workspace.source}/${workspace.focused_fixture_file} must be a match fixture`);
  }
  return { integration, fixture: fixture.name };
}

async function hasAuthoredFixtures(projectRoot, project) {
  for (const reference of Object.values(project.integrations ?? {})) {
    const fixtureDirectory = join(projectRoot, dirname(reference.file), 'fixtures');
    try {
      if ((await readdir(fixtureDirectory)).some((name) => name.endsWith('.yaml'))) return true;
    } catch (error) {
      if (error?.code !== 'ENOENT') throw error;
    }
  }
  return false;
}

function buildCommands(workspace, selection) {
  const commands = [];
  for (const step of workspace.steps) {
    switch (step) {
      case 'init':
        commands.push(
          `registryctl init --from ${workspace.starter} --project-dir ${workspace.project_dir}`,
        );
        break;
      case 'editor':
        commands.push(`registryctl authoring editor --project-dir ${workspace.project_dir}`);
        break;
      case 'trace':
        commands.push(
          `registryctl test --project-dir ${workspace.project_dir} --integration ${selection.integration} --fixture ${selection.fixture} --trace`,
        );
        break;
      case 'watch':
        commands.push(
          `registryctl test --project-dir ${workspace.project_dir} --integration ${selection.integration} --fixture ${selection.fixture} --watch`,
        );
        break;
      case 'test':
        commands.push(`registryctl test --project-dir ${workspace.project_dir}`);
        break;
      case 'check':
        commands.push(
          `registryctl check --project-dir ${workspace.project_dir} --environment ${workspace.environment}${workspace.check_explain ? ' --explain' : ''}`,
        );
        break;
      case 'build':
        commands.push(
          `registryctl build --project-dir ${workspace.project_dir} --environment ${workspace.environment}`,
        );
        break;
      default:
        throw new Error(`${workspace.id} contains unsupported step ${step}`);
    }
  }
  return commands;
}

function selectPublicStarters(journeys) {
  const starterJourneys = journeys.filter((journey) => journey.starter);
  if (starterJourneys.length !== publicStarterOrder.length) {
    throw new Error(
      `public starter catalog must contain exactly ${publicStarterOrder.length} entries`,
    );
  }
  const byStarter = new Map(
    starterJourneys.map((journey) => [journey.starter, journey]),
  );
  if (byStarter.size !== starterJourneys.length) {
    throw new Error('public starter catalog contains a duplicate starter');
  }
  if (
    publicStarterOrder.some((starter) => !byStarter.has(starter))
  ) {
    throw new Error(
      `public starter catalog must contain exactly ${publicStarterOrder.join(', ')}`,
    );
  }
  return publicStarterOrder.map((starter) => byStarter.get(starter));
}

export async function buildProjectAuthoringJourneyMatrix(repoRoot = defaultRepoRoot) {
  const catalog = await readYaml(resolve(repoRoot, catalogRelative));
  if (catalog.version !== 1 || !Array.isArray(catalog.workspaces)) {
    throw new Error(`${catalogRelative} must be a version 1 workspace catalog`);
  }

  const actualGoldens = new Set(
    (await readdir(resolve(repoRoot, goldenPrefix), { withFileTypes: true }))
      .filter((entry) => entry.isDirectory())
      .map((entry) => entry.name),
  );
  const catalogGoldens = new Set();
  const ids = new Set();
  const sources = new Set();
  const journeys = [];

  for (const workspace of catalog.workspaces) {
    validateCatalogCommandArguments(workspace);
    if (ids.has(workspace.id)) throw new Error(`duplicate catalog id ${workspace.id}`);
    if (sources.has(workspace.source)) throw new Error(`duplicate catalog source ${workspace.source}`);
    ids.add(workspace.id);
    sources.add(workspace.source);
    if (workspace.source.startsWith(goldenPrefix)) {
      catalogGoldens.add(workspace.source.slice(goldenPrefix.length));
    }
    if (!['maintained', 'conformance-only'].includes(workspace.classification)) {
      throw new Error(`${workspace.id} has unknown classification ${workspace.classification}`);
    }
    if (!Array.isArray(workspace.steps) || new Set(workspace.steps).size !== workspace.steps.length) {
      throw new Error(`${workspace.id} must list each supported step once`);
    }
    if (!workspace.steps.every((step) => supportedSteps.includes(step))) {
      throw new Error(`${workspace.id} contains an unsupported step`);
    }
    if (workspace.environment !== 'local' || workspace.check_explain !== true) {
      throw new Error(`${workspace.id} must document check --environment local --explain`);
    }
    if (!workspace.steps.includes('check') || !workspace.steps.includes('build')) {
      throw new Error(`${workspace.id} must support check and build`);
    }
    if (workspace.starter) {
      if (!equalValues(workspace.steps, starterSteps)) {
        throw new Error(`${workspace.id} starter must expose the canonical seven-command journey`);
      }
    } else if (workspace.steps.includes('init')) {
      throw new Error(`${workspace.id} is not a starter and cannot emit init --from`);
    }

    const projectRoot = resolve(repoRoot, workspace.source);
    const project = await readYaml(join(projectRoot, 'registry-stack.yaml'));
    const topology = deriveTopology(project, workspace.source);
    if (workspace.topology !== topology) {
      throw new Error(
        `${workspace.id} declares ${workspace.topology} but workspace content is ${topology}`,
      );
    }
    const authoredFixtures = await hasAuthoredFixtures(projectRoot, project);
    if (!authoredFixtures && !equalValues(workspace.steps, ['check', 'build'])) {
      throw new Error(
        `${workspace.id} is fixtureless and may document only check and build`,
      );
    }
    if (
      authoredFixtures &&
      workspace.classification === 'maintained' &&
      !workspace.steps.includes('watch')
    ) {
      throw new Error(`${workspace.id} is maintained with fixtures and must document watch`);
    }

    const focused = workspace.steps.some((step) => step === 'trace' || step === 'watch')
      ? await deriveFocusedSelection(projectRoot, project, workspace)
      : {};
    journeys.push({
      id: workspace.id,
      label: workspace.label,
      summary: workspace.summary,
      source: workspace.source,
      classification: workspace.classification,
      ...(workspace.focus ? { focus: workspace.focus } : {}),
      topology,
      ...(workspace.evidence ? { evidence: workspace.evidence } : {}),
      ...(workspace.starter ? { starter: workspace.starter } : {}),
      project_dir: workspace.project_dir,
      capabilities: workspace.steps,
      ...focused,
      commands: buildCommands(workspace, focused),
    });
  }

  if (!equalValues([...catalogGoldens].toSorted(), [...actualGoldens].toSorted())) {
    throw new Error(
      `project-authoring golden catalog drift: catalog=${[...catalogGoldens].toSorted().join(',')} actual=${[...actualGoldens].toSorted().join(',')}`,
    );
  }
  selectPublicStarters(journeys);
  return journeys;
}

export async function buildProjectStarterMatrix(repoRoot = defaultRepoRoot) {
  return selectPublicStarters(await buildProjectAuthoringJourneyMatrix(repoRoot));
}

export async function generateProjectStarterMatrix(repoRoot = defaultRepoRoot) {
  const outputDir = resolve(docsRoot, 'src/data/generated');
  await mkdir(outputDir, { recursive: true });
  const journeys = await buildProjectAuthoringJourneyMatrix(repoRoot);
  const starters = selectPublicStarters(journeys);
  await Promise.all([
    writeFile(
      resolve(outputDir, 'project-authoring-journeys.json'),
      `${JSON.stringify(journeys, null, 2)}\n`,
    ),
    writeFile(
      resolve(outputDir, 'project-starters.json'),
      `${JSON.stringify(starters, null, 2)}\n`,
    ),
  ]);
  console.log(
    `Generated project-authoring command matrix for ${journeys.length} workspaces and ${starters.length} starters.`,
  );
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await generateProjectStarterMatrix();
}
