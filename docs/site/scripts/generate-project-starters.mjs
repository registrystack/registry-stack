import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';
import YAML from 'yaml';

const scriptDir = dirname(fileURLToPath(import.meta.url));
const docsRoot = resolve(scriptDir, '..');
const defaultRepoRoot = resolve(docsRoot, '../..');
const catalogRelative = 'crates/registryctl/tests/fixtures/project-authoring-journeys.yaml';
const goldenPrefix = 'crates/registryctl/tests/fixtures/project-authoring/';
const supportedSteps = ['init', 'editor', 'trace', 'watch', 'test', 'check', 'compare', 'build'];
const publicTemplates = [
  {
    id: 'http',
    label: 'HTTP',
    summary: 'One fixed bounded HTTP request with a closed response projection.',
    source: 'crates/registryctl/assets/project-starters/bounded-http',
    project_dir: 'http-project',
    focused_fixture_file: 'active.yaml',
  },
];
const publicTemplateOrder = publicTemplates.map(({ id }) => id);
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

function buildCommands(workspace, selection, { publicTemplate = false } = {}) {
  const commands = [];
  const project = workspace.project_dir;
  for (const step of workspace.steps) {
    switch (step) {
      case 'init':
        if (!publicTemplate) break;
        commands.push(
          `registryctl init ${project} --template ${workspace.starter}`,
        );
        break;
      case 'editor':
        commands.push(`registryctl -C ${project} tooling editor`);
        break;
      case 'trace':
        commands.push(
          `registryctl -C ${project} test --integration ${selection.integration} --fixture ${selection.fixture} --trace`,
        );
        break;
      case 'watch':
        commands.push(
          `registryctl -C ${project} test --integration ${selection.integration} --fixture ${selection.fixture} --watch`,
        );
        break;
      case 'test':
        commands.push(`registryctl -C ${project} test`);
        break;
      case 'check':
        commands.push(
          `registryctl -C ${project} check --environment ${workspace.environment}${workspace.check_explain ? ' --explain' : ''}`,
        );
        break;
      case 'compare':
        commands.push(
          `registryctl -C ${project} review compare --environment ${workspace.environment}`,
        );
        break;
      case 'build':
        commands.push(
          `registryctl -C ${project} build --environment ${workspace.environment}`,
        );
        break;
      default:
        throw new Error(`${workspace.id} contains unsupported step ${step}`);
    }
  }
  if (publicTemplate) {
    commands.push(
      `registryctl -C ${project} dev --detach`,
      `registryctl -C ${project} dev smoke`,
      `registryctl -C ${project} dev down`,
    );
  }
  return commands;
}

function selectPublicStarters(journeys) {
  const starterJourneys = journeys.filter((journey) => journey.starter);
  if (starterJourneys.length !== publicTemplateOrder.length) {
    throw new Error(
      `public template catalog must contain exactly ${publicTemplateOrder.length} entries`,
    );
  }
  const byStarter = new Map(
    starterJourneys.map((journey) => [journey.starter, journey]),
  );
  if (byStarter.size !== starterJourneys.length) {
    throw new Error('public starter catalog contains a duplicate starter');
  }
  if (
    publicTemplateOrder.some((starter) => !byStarter.has(starter))
  ) {
    throw new Error(
      `public template catalog must contain exactly ${publicTemplateOrder.join(', ')}`,
    );
  }
  return publicTemplateOrder.map((starter) => byStarter.get(starter));
}

async function buildPublicTemplateJourney(repoRoot, template) {
  const workspace = {
    id: template.id,
    starter: template.id,
    source: template.source,
    project_dir: template.project_dir,
    environment: 'local',
    check_explain: true,
    focused_fixture_file: template.focused_fixture_file,
    steps: supportedSteps,
  };
  validateCatalogCommandArguments(workspace);
  const projectRoot = resolve(repoRoot, template.source);
  const project = await readYaml(join(projectRoot, 'registry-stack.yaml'));
  const focused = await deriveFocusedSelection(projectRoot, project, workspace);
  return {
    ...template,
    classification: 'maintained',
    topology: deriveTopology(project, template.source),
    starter: template.id,
    environment: 'local',
    check_explain: true,
    capabilities: [...supportedSteps, 'dev'],
    ...focused,
    commands: buildCommands(workspace, focused, { publicTemplate: true }),
  };
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
    if (!workspace.steps.includes('check')) {
      throw new Error(`${workspace.id} must support check`);
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
    if (
      !authoredFixtures &&
      workspace.steps.some((step) => ['trace', 'watch'].includes(step))
    ) {
      throw new Error(
        `${workspace.id} is fixtureless and cannot document trace or watch`,
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
    const isPublicTemplate = publicTemplates.some(
      ({ id, source }) =>
        workspace.id === id &&
        workspace.starter === id &&
        workspace.source === source,
    );
    const commandWorkspace = {
      ...workspace,
      project_dir: isPublicTemplate ? workspace.project_dir : workspace.source,
    };
    journeys.push({
      id: workspace.id,
      label: workspace.label,
      summary: workspace.summary,
      source: workspace.source,
      classification: workspace.classification,
      ...(workspace.focus ? { focus: workspace.focus } : {}),
      topology,
      ...(workspace.evidence ? { evidence: workspace.evidence } : {}),
      ...(isPublicTemplate ? { starter: workspace.starter } : {}),
      project_dir: commandWorkspace.project_dir,
      capabilities: workspace.steps.filter((step) => step !== 'init'),
      ...focused,
      commands: buildCommands(commandWorkspace, focused),
    });
  }

  if (!equalValues([...catalogGoldens].toSorted(), [...actualGoldens].toSorted())) {
    throw new Error(
      `project-authoring golden catalog drift: catalog=${[...catalogGoldens].toSorted().join(',')} actual=${[...actualGoldens].toSorted().join(',')}`,
    );
  }
  for (const template of publicTemplates) {
    const generatedTemplate = await buildPublicTemplateJourney(repoRoot, template);
    const existing = journeys.findIndex(({ id }) => id === template.id);
    if (existing === -1) journeys.push(generatedTemplate);
    else journeys[existing] = { ...journeys[existing], ...generatedTemplate };
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
