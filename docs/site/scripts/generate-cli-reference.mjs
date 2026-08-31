import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  unlink,
  writeFile,
} from 'node:fs/promises';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import YAML from 'yaml';

const execFileAsync = promisify(execFile);
const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = dirname(scriptPath);
const defaultDocsRoot = resolve(scriptDir, '..');
const defaultRepoRoot = resolve(defaultDocsRoot, '../..');

export const schemaVersion = 'registry.cli-reference/v2';
export const reviewSchemaVersion = 'registry.cli-reference-review/v2';
export const expectedBinaries = [
  'evidence',
  'evidence-oid4vci',
  'evidencectl',
  'mint',
  'registry-server',
  'registry-serverctl',
  'relay',
  'relayctl',
];

const generatedTree = 'src/content/docs/reference/cli';
const generatedData = 'src/data/generated/cli-reference.json';
const reviewMetadataFile = 'src/data/cli-reference.yaml';
const hiddenCommands = new Set([
  '__dev-supervisor',
  'bundle-check',
  'bundle-evaluate',
  'prepare-local-relying-procedure',
  'local-audit-last-operation',
]);
const groups = [
  { title: 'Registry Server', binaries: ['registry-server', 'registry-serverctl'] },
  { title: 'Registry Relay', binaries: ['relay', 'relayctl'] },
  { title: 'Evidence Gateway', binaries: ['evidence', 'evidencectl'] },
  {
    title: 'Supporting Evidence services',
    binaries: ['mint', 'evidence-oid4vci'],
  },
];

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    throw new Error(`${label} must contain exactly ${wanted.join(', ')}`);
  }
}

function nonempty(value, label) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new Error(`${label} must be a non-empty string`);
  }
}

function stringArray(value, label) {
  if (!Array.isArray(value) || !value.every((entry) => typeof entry === 'string')) {
    throw new Error(`${label} must be an array of strings`);
  }
}

function validateArgument(argument, label) {
  exactKeys(
    argument,
    new Set([
      'display',
      'description',
      'always_required',
      'repeatable',
      'default_values',
      'possible_values',
      'environment',
    ]),
    label,
  );
  nonempty(argument.display, `${label}.display`);
  nonempty(argument.description, `${label}.description`);
  if (typeof argument.always_required !== 'boolean') {
    throw new Error(`${label}.always_required must be a boolean`);
  }
  if (typeof argument.repeatable !== 'boolean') {
    throw new Error(`${label}.repeatable must be a boolean`);
  }
  stringArray(argument.default_values, `${label}.default_values`);
  stringArray(argument.possible_values, `${label}.possible_values`);
  if (argument.environment !== null && typeof argument.environment !== 'string') {
    throw new Error(`${label}.environment must be a string or null`);
  }
}

function validateConstraint(constraint, label) {
  exactKeys(constraint, new Set(['kind', 'when', 'arguments']), label);
  if (
    ![
      'required_exactly_one',
      'required_one_or_more',
      'requires_all',
      'mutually_exclusive',
    ].includes(
      constraint.kind,
    )
  ) {
    throw new Error(
      `${label}.kind must be required_exactly_one, required_one_or_more, requires_all, or mutually_exclusive`,
    );
  }
  if (constraint.when !== null && typeof constraint.when !== 'string') {
    throw new Error(`${label}.when must be a string or null`);
  }
  if (constraint.kind.startsWith('required_') && constraint.when !== null) {
    throw new Error(`${label}.when must be null for required groups`);
  }
  if (constraint.kind === 'requires_all') {
    nonempty(constraint.when, `${label}.when`);
  }
  stringArray(constraint.arguments, `${label}.arguments`);
  if (constraint.arguments.length === 0) {
    throw new Error(`${label}.arguments must not be empty`);
  }
  if (constraint.kind === 'mutually_exclusive') {
    if (constraint.when !== null) {
      throw new Error(`${label}.when must be null for mutually exclusive arguments`);
    }
    if (constraint.arguments.length !== 2) {
      throw new Error(`${label}.arguments must contain exactly two mutually exclusive arguments`);
    }
    const sorted = [...constraint.arguments].sort();
    if (
      sorted[0] === sorted[1] ||
      JSON.stringify(sorted) !== JSON.stringify(constraint.arguments)
    ) {
      throw new Error(`${label}.arguments must be distinct and sorted`);
    }
  }
}

function validateCommand(command, parent, invocations) {
  const label = parent ? `${parent}.subcommands[${command?.name ?? '?'}]` : 'binary';
  exactKeys(
    command,
    new Set([
      'name',
      'invocation',
      'about',
      'long_about',
      'usage',
      'arguments',
      'options',
      'constraints',
      'subcommands',
    ]),
    label,
  );
  nonempty(command.name, `${label}.name`);
  if (!/^[a-z0-9][a-z0-9-]*$/u.test(command.name)) {
    throw new Error(`${label}.name is not a safe command segment`);
  }
  if (hiddenCommands.has(command.name)) {
    throw new Error(`${label} publishes hidden command ${command.name}`);
  }
  const expectedInvocation = parent ? `${parent} ${command.name}` : command.name;
  if (command.invocation !== expectedInvocation) {
    throw new Error(`${label}.invocation must be ${expectedInvocation}`);
  }
  if (invocations.has(command.invocation)) {
    throw new Error(`${label}.invocation is duplicated`);
  }
  invocations.add(command.invocation);
  nonempty(command.about, `${label}.about`);
  if (command.long_about !== null && typeof command.long_about !== 'string') {
    throw new Error(`${label}.long_about must be a string or null`);
  }
  nonempty(command.usage, `${label}.usage`);
  for (const field of ['arguments', 'options', 'constraints', 'subcommands']) {
    if (!Array.isArray(command[field])) {
      throw new Error(`${label}.${field} must be an array`);
    }
  }
  command.arguments.forEach((argument, index) =>
    validateArgument(argument, `${label}.arguments[${index}]`),
  );
  command.options.forEach((argument, index) =>
    validateArgument(argument, `${label}.options[${index}]`),
  );
  command.constraints.forEach((constraint, index) =>
    validateConstraint(constraint, `${label}.constraints[${index}]`),
  );
  command.subcommands.forEach((subcommand) =>
    validateCommand(subcommand, command.invocation, invocations),
  );
}

export function validateCatalog(catalog) {
  exactKeys(
    catalog,
    new Set(['schema_version', 'source_version', 'binaries']),
    'CLI reference catalog',
  );
  if (catalog.schema_version !== schemaVersion) {
    throw new Error(`CLI reference catalog must use ${schemaVersion}`);
  }
  nonempty(catalog.source_version, 'CLI reference catalog.source_version');
  if (!/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u.test(catalog.source_version)) {
    throw new Error('CLI reference catalog.source_version must be a semantic version');
  }
  if (!Array.isArray(catalog.binaries)) {
    throw new Error('CLI reference catalog binaries must be an array');
  }
  const names = catalog.binaries.map((binary) => binary.name);
  if (JSON.stringify(names) !== JSON.stringify(expectedBinaries)) {
    throw new Error(`CLI reference binaries must be ${expectedBinaries.join(', ')}`);
  }
  const invocations = new Set();
  catalog.binaries.forEach((binary) => validateCommand(binary, null, invocations));
  return catalog;
}

export function catalogDigest(catalog) {
  validateCatalog(catalog);
  return createHash('sha256').update(JSON.stringify(catalog)).digest('hex');
}

function validCalendarDate(value) {
  if (!/^\d{4}-\d{2}-\d{2}$/u.test(value)) return false;
  const [year, month, day] = value.split('-').map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));
  return date.getUTCFullYear() === year
    && date.getUTCMonth() === month - 1
    && date.getUTCDate() === day;
}

export function validateReviewMetadata(metadata, sourceVersion, sourceDigest) {
  exactKeys(
    metadata,
    new Set([
      'schema_version',
      'status',
      'last_reviewed',
      'reviewed_source_version',
      'reviewed_catalog_sha256',
    ]),
    'CLI reference review metadata',
  );
  if (metadata.schema_version !== reviewSchemaVersion) {
    throw new Error(`CLI reference review metadata must use ${reviewSchemaVersion}`);
  }
  if (!['draft', 'current'].includes(metadata.status)) {
    throw new Error('CLI reference review metadata.status must be draft or current');
  }
  nonempty(metadata.last_reviewed, 'CLI reference review metadata.last_reviewed');

  if (metadata.last_reviewed === 'unreviewed') {
    if (
      metadata.status !== 'draft'
      || metadata.reviewed_source_version !== null
      || metadata.reviewed_catalog_sha256 !== null
    ) {
      throw new Error(
        'unreviewed CLI reference metadata must be draft with no reviewed source version or catalog digest',
      );
    }
    return metadata;
  }

  if (!validCalendarDate(metadata.last_reviewed)) {
    throw new Error('CLI reference review metadata.last_reviewed must be unreviewed or YYYY-MM-DD');
  }
  nonempty(
    metadata.reviewed_source_version,
    'CLI reference review metadata.reviewed_source_version',
  );
  if (metadata.reviewed_source_version !== sourceVersion) {
    throw new Error(
      `CLI reference review metadata covers ${metadata.reviewed_source_version}, not ${sourceVersion}`,
    );
  }
  if (!/^[0-9a-f]{64}$/u.test(metadata.reviewed_catalog_sha256 ?? '')) {
    throw new Error('CLI reference review metadata.reviewed_catalog_sha256 must be a lowercase SHA-256 digest');
  }
  if (metadata.reviewed_catalog_sha256 !== sourceDigest) {
    throw new Error('CLI reference review metadata does not cover the current command catalog digest');
  }
  return metadata;
}

async function loadReviewMetadata(docsRoot, sourceVersion, sourceDigest) {
  const path = resolve(docsRoot, reviewMetadataFile);
  let metadata;
  try {
    metadata = YAML.parse(await readFile(path, 'utf8'));
  } catch (error) {
    throw new Error(`${reviewMetadataFile} could not be read: ${error.message}`);
  }
  return validateReviewMetadata(metadata, sourceVersion, sourceDigest);
}

async function executeCatalog(repoRoot) {
  const environment = {
    ...process.env,
    CARGO_INCREMENTAL: '0',
    CARGO_PROFILE_DEV_DEBUG: '0',
    CARGO_PROFILE_TEST_DEBUG: '0',
  };
  try {
    const { stdout } = await execFileAsync(
      'cargo',
      ['run', '--locked', '--quiet', '-p', 'registry-cli-docs'],
      {
        cwd: repoRoot,
        encoding: 'utf8',
        env: environment,
        maxBuffer: 16 * 1024 * 1024,
      },
    );
    return stdout;
  } catch (error) {
    const stderr = typeof error?.stderr === 'string' ? error.stderr.trim() : '';
    throw new Error(`CLI reference collector failed: ${stderr || error.message}`);
  }
}

function sentence(value) {
  return /[.!?]$/u.test(value) ? value : `${value}.`;
}

function inlineCode(value) {
  return value.includes('`') ? `\`\`${value}\`\`` : `\`${value}\``;
}

function tableText(value) {
  return value.replaceAll('|', '\\|').replaceAll('\n', ' ');
}

function values(values) {
  return values.length === 0 ? 'n/a' : values.map(inlineCode).join(', ');
}

function frontmatter(title, description, reviewMetadata) {
  const draft = reviewMetadata.status === 'draft' ? '\ndraft: true' : '';
  return `---
title: ${JSON.stringify(title)}
description: ${JSON.stringify(description)}
status: ${reviewMetadata.status}${draft}
owner: registry-docs
source_repos:
  - registry-stack
last_reviewed: ${JSON.stringify(reviewMetadata.last_reviewed)}
doc_type: reference
locale: en
standards_referenced: []
---`;
}

function commandPath(command) {
  const [binary, ...segments] = command.invocation.split(' ');
  return segments.length === 0
    ? `${binary}.mdx`
    : join(binary, ...segments.slice(0, -1), `${segments.at(-1)}.mdx`);
}

function routePath(sourcePath) {
  return sourcePath === 'index.mdx' ? '' : sourcePath.slice(0, -'.mdx'.length);
}

function commandLink(from, command) {
  const source = routePath(from);
  const target = routePath(commandPath(command));
  let path = relative(source, target).split(sep).join('/');
  if (!path.startsWith('.')) path = `./${path}`;
  return `${path}/`;
}

function argumentTable(entries, heading, firstColumn) {
  if (entries.length === 0) return '';
  const showsRepeatability = entries.some((argument) => argument.repeatable);
  const rows = entries.map((argument) =>
    [
      inlineCode(argument.display),
      argument.always_required ? 'Yes' : 'No',
      ...(showsRepeatability ? [argument.repeatable ? 'Yes' : 'No'] : []),
      values(argument.default_values),
      values(argument.possible_values),
      argument.environment === null ? 'n/a' : inlineCode(argument.environment),
      tableText(argument.description || 'n/a'),
    ].join(' | '),
  );
  const columns = [firstColumn, 'Always required'];
  if (showsRepeatability) columns.push('Repeatable');
  columns.push('Default', 'Values', 'Environment', 'Description');
  return `
## ${heading}

| ${columns.join(' | ')} |
| ${columns.map(() => '---').join(' | ')} |
${rows.map((row) => `| ${row} |`).join('\n')}
`;
}

function constraintTable(constraints) {
  if (constraints.length === 0) return '';
  const rows = constraints.map((constraint) => {
    if (constraint.kind === 'mutually_exclusive') {
      const [left, right] = constraint.arguments.map(inlineCode);
      return `| Command invocation | ${left} and ${right} cannot be used together. |`;
    }
    if (constraint.kind === 'required_exactly_one') {
      const requirement =
        constraint.arguments.length === 1
          ? `${inlineCode(constraint.arguments[0])} is required.`
          : `Exactly one of ${values(constraint.arguments)} is required.`;
      return `| Command invocation | ${requirement} |`;
    }
    if (constraint.kind === 'required_one_or_more') {
      const requirement =
        constraint.arguments.length === 1
          ? `${inlineCode(constraint.arguments[0])} is required.`
          : `One or more of ${values(constraint.arguments)} are required.`;
      return `| Command invocation | ${requirement} |`;
    }
    const requirement =
      constraint.arguments.length === 1
        ? `${inlineCode(constraint.arguments[0])} is required.`
        : `All of ${values(constraint.arguments)} are required.`;
    return `| ${inlineCode(constraint.when)} is present | ${requirement} |`;
  });
  return `
## Constraints

| Condition | Requirement |
| --- | --- |
${rows.join('\n')}
`;
}

function renderCommand(command, catalog, reviewMetadata, sourceDigest) {
  const path = commandPath(command);
  const lines = [
    frontmatter(
      `${command.invocation} command reference`,
      `Generated syntax and options for ${command.invocation}.`,
      reviewMetadata,
    ),
    '',
    '{/* Generated from Clap command definitions by scripts/generate-cli-reference.mjs. Run npm run generate. */}',
    '',
    sentence(command.about),
    '',
    '## Contract status',
    '',
    `This page is generated from the public Clap command tree for Registry Stack source version ${inlineCode(catalog.source_version)} and catalog SHA-256 ${inlineCode(sourceDigest)}. Hidden implementation commands are omitted.`,
  ];
  if (command.long_about !== null) {
    lines.push('', '## Description', '', sentence(command.long_about));
  }
  lines.push('', '## Usage', '', '```text', command.usage, '```');
  lines.push(constraintTable(command.constraints));

  if (command.subcommands.length > 0) {
    lines.push(
      '',
      '## Commands',
      '',
      '| Command | Description |',
      '| --- | --- |',
      ...command.subcommands.map(
        (subcommand) =>
          `| [${inlineCode(subcommand.name)}](${commandLink(path, subcommand)}) | ${tableText(subcommand.about)} |`,
      ),
    );
  }
  lines.push(argumentTable(command.arguments, 'Arguments', 'Argument'));
  lines.push(argumentTable(command.options, 'Options', 'Option'));
  lines.push(
    '## Generation contract',
    '',
    'Run `npm run generate` from `docs/site` after changing a public command, argument, option, default, environment binding, or help description.',
    '',
  );
  const rendered = lines
    .filter((line, index) => line !== '' || lines[index - 1] !== '')
    .join('\n')
    .replace(/\n{3,}/gu, '\n\n');
  return `${rendered.trimEnd()}\n`;
}

function renderIndex(catalog, reviewMetadata, sourceDigest) {
  const binaries = new Map(catalog.binaries.map((binary) => [binary.name, binary]));
  const lines = [
    frontmatter(
      'Command-line interfaces',
      'Generated command references for Registry Relay and Evidence binaries.',
      reviewMetadata,
    ),
    '',
    '{/* Generated from Clap command definitions by scripts/generate-cli-reference.mjs. Run npm run generate. */}',
    '',
    'Use these generated references for exact command syntax, arguments, options, defaults, and environment bindings.',
    '',
    '## Contract status',
    '',
    `The pages in this section are generated from the public Clap command trees for Registry Stack source version ${inlineCode(catalog.source_version)} and catalog SHA-256 ${inlineCode(sourceDigest)}. Hidden implementation commands are omitted.`,
  ];
  for (const group of groups) {
    lines.push('', `## ${group.title}`, '', '| Binary | Description |', '| --- | --- |');
    for (const name of group.binaries) {
      const binary = binaries.get(name);
      lines.push(`| [${inlineCode(name)}](./${name}/) | ${tableText(binary.about)} |`);
    }
  }
  lines.push(
    '',
    '## Generation contract',
    '',
    'Run `npm run generate` from `docs/site` after changing a supported command-line surface. The docs check compares the generated pages and JSON catalog with the current Clap definitions.',
    '',
  );
  return `${lines.join('\n').trimEnd()}\n`;
}

export function renderCatalog(catalog, reviewMetadata) {
  validateCatalog(catalog);
  const sourceDigest = catalogDigest(catalog);
  validateReviewMetadata(reviewMetadata, catalog.source_version, sourceDigest);
  const files = new Map([['index.mdx', renderIndex(catalog, reviewMetadata, sourceDigest)]]);
  const add = (command) => {
    files.set(commandPath(command), renderCommand(command, catalog, reviewMetadata, sourceDigest));
    command.subcommands.forEach(add);
  };
  catalog.binaries.forEach(add);
  return files;
}

async function filesBelow(root, prefix = '') {
  const found = new Map();
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    const relativePath = join(prefix, entry.name).split(sep).join('/');
    if (entry.isDirectory()) {
      for (const [name, contents] of await filesBelow(path, relativePath)) {
        found.set(name, contents);
      }
    } else if (entry.isFile()) {
      found.set(relativePath, await readFile(path, 'utf8'));
    }
  }
  return found;
}

function compareFiles(actual, expected, label) {
  const actualNames = [...actual.keys()].sort();
  const expectedNames = [...expected.keys()].sort();
  if (JSON.stringify(actualNames) !== JSON.stringify(expectedNames)) {
    throw new Error(`${label} file set is stale; run npm run generate`);
  }
  for (const name of expectedNames) {
    if (actual.get(name) !== expected.get(name)) {
      throw new Error(`${label}/${name} is stale; run npm run generate`);
    }
  }
}

async function writeTree(root, files) {
  const parent = dirname(root);
  await mkdir(parent, { recursive: true });
  const staging = await mkdtemp(join(parent, '.cli-reference-'));
  try {
    for (const [name, contents] of files) {
      const target = join(staging, name);
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, contents, 'utf8');
    }
    await rm(root, { recursive: true, force: true });
    await rename(staging, root);
  } catch (error) {
    await rm(staging, { recursive: true, force: true });
    throw error;
  }
}

async function writeAtomic(path, contents) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}`;
  try {
    await writeFile(temporary, contents, 'utf8');
    await rename(temporary, path);
  } finally {
    await unlink(temporary).catch(() => {});
  }
}

export async function generateCliReference(
  docsRoot = defaultDocsRoot,
  repoRoot = defaultRepoRoot,
  { check = false, execute = executeCatalog } = {},
) {
  const first = await execute(repoRoot);
  const second = await execute(repoRoot);
  if (first !== second) {
    throw new Error('CLI reference collector is not byte deterministic');
  }
  let catalog;
  try {
    catalog = JSON.parse(first);
  } catch (error) {
    throw new Error(`CLI reference collector did not emit JSON: ${error.message}`);
  }
  validateCatalog(catalog);
  const reviewMetadata = await loadReviewMetadata(
    docsRoot,
    catalog.source_version,
    catalogDigest(catalog),
  );
  const pages = renderCatalog(catalog, reviewMetadata);
  const data = `${JSON.stringify(catalog, null, 2)}\n`;
  const treePath = resolve(docsRoot, generatedTree);
  const dataPath = resolve(docsRoot, generatedData);

  if (check) {
    compareFiles(await filesBelow(treePath), pages, generatedTree);
    if ((await readFile(dataPath, 'utf8')) !== data) {
      throw new Error(`${generatedData} is stale; run npm run generate`);
    }
    return;
  }
  await writeTree(treePath, pages);
  await writeAtomic(dataPath, data);
}

if (process.argv[1] === scriptPath) {
  const unknown = process.argv.slice(2).filter((argument) => argument !== '--check');
  if (unknown.length > 0) {
    throw new Error(`unknown argument ${unknown[0]}`);
  }
  await generateCliReference(defaultDocsRoot, defaultRepoRoot, {
    check: process.argv.includes('--check'),
  });
}
