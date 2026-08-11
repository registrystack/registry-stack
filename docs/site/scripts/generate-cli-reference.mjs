import { execFile } from 'node:child_process';
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

const execFileAsync = promisify(execFile);
const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = dirname(scriptPath);
const defaultDocsRoot = resolve(scriptDir, '..');
const defaultRepoRoot = resolve(defaultDocsRoot, '../..');

export const schemaVersion = 'registry.cli-reference/v1';
export const expectedBinaries = [
  'evidence',
  'evidence-oid4vci',
  'evidencectl',
  'mint',
  'relay',
  'relayctl',
];

const generatedTree = 'src/content/docs/reference/cli';
const generatedData = 'src/data/generated/cli-reference.json';
const hiddenCommands = new Set([
  '__dev-supervisor',
  'bundle-check',
  'bundle-evaluate',
  'prepare-local-relying-procedure',
  'local-audit-last-operation',
]);
const groups = [
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
      'default_values',
      'possible_values',
      'environment',
    ]),
    label,
  );
  nonempty(argument.display, `${label}.display`);
  if (typeof argument.description !== 'string') {
    throw new Error(`${label}.description must be a string`);
  }
  if (typeof argument.always_required !== 'boolean') {
    throw new Error(`${label}.always_required must be a boolean`);
  }
  stringArray(argument.default_values, `${label}.default_values`);
  stringArray(argument.possible_values, `${label}.possible_values`);
  if (argument.environment !== null && typeof argument.environment !== 'string') {
    throw new Error(`${label}.environment must be a string or null`);
  }
}

function validateConstraint(constraint, label) {
  exactKeys(constraint, new Set(['kind', 'when', 'arguments']), label);
  if (!['required_one_of', 'requires_all'].includes(constraint.kind)) {
    throw new Error(`${label}.kind must be required_one_of or requires_all`);
  }
  if (constraint.when !== null && typeof constraint.when !== 'string') {
    throw new Error(`${label}.when must be a string or null`);
  }
  if (constraint.kind === 'required_one_of' && constraint.when !== null) {
    throw new Error(`${label}.when must be null for required_one_of`);
  }
  if (constraint.kind === 'requires_all') {
    nonempty(constraint.when, `${label}.when`);
  }
  stringArray(constraint.arguments, `${label}.arguments`);
  if (constraint.arguments.length === 0) {
    throw new Error(`${label}.arguments must not be empty`);
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
  exactKeys(catalog, new Set(['schema_version', 'binaries']), 'CLI reference catalog');
  if (catalog.schema_version !== schemaVersion) {
    throw new Error(`CLI reference catalog must use ${schemaVersion}`);
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

function frontmatter(title, description) {
  return `---
title: ${JSON.stringify(title)}
description: ${JSON.stringify(description)}
status: current
owner: registry-docs
source_repos:
  - registry-stack
last_reviewed: "2026-08-11"
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
  const rows = entries.map((argument) =>
    [
      inlineCode(argument.display),
      argument.always_required ? 'Yes' : 'No',
      values(argument.default_values),
      values(argument.possible_values),
      argument.environment === null ? 'n/a' : inlineCode(argument.environment),
      tableText(argument.description || 'n/a'),
    ].join(' | '),
  );
  return `
## ${heading}

| ${firstColumn} | Always required | Default | Values | Environment | Description |
| --- | --- | --- | --- | --- | --- |
${rows.map((row) => `| ${row} |`).join('\n')}
`;
}

function constraintTable(constraints) {
  if (constraints.length === 0) return '';
  const rows = constraints.map((constraint) => {
    if (constraint.kind === 'required_one_of') {
      const requirement =
        constraint.arguments.length === 1
          ? `${inlineCode(constraint.arguments[0])} is required.`
          : `One of ${values(constraint.arguments)} is required.`;
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

function renderCommand(command) {
  const path = commandPath(command);
  const lines = [
    frontmatter(
      `${command.invocation} command reference`,
      `Generated syntax and options for ${command.invocation}.`,
    ),
    '',
    '{/* Generated from Clap command definitions by scripts/generate-cli-reference.mjs. Run npm run generate. */}',
    '',
    sentence(command.about),
    '',
    '## Contract status',
    '',
    'This page is generated from the public Clap command tree. Hidden implementation commands are omitted.',
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

function renderIndex(catalog) {
  const binaries = new Map(catalog.binaries.map((binary) => [binary.name, binary]));
  const lines = [
    frontmatter(
      'Command-line interfaces',
      'Generated command references for released Registry Relay and Evidence binaries.',
    ),
    '',
    '{/* Generated from Clap command definitions by scripts/generate-cli-reference.mjs. Run npm run generate. */}',
    '',
    'Use these generated references for exact command syntax, arguments, options, defaults, and environment bindings.',
    '',
    '## Contract status',
    '',
    'The pages in this section are generated from each released binary\'s public Clap command tree. Hidden implementation commands are omitted.',
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

export function renderCatalog(catalog) {
  validateCatalog(catalog);
  const files = new Map([['index.mdx', renderIndex(catalog)]]);
  const add = (command) => {
    files.set(commandPath(command), renderCommand(command));
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
  const pages = renderCatalog(catalog);
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
