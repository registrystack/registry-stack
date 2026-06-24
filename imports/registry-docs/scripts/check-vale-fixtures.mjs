import { spawn } from 'node:child_process';
import { access, readdir, readFile } from 'node:fs/promises';
import { basename, join, relative, resolve } from 'node:path';

const rootDir = resolve(import.meta.dirname, '..');
const fixturesDir = join(rootDir, 'fixtures', 'vale');
const valePackageDir = join(rootDir, 'node_modules', '@vvago', 'vale');
const valeBin = join(valePackageDir, 'bin', process.platform === 'win32' ? 'vale.exe' : 'vale');
const fixturePattern = /\.mdx?$/;
const directivePattern = /<!--\s*ValeFixture\s+expect:\s*([\s\S]*?)-->/i;

async function ensureVale() {
  try {
    await access(valeBin);
  } catch {
    await new Promise((resolveRun, rejectRun) => {
      const child = spawn(process.execPath, [join(valePackageDir, 'index.js')], {
        cwd: rootDir,
        stdio: 'inherit',
      });

      child.on('error', rejectRun);
      child.on('close', (code) => {
        if (code === 0) {
          resolveRun();
        } else {
          rejectRun(new Error(`Unable to install Vale binary, installer exited with ${code ?? 1}`));
        }
      });
    });
  }
}

async function collectFixtures(dir) {
  let entries;

  try {
    entries = await readdir(dir, { withFileTypes: true });
  } catch (error) {
    if (error?.code === 'ENOENT') {
      return [];
    }

    throw error;
  }

  const fixtures = [];

  for (const entry of entries) {
    const path = join(dir, entry.name);

    if (entry.isDirectory()) {
      fixtures.push(...await collectFixtures(path));
    } else if (entry.isFile() && fixturePattern.test(entry.name)) {
      fixtures.push(path);
    }
  }

  return fixtures.sort((left, right) => left.localeCompare(right));
}

function parseExpectedChecks(source, filePath) {
  const directive = source.match(directivePattern);

  if (!directive) {
    throw new Error(`${relative(rootDir, filePath)} is missing <!-- ValeFixture expect: Rule.ID -->`);
  }

  const checks = directive[1]
    .split(/[\s,]+/)
    .map((check) => check.trim())
    .filter(Boolean);

  if (checks.length === 0) {
    throw new Error(`${relative(rootDir, filePath)} has an empty ValeFixture expect directive`);
  }

  return [...new Set(checks)].sort();
}

function runVale(files) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(
      valeBin,
      [
        '--output=JSON',
        '--config=.vale.ini',
        '--no-global',
        '--ignore-syntax',
        ...files.map((file) => relative(rootDir, file)),
      ],
      {
        cwd: rootDir,
        env: { ...process.env, NO_COLOR: '1' },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );

    let stdout = '';
    let stderr = '';

    child.stdout.setEncoding('utf8');
    child.stderr.setEncoding('utf8');
    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('error', rejectRun);
    child.on('close', (code) => {
      resolveRun({ code, stdout, stderr });
    });
  });
}

function parseValeOutput(stdout) {
  const trimmed = stdout.trim();

  if (trimmed.length === 0) {
    return {};
  }

  try {
    return JSON.parse(trimmed);
  } catch (error) {
    throw new Error(`Vale did not return JSON output: ${error.message}`);
  }
}

function checksForFile(alertsByPath, filePath) {
  const expectedBasename = basename(filePath);
  const expectedRelative = relative(rootDir, filePath);
  const matches = Object.entries(alertsByPath)
    .filter(([alertPath]) => {
      const normalized = alertPath.replaceAll('\\', '/');

      return normalized === expectedRelative
        || normalized.endsWith(`/${expectedRelative}`)
        || basename(normalized) === expectedBasename;
    })
    .flatMap(([, alerts]) => Array.isArray(alerts) ? alerts : []);

  return [...new Set(matches.map((alert) => alert?.Check).filter(Boolean))].sort();
}

function difference(left, right) {
  const rightSet = new Set(right);

  return left.filter((item) => !rightSet.has(item));
}

function formatList(items) {
  return items.length > 0 ? items.join(', ') : '(none)';
}

const fixtureFiles = await collectFixtures(fixturesDir);

if (fixtureFiles.length === 0) {
  console.log('No Vale fixtures found.');
  process.exit(0);
}

const expectations = new Map();

for (const file of fixtureFiles) {
  expectations.set(file, parseExpectedChecks(await readFile(file, 'utf8'), file));
}

await ensureVale();

const result = await runVale(fixtureFiles);
const alertsByPath = parseValeOutput(result.stdout);
const failures = [];

for (const file of fixtureFiles) {
  const expected = expectations.get(file);
  const actual = checksForFile(alertsByPath, file);
  const missing = difference(expected, actual);
  const unexpected = difference(actual, expected);

  if (missing.length > 0 || unexpected.length > 0) {
    failures.push([
      relative(rootDir, file),
      `expected: ${formatList(expected)}`,
      `actual:   ${formatList(actual)}`,
      missing.length > 0 ? `missing:  ${formatList(missing)}` : null,
      unexpected.length > 0 ? `extra:    ${formatList(unexpected)}` : null,
    ].filter(Boolean).join('\n  '));
  }
}

if (result.code !== 0 && Object.keys(alertsByPath).length === 0) {
  failures.push(`Vale exited with ${result.code} and produced no JSON alerts.`);
}

if (failures.length > 0) {
  console.error(`Vale fixture check failed:\n\n${failures.join('\n\n')}`);

  if (result.stderr.trim().length > 0) {
    console.error(`\nVale stderr:\n${result.stderr.trim()}`);
  }

  process.exit(1);
}

console.log(`Vale fixture check passed for ${fixtureFiles.length} fixture${fixtureFiles.length === 1 ? '' : 's'}.`);
