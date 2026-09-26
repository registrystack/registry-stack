#!/usr/bin/env node
// Replay a tutorial page the way a reader follows it.
//
//   node scripts/run-tutorial.mjs [--dry-run] [--toolset breg|none] <page.mdx>
//
// The page is the specification (see tutorial-runner/page.mjs): its sh fences
// run in document order in one bash shell, from an empty reader directory
// outside the checkout, so a `cd` or a shell variable carries from one fence
// to the next as it does for a reader. The first failing command stops the
// journey. Once every fence has run, each test-expect block is compared with
// the output of the fence it follows (tutorial-runner/expect.mjs).
//
// The toolset puts the product binaries under test on PATH and stops any
// service the journey left running, whether it passed or failed.
//
// Exit status: 0 when the journey and every expectation pass, 1 when either
// fails, 2 for a usage, annotation, or toolset error, 130 when interrupted.

import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { checkExpectation } from './tutorial-runner/expect.mjs';
import { readJourney } from './tutorial-runner/page.mjs';
import { TOOLSETS, ToolsetError } from './tutorial-runner/toolsets.mjs';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const USAGE = 'usage: run-tutorial.mjs [--dry-run] [--toolset breg|none] <page.mdx>';

function usageError(message) {
  console.error(`${message}\n${USAGE}`);
  process.exit(2);
}

function parseArgs(argv) {
  const options = { dryRun: false, toolset: 'none', page: undefined };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--dry-run') options.dryRun = true;
    else if (arg === '--toolset') options.toolset = argv[++i];
    else if (arg.startsWith('-')) usageError(`unknown option: ${arg}`);
    else if (options.page === undefined) options.page = arg;
    else usageError(`unexpected argument: ${arg}`);
  }
  if (options.page === undefined) usageError('missing page');
  if (!Object.hasOwn(TOOLSETS, options.toolset ?? '')) {
    usageError(`unknown toolset: ${options.toolset} (expected ${Object.keys(TOOLSETS).join(' or ')})`);
  }
  return options;
}

const where = (step) => `line ${step.line}${step.heading ? ` (${step.heading})` : ''}`;
const quote = (text) => `'${text.replaceAll("'", "'\\''")}'`;
const outName = (index) => `${String(index).padStart(3, '0')}.out`;

function printPlan(steps) {
  for (const step of steps) {
    if (step.kind === 'run') console.log(`run   ${where(step)}: ${step.code.split('\n')[0]}`);
    else if (step.kind === 'skip') console.log(`skip  ${where(step)}: ${step.reason}`);
    else console.log(`expect line ${step.line}: checks line ${steps[step.runIndex].line}`);
  }
}

// One bash script for the whole journey. Each fence runs as a brace group, not
// a subshell, so its `cd` and assignments persist; its output goes to its own
// file outside the reader directory, then to the log. Standard input is
// closed, and nothing runs on a terminal, so tools print no colour codes.
function journeyScript(steps, outDir) {
  const lines = ['set -euo pipefail', "trap 'exit 130' HUP INT TERM", `OUT=${quote(outDir)}`];
  steps.forEach((step, index) => {
    if (step.kind === 'skip') {
      lines.push(`printf '%s\\n' ${quote(`skip  ${where(step)}: ${step.reason}`)}`);
    } else if (step.kind === 'run') {
      lines.push(`printf '\\n%s\\n' ${quote(`==> ${where(step)}`)}`);
      lines.push(`{\n${step.code}\n} >"$OUT/${outName(index)}" 2>&1 </dev/null`);
      lines.push(`cat "$OUT/${outName(index)}"`);
    }
  });
  lines.push('printf "\\n" >"$OUT/complete"');
  return `${lines.join('\n')}\n`;
}

function runScript(scriptPath, readerDir, binDir) {
  const env = { ...process.env, PATH: `${binDir}:${process.env.PATH}` };
  // A reader has no CARGO_TARGET_DIR pointing into this checkout.
  delete env.CARGO_TARGET_DIR;
  return new Promise((resolvePromise, reject) => {
    const child = spawn('bash', [scriptPath], { cwd: readerDir, env, stdio: ['ignore', 'inherit', 'inherit'] });
    child.on('error', reject);
    child.on('close', (code, signal) => resolvePromise(signal ? 130 : code));
  });
}

// The fence that stopped the journey is the last one whose output file exists.
async function stoppedAt(steps, outDir) {
  const names = (await readdir(outDir)).filter((name) => name.endsWith('.out')).sort();
  if (names.length === 0) return undefined;
  const last = names.at(-1);
  return { step: steps[Number.parseInt(last, 10)], output: await readFile(join(outDir, last), 'utf8') };
}

async function checkExpectations(steps, outDir) {
  let failures = 0;
  for (const step of steps.filter((candidate) => candidate.kind === 'expect')) {
    const checked = steps[step.runIndex];
    const output = await readFile(join(outDir, outName(step.runIndex)), 'utf8');
    const problem = checkExpectation(step.format, step.text, output);
    if (problem === null) {
      console.log(`expect line ${step.line}: ok`);
    } else {
      failures += 1;
      console.log(`expect line ${step.line}: output of the sh fence at line ${checked.line} does not match\n${problem}`);
    }
  }
  return failures;
}

async function replay(steps, toolset) {
  const workRoot = await realpath(await mkdtemp(join(tmpdir(), 'tutorial-run.')));
  const readerDir = join(workRoot, 'reader');
  const outDir = join(workRoot, 'out');
  const binDir = join(workRoot, 'bin');
  await Promise.all([mkdir(readerDir), mkdir(outDir), mkdir(binDir)]);

  let interrupted = false;
  const onSignal = () => {
    interrupted = true;
  };
  for (const signal of ['SIGHUP', 'SIGINT', 'SIGTERM']) process.on(signal, onSignal);

  let status = 1;
  let prepared = false;
  try {
    await toolset.prepare({ repoRoot: REPO_ROOT, binDir });
    prepared = true;
    const scriptPath = join(workRoot, 'journey.sh');
    await writeFile(scriptPath, journeyScript(steps, outDir));
    const code = await runScript(scriptPath, readerDir, binDir);
    if (interrupted || code === 130) {
      console.log('\ntutorial interrupted');
      status = 130;
    } else if (code !== 0 || !existsSync(join(outDir, 'complete'))) {
      const stop = await stoppedAt(steps, outDir);
      // The failing fence never reached its `cat`, so its output is shown here.
      if (stop) process.stdout.write(stop.output);
      const what = stop ? `the sh fence at ${where(stop.step)}` : 'the journey';
      console.log(`\n${what} ${code !== 0 ? `failed with exit status ${code}` : 'ended the shell early'}`);
      console.log('tutorial FAIL');
    } else {
      console.log('');
      const failures = await checkExpectations(steps, outDir);
      console.log(failures === 0 ? 'tutorial PASS' : 'tutorial FAIL');
      status = failures === 0 ? 0 : 1;
    }
  } catch (error) {
    if (!(error instanceof ToolsetError)) throw error;
    console.error(error.message);
    status = 2;
  } finally {
    const stoppedAll = prepared ? await toolset.teardown({ readerDir, binDir }) : true;
    if (stoppedAll) {
      await rm(workRoot, { recursive: true, force: true });
    } else {
      console.error(`keeping ${workRoot}: stop the sessions it holds, then remove it`);
      if (status === 0) status = 1;
    }
  }
  return status;
}

const options = parseArgs(process.argv.slice(2));
const { steps, errors } = readJourney(await readFile(options.page, 'utf8'));
if (errors.length > 0) {
  for (const error of errors) console.error(`${options.page}: ${error}`);
  process.exit(2);
}
if (options.dryRun) {
  printPlan(steps);
  process.exit(0);
}
process.exit(await replay(steps, TOOLSETS[options.toolset]));
