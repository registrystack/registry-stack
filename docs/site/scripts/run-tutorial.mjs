#!/usr/bin/env node
// Replay a tutorial page the way a reader follows it.
//
//   node scripts/run-tutorial.mjs [--dry-run] [--toolset breg|none] <page.mdx>...
//
// The page is the specification (see tutorial-runner/page.mjs): its sh fences
// run in document order in one bash shell, from an empty reader directory
// outside the checkout, so a `cd` or a shell variable carries from one fence
// to the next as it does for a reader. The first failing command stops the
// journey. A test-edit block changes its file between fences
// (tutorial-runner/edit.mjs). Once every fence has run, each test-expect block
// is compared with the output of the fence it follows
// (tutorial-runner/expect.mjs).
//
// Several pages replay in the order given, in the same reader directory, each
// in a fresh shell: a tutorial that continues from another starts where the
// reader left off, in a new terminal.
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
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { checkExpectation } from './tutorial-runner/expect.mjs';
import { readJourney } from './tutorial-runner/page.mjs';
import { TOOLSETS, ToolsetError } from './tutorial-runner/toolsets.mjs';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const USAGE = 'usage: run-tutorial.mjs [--dry-run] [--toolset breg|none] <page.mdx>...';
const APPLY_EDIT = join(dirname(fileURLToPath(import.meta.url)), 'tutorial-runner/apply-edit.mjs');

function usageError(message) {
  console.error(`${message}\n${USAGE}`);
  process.exit(2);
}

function parseArgs(argv) {
  const options = { dryRun: false, toolset: 'none', pages: [] };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--dry-run') options.dryRun = true;
    else if (arg === '--toolset') options.toolset = argv[++i];
    else if (arg.startsWith('-')) usageError(`unknown option: ${arg}`);
    else options.pages.push(arg);
  }
  if (options.pages.length === 0) usageError('missing page');
  if (!Object.hasOwn(TOOLSETS, options.toolset ?? '')) {
    usageError(`unknown toolset: ${options.toolset} (expected ${Object.keys(TOOLSETS).join(' or ')})`);
  }
  return options;
}

const at = (step) => `${step.page ? `${step.page} ` : ''}line ${step.line}`;
const where = (step) => `${at(step)}${step.heading ? ` (${step.heading})` : ''}`;
const blockName = (step) => (step.kind === 'edit' ? 'the edit' : 'the sh fence');
const quote = (text) => `'${text.replaceAll("'", "'\\''")}'`;
const outName = (index) => `${String(index).padStart(3, '0')}.out`;

function printPlan(steps) {
  for (const step of steps) {
    const exit = step.exit === undefined ? '' : ` (expects exit ${step.exit})`;
    if (step.kind === 'run') console.log(`run   ${where(step)}: ${step.code.split('\n')[0]}${exit}`);
    else if (step.kind === 'skip') console.log(`skip  ${where(step)}: ${step.reason}`);
    else if (step.kind === 'edit') console.log(`edit  ${where(step)}: ${step.path}`);
    else console.log(`expect ${at(step)}: checks line ${steps[step.runIndex].line}`);
  }
}

// One bash script for the whole journey, one subshell per page. Each fence
// runs as a brace group, not a subshell, so its `cd` and assignments persist
// to the end of its page; its output goes to its own file outside the reader
// directory, then to the log. Standard input is closed, and nothing runs on a
// terminal, so tools print no colour codes. An edit runs apply-edit.mjs from
// the shell's current directory, where the reader would open the file.
async function journeyScript(pages, outDir) {
  const lines = ['set -euo pipefail', "trap 'exit 130' HUP INT TERM", `OUT=${quote(outDir)}`];
  let index = 0;
  for (const steps of pages) {
    lines.push('(');
    for (const step of steps) {
      const out = `"$OUT/${outName(index)}"`;
      if (step.kind === 'skip') {
        lines.push(`printf '%s\\n' ${quote(`skip  ${where(step)}: ${step.reason}`)}`);
      } else if (step.kind === 'edit') {
        const request = join(outDir, `${String(index).padStart(3, '0')}.edit.json`);
        await writeFile(request, JSON.stringify({ path: step.path, before: step.before, after: step.after }));
        lines.push(`printf '\\n%s\\n' ${quote(`==> ${where(step)}`)}`);
        lines.push(`${quote(process.execPath)} ${quote(APPLY_EDIT)} ${quote(request)} >${out} 2>&1 </dev/null`);
        lines.push(`cat ${out}`);
      } else if (step.kind === 'run' && step.exit === undefined) {
        lines.push(`printf '\\n%s\\n' ${quote(`==> ${where(step)}`)}`);
        lines.push(`{\n${step.code}\n} >${out} 2>&1 </dev/null`);
        lines.push(`cat ${out}`);
      } else if (step.kind === 'run') {
        // A demonstrated refusal: the fence's final status is what the page
        // promises, and any other status, success included, stops the journey.
        lines.push(`printf '\\n%s\\n' ${quote(`==> ${where(step)}`)}`);
        lines.push('set +e');
        lines.push(`{\n${step.code}\n} >${out} 2>&1 </dev/null`);
        lines.push('status=$?', 'set -e');
        lines.push(`if [[ $status -ne ${step.exit} ]]; then`);
        lines.push(`  printf '%s exited %s; the page expects ${step.exit}\\n' ${quote(`the sh fence at ${where(step)}`)} "$status" >>${out}`);
        lines.push('  exit 1', 'fi');
        lines.push(`cat ${out}`);
      }
      index += 1;
    }
    lines.push(')');
  }
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
      console.log(`expect ${at(step)}: ok`);
    } else {
      failures += 1;
      console.log(`expect ${at(step)}: output of the sh fence at line ${checked.line} does not match\n${problem}`);
    }
  }
  return failures;
}

async function replay(pages, toolset) {
  const steps = pages.flat();
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
    await writeFile(scriptPath, await journeyScript(pages, outDir));
    const code = await runScript(scriptPath, readerDir, binDir);
    if (interrupted || code === 130) {
      console.log('\ntutorial interrupted');
      status = 130;
    } else if (code !== 0 || !existsSync(join(outDir, 'complete'))) {
      const stop = await stoppedAt(steps, outDir);
      // The failing fence never reached its `cat`, so its output is shown here.
      if (stop) process.stdout.write(stop.output);
      const what = stop ? `${blockName(stop.step)} at ${where(stop.step)}` : 'the journey';
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

// Read every page before anything runs. With more than one page, each step is
// named with its page, and an expectation's runIndex points into the whole
// journey rather than its own page.
const options = parseArgs(process.argv.slice(2));
const pages = [];
let offset = 0;
let annotationErrors = 0;
for (const page of options.pages) {
  const { steps, errors } = readJourney(await readFile(page, 'utf8'));
  for (const error of errors) console.error(`${page}: ${error}`);
  annotationErrors += errors.length;
  const name = options.pages.length > 1 ? basename(page) : undefined;
  pages.push(
    steps.map((step) => ({
      ...step,
      ...(name ? { page: name } : {}),
      ...(step.kind === 'expect' ? { runIndex: step.runIndex + offset } : {}),
    })),
  );
  offset += steps.length;
}
if (annotationErrors > 0) process.exit(2);
if (options.dryRun) {
  printPlan(pages.flat());
  process.exit(0);
}
process.exit(await replay(pages, TOOLSETS[options.toolset]));
