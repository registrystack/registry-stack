#!/usr/bin/env node
// Replay a tutorial page the way a reader follows it.
//
//   node scripts/run-tutorial.mjs [--dry-run] [--toolset breg|none] <page.mdx>...
//   node scripts/run-tutorial.mjs [--dry-run] --gate breg
//
// The page is the specification (see tutorial-runner/page.mjs): its sh fences
// run in document order in one bash shell, from an empty reader directory
// outside the checkout, so a `cd` or a shell variable carries from one fence
// to the next as it does for a reader. The first failing command stops the
// journey. A test-edit block changes its file between fences
// (tutorial-runner/edit.mjs), and a test-excerpt block naming a file takes a
// copy of that file as it stands then. Once every fence has run, each
// test-expect block is compared with the output of the fence it follows
// (tutorial-runner/expect.mjs), and each test-excerpt block is looked for in
// its file or its fence's output (tutorial-runner/excerpt.mjs).
//
// Several pages replay in the order given, in the same reader directory, each
// in a fresh shell: a tutorial that continues from another starts where the
// reader left off, in a new terminal. When the first page's frontmatter sets
// tutorial_test.checkout, the reader directory starts as a copy of this
// checkout instead (tutorial-runner/checkout.mjs).
//
// The toolset puts the product binaries under test on PATH and stops any
// service the journey left running, whether it passed or failed.
//
// With --gate, the pages come from their own frontmatter instead of the
// command line (tutorial-runner/gate.mjs): every page under start/ or
// tutorials/ that runs the toolset's commands is replayed, as the start of or
// part of a journey, or names why it is skipped. Every journey replays, even
// after one fails, unless the toolset itself cannot be prepared.
//
// Exit status: 0 when the journey and every expectation pass, 1 when either
// fails, 2 for a usage, annotation, or toolset error, 130 when interrupted.

import { spawn, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import { checkExcerpt } from './tutorial-runner/excerpt.mjs';
import { checkExpectation } from './tutorial-runner/expect.mjs';
import { copyCheckout } from './tutorial-runner/checkout.mjs';
import { frontmatter, planGate } from './tutorial-runner/gate.mjs';
import { readJourney } from './tutorial-runner/page.mjs';
import { TOOLSETS, ToolsetError } from './tutorial-runner/toolsets.mjs';

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
const USAGE = 'usage: run-tutorial.mjs [--dry-run] [--toolset breg|none] <page.mdx>...\n       run-tutorial.mjs [--dry-run] --gate breg';
const DOCS_ROOT = process.env.TUTORIAL_DOCS_ROOT ?? resolve(dirname(fileURLToPath(import.meta.url)), '../src/content/docs');
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
    else if (arg === '--gate') options.gate = options.toolset = argv[++i];
    else if (arg.startsWith('-')) usageError(`unknown option: ${arg}`);
    else options.pages.push(arg);
  }
  if (options.gate !== undefined && options.pages.length > 0) usageError('--gate takes no pages; they come from frontmatter');
  if (options.gate === undefined && options.pages.length === 0) usageError('missing page');
  if (!Object.hasOwn(TOOLSETS, options.toolset ?? '')) {
    usageError(`unknown toolset: ${options.toolset} (expected ${Object.keys(TOOLSETS).join(' or ')})`);
  }
  if (options.gate !== undefined && !TOOLSETS[options.gate].commands) usageError(`toolset ${options.gate} has no commands to gate`);
  return options;
}

const at = (step) => `${step.page ? `${step.page} ` : ''}line ${step.line}`;
const where = (step) => `${at(step)}${step.heading ? ` (${step.heading})` : ''}`;
const BLOCK_NAMES = { edit: 'the edit', excerpt: 'the excerpt' };
const blockName = (step) => BLOCK_NAMES[step.kind] ?? 'the sh fence';
const quote = (text) => `'${text.replaceAll("'", "'\\''")}'`;
const outName = (index) => `${String(index).padStart(3, '0')}.out`;

function printPlan(steps, checkout) {
  if (checkout) console.log('start in a copy of the checkout');
  for (const step of steps) {
    const exit = step.exit === undefined ? '' : ` (expects exit ${step.exit})`;
    if (step.kind === 'run') console.log(`run   ${where(step)}: ${step.code.split('\n')[0]}${exit}`);
    else if (step.kind === 'skip') console.log(`skip  ${where(step)}: ${step.reason}`);
    else if (step.kind === 'edit') console.log(`edit  ${where(step)}: ${step.path}`);
    else if (step.kind === 'excerpt' && step.path) console.log(`excerpt ${at(step)}: ${step.path}`);
    else if (step.kind === 'excerpt') console.log(`excerpt ${at(step)}: checks line ${steps[step.runIndex].line}`);
    else console.log(`expect ${at(step)}: checks line ${steps[step.runIndex].line}`);
  }
}

// One bash script for the whole journey, one subshell per page. Each fence
// runs as a brace group, not a subshell, so its `cd` and assignments persist
// to the end of its page; its output goes to its own file outside the reader
// directory, then to the log. Standard input is closed, and nothing runs on a
// terminal, so tools print no colour codes. An edit runs apply-edit.mjs from
// the shell's current directory, where the reader would open the file, and a
// file excerpt copies its file from there.
//
// The file `current` names what is running: `page N` before bash parses a
// page, then the index of each block as it starts, so a failure is blamed on
// the block that was running, or on a page bash could not parse. A page that
// reaches its end leaves `page-N.done`; one whose fence ran `exit` does not,
// and the journey stops there.
//
// The script names every harness file by its literal path and sets no shell
// variable, so a page's own variables neither see nor clobber the harness.
async function journeyScript(pages, outDir) {
  const file = (name) => quote(join(outDir, name));
  const lines = ['set -euo pipefail', "trap 'exit 130' HUP INT TERM"];
  let index = 0;
  for (const [pageIndex, steps] of pages.entries()) {
    lines.push(`printf 'page %s\n' ${pageIndex} >${file('current')}`, '(');
    for (const step of steps) {
      const out = file(outName(index));
      lines.push(`printf '%s\n' ${index} >${file('current')}`);
      if (step.kind === 'skip') {
        lines.push(`printf '%s\\n' ${quote(`skip  ${where(step)}: ${step.reason}`)}`);
      } else if (step.kind === 'edit') {
        const request = join(outDir, `${String(index).padStart(3, '0')}.edit.json`);
        await writeFile(request, JSON.stringify({ path: step.path, before: step.before, after: step.after }));
        lines.push(`printf '\\n%s\\n' ${quote(`==> ${where(step)}`)}`);
        lines.push(`${quote(process.execPath)} ${quote(APPLY_EDIT)} ${quote(request)} >${out} 2>&1 </dev/null`);
        lines.push(`cat ${out}`);
      } else if (step.kind === 'excerpt' && step.path) {
        lines.push(`printf '\\n%s\\n' ${quote(`==> ${where(step)}`)}`);
        lines.push(`cat -- ${quote(step.path)} >${out} 2>&1 </dev/null`);
        lines.push(`printf 'read %s\\n' ${quote(step.path)}`);
      } else if (step.kind === 'run' && step.exit === undefined) {
        lines.push(`printf '\\n%s\\n' ${quote(`==> ${where(step)}`)}`);
        lines.push(`{\n${step.code}\n} >${out} 2>&1 </dev/null`);
        lines.push(`cat ${out}`);
      } else if (step.kind === 'run') {
        // A demonstrated refusal: the fence's final status is what the page
        // promises, and any other status, success included, stops the journey.
        lines.push(`printf '\\n%s\\n' ${quote(`==> ${where(step)}`)}`);
        lines.push('set +e');
        const status = file('status');
        lines.push(`{\n${step.code}\n} >${out} 2>&1 </dev/null`);
        lines.push(`printf '%s\\n' "$?" >${status}`, 'set -e');
        lines.push(`if [[ "$(<${status})" -ne ${step.exit} ]]; then`);
        lines.push(`  printf '%s exited %s; the page expects ${step.exit}\\n' ${quote(`the sh fence at ${where(step)}`)} "$(<${status})" >>${out}`);
        lines.push('  exit 1', 'fi');
        lines.push(`cat ${out}`);
      }
      index += 1;
    }
    const done = file(`page-${pageIndex}.done`);
    lines.push(`: >${done}`, ')', `[[ -e ${done} ]] || exit 0`);
  }
  lines.push(`printf "\\n" >${file('complete')}`);
  return `${lines.join('\n')}\n`;
}

// The journey runs in its own process group, so that an interrupt reaches the
// command a fence is running and not only the shell waiting for it, which
// would run its trap only once that command ended. onSpawn receives a
// function that sends a signal to the whole group.
function runScript(scriptPath, readerDir, binDir, onSpawn) {
  const env = { ...process.env, PATH: `${binDir}:${process.env.PATH}` };
  // A reader has no CARGO_TARGET_DIR pointing into this checkout.
  delete env.CARGO_TARGET_DIR;
  return new Promise((resolvePromise, reject) => {
    const child = spawn('bash', [scriptPath], { cwd: readerDir, env, stdio: ['ignore', 'inherit', 'inherit'], detached: true });
    onSpawn((signal) => {
      if (child.exitCode === null && child.signalCode === null) process.kill(-child.pid, signal);
    });
    child.on('error', reject);
    child.on('close', (code, signal) => resolvePromise(signal ? 130 : code));
  });
}

// What was running when the journey stopped: a block, with what its output
// file holds so far, or a page bash never started because it could not parse
// it. Undefined when nothing started.
async function stoppedAt(pages, outDir) {
  let current;
  try {
    current = (await readFile(join(outDir, 'current'), 'utf8')).trim();
  } catch (error) {
    if (error.code === 'ENOENT') return undefined;
    throw error;
  }
  if (current.startsWith('page ')) {
    const steps = pages[Number.parseInt(current.slice('page '.length), 10)];
    return { what: steps[0]?.page ?? 'the page', before: true };
  }
  const index = Number.parseInt(current, 10);
  const step = pages.flat()[index];
  const out = join(outDir, outName(index));
  return { what: `${blockName(step)} at ${where(step)}`, output: existsSync(out) ? await readFile(out, 'utf8') : '' };
}

// Make everything under root writable and readable, so that a directory the
// journey locked cannot stop the teardown from finding sessions or the work
// directory from being removed.
function unlock(root) {
  const result = spawnSync('chmod', ['-R', 'u+rwX', root], { encoding: 'utf8' });
  if (result.status !== 0) console.error(`could not make ${root} writable:\n${result.stderr}`);
}

// Check every test-expect and test-excerpt block, in page order, against the
// output or file copy the journey left for it. Returns the number that fail.
async function checkBlocks(steps, outDir) {
  let failures = 0;
  for (const [index, step] of steps.entries()) {
    if (step.kind !== 'expect' && step.kind !== 'excerpt') continue;
    const sourceIndex = step.path ? index : step.runIndex;
    const source = await readFile(join(outDir, outName(sourceIndex)), 'utf8');
    const fenceOutput = step.path ? undefined : `the output of the sh fence at line ${steps[step.runIndex].line}`;
    let problem;
    if (step.kind === 'expect') {
      problem = checkExpectation(step.format, step.text, source);
      if (problem) problem = `output of the sh fence at line ${steps[step.runIndex].line} does not match\n${problem}`;
    } else {
      problem = checkExcerpt(step.format, step.text, source);
      if (problem) problem = `${fenceOutput ?? step.path} does not contain it: ${problem}`;
    }
    if (problem === null) {
      console.log(`${step.kind} ${at(step)}: ok`);
    } else {
      failures += 1;
      console.log(`${step.kind} ${at(step)}: ${problem}`);
    }
  }
  return failures;
}

async function replay(pages, toolset, checkout) {
  const steps = pages.flat();
  const workRoot = await realpath(await mkdtemp(join(tmpdir(), 'tutorial-run.')));
  const readerDir = join(workRoot, 'reader');
  const outDir = join(workRoot, 'out');
  const binDir = join(workRoot, 'bin');
  await Promise.all([mkdir(readerDir), mkdir(outDir), mkdir(binDir)]);

  let interrupted = false;
  let signalJourney = () => {};
  const onSignal = (signal) => {
    interrupted = true;
    signalJourney(signal);
  };
  const signals = ['SIGHUP', 'SIGINT', 'SIGTERM'];
  for (const signal of signals) process.on(signal, onSignal);

  let status = 1;
  let prepared = false;
  try {
    await toolset.prepare({ repoRoot: REPO_ROOT, binDir });
    prepared = true;
    if (checkout) await copyCheckout(REPO_ROOT, readerDir);
    const scriptPath = join(workRoot, 'journey.sh');
    await writeFile(scriptPath, await journeyScript(pages, outDir));
    const code = await runScript(scriptPath, readerDir, binDir, (send) => {
      signalJourney = send;
    });
    if (interrupted || code === 130) {
      // The running fence never reached its `cat`, so what it printed is shown here.
      const stop = await stoppedAt(pages, outDir);
      if (stop?.output) process.stdout.write(stop.output);
      console.log(`\ntutorial interrupted${stop ? ` during ${stop.what}` : ''}`);
      status = 130;
    } else if (code !== 0 || !existsSync(join(outDir, 'complete'))) {
      const stop = await stoppedAt(pages, outDir);
      // The failing fence never reached its `cat`, so its output is shown here.
      if (stop?.output) process.stdout.write(stop.output);
      const what = stop?.what ?? 'the journey';
      const how = code !== 0 ? `failed with exit status ${code}` : 'ended the shell early';
      console.log(`\n${what} ${how}${stop?.before ? ' before its first block ran' : ''}`);
      console.log('tutorial FAIL');
    } else {
      console.log('');
      const failures = await checkBlocks(steps, outDir);
      console.log(failures === 0 ? 'tutorial PASS' : 'tutorial FAIL');
      status = failures === 0 ? 0 : 1;
    }
  } catch (error) {
    if (!(error instanceof ToolsetError)) throw error;
    console.error(error.message);
    status = 2;
  } finally {
    for (const signal of signals) process.off(signal, onSignal);
    try {
      unlock(workRoot);
      const stoppedAll = prepared ? await toolset.teardown({ readerDir, binDir }) : true;
      if (stoppedAll) {
        await rm(workRoot, { recursive: true, force: true });
      } else {
        console.error(`keeping ${workRoot}: stop the sessions it holds, then remove it`);
        if (status === 0) status = 1;
      }
    } catch (error) {
      console.error(`cleaning up ${workRoot} failed: ${error.message}`);
      if (status === 0) status = 1;
    }
  }
  return status;
}

// Read every page before anything runs. With more than one page, each step is
// named with its page, and the runIndex of an expectation or excerpt points
// into the whole journey rather than its own page. Returns null after printing
// any annotation error.
async function readPages(paths) {
  const pages = [];
  let checkout = false;
  let offset = 0;
  let annotationErrors = 0;
  for (const page of paths) {
    const text = await readFile(page, 'utf8');
    if (pages.length === 0) checkout = frontmatter(text).tutorial_test?.checkout === true;
    const { steps, errors } = readJourney(text);
    for (const error of errors) console.error(`${page}: ${error}`);
    annotationErrors += errors.length;
    const name = paths.length > 1 ? basename(page) : undefined;
    pages.push(
      steps.map((step) => ({
        ...step,
        ...(name ? { page: name } : {}),
        ...(step.runIndex === undefined ? {} : { runIndex: step.runIndex + offset }),
      })),
    );
    offset += steps.length;
  }
  return annotationErrors > 0 ? null : { pages, checkout };
}

async function runGate(toolsetName, dryRun) {
  const toolset = TOOLSETS[toolsetName];
  const { journeys, checkout, skipped, errors } = await planGate(DOCS_ROOT, toolsetName, toolset.commands, Object.keys(TOOLSETS));
  for (const error of errors) console.error(error);
  if (errors.length > 0) return 2;
  const planned = [];
  for (const journey of journeys) {
    const read = await readPages(journey.map((slug) => join(DOCS_ROOT, `${slug}.mdx`)));
    if (!read) return 2;
    planned.push({ journey, pages: read.pages, checkout: checkout.includes(journey[0]) });
  }
  for (const { slug, reason } of skipped) console.log(`skip  page ${slug}: ${reason}`);
  const failed = [];
  for (const { journey, pages, checkout: fromCheckout } of planned) {
    console.log(`\njourney ${journey.join(' -> ')}`);
    if (dryRun) {
      printPlan(pages.flat(), fromCheckout);
      continue;
    }
    const status = await replay(pages, toolset, fromCheckout);
    // A toolset that cannot be prepared fails every journey the same way.
    if (status === 130 || status === 2) return status;
    if (status !== 0) failed.push(journey.at(-1));
  }
  if (dryRun) return 0;
  const count = (n, noun) => `${n} ${noun}${n === 1 ? '' : 's'}`;
  const summary = `${count(planned.length, 'journey')} replayed, ${count(skipped.length, 'page')} skipped`;
  if (failed.length === 0) {
    console.log(`\ngate PASS: ${summary}`);
    return 0;
  }
  console.log(`\ngate FAIL: ${summary}; failed: ${failed.join(', ')}`);
  return 1;
}

const options = parseArgs(process.argv.slice(2));
if (options.gate !== undefined) process.exit(await runGate(options.gate, options.dryRun));
const read = await readPages(options.pages);
if (!read) process.exit(2);
if (options.dryRun) {
  printPlan(read.pages.flat(), read.checkout);
  process.exit(0);
}
process.exit(await replay(read.pages, TOOLSETS[options.toolset], read.checkout));
