#!/usr/bin/env node
// Decide whether a test-retry fence runs again during a replay: the journey
// script calls this after each run of the fence with the JSON file the runner
// wrote for it, { retry, attempts, blocks }, and the fence's output file.
// blocks are the test-expect and test-excerpt blocks below the fence, each
// { kind, format, text }; attempts is a file counting the runs so far.
//
// Exit 0, after a second's wait, when the output does not match every block
// yet and fewer than retry re-runs have happened: the fence runs again. Exit
// 1 when it matches or the time is up: the journey goes on, and the blocks
// are checked against the last output as usual. The decision is the exit
// status rather than a shell variable, so the harness sets none.

import { readFile, writeFile } from 'node:fs/promises';

import { checkExcerpt } from './excerpt.mjs';
import { checkExpectation } from './expect.mjs';

const { retry, attempts, blocks } = JSON.parse(await readFile(process.argv[2], 'utf8'));
const output = await readFile(process.argv[3], 'utf8');
const check = (block) =>
  block.kind === 'expect' ? checkExpectation(block.format, block.text, output) : checkExcerpt(block.format, block.text, output);
if (blocks.every((block) => check(block) === null)) process.exit(1);

let done = 0;
try {
  done = Number.parseInt(await readFile(attempts, 'utf8'), 10);
} catch (error) {
  if (error.code !== 'ENOENT') throw error;
}
if (done >= retry) process.exit(1);
await writeFile(attempts, `${done + 1}\n`);
await new Promise((resolvePromise) => setTimeout(resolvePromise, 1000));
console.log(`again (${done + 1}/${retry})`);
