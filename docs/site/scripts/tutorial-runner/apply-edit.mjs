#!/usr/bin/env node
// Apply one test-edit block during a replay: the journey script calls this
// from the reader's current directory with the JSON file the runner wrote
// for the block, { path, before, after }.

import { readFile, writeFile } from 'node:fs/promises';

import { applyEdit } from './edit.mjs';

const { path, before, after } = JSON.parse(await readFile(process.argv[2], 'utf8'));
let text;
try {
  text = await readFile(path, 'utf8');
} catch (error) {
  console.log(`${path}: ${error.code === 'ENOENT' ? 'no such file' : error.message}`);
  process.exit(1);
}
const result = applyEdit(text, before, after);
if (result.error) {
  console.log(`${path}: ${result.error}`);
  process.exit(1);
}
await writeFile(path, result.text);
console.log(`edited ${path}`);
