'use strict';

const { readFileSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');

const loader = join(__dirname, '..', 'index.js');
const source = readFileSync(loader, 'utf8');
const generatedPattern = /^  if \(!wasiBindingLoaded && \(!__napiWasiFlavorRequested \|\| __napiWasiFlavor === (['"])wasm32-wasi\1\)\) \{$/gm;
const normalizedPattern = /^  if \(!__napiWasiFlavorRequested \|\| __napiWasiFlavor === (['"])wasm32-wasi\1\) \{$/gm;
const generatedGuards = [...source.matchAll(generatedPattern)];
const normalizedGuards = [...source.matchAll(normalizedPattern)];

if (generatedGuards.length === 1 && normalizedGuards.length === 1) {
  process.exit(0);
}
if (generatedGuards.length !== 2 || normalizedGuards.length !== 0) {
  throw new Error('the generated NAPI loader no longer contains the expected WASI guards');
}

const [first] = generatedGuards;
const quote = first[1];
const normalized = `  if (!__napiWasiFlavorRequested || __napiWasiFlavor === ${quote}wasm32-wasi${quote}) {`;
const output = source.slice(0, first.index) + normalized + source.slice(first.index + first[0].length);
writeFileSync(loader, output, 'utf8');
