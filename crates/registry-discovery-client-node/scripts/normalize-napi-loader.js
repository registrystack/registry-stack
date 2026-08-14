'use strict';

const { readFileSync, writeFileSync } = require('node:fs');
const { join } = require('node:path');

const loader = join(__dirname, '..', 'index.js');
const generated = '  if (!wasiBindingLoaded && (!__napiWasiFlavorRequested || __napiWasiFlavor === "wasm32-wasi")) {';
const normalized = '  if (!__napiWasiFlavorRequested || __napiWasiFlavor === "wasm32-wasi") {';
const source = readFileSync(loader, 'utf8');
const generatedCount = source.split(generated).length - 1;
const normalizedCount = source.split(normalized).length - 1;
const first = source.indexOf(generated);

if (generatedCount === 1 && normalizedCount === 1) {
  process.exit(0);
}
if (generatedCount !== 2 || normalizedCount !== 0 || first < 0) {
  throw new Error('the generated NAPI loader no longer contains the expected WASI guards');
}

const output = source.slice(0, first) + normalized + source.slice(first + generated.length);
writeFileSync(loader, output, 'utf8');
