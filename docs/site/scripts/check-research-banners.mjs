#!/usr/bin/env node

import { readdirSync, readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = dirname(scriptPath);

export const RESEARCH_STATUS_BANNER = `> **Status: historical research note**
>
> This note records pre-monorepo research and is not current architecture or release evidence. Use the published documentation and pinned source links for current claims.

`;

export function researchBannerErrors(researchDir = resolve(scriptDir, '../.research')) {
  const names = readdirSync(researchDir)
    .filter((name) => name.endsWith('.md') && name !== 'README.md')
    .sort();
  return names
    .filter((name) => !readFileSync(resolve(researchDir, name), 'utf8').startsWith(RESEARCH_STATUS_BANNER))
    .map((name) => `${name} is missing the exact historical-research banner`);
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  const errors = researchBannerErrors();
  if (errors.length > 0) {
    console.error('Research status banner check failed:');
    for (const error of errors) {
      console.error(`- ${error}`);
    }
    process.exitCode = 1;
  } else {
    console.log('All research notes carry the historical-research banner.');
  }
}
