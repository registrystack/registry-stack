import { resolve } from 'node:path';
import {
  applyDocsetRefs,
  currentProductsMatchRepoManifest,
  getDocset,
  loadDocsets,
  loadYaml,
  selectedDocsetId,
} from './docsets.mjs';

const dataDir = resolve(process.cwd(), 'src/data');
const docsets = await loadDocsets({ dataDir });
const repoManifest = await loadYaml(resolve(dataDir, 'repo-docs.yaml'));

const selected = getDocset(docsets, selectedDocsetId(docsets));

const errors = [];
if (selected.id === docsets.current) {
  errors.push(...currentProductsMatchRepoManifest(repoManifest, docsets));
} else {
  applyDocsetRefs(repoManifest, selected);
}

if (errors.length) {
  console.error(errors.join('\n'));
  process.exit(1);
}

console.log(`Docset check passed for ${selected.id}.`);
