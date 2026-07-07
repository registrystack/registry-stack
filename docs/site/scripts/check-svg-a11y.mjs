import { readdir, readFile } from 'node:fs/promises';
import { join, relative } from 'node:path';

const imageDir = 'public/images';
const expected = new Set([
  'registry-family-map.svg',
  'registry-architecture-flow.svg',
  'registry-claim-model.svg',
  'registry-country-evidence-mesh.svg',
  'registry-evidence-transports.svg',
  'registry-notary-three-parties.svg',
  'registry-publishing-pipeline.svg',
  'registry-relay-or-notary.svg',
  'registry-relay-request-lifecycle.svg',
  'registry-relay-two-rooms.svg',
  'registry-trust-boundaries.svg',
  'solmara-lab-topology.svg',
  'standards-claim-levels.svg',
]);

const entries = await readdir(imageDir, { withFileTypes: true });
const errors = [];
const seen = new Set();

for (const entry of entries) {
  if (!entry.isFile() || !entry.name.endsWith('.svg')) continue;
  const file = join(imageDir, entry.name);
  const text = await readFile(file, 'utf8');
  seen.add(entry.name);
  if (!/<title[>\s]/.test(text)) errors.push(`${relative('.', file)} missing <title>`);
  if (!/<desc[>\s]/.test(text)) errors.push(`${relative('.', file)} missing <desc>`);
  if (!/role="img"/.test(text)) errors.push(`${relative('.', file)} missing role="img"`);
}

for (const name of expected) {
  if (!seen.has(name)) errors.push(`public/images/${name} is missing`);
}

if (errors.length) {
  console.error(errors.join('\n'));
  process.exit(1);
}

console.log('SVG accessibility check passed.');
