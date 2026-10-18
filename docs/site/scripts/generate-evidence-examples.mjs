// Package the Evidence example projects a tutorial reader downloads. Service
// setup remains in evidencectl.
import { mkdir, lstat } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import * as tar from 'tar';

export const exampleFiles = [
  'fhir/.gitignore',
  'fhir/README.md',
  'fhir/dev-authority.yaml',
  'fhir/discover-records.py',
  'fhir/evidence.yaml',
  'fhir/fixtures/coverage-status.yaml',
  'fhir/fixtures/healthcare-establishment.yaml',
  'fhir/functions/derive-coverage-status.rhai',
  'fhir/functions/derive-healthcare-establishment.rhai',
  'fhir/functions/extract-coverage.rhai',
  'fhir/functions/extract-organization.rhai',
  'fhir/local-target.yaml',
  'fhir/serve-source.py',
  'fhir/source.openapi.yaml',
  'fhir/test_source.py',
  'standalone/.gitignore',
  'standalone/README.md',
  'standalone/access/clients/example-caller.yaml',
  'standalone/dev-authority.yaml',
  'standalone/evidence.yaml',
  'standalone/fixtures/adult-status.yaml',
  'standalone/fixtures/legal-parent-relationship.yaml',
  'standalone/fixtures/professional-licence-status.yaml',
  'standalone/fixtures/residence-region.yaml',
  'standalone/functions/derive-adult-status.rhai',
  'standalone/functions/derive-licence-status.rhai',
  'standalone/functions/derive-parent-relationship.rhai',
  'standalone/functions/derive-residence-region.rhai',
  'standalone/functions/extract-licence.rhai',
  'standalone/functions/extract-parents.rhai',
  'standalone/functions/extract-person.rhai',
  'standalone/local-target.yaml',
  'standalone/serve-source.py',
].sort();

export async function packageExamples(source, output) {
  // Explicit inventory excludes generated keys, dev sessions, and responses
  // even if they exist beside the examples.
  for (const file of exampleFiles) {
    const info = await lstat(resolve(source, file));
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`Example input is not a plain file: ${file}`);
  }
  await mkdir(dirname(output), { recursive: true });
  await tar.create({
    cwd: source,
    file: output,
    gzip: { level: 9, mtime: 0 },
    mtime: new Date(0),
    portable: true,
    noDirRecurse: true,
    noPax: true,
    strict: true,
    filter(_path, info) { info.mode = (info.mode & ~0o7777) | 0o644; return true; },
  }, exampleFiles);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const site = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  await packageExamples(resolve(site, '../../products/evidence/examples'), resolve(site, 'public/examples/evidence-examples.tar.gz'));
}
