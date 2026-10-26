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

export const sourceRecipeFiles = [
  'LICENSE',
  'README.md',
  'run-fixtures.sh',
  'dhis2-tracker/README.md',
  'dhis2-tracker/adapters/dhis2-tracker-extract.rhai',
  'dhis2-tracker/adapters/dhis2-tracker-prepare.rhai',
  'dhis2-tracker/fixture-validation/assertion-definitions.yaml',
  'dhis2-tracker/fixture-validation/authority.yaml',
  'dhis2-tracker/fixture-validation/evidence.yaml',
  'dhis2-tracker/fixture-validation/fixtures/active-status.yaml',
  'dhis2-tracker/fixture-validation/functions/derive-active-status.rhai',
  'dhis2-tracker/fixture-validation/functions/validation-seed-derive.rhai',
  'dhis2-tracker/fixture-validation/functions/validation-seed-extract.rhai',
  'dhis2-tracker/fixture-validation/local-target.yaml',
  'dhis2-tracker/fixture-validation/public-key.jwk.json',
  'dhis2-tracker/schemas/dhis2-tracker-facts.yaml',
  'dhis2-tracker/schemas/dhis2-tracker-parameters.yaml',
  'dhis2-tracker/schemas/dhis2-tracker-response.yaml',
  'dhis2-tracker/selectors/dhis2-tracked-entity-id-v1.yaml',
  'dhis2-tracker/source-export.json',
  'dhis2-tracker/sources/dhis2-tracker.yaml',
  'opencrvs-event-search/README.md',
  'opencrvs-event-search/adapters/opencrvs-event-search-extract.rhai',
  'opencrvs-event-search/adapters/opencrvs-event-search-prepare.rhai',
  'opencrvs-event-search/fixture-validation/assertion-definitions.yaml',
  'opencrvs-event-search/fixture-validation/authority.yaml',
  'opencrvs-event-search/fixture-validation/evidence.yaml',
  'opencrvs-event-search/fixture-validation/fixtures/registered-parent.yaml',
  'opencrvs-event-search/fixture-validation/functions/derive-registered-parent.rhai',
  'opencrvs-event-search/fixture-validation/functions/validation-seed-derive.rhai',
  'opencrvs-event-search/fixture-validation/functions/validation-seed-extract.rhai',
  'opencrvs-event-search/fixture-validation/local-target.yaml',
  'opencrvs-event-search/fixture-validation/public-key.jwk.json',
  'opencrvs-event-search/schemas/opencrvs-event-search-facts.yaml',
  'opencrvs-event-search/schemas/opencrvs-event-search-parameters.yaml',
  'opencrvs-event-search/schemas/opencrvs-event-search-response.yaml',
  'opencrvs-event-search/selectors/opencrvs-tracking-id-v1.yaml',
  'opencrvs-event-search/source-export.json',
  'opencrvs-event-search/sources/opencrvs-event-search.yaml',
].sort();

export async function packageExamples(source, output) {
  await packageReviewedFiles(source, output, exampleFiles, 'Example');
}

export async function packageSourceRecipes(source, output) {
  await packageReviewedFiles(source, output, sourceRecipeFiles, 'Source recipe');
}

async function packageReviewedFiles(source, output, files, label) {
  // Explicit inventory excludes generated keys, dev sessions, and responses
  // even if they exist beside the reviewed inputs.
  for (const file of files) {
    const info = await lstat(resolve(source, file));
    if (!info.isFile() || info.isSymbolicLink()) throw new Error(`${label} input is not a plain file: ${file}`);
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
  }, files);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const site = resolve(dirname(fileURLToPath(import.meta.url)), '..');
  await packageExamples(resolve(site, '../../products/evidence/examples'), resolve(site, 'public/examples/evidence-examples.tar.gz'));
  await packageSourceRecipes(resolve(site, '../../products/evidence/source-recipes'), resolve(site, 'public/examples/evidence-source-recipes.tar.gz'));
}
