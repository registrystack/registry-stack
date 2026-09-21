import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const docs = resolve(here, '../src/content/docs');
const tutorial = readFileSync(
  resolve(docs, 'tutorials/review-breg-changes-in-casework.mdx'),
  'utf8',
);
const caseworkOperate = readFileSync(resolve(docs, 'operate/casework.mdx'), 'utf8');
const bregOperate = readFileSync(resolve(docs, 'operate/breg.mdx'), 'utf8');

test('the paired authoring journey uses one BReg and Casework namespace', () => {
  for (const command of [
    'bregctl check review-work/registry',
    'bregctl explain change-requests review-work/registry',
    'caseworkctl source add review-work/registry',
    '--source-id professional-licences --apply',
    'caseworkctl check review-work/casework',
    'caseworkctl explain review-work/casework',
    'caseworkctl test review-work/casework',
    'caseworkctl package review-work/casework',
    'bregctl dev start review-work/registry',
    'caseworkctl dev start review-work/casework',
  ]) {
    assert.ok(tutorial.includes(command), `missing journey command: ${command}`);
  }
  assert.doesNotMatch(tutorial, /--source-id professional-register/u);
});

test('the operated journey states result and recovery boundaries', () => {
  assert.match(tutorial, /empty HTTP `204 No Content`/u);
  assert.match(tutorial, /`202` pending, `200` retained, `410` expired/u);
  assert.match(tutorial, /do not query\s+the database directly/u);
  assert.match(caseworkOperate, /same package, runtime file, and database/u);
  assert.match(caseworkOperate, /no in-place legacy conversion command/u);
  assert.match(caseworkOperate, /does not summarize an individual\s+review/u);
  assert.match(bregOperate, /resumes the\s+durable review submission/u);
});
