import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';

const here = dirname(fileURLToPath(import.meta.url));
const guide = readFileSync(resolve(here, '../src/content/docs/configure/casework.mdx'), 'utf8');

function fencedYamlUnder(heading) {
  const start = guide.indexOf(`## ${heading}`);
  assert.notEqual(start, -1, `missing ${heading} heading`);
  const section = guide.slice(start).split(/\n## /u, 1)[0];
  const fence = section.match(/```yaml\n([\s\S]*?)\n```/u);
  assert.ok(fence, `missing YAML example under ${heading}`);
  return parse(fence[1]);
}

test('the documented local Casework callers form a complete valid directory seed', () => {
  const example = fencedYamlUnder('Local callers in `dev-clients.yaml`');
  const clients = new Map(example.clients.map((client) => [client.id, client]));

  assert.deepEqual([...clients.keys()].sort(), [
    'administrator',
    'requester',
    'staff',
    'supervisor',
  ]);
  for (const role of ['administrator', 'staff', 'supervisor']) {
    assert.equal(clients.get(role).accessProfile, role);
    assert.equal(clients.get(role).claims.registry_actor_kind, 'human');
  }
  for (const team of example.directory) {
    for (const client of [...team.staff, ...team.supervisors]) {
      assert.ok(clients.has(client), `directory references undeclared client ${client}`);
    }
  }
});
