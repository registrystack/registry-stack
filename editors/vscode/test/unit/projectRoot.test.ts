// SPDX-License-Identifier: Apache-2.0

import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { test } from 'node:test';

import { isProjectRoot } from '../../src/projectRoot.js';

function tempDirectory(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'registry-stack-project-root-'));
}

test('a legacy registry-stack.yaml does not declare a project root', () => {
  const directory = tempDirectory();
  fs.writeFileSync(path.join(directory, 'registry-stack.yaml'), 'version: 1\n');
  assert.strictEqual(isProjectRoot(directory), false);
});

test('a plain registry.yaml declares a Relay V2 project root', () => {
  const directory = tempDirectory();
  fs.writeFileSync(path.join(directory, 'registry.yaml'), 'kind: RegistryContract\n');
  assert.strictEqual(isProjectRoot(directory), true);
});

// registry.yaml is also what the Base Registry Engine calls its project
// document, so the name alone says nothing about which product wrote the
// directory. These are the documents the two init commands write.
test('a Base Registry Engine registry.yaml does not declare a project root', () => {
  const directory = tempDirectory();
  fs.writeFileSync(
    path.join(directory, 'registry.yaml'),
    'apiVersion: registry.registrystack.org/v1alpha1\nkind: RegistryProject\nregistry:\n  id: business\n',
  );
  assert.strictEqual(isProjectRoot(directory), false);
});

test('a Relay V2 apiVersion alone declares a project root', () => {
  const directory = tempDirectory();
  fs.writeFileSync(
    path.join(directory, 'registry.yaml'),
    'apiVersion: relay.registrystack.org/v2alpha1\nresources: []\n',
  );
  assert.strictEqual(isProjectRoot(directory), true);
});

test('a quoted Relay V2 discriminator declares a project root', () => {
  const directory = tempDirectory();
  fs.writeFileSync(
    path.join(directory, 'registry.yaml'),
    "kind: 'RegistryContract'  # the governed contract\n",
  );
  assert.strictEqual(isProjectRoot(directory), true);
});

test('a nested kind does not declare a Relay V2 project root', () => {
  const directory = tempDirectory();
  fs.writeFileSync(
    path.join(directory, 'registry.yaml'),
    'metadata:\n  kind: RegistryContract\n',
  );
  assert.strictEqual(isProjectRoot(directory), false);
});

test('a registry.yaml naming neither discriminator does not declare a project root', () => {
  const directory = tempDirectory();
  fs.writeFileSync(path.join(directory, 'registry.yaml'), 'resources: []\n');
  assert.strictEqual(isProjectRoot(directory), false);
});

test('an empty registry.yaml does not declare a project root', () => {
  const directory = tempDirectory();
  fs.writeFileSync(path.join(directory, 'registry.yaml'), '');
  assert.strictEqual(isProjectRoot(directory), false);
});

// A Base Registry Engine project directory that also holds an Evidence
// project keeps the Evidence root: the registry.yaml is what stops declaring
// one, not the directory.
test('a Base Registry Engine registry.yaml beside an Evidence marker declares a project root', () => {
  const directory = tempDirectory();
  fs.writeFileSync(
    path.join(directory, 'registry.yaml'),
    'apiVersion: registry.registrystack.org/v1alpha1\nkind: RegistryProject\n',
  );
  fs.writeFileSync(path.join(directory, 'evidence-project.yaml'), 'version: 1\n');
  assert.strictEqual(isProjectRoot(directory), true);
});

test('a symlinked registry.yaml does not declare a Relay V2 project root', () => {
  const directory = tempDirectory();
  const real = path.join(directory, 'real-registry.yaml');
  fs.writeFileSync(real, 'kind: RegistryContract\n');
  fs.symlinkSync(real, path.join(directory, 'registry.yaml'));
  assert.strictEqual(isProjectRoot(directory), false);
});

test('a plain evidence-project.yaml declares a project root', () => {
  const directory = tempDirectory();
  fs.writeFileSync(path.join(directory, 'evidence-project.yaml'), 'version: 1\n');
  assert.strictEqual(isProjectRoot(directory), true);
});

test('a symlinked evidence-project.yaml does not declare a project root', () => {
  const directory = tempDirectory();
  const real = path.join(directory, 'real-evidence-project.yaml');
  fs.writeFileSync(real, 'version: 1\n');
  fs.symlinkSync(real, path.join(directory, 'evidence-project.yaml'));
  assert.strictEqual(isProjectRoot(directory), false);
});

test('a plain OpenAPI description with a questions directory declares a project root', () => {
  const directory = tempDirectory();
  fs.writeFileSync(path.join(directory, 'source.openapi.yaml'), 'openapi: 3.1.0\n');
  fs.mkdirSync(path.join(directory, 'questions'));
  assert.strictEqual(isProjectRoot(directory), true);
});

test('a symlinked questions directory does not declare a project root', () => {
  const directory = tempDirectory();
  fs.writeFileSync(path.join(directory, 'source.openapi.yaml'), 'openapi: 3.1.0\n');
  const realQuestions = path.join(directory, 'real-questions');
  fs.mkdirSync(realQuestions);
  fs.symlinkSync(realQuestions, path.join(directory, 'questions'));
  assert.strictEqual(isProjectRoot(directory), false);
});
