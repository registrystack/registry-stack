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

test('a plain registry-stack.yaml declares a project root', () => {
  const directory = tempDirectory();
  fs.writeFileSync(path.join(directory, 'registry-stack.yaml'), 'version: 1\n');
  assert.strictEqual(isProjectRoot(directory), true);
});

test('a symlinked registry-stack.yaml does not declare a project root', () => {
  const directory = tempDirectory();
  const real = path.join(directory, 'real-registry-stack.yaml');
  fs.writeFileSync(real, 'version: 1\n');
  fs.symlinkSync(real, path.join(directory, 'registry-stack.yaml'));
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
