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

test('a plain registry.yaml does not declare a retired Relay project root', () => {
  const directory = tempDirectory();
  fs.writeFileSync(path.join(directory, 'registry.yaml'), 'kind: RegistryContract\n');
  assert.strictEqual(isProjectRoot(directory), false);
});

// registry.yaml is also what the Base Registry Engine calls its project
// document, so the name alone says nothing about which product wrote the
// directory. These are the documents the two init commands write.
test('a Base Registry Engine registry.yaml declares a project root', () => {
  const directory = tempDirectory();
  fs.writeFileSync(
    path.join(directory, 'registry.yaml'),
    'apiVersion: registry.registrystack.org/v1alpha1\nkind: RegistryProject\nregistry:\n  id: business\n',
  );
  assert.strictEqual(isProjectRoot(directory), true);
});

test('a Relay V2 apiVersion alone does not declare a supported project root', () => {
  const directory = tempDirectory();
  fs.writeFileSync(
    path.join(directory, 'registry.yaml'),
    'apiVersion: relay.registrystack.org/v2alpha1\nresources: []\n',
  );
  assert.strictEqual(isProjectRoot(directory), false);
});

test('a quoted Relay V2 discriminator does not declare a supported project root', () => {
  const directory = tempDirectory();
  fs.writeFileSync(
    path.join(directory, 'registry.yaml'),
    "kind: 'RegistryContract'  # the governed contract\n",
  );
  assert.strictEqual(isProjectRoot(directory), false);
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
// project also declares the directory as a root.
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


for (const [file, content] of [
  ['casework.yaml', 'kind: CaseworkProject\n'],
  ['scheduling.yaml', 'apiVersion: id.registrystack.org/formats/scheduling/project/v1alpha1\n'],
  ['messaging.yaml', 'kind: MessagingProject\n'],
  ['origins.yaml', 'schemaVersion: registry-discovery/origins/v1alpha1\n'],
  ['manifest.yaml', 'apiVersion: id.registrystack.org/formats/render/bundle/v1alpha1\nkind: RenderBundle\n'],
  ['metadata.yaml', 'schema_version: registry-manifest/v1\n'],
]) {
  test(`${file} declares its current product family`, () => {
    const directory = tempDirectory();
    fs.writeFileSync(path.join(directory, file), content);
    assert.strictEqual(isProjectRoot(directory), true);
  });
  test(`a symlinked ${file} does not declare a product root`, () => {
    const directory = tempDirectory();
    const target = path.join(directory, 'target.yaml');
    fs.writeFileSync(target, content);
    fs.symlinkSync(target, path.join(directory, file));
    assert.strictEqual(isProjectRoot(directory), false);
  });
}

test('an unrelated runtime.yaml does not declare a product root', () => {
  const directory = tempDirectory();
  fs.writeFileSync(path.join(directory, 'runtime.yaml'), 'listen: 127.0.0.1:8100\n');
  assert.strictEqual(isProjectRoot(directory), false);
});

test('a marker exceeding the authoring size limit does not declare a root', () => {
  const directory = tempDirectory();
  fs.writeFileSync(path.join(directory, 'casework.yaml'), `kind: CaseworkProject\n${' '.repeat(1024 * 1024)}`);
  assert.strictEqual(isProjectRoot(directory), false);
});

function writeExplicitMarker(directory: string, product: string, document: string): void {
  fs.mkdirSync(path.join(directory, '.registry-stack-editor'), { recursive: true });
  fs.writeFileSync(path.join(directory, '.registry-stack-editor/project.json'), JSON.stringify({ product, document }));
}

for (const product of ['manifest', 'evidence-oid4vci']) {
  test(`an explicit ${product} marker anchors an adopter-named document`, () => {
    const directory = tempDirectory();
    fs.mkdirSync(path.join(directory, 'authored'));
    fs.writeFileSync(path.join(directory, 'authored/custom.yml'), 'version: 1\n');
    writeExplicitMarker(directory, product, 'authored/custom.yml');
    assert.strictEqual(isProjectRoot(directory), true);
  });
}

for (const document of ['../outside.yaml', '/outside.yaml', 'folder\\outside.yaml', './document.yaml', 'document.txt', 'missing.yaml']) {
  test(`an explicit marker rejects unsafe or missing document ${document}`, () => {
    const directory = tempDirectory();
    writeExplicitMarker(directory, 'manifest', document);
    assert.strictEqual(isProjectRoot(directory), false);
  });
}

test('an explicit marker rejects a symlinked document directory', () => {
  const directory = tempDirectory();
  const target = tempDirectory();
  fs.writeFileSync(path.join(target, 'document.yaml'), 'schema_version: registry-manifest/v1\n');
  fs.symlinkSync(target, path.join(directory, 'authored'));
  writeExplicitMarker(directory, 'manifest', 'authored/document.yaml');
  assert.strictEqual(isProjectRoot(directory), false);
});

test('an explicit marker rejects unknown product names', () => {
  const directory = tempDirectory();
  fs.writeFileSync(path.join(directory, 'document.yaml'), 'version: 1\n');
  writeExplicitMarker(directory, 'unknown', 'document.yaml');
  assert.strictEqual(isProjectRoot(directory), false);
});

test('a symlinked explicit marker directory does not declare a product root', () => {
  const directory = tempDirectory();
  const target = tempDirectory();
  fs.writeFileSync(path.join(directory, 'document.yaml'), 'version: 1\n');
  fs.writeFileSync(path.join(target, 'project.json'), JSON.stringify({ product: 'manifest', document: 'document.yaml' }));
  fs.symlinkSync(target, path.join(directory, '.registry-stack-editor'));
  assert.strictEqual(isProjectRoot(directory), false);
});

test('malformed explicit marker JSON does not declare a product root', () => {
  const directory = tempDirectory();
  fs.mkdirSync(path.join(directory, '.registry-stack-editor'));
  fs.writeFileSync(path.join(directory, '.registry-stack-editor/project.json'), '{');
  assert.strictEqual(isProjectRoot(directory), false);
});
