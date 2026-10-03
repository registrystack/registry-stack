// SPDX-License-Identifier: Apache-2.0

import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, test } from 'node:test';

import { findLanguageServerOnPath, hostsMatchingLanguageServer } from '../../src/serverCommand.js';

const originalPath = process.env.PATH;
// The compiled test runs from out/unit/test/unit; the manifest is the
// extension's own, so the fixtures follow the release version.
const expectedVersion: string = JSON.parse(
  fs.readFileSync(path.resolve(__dirname, '../../../../package.json'), 'utf8'),
).version;

afterEach(() => {
  process.env.PATH = originalPath;
});

function pathDirectory(): string {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'registry-stack-server-command-'));
  process.env.PATH = directory;
  return directory;
}

// A CLI whose build hosts the language server: it answers the probe the
// extension makes, and nothing else.
function writeHostingCli(directory: string, name: string, version = expectedVersion): string {
  return writeScript(
    directory,
    name,
    [
      `if [ "$1" = "--version" ]; then printf '%s\\n' '${name} ${version}'; exit 0; fi`,
      'if [ "$1" = "tooling" ] && [ "$2" = "language-server" ]; then',
      'exit 0', 'fi', 'exit 2',
    ],
  );
}

// A CLI that predates the language server being hosted in it. It is on PATH
// and executable, and it refuses the subcommand.
function writeLegacyCli(directory: string, name: string): string {
  return writeScript(directory, name, ['exit 2']);
}

function writeScript(directory: string, name: string, body: string[]): string {
  const script = path.join(directory, name);
  fs.writeFileSync(script, `#!/bin/sh\n${body.join('\n')}\n`);
  fs.chmodSync(script, 0o755);
  return script;
}

test('registryctl is not a supported language-server launcher', () => {
  const directory = pathDirectory();
  writeHostingCli(directory, 'registryctl');
  const evidencectl = writeHostingCli(directory, 'evidencectl');
  assert.deepStrictEqual(findLanguageServerOnPath(expectedVersion), {
    command: evidencectl,
    args: ['tooling', 'language-server'],
  });
});

test('evidencectl hosts the server while retired relayctl is ignored', () => {
  const directory = pathDirectory();
  const evidencectl = writeHostingCli(directory, 'evidencectl');
  writeHostingCli(directory, 'relayctl');
  assert.deepStrictEqual(findLanguageServerOnPath(expectedVersion), {
    command: evidencectl,
    args: ['tooling', 'language-server'],
  });
});

test('retired relayctl cannot host the server when evidencectl is unavailable', () => {
  const directory = pathDirectory();
  writeLegacyCli(directory, 'evidencectl');
  writeHostingCli(directory, 'relayctl');
  assert.strictEqual(findLanguageServerOnPath(expectedVersion), undefined);
});

test('an unversioned standalone server on PATH requires an explicit setting', () => {
  const directory = pathDirectory();
  writeScript(directory, 'registry-language-server', ['exit 0']);
  assert.strictEqual(findLanguageServerOnPath(expectedVersion), undefined);
  const evidencectl = writeHostingCli(directory, 'evidencectl');
  assert.deepStrictEqual(findLanguageServerOnPath(expectedVersion), {
    command: evidencectl, args: ['tooling', 'language-server'],
  });
});

test('no candidate hosting the server resolves to nothing', () => {
  const directory = pathDirectory();
  writeHostingCli(directory, 'registryctl');
  writeLegacyCli(directory, 'evidencectl');
  writeLegacyCli(directory, 'relayctl');
  assert.strictEqual(findLanguageServerOnPath(expectedVersion), undefined);
});

test('an empty PATH resolves to nothing', () => {
  process.env.PATH = '';
  assert.strictEqual(findLanguageServerOnPath(expectedVersion), undefined);
});


test('retired relayctl does not bypass the Evidence version requirement', () => {
  const directory = pathDirectory();
  writeHostingCli(directory, 'evidencectl', '0.2.0');
  writeHostingCli(directory, 'relayctl');
  assert.strictEqual(findLanguageServerOnPath(expectedVersion), undefined);
});

test('a development build of the extension release is accepted', () => {
  const directory = pathDirectory();
  const evidencectl = writeHostingCli(directory, 'evidencectl', `${expectedVersion}-dev`);
  assert.deepStrictEqual(findLanguageServerOnPath(expectedVersion), {
    command: evidencectl, args: ['tooling', 'language-server'],
  });
});

test('a previously selected CLI replaced with another version is rejected', () => {
  const directory = pathDirectory();
  const evidencectl = writeHostingCli(directory, 'evidencectl');
  assert.strictEqual(hostsMatchingLanguageServer(evidencectl, expectedVersion), true);
  writeHostingCli(directory, 'evidencectl', '0.36.0');
  assert.strictEqual(hostsMatchingLanguageServer(evidencectl, expectedVersion), false);
});

test('unexpected version output is rejected even if hosting is available', () => {
  const directory = pathDirectory();
  const executable = writeHostingCli(directory, 'registryctl');
  assert.strictEqual(hostsMatchingLanguageServer(executable, expectedVersion), false);
});

test('a stale same-name CLI earlier on PATH does not hide a matching build', () => {
  const first = pathDirectory();
  const second = fs.mkdtempSync(path.join(os.tmpdir(), 'registry-stack-server-command-'));
  writeHostingCli(first, 'evidencectl', '0.2.0');
  const evidencectl = writeHostingCli(second, 'evidencectl');
  process.env.PATH = `${first}${path.delimiter}${second}`;
  assert.deepStrictEqual(findLanguageServerOnPath(expectedVersion), {
    command: evidencectl, args: ['tooling', 'language-server'],
  });
});
