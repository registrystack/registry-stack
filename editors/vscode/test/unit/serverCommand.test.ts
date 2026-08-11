// SPDX-License-Identifier: Apache-2.0

import * as assert from 'node:assert';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, test } from 'node:test';

import { findLanguageServerOnPath } from '../../src/serverCommand.js';

const originalPath = process.env.PATH;

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
function writeHostingCli(directory: string, name: string): string {
  return writeScript(
    directory,
    name,
    ['if [ "$1" = "tooling" ] && [ "$2" = "language-server" ]; then', 'exit 0', 'fi', 'exit 2'],
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
  assert.deepStrictEqual(findLanguageServerOnPath(), {
    command: evidencectl,
    args: ['tooling', 'language-server'],
  });
});

test('evidencectl is preferred over relayctl', () => {
  const directory = pathDirectory();
  const evidencectl = writeHostingCli(directory, 'evidencectl');
  writeHostingCli(directory, 'relayctl');
  assert.deepStrictEqual(findLanguageServerOnPath(), {
    command: evidencectl,
    args: ['tooling', 'language-server'],
  });
});

test('relayctl hosts the server when evidencectl cannot', () => {
  const directory = pathDirectory();
  writeLegacyCli(directory, 'evidencectl');
  const relayctl = writeHostingCli(directory, 'relayctl');
  assert.deepStrictEqual(findLanguageServerOnPath(), {
    command: relayctl,
    args: ['tooling', 'language-server'],
  });
});

test('a standalone server is preferred over adopter CLIs', () => {
  const directory = pathDirectory();
  const standalone = writeScript(directory, 'registry-language-server', ['exit 0']);
  writeHostingCli(directory, 'evidencectl');
  assert.deepStrictEqual(findLanguageServerOnPath(), { command: standalone, args: [] });
});

test('no candidate hosting the server resolves to nothing', () => {
  const directory = pathDirectory();
  writeHostingCli(directory, 'registryctl');
  writeLegacyCli(directory, 'evidencectl');
  writeLegacyCli(directory, 'relayctl');
  assert.strictEqual(findLanguageServerOnPath(), undefined);
});

test('an empty PATH resolves to nothing', () => {
  process.env.PATH = '';
  assert.strictEqual(findLanguageServerOnPath(), undefined);
});
