// SPDX-License-Identifier: Apache-2.0

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { defineConfig } = require('@vscode/test-cli');

const testRunDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'registry-stack-vscode-'));
const trustedUserData = path.join(testRunDirectory, 'trusted-user-data');
const projectAlpha = path.join(testRunDirectory, 'project-alpha');
const projectBeta = path.join(testRunDirectory, 'project-beta');
const workspaceFolder = path.join(testRunDirectory, 'multi-root.code-workspace');
const languageServer = path.resolve(__dirname, '../../target/debug/registry-language-server');
const registryctlWrapper = path.join(testRunDirectory, 'registryctl');
const installerMetadata = path.join(__dirname, 'dist', 'registryctl-path');
fs.mkdirSync(projectAlpha, { recursive: true });
fs.mkdirSync(projectBeta, { recursive: true });
fs.writeFileSync(
  registryctlWrapper,
  [
    '#!/bin/sh',
    'if [ "$#" -ne 2 ] || [ "$1" != "authoring" ] || [ "$2" != "language-server" ]; then',
    '  exit 64',
    'fi',
    `exec ${shellQuote(languageServer)}`,
    '',
  ].join('\n'),
);
fs.chmodSync(registryctlWrapper, 0o755);
fs.mkdirSync(path.dirname(installerMetadata), { recursive: true });
fs.writeFileSync(installerMetadata, `${registryctlWrapper}\n`);
fs.writeFileSync(
  path.join(projectAlpha, 'registry-stack.yaml'),
  'version: 1\nregistry: { id: alpha-registry }\nservices: {}\n',
);
fs.writeFileSync(
  path.join(projectBeta, 'registry-stack.yaml'),
  'version: 1\nregistry: { id: beta-registry }\nservices: {}\n',
);
fs.writeFileSync(
  workspaceFolder,
  JSON.stringify({
    folders: [
      { name: 'alpha', path: projectAlpha },
      { name: 'beta', path: projectBeta },
    ],
  }),
);

function shellQuote(value) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

module.exports = defineConfig({
  files: 'out/test/trusted.test.js',
  version: '1.91.1',
  workspaceFolder,
  launchArgs: ['--disable-extensions', '--user-data-dir', trustedUserData],
  mocha: { timeout: 30_000 },
});
