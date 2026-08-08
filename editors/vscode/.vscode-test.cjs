// SPDX-License-Identifier: Apache-2.0

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { defineConfig } = require('@vscode/test-cli');

const testRunDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'registry-stack-vscode-'));
const trustedUserData = path.join(testRunDirectory, 'trusted-user-data');
const projectAlpha = path.join(testRunDirectory, 'project-alpha');
const projectBeta = path.join(testRunDirectory, 'project-beta');
const projectEvidence = path.join(testRunDirectory, 'project-evidence');
const workspaceFolder = path.join(testRunDirectory, 'multi-root.code-workspace');
const languageServer = path.resolve(__dirname, '../../target/debug/registry-language-server');
// The registryctl wrapper is deliberately kept off PATH and reachable only
// through the installer metadata below, so the tests can prove the metadata
// route works. evidencectl sits in a directory added to PATH instead, so a
// later test can delete the metadata and prove the PATH fallback tier finds
// it on its own.
const registryctlWrapper = path.join(testRunDirectory, 'registryctl');
const pathBinDirectory = path.join(testRunDirectory, 'path-bin');
const evidencectlWrapper = path.join(pathBinDirectory, 'evidencectl');
const installerMetadata = path.join(__dirname, 'dist', 'registry-stack-cli-path');
fs.mkdirSync(projectAlpha, { recursive: true });
fs.mkdirSync(projectBeta, { recursive: true });
fs.mkdirSync(path.join(projectEvidence, 'selectors'), { recursive: true });
fs.mkdirSync(pathBinDirectory, { recursive: true });
writeToolingLanguageServerWrapper(registryctlWrapper);
writeToolingLanguageServerWrapper(evidencectlWrapper);
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
  path.join(projectEvidence, 'evidence-project.yaml'),
  'version: 1\nproject: evidence-authoring\n',
);
fs.writeFileSync(path.join(projectEvidence, 'selectors', 'smoke.yaml'), 'fields: {}\n');
fs.writeFileSync(
  workspaceFolder,
  JSON.stringify({
    folders: [
      { name: 'alpha', path: projectAlpha },
      { name: 'beta', path: projectBeta },
      { name: 'evidence', path: projectEvidence },
    ],
  }),
);
process.env.PATH = `${pathBinDirectory}${path.delimiter}${process.env.PATH ?? ''}`;

function writeToolingLanguageServerWrapper(wrapperPath) {
  fs.writeFileSync(
    wrapperPath,
    [
      '#!/bin/sh',
      'if [ "$#" -ne 2 ] || [ "$1" != "tooling" ] || [ "$2" != "language-server" ]; then',
      '  exit 64',
      'fi',
      `exec ${shellQuote(languageServer)}`,
      '',
    ].join('\n'),
  );
  fs.chmodSync(wrapperPath, 0o755);
}

function shellQuote(value) {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

module.exports = defineConfig({
  files: 'out/test/trusted.test.js',
  version: '1.91.1',
  workspaceFolder,
  launchArgs: ['--disable-extensions', '--user-data-dir', trustedUserData],
  mocha: { timeout: 60_000 },
});
