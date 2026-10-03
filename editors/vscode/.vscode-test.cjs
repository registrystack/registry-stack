// SPDX-License-Identifier: Apache-2.0

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { defineConfig } = require('@vscode/test-cli');
const extensionVersion = require('./package.json').version;

const testRunDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'registry-stack-vscode-'));
const trustedUserData = path.join(testRunDirectory, 'trusted-user-data');
const projectAlpha = path.join(testRunDirectory, 'project-alpha');
const projectBeta = path.join(testRunDirectory, 'project-beta');
const projectEvidence = path.join(testRunDirectory, 'project-evidence');
const workspaceFolder = path.join(testRunDirectory, 'multi-root.code-workspace');
const languageServer = path.join(process.env.CARGO_TARGET_DIR ?? path.resolve(__dirname, '../../target'), 'debug/registry-language-server');
// The installed Evidence wrapper is off PATH; a second matching copy on PATH
// proves fallback after installed metadata is replaced or removed.
const evidencectlWrapper = path.join(testRunDirectory, 'evidencectl');
const pathBinDirectory = path.join(testRunDirectory, 'path-bin');
const pathEvidencectlWrapper = path.join(pathBinDirectory, 'evidencectl');
// A stale Evidence copy earlier on PATH must not hide the matching host.
const legacyEvidencectlWrapper = path.join(testRunDirectory, 'legacy-bin', 'evidencectl');
const installerMetadata = path.join(__dirname, 'dist', 'registry-stack-cli-path');
fs.mkdirSync(projectAlpha, { recursive: true });
fs.mkdirSync(projectBeta, { recursive: true });
fs.mkdirSync(path.join(projectEvidence, 'selectors'), { recursive: true });
fs.mkdirSync(pathBinDirectory, { recursive: true });
fs.mkdirSync(path.dirname(legacyEvidencectlWrapper), { recursive: true });
writeToolingLanguageServerWrapper(evidencectlWrapper);
writeToolingLanguageServerWrapper(pathEvidencectlWrapper);
writeLegacyWrapper(legacyEvidencectlWrapper);
fs.mkdirSync(path.dirname(installerMetadata), { recursive: true });
fs.writeFileSync(installerMetadata, `${evidencectlWrapper}\n`);
fs.writeFileSync(
  path.join(projectAlpha, 'registry.yaml'),
  'apiVersion: registry.registrystack.org/v1alpha1\nkind: RegistryProject\nregistry: { id: alpha-registry }\n',
);
fs.writeFileSync(
  path.join(projectBeta, 'registry.yaml'),
  'apiVersion: registry.registrystack.org/v1alpha1\nkind: RegistryProject\nregistry: { id: beta-registry }\n',
);
fs.writeFileSync(
  path.join(projectEvidence, 'evidence-project.yaml'),
  'version: 1\nproject: evidence-authoring\n',
);
fs.writeFileSync(
  path.join(projectEvidence, 'source.openapi.yaml'),
  'openapi: 3.1.0\ninfo: { title: test, version: 1.0.0 }\npaths: {}\n',
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
process.env.PATH = `${path.dirname(legacyEvidencectlWrapper)}${path.delimiter}${pathBinDirectory}${path.delimiter}${process.env.PATH ?? ''}`;

function writeToolingLanguageServerWrapper(wrapperPath) {
  fs.writeFileSync(
    wrapperPath,
    [
      '#!/bin/sh',
      // macOS strips DYLD_* variables while launching Electron and /bin/sh.
      // Restore the local Cargo library path inside the test-only wrapper.
      ...(process.platform === 'darwin' && process.env.REGISTRY_STACK_TEST_LIBRARY_PATH
        ? [`export DYLD_LIBRARY_PATH=${shellQuote(process.env.REGISTRY_STACK_TEST_LIBRARY_PATH)}`]
        : []),
      `if [ "$1" = "--version" ]; then printf '%s\\n' '${path.basename(wrapperPath)} ${extensionVersion}'; exit 0; fi`,
      'if [ "$1" != "tooling" ] || [ "$2" != "language-server" ]; then',
      '  exit 64',
      'fi',
      '# The capability probe the extension makes before it starts a candidate',
      '# found on PATH. A real CLI answers it from the same subcommand.',
      'if [ "$#" -eq 3 ] && [ "$3" = "--help" ]; then',
      '  exit 0',
      'fi',
      'if [ "$#" -ne 2 ]; then',
      '  exit 64',
      'fi',
      `exec ${shellQuote(languageServer)}`,
      '',
    ].join('\n'),
  );
  fs.chmodSync(wrapperPath, 0o755);
}

function writeLegacyWrapper(wrapperPath) {
  fs.writeFileSync(wrapperPath, ['#!/bin/sh', 'exit 64', ''].join('\n'));
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
