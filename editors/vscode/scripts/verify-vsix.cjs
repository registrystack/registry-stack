// SPDX-License-Identifier: Apache-2.0

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const vsixPath = process.argv[2];
if (typeof vsixPath !== 'string' || vsixPath.length === 0) {
  throw new Error('usage: node scripts/verify-vsix.cjs <extension.vsix>');
}

const entries = execFileSync('unzip', ['-Z1', vsixPath], { encoding: 'utf8' }).split('\n');
const requiredEntries = ['extension/package.json', 'extension/dist/extension.js'];
const expectedCliPath = process.env.REGISTRY_STACK_EXPECT_CLI_PATH;
if (expectedCliPath) {
  requiredEntries.push('extension/dist/registry-stack-cli-path');
}
for (const entry of requiredEntries) {
  if (!entries.includes(entry)) {
    throw new Error(`VSIX is missing required runtime entry: ${entry}`);
  }
}
if (entries.some((entry) => entry.startsWith('extension/node_modules/'))) {
  throw new Error('VSIX contains node_modules; runtime dependencies must be bundled in dist/extension.js');
}

const sourceManifest = require('../package.json');
const lockfile = require('../package-lock.json');
const workspaceManifest = fs.readFileSync(path.resolve(__dirname, '../../../Cargo.toml'), 'utf8');
const workspacePackage = workspaceManifest.match(/\[workspace\.package\]\s*\n([\s\S]*?)(?=\n\[|$)/)?.[1];
const workspaceVersion = workspacePackage?.match(/^version\s*=\s*"([^"]+)"/m)?.[1];
if (workspaceVersion === undefined || sourceManifest.version !== workspaceVersion) {
  throw new Error('VS Code extension version must match the Registry Stack workspace version');
}
if (lockfile.version !== sourceManifest.version || lockfile.packages?.['']?.version !== sourceManifest.version) {
  throw new Error('VS Code package-lock version does not match package.json');
}
const packagedManifest = JSON.parse(execFileSync('unzip', ['-p', vsixPath, 'extension/package.json'], {
  encoding: 'utf8',
}));
if (packagedManifest.name !== sourceManifest.name || packagedManifest.version !== sourceManifest.version) {
  throw new Error('VSIX package identity does not match the source manifest');
}

const bundle = execFileSync('unzip', ['-p', vsixPath, 'extension/dist/extension.js'], {
  encoding: 'utf8',
});
if (bundle.includes('require("vscode-languageclient') || bundle.includes("require('vscode-languageclient")) {
  throw new Error('VSIX leaves vscode-languageclient as an external runtime dependency');
}

if (expectedCliPath) {
  const packagedCliPath = execFileSync(
    'unzip',
    ['-p', vsixPath, 'extension/dist/registry-stack-cli-path'],
    { encoding: 'utf8' },
  ).trim();
  if (packagedCliPath !== expectedCliPath) {
    throw new Error('VSIX does not contain the CLI path selected by the installer');
  }
}
