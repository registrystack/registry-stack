// SPDX-License-Identifier: Apache-2.0

const { execFileSync } = require('node:child_process');

const vsixPath = process.argv[2];
if (typeof vsixPath !== 'string' || vsixPath.length === 0) {
  throw new Error('usage: node scripts/verify-vsix.cjs <extension.vsix>');
}

const entries = execFileSync('unzip', ['-Z1', vsixPath], { encoding: 'utf8' }).split('\n');
const requiredEntries = ['extension/package.json', 'extension/dist/extension.js'];
const expectedRegistryctlPath = process.env.REGISTRY_STACK_EXPECT_REGISTRYCTL_PATH;
if (expectedRegistryctlPath) {
  requiredEntries.push('extension/dist/registryctl-path');
}
for (const entry of requiredEntries) {
  if (!entries.includes(entry)) {
    throw new Error(`VSIX is missing required runtime entry: ${entry}`);
  }
}
if (entries.some((entry) => entry.startsWith('extension/node_modules/'))) {
  throw new Error('VSIX contains node_modules; runtime dependencies must be bundled in dist/extension.js');
}

const bundle = execFileSync('unzip', ['-p', vsixPath, 'extension/dist/extension.js'], {
  encoding: 'utf8',
});
if (bundle.includes('require("vscode-languageclient') || bundle.includes("require('vscode-languageclient")) {
  throw new Error('VSIX leaves vscode-languageclient as an external runtime dependency');
}

if (expectedRegistryctlPath) {
  const packagedRegistryctlPath = execFileSync(
    'unzip',
    ['-p', vsixPath, 'extension/dist/registryctl-path'],
    { encoding: 'utf8' },
  ).trim();
  if (packagedRegistryctlPath !== expectedRegistryctlPath) {
    throw new Error('VSIX does not contain the registryctl path selected by the installer');
  }
}
