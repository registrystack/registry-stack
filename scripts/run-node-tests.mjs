#!/usr/bin/env node
// Run native Node binding tests with Cargo's macOS runtime library available.
// npm launches package scripts through a protected shell that strips DYLD_*;
// the non-DYLD carrier survives, so restore the loader path on the Node child
// that actually imports the addon.

import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';

export function cargoRuntimeEnvironment(environment, platform = process.platform) {
  const child = { ...environment };
  const runtime = child.REGISTRY_CARGO_RUNTIME_LIBRARY_PATH;
  if (platform === 'darwin' && runtime) {
    child.DYLD_LIBRARY_PATH = runtime + (child.DYLD_LIBRARY_PATH ? `:${child.DYLD_LIBRARY_PATH}` : '');
  }
  return child;
}

export function run(arguments_) {
  if (arguments_.length === 0) {
    console.error('run-node-tests: at least one test path is required');
    return 2;
  }
  const completed = spawnSync(process.execPath, ['--test', ...arguments_], {
    env: cargoRuntimeEnvironment(process.env),
    stdio: 'inherit',
  });
  if (completed.error) {
    console.error(`run-node-tests: ${completed.error.message}`);
    return 1;
  }
  return completed.status ?? 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exitCode = run(process.argv.slice(2));
}
