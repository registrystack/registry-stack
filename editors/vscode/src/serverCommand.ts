// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';

export interface ServerCommand {
  command: string;
  args: string[];
}

// The subcommand an adopter CLI answers to when it hosts the language server.
// editors/install.sh probes the same one before it records a CLI, so both
// halves of the integration ask a candidate the same question.
const HOSTED_SERVER_ARGUMENTS = ['tooling', 'language-server'];

// Evidence tooling hosts the shared server for every supported product.
const HOSTING_CLI_NAMES = ['evidencectl'];

const PROBE_TIMEOUT_MILLISECONDS = 5000;

export function isExecutableFile(candidate: string): boolean {
  try {
    if (!fs.statSync(candidate).isFile()) {
      return false;
    }
    if (process.platform !== 'win32') {
      fs.accessSync(candidate, fs.constants.X_OK);
    }
    return true;
  } catch {
    return false;
  }
}

function findExecutablesOnPath(executable: string): string[] {
  const pathEntries = process.env.PATH?.split(path.delimiter) ?? [];
  const candidates = new Set<string>();
  for (const entry of pathEntries) {
    if (entry === '') {
      continue;
    }
    const candidate = path.join(entry, executable);
    if (isExecutableFile(candidate)) {
      candidates.add(candidate);
    }
  }
  return [...candidates];
}

// The first PATH candidate that can actually serve this workspace, or nothing.
// A name on PATH is not the answer on its own: an adopter can hold a CLI built
// before the language server was hosted in it, and the presence of that one
// must not hide a later CLI standing beside it.
export function findLanguageServerOnPath(expectedVersion: string): ServerCommand | undefined {
  // The standalone development binary has no version contract. It remains
  // available through the explicit setting, where the author selects a build.
  for (const name of HOSTING_CLI_NAMES) {
    for (const candidate of findExecutablesOnPath(platformExecutable(name))) {
      if (hostsMatchingLanguageServer(candidate, expectedVersion)) {
        return { command: candidate, args: [...HOSTED_SERVER_ARGUMENTS] };
      }
    }
  }
  return undefined;
}

function platformExecutable(name: string): string {
  return process.platform === 'win32' ? `${name}.exe` : name;
}

// Whether this command hosts the language server, asked of the command rather
// than inferred from its name. The probe is the CLI's own help for the
// subcommand, so it starts no server and reads no project.
export function hostsMatchingLanguageServer(command: string, expectedVersion: string): boolean {
  const version = spawnSync(command, ['--version'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
    timeout: PROBE_TIMEOUT_MILLISECONDS,
    maxBuffer: 4096,
  });
  if (version.error !== undefined || version.status !== 0) {
    return false;
  }
  const [name, reportedVersion] = version.stdout.trim().split(/\s+/);
  if (
    !HOSTING_CLI_NAMES.includes(name) ||
    (reportedVersion !== expectedVersion && reportedVersion !== `${expectedVersion}-dev`)
  ) {
    return false;
  }
  const probe = spawnSync(command, [...HOSTED_SERVER_ARGUMENTS, '--help'], {
    stdio: 'ignore',
    timeout: PROBE_TIMEOUT_MILLISECONDS,
  });
  return probe.error === undefined && probe.status === 0;
}
