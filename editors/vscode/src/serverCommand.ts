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

// The adopter CLIs that may host the server, in the order a Relay adopter's
// PATH is expected to answer them. Both are tried: an Evidence adopter can
// have an older registryctl on PATH that this extension is not installed for.
const HOSTING_CLI_NAMES = ['registryctl', 'evidencectl'];

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

export function findExecutableOnPath(executable: string): string | undefined {
  const pathEntries = process.env.PATH?.split(path.delimiter) ?? [];
  for (const entry of pathEntries) {
    if (entry === '') {
      continue;
    }
    const candidate = path.join(entry, executable);
    if (isExecutableFile(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

// The first PATH candidate that can actually serve this workspace, or nothing.
// A name on PATH is not the answer on its own: an adopter can hold a CLI built
// before the language server was hosted in it, and the presence of that one
// must not hide a later CLI standing beside it.
export function findLanguageServerOnPath(): ServerCommand | undefined {
  const standalone = findExecutableOnPath(platformExecutable('registry-language-server'));
  if (standalone !== undefined) {
    return { command: standalone, args: [] };
  }
  for (const name of HOSTING_CLI_NAMES) {
    const candidate = findExecutableOnPath(platformExecutable(name));
    if (candidate !== undefined && hostsLanguageServer(candidate)) {
      return { command: candidate, args: [...HOSTED_SERVER_ARGUMENTS] };
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
function hostsLanguageServer(command: string): boolean {
  const probe = spawnSync(command, [...HOSTED_SERVER_ARGUMENTS, '--help'], {
    stdio: 'ignore',
    timeout: PROBE_TIMEOUT_MILLISECONDS,
  });
  return probe.error === undefined && probe.status === 0;
}
