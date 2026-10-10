// Product toolsets a tutorial journey runs against.
//
// A toolset puts the binaries under test on the reader's PATH, the way a
// reader has them after installing, and stops whatever long-running services
// the journey left behind, whether it passed or failed. This is the only
// product-specific code in the runner.

import { spawn, spawnSync } from 'node:child_process';
import { accessSync, closeSync, constants, existsSync, mkdtempSync, openSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { chmod, mkdir, readdir, stat, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';

import { stopGroup } from './background.mjs';

export class ToolsetError extends Error {}

function checkBinary(variable, path) {
  if (!isAbsolute(path)) throw new ToolsetError(`${variable} must be an absolute path: ${path}`);
  try {
    accessSync(path, constants.X_OK);
  } catch {
    throw new ToolsetError(`${variable} is not executable: ${path}`);
  }
}

// Runs cargo with args. On macOS, returns the directory holding the AWS-LC
// FIPS dylib the built binaries load at run time, which Cargo supplies only to
// the processes it launches itself; the build messages name it, and
// scripts/cargo_runtime_library_path.py reads them the way
// scripts/cargo-runtime-library-path.sh does for a reader's shell.
export function cargoBuild({ repoRoot, args, env = process.env, platform = process.platform }) {
  if (platform !== 'darwin') {
    const build = spawnSync('cargo', args, { cwd: repoRoot, stdio: 'inherit', env });
    if (build.status !== 0) throw new ToolsetError('cargo build failed');
    return undefined;
  }
  const build = spawnSync('cargo', [...args, '--message-format=json-render-diagnostics'], {
    cwd: repoRoot,
    stdio: ['ignore', 'pipe', 'inherit'],
    env,
    maxBuffer: 1 << 30,
  });
  const scratch = mkdtempSync(join(tmpdir(), 'tutorial-cargo-'));
  try {
    const messages = join(scratch, 'messages.json');
    writeFileSync(messages, build.stdout ?? '');
    const parser = join(repoRoot, 'scripts', 'cargo_runtime_library_path.py');
    if (build.status !== 0) {
      spawnSync('python3', [parser, '--render-diagnostics', messages], { stdio: ['ignore', 2, 'inherit'], env });
      throw new ToolsetError('cargo build failed');
    }
    const resolved = spawnSync('python3', [parser, messages], { stdio: ['ignore', 'pipe', 'inherit'], encoding: 'utf8', env });
    if (resolved.status !== 0) throw new ToolsetError('could not find the AWS-LC FIPS runtime library of the build');
    return resolved.stdout.trim();
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

const quote = (value) => `'${value.replaceAll("'", `'\\''`)}'`;

// Serves each [name, path] binary by name from binDir. With a runtime library
// directory, each name is a wrapper that sets DYLD_FALLBACK_LIBRARY_PATH
// itself, because macOS drops that variable whenever a protected binary such
// as /bin/sh or /usr/bin/env starts a process.
export async function serveBinaries(binDir, entries, libraryDir) {
  await mkdir(binDir, { recursive: true });
  for (const [name, path] of entries) {
    const served = join(binDir, name);
    if (!libraryDir) {
      await symlink(path, served);
      continue;
    }
    await writeFile(
      served,
      `#!/bin/sh\nDYLD_FALLBACK_LIBRARY_PATH=${quote(libraryDir)}\${DYLD_FALLBACK_LIBRARY_PATH:+:\$DYLD_FALLBACK_LIBRARY_PATH}\nexport DYLD_FALLBACK_LIBRARY_PATH\nexec ${quote(path)} "\$@"\n`,
    );
    await chmod(served, 0o755);
  }
}

// A product toolset: its binaries, built from this checkout unless every one
// of their variables names an exact candidate or released binary, served by
// name from binDir; and its local development sessions, stopped in the order
// given when the journey ends, each with the arguments stopArgs gives for its
// project directory.
function productToolset({
  label,
  binaries,
  cargoArgs,
  profileVariable,
  targetName,
  sessions,
  stopArgs = (project) => ['dev', 'stop', project, '--remove'],
  ...rest
}) {
  const variables = binaries.map(([, variable]) => variable);
  return {
    ...rest,

    // Returns the variables the journey's environment adds, if any.
    async prepare({ repoRoot, binDir }) {
      const given = binaries.map(([, variable]) => process.env[variable] || undefined);
      if (given.some(Boolean) && !given.every(Boolean)) {
        const names = variables.length > 2 ? `${variables.slice(0, -1).join(', ')}, and ${variables.at(-1)}` : variables.join(' and ');
        const neither = variables.length > 2 ? 'none of them' : 'neither';
        throw new ToolsetError(`set ${names}, or ${neither} to build from source`);
      }
      let paths = given;
      let libraryDir;
      if (!given[0]) {
        const profile = process.env[profileVariable] ?? 'ci';
        if (!['ci', 'release'].includes(profile)) {
          throw new ToolsetError(`unsupported tutorial Cargo profile: ${profile} (expected ci or release)`);
        }
        const targetDir = join(repoRoot, 'target', targetName);
        try {
          libraryDir = cargoBuild({
            repoRoot,
            args: ['build', '--locked', '--profile', profile, ...cargoArgs, '--bins'],
            env: { ...process.env, CARGO_TARGET_DIR: targetDir },
          });
        } catch (error) {
          if (error instanceof ToolsetError) throw new ToolsetError(`building ${label} failed: ${error.message}`);
          throw error;
        }
        paths = binaries.map(([name]) => join(targetDir, profile, name));
      }
      binaries.forEach(([, variable], i) => checkBinary(variable, paths[i]));
      await serveBinaries(binDir, binaries.map(([name], i) => [name, paths[i]]), libraryDir);
      return {};
    },

    // Stop every local development session the journey started and reclaim
    // its container and volume, if it has one. A journey that fails halfway
    // leaves its sessions running, and deleting the reader directory alone
    // would orphan them. Stopping is idempotent. A session state file the
    // checkout copy carried in and the journey never rewrote (inherited maps
    // its path to the modification time it had) belongs to a committed example,
    // not to a session the journey started, so it is left alone. Returns false
    // when a session could not be stopped, so its project is kept for a second
    // attempt.
    async teardown({ readerDir, binDir, inherited = new Map() }) {
      let entries;
      try {
        entries = await readdir(readerDir, { recursive: true });
      } catch (error) {
        if (error.code === 'ENOENT') return true;
        throw error;
      }
      let stoppedAll = true;
      for (const [tool, state] of sessions) {
        for (const entry of entries.filter((path) => path.endsWith(state)).sort()) {
          if (inherited.get(entry) === (await stat(join(readerDir, entry))).mtimeMs) continue;
          const project = dirname(dirname(dirname(join(readerDir, entry))));
          const stop = spawnSync(join(binDir, tool), stopArgs(project), { encoding: 'utf8' });
          if (stop.status === 0) {
            console.log(`stopped the local development session in ${project}`);
          } else {
            console.error(`could not stop the local development session in ${project}:\n${stop.stdout}${stop.stderr}`);
            stoppedAll = false;
          }
        }
      }
      return stoppedAll;
    },
  };
}

// Base Registry Engine: breg and bregctl. `bregctl dev` resolves `breg` from
// PATH, so both are served by name.
const breg = productToolset({
  label: 'breg and bregctl',
  // A page whose sh fences match this runs the toolset, so its gate must
  // cover it (tutorial-runner/gate.mjs). A path such as .breg/dev or
  // tutorial-work/breg names no command, and neither does a value such as
  // serviceKind=breg.
  commands: /(^|[^\w./=-])(bregctl|breg)([^\w./-]|$)/mu,
  binaries: [
    ['breg', 'BREG_BIN'],
    ['bregctl', 'BREGCTL_BIN'],
  ],
  cargoArgs: ['-p', 'registry-breg', '--features', 'registry-breg/runtime', '-p', 'registry-bregctl'],
  profileVariable: 'BREG_TUTORIAL_CARGO_PROFILE',
  targetName: 'breg-tutorial-source',
  sessions: [['bregctl', '.breg/dev/state.json']],
});

// Registry Casework: casework and caseworkctl, with breg and bregctl because
// a Casework journey may review work a local registry holds. `caseworkctl dev`
// resolves `casework` and `bregctl` from PATH. Casework sessions stop first,
// so they no longer reconcile against a registry that is stopping.
const casework = productToolset({
  label: 'casework, caseworkctl, breg, and bregctl',
  commands: /(^|[^\w./=-])(caseworkctl|casework)([^\w./-]|$)/mu,
  includes: ['breg'],
  binaries: [
    ['casework', 'CASEWORK_BIN'],
    ['caseworkctl', 'CASEWORKCTL_BIN'],
    ['breg', 'BREG_BIN'],
    ['bregctl', 'BREGCTL_BIN'],
  ],
  cargoArgs: ['-p', 'registry-casework', '-p', 'registry-caseworkctl', '-p', 'registry-breg', '--features', 'registry-breg/runtime', '-p', 'registry-bregctl'],
  profileVariable: 'CASEWORK_TUTORIAL_CARGO_PROFILE',
  targetName: 'casework-tutorial-source',
  sessions: [
    ['caseworkctl', '.casework/dev/state.json'],
    ['bregctl', '.breg/dev/state.json'],
  ],
});

// Registry Discovery: discovery and discoveryctl. A page serves the index
// from a background fence, which the runner stops itself, so there is no
// local development session to stop here.
const discovery = productToolset({
  label: 'discovery and discoveryctl',
  // Not the discovery-project directory or the products/discovery/ paths a
  // page names.
  commands: /(^|[^\w./=-])(discoveryctl|discovery)([^\w./-]|$)/mu,
  binaries: [
    ['discovery', 'DISCOVERY_BIN'],
    ['discoveryctl', 'DISCOVERYCTL_BIN'],
  ],
  cargoArgs: ['-p', 'registry-discovery', '-p', 'registry-discoveryctl'],
  profileVariable: 'DISCOVERY_TUTORIAL_CARGO_PROFILE',
  targetName: 'discovery-tutorial-source',
  sessions: [],
});

// Evidence: evidence, evidencectl, and evidence-oid4vci. Two things a reader
// sets up themselves are set up here instead:
//
// - The Python client package a reader installs with pip is unpacked from
//   REGISTRY_CLIENT_PY_WHEEL, a wheel assembled from this checkout with
//   release/scripts/assemble-registry-client-packages.py, onto PYTHONPATH.
//   The package declares no dependencies, so unpacking is enough, and its
//   bindings are built for the stable ABI, so it imports under any CPython.
// - The FHIR server a page reads is replaced by the sanitized local mock in
//   fixtures/fhir-tutorial-mock.py, at FHIR_TUTORIAL_TEST_BASE_URL, for every
//   journey.
//
// EVIDENCE_OID4VCI_BIN names the served evidence-oid4vci for the
// interoperability checks, which also take EVIDENCE_OID4VCI_INTEROP_TEST_BIN
// from the environment when it names a prebuilt interoperability test.
const FHIR_MOCK = resolve(dirname(fileURLToPath(import.meta.url)), '../fixtures/fhir-tutorial-mock.py');
const FHIR_BASE_URL = 'http://127.0.0.1:8003';
const FHIR_READY_TIMEOUT_MS = 30_000;
const WHEEL_HINT = 'release/scripts/assemble-registry-client-packages.py';

function clientWheel() {
  const wheel = process.env.REGISTRY_CLIENT_PY_WHEEL ?? '';
  if (wheel === '') throw new ToolsetError(`REGISTRY_CLIENT_PY_WHEEL is unset: name a client wheel assembled with ${WHEEL_HINT}`);
  if (!isAbsolute(wheel)) throw new ToolsetError(`REGISTRY_CLIENT_PY_WHEEL must be an absolute path: ${wheel}`);
  if (!existsSync(wheel) || !statSync(wheel).isFile()) {
    throw new ToolsetError(`client wheel not found: ${wheel}; assemble one with ${WHEEL_HINT}`);
  }
  return wheel;
}

// Start the FHIR mock in its own process group and wait until it answers.
// Returns its process group.
async function startFhirMock(workRoot) {
  const log = join(workRoot, 'fhir-tutorial-mock.log');
  const fd = openSync(log, 'w');
  const child = spawn('python3', [FHIR_MOCK], { detached: true, stdio: ['ignore', fd, fd] });
  closeSync(fd);
  const failed = async (why) => {
    await stopGroup(child.pid);
    return new ToolsetError(`the FHIR tutorial mock ${why}:\n${readFileSync(log, 'utf8')}`);
  };
  const deadline = Date.now() + FHIR_READY_TIMEOUT_MS;
  for (;;) {
    if (child.exitCode !== null || child.signalCode !== null) throw await failed(`ended before ${FHIR_BASE_URL} answered`);
    try {
      const response = await fetch(`${FHIR_BASE_URL}/healthz`, { signal: AbortSignal.timeout(2000) });
      if (response.ok) break;
    } catch {
      // Not answering yet: the mock may still be starting.
    }
    if (Date.now() > deadline) throw await failed(`did not answer within ${FHIR_READY_TIMEOUT_MS / 1000} seconds`);
    await sleep(100);
  }
  // Another process may hold the port and have answered in its place.
  await sleep(100);
  if (child.exitCode !== null || child.signalCode !== null) throw await failed(`could not serve ${FHIR_BASE_URL}`);
  return child.pid;
}

const evidenceProduct = productToolset({
  label: 'evidence, evidencectl, and evidence-oid4vci',
  // Not a path such as .evidence/dev, which a page may name; but a page that
  // runs Evidence's own checks from a checkout runs Evidence.
  commands: /(^|[^\w./=-])(evidencectl|evidence-oid4vci|evidence)([^\w./-]|$)|(^|\s)products\/evidence\/scripts\//mu,
  binaries: [
    ['evidence', 'EVIDENCE_BIN'],
    ['evidencectl', 'EVIDENCECTL_BIN'],
    ['evidence-oid4vci', 'EVIDENCE_OID4VCI_BIN'],
  ],
  cargoArgs: ['-p', 'registry-evidence', '-p', 'registry-evidencectl', '-p', 'registry-evidence-oid4vci'],
  profileVariable: 'EVIDENCE_TUTORIAL_CARGO_PROFILE',
  targetName: 'evidence-tutorial-source',
  sessions: [['evidencectl', '.evidence/dev/control.sock']],
  stopArgs: (project) => ['dev', 'stop', project],
});

let fhirMock;
const evidence = {
  ...evidenceProduct,

  async prepare({ repoRoot, binDir, workRoot }) {
    const wheel = clientWheel();
    await evidenceProduct.prepare({ repoRoot, binDir });
    const clientPackage = join(workRoot, 'client-package');
    const unpack = spawnSync('python3', ['-m', 'zipfile', '-e', wheel, clientPackage], { encoding: 'utf8' });
    if (unpack.status !== 0) throw new ToolsetError(`could not unpack ${wheel}:\n${unpack.stderr}`);
    fhirMock = await startFhirMock(workRoot);
    const pythonPath = process.env.PYTHONPATH ? `${clientPackage}:${process.env.PYTHONPATH}` : clientPackage;
    return {
      PYTHONPATH: pythonPath,
      EVIDENCE_OID4VCI_BIN: join(binDir, 'evidence-oid4vci'),
      FHIR_TUTORIAL_TEST_BASE_URL: FHIR_BASE_URL,
    };
  },

  async teardown(context) {
    const stoppedAll = await evidenceProduct.teardown(context);
    if (fhirMock !== undefined) await stopGroup(fhirMock);
    fhirMock = undefined;
    return stoppedAll;
  },
};

// No product binaries: the journey runs against what is already on PATH.
const none = {
  async prepare() {
    return {};
  },
  async teardown() {
    return true;
  },
};

export const TOOLSETS = { breg, casework, discovery, evidence, none };
