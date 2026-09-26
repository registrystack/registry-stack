// Product toolsets a tutorial journey runs against.
//
// A toolset puts the binaries under test on the reader's PATH, the way a
// reader has them after installing, and stops whatever long-running services
// the journey left behind, whether it passed or failed. This is the only
// product-specific code in the runner.

import { spawnSync } from 'node:child_process';
import { accessSync, constants } from 'node:fs';
import { mkdir, readdir, symlink } from 'node:fs/promises';
import { dirname, isAbsolute, join } from 'node:path';

export class ToolsetError extends Error {}

function checkBinary(variable, path) {
  if (!isAbsolute(path)) throw new ToolsetError(`${variable} must be an absolute path: ${path}`);
  try {
    accessSync(path, constants.X_OK);
  } catch {
    throw new ToolsetError(`${variable} is not executable: ${path}`);
  }
}

// A product toolset: its binaries, built from this checkout unless every one
// of their variables names an exact candidate or released binary, served by
// name from binDir; and its local development sessions, stopped in the order
// given when the journey ends.
function productToolset({ label, binaries, cargoArgs, profileVariable, targetName, sessions, ...rest }) {
  const variables = binaries.map(([, variable]) => variable);
  return {
    ...rest,

    async prepare({ repoRoot, binDir }) {
      const given = binaries.map(([, variable]) => process.env[variable] || undefined);
      if (given.some(Boolean) && !given.every(Boolean)) {
        const names = variables.length > 2 ? `${variables.slice(0, -1).join(', ')}, and ${variables.at(-1)}` : variables.join(' and ');
        const neither = variables.length > 2 ? 'none of them' : 'neither';
        throw new ToolsetError(`set ${names}, or ${neither} to build from source`);
      }
      let paths = given;
      if (!given[0]) {
        const profile = process.env[profileVariable] ?? 'ci';
        if (!['ci', 'release'].includes(profile)) {
          throw new ToolsetError(`unsupported tutorial Cargo profile: ${profile} (expected ci or release)`);
        }
        const targetDir = join(repoRoot, 'target', targetName);
        const build = spawnSync('cargo', ['build', '--locked', '--profile', profile, ...cargoArgs, '--bins'], {
          cwd: repoRoot,
          stdio: 'inherit',
          env: { ...process.env, CARGO_TARGET_DIR: targetDir },
        });
        if (build.status !== 0) throw new ToolsetError(`building ${label} failed`);
        paths = binaries.map(([name]) => join(targetDir, profile, name));
      }
      binaries.forEach(([, variable], i) => checkBinary(variable, paths[i]));
      await mkdir(binDir, { recursive: true });
      for (const [i, [name]] of binaries.entries()) await symlink(paths[i], join(binDir, name));
    },

    // Stop every local development session the journey started and reclaim
    // its container and volume. A journey that fails halfway leaves its
    // sessions running, and deleting the reader directory alone would orphan
    // their containers. Stopping with --remove is idempotent. Returns false
    // when a session could not be stopped, so its project is kept for a second
    // attempt.
    async teardown({ readerDir, binDir }) {
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
          const project = dirname(dirname(dirname(join(readerDir, entry))));
          const stop = spawnSync(join(binDir, tool), ['dev', 'stop', project, '--remove'], { encoding: 'utf8' });
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
  // cover it (tutorial-runner/gate.mjs).
  commands: /(^|[^\w-])(bregctl|breg)([^\w-]|$)/mu,
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
  commands: /(^|[^\w-])(caseworkctl|casework)([^\w-]|$)/mu,
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

// No product binaries: the journey runs against what is already on PATH.
const none = {
  async prepare() {},
  async teardown() {
    return true;
  },
};

export const TOOLSETS = { breg, casework, none };
