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

// Base Registry Engine: breg and bregctl, built from this checkout unless
// BREG_BIN and BREGCTL_BIN name exact candidate or released binaries.
// `bregctl dev` resolves `breg` from PATH, so both are served by name.
const breg = {
  // A page whose sh fences match this runs the toolset, so its gate must
  // cover it (tutorial-runner/gate.mjs).
  commands: /(^|[^\w-])(bregctl|breg)([^\w-]|$)/mu,

  async prepare({ repoRoot, binDir }) {
    let bregBin = process.env.BREG_BIN;
    let bregctlBin = process.env.BREGCTL_BIN;
    if (Boolean(bregBin) !== Boolean(bregctlBin)) {
      throw new ToolsetError('set both BREG_BIN and BREGCTL_BIN, or neither to build from source');
    }
    if (!bregBin) {
      const profile = process.env.BREG_TUTORIAL_CARGO_PROFILE ?? 'ci';
      if (!['ci', 'release'].includes(profile)) {
        throw new ToolsetError(`unsupported tutorial Cargo profile: ${profile} (expected ci or release)`);
      }
      const targetDir = join(repoRoot, 'target/breg-tutorial-source');
      const build = spawnSync(
        'cargo',
        ['build', '--locked', '--profile', profile, '-p', 'registry-breg', '--features', 'registry-breg/runtime', '-p', 'registry-bregctl', '--bins'],
        { cwd: repoRoot, stdio: 'inherit', env: { ...process.env, CARGO_TARGET_DIR: targetDir } },
      );
      if (build.status !== 0) throw new ToolsetError('building breg and bregctl failed');
      bregBin = join(targetDir, profile, 'breg');
      bregctlBin = join(targetDir, profile, 'bregctl');
    }
    checkBinary('BREG_BIN', bregBin);
    checkBinary('BREGCTL_BIN', bregctlBin);
    await mkdir(binDir, { recursive: true });
    await symlink(bregBin, join(binDir, 'breg'));
    await symlink(bregctlBin, join(binDir, 'bregctl'));
  },

  // Stop every local development session the journey started and reclaim its
  // container and volume. A journey that fails halfway leaves `bregctl dev`
  // running, and deleting the reader directory alone would orphan the
  // container. Stopping with --remove is idempotent. Returns false when a
  // session could not be stopped, so its project is kept for a second attempt.
  async teardown({ readerDir, binDir }) {
    let entries;
    try {
      entries = await readdir(readerDir, { recursive: true });
    } catch (error) {
      if (error.code === 'ENOENT') return true;
      throw error;
    }
    let stoppedAll = true;
    for (const entry of entries.filter((path) => path.endsWith('.breg/dev/state.json')).sort()) {
      const project = dirname(dirname(dirname(join(readerDir, entry))));
      const stop = spawnSync(join(binDir, 'bregctl'), ['dev', 'stop', project, '--remove'], { encoding: 'utf8' });
      if (stop.status === 0) {
        console.log(`stopped the local development session in ${project}`);
      } else {
        console.error(`could not stop the local development session in ${project}:\n${stop.stdout}${stop.stderr}`);
        stoppedAll = false;
      }
    }
    return stoppedAll;
  },
};

// No product binaries: the journey runs against what is already on PATH.
const none = {
  async prepare() {},
  async teardown() {
    return true;
  },
};

export const TOOLSETS = { breg, none };
