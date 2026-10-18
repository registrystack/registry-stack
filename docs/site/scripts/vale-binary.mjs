// Locates the Vale binary the style checks run.
//
// VALE_BIN names a Vale binary installed outside npm, as CI does with a
// pinned release download. It must report the Vale version the installed
// @vvago/vale package pins, so bumping the package without bumping that
// install fails visibly. Without VALE_BIN, the package's own binary is used,
// and its installer runs once if the binary is missing.

import { access, readFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);

export const defaultValePackageDir = resolve(import.meta.dirname, '..', 'node_modules', '@vvago', 'vale');

async function pinnedVersion(packageDir) {
  const { version } = JSON.parse(await readFile(join(packageDir, 'package.json'), 'utf8'));
  // The package publishes Vale's version, with an optional suffix for repackaging.
  return version.split('-')[0];
}

async function checkValeBin(valeBin, packageDir) {
  const expected = await pinnedVersion(packageDir);
  let stdout;

  try {
    ({ stdout } = await run(valeBin, ['--version']));
  } catch (error) {
    throw new Error(`VALE_BIN=${valeBin} could not report its version: ${error.message}`);
  }

  const reported = stdout.match(/\d+\.\d+\.\d+/)?.[0];

  if (reported !== expected) {
    throw new Error(
      `VALE_BIN=${valeBin} reports Vale ${reported ?? `(unrecognized: ${stdout.trim()})`}, `
        + `but @vvago/vale pins Vale ${expected}. Install Vale ${expected} or update the package.`,
    );
  }
}

function installPackageBinary(packageDir) {
  return new Promise((resolveRun, rejectRun) => {
    const child = spawn(process.execPath, [join(packageDir, 'dist', 'index.cjs')], { stdio: 'inherit' });

    child.on('error', rejectRun);
    child.on('close', (code) => {
      if (code === 0) {
        resolveRun();
      } else {
        rejectRun(new Error(`Unable to install Vale binary, installer exited with ${code ?? 1}`));
      }
    });
  });
}

export async function resolveVale({ packageDir = defaultValePackageDir, env = process.env } = {}) {
  if (env.VALE_BIN) {
    await checkValeBin(env.VALE_BIN, packageDir);
    return env.VALE_BIN;
  }

  const valeBin = join(packageDir, 'native', process.platform === 'win32' ? 'vale.exe' : 'vale');

  try {
    await access(valeBin);
  } catch {
    await installPackageBinary(packageDir);
  }

  return valeBin;
}
