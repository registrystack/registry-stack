import { access } from 'node:fs/promises';
import { join } from 'node:path';
import { execFile, spawn } from 'node:child_process';
import { promisify } from 'node:util';

const run = promisify(execFile);
const valePackageDir = join('node_modules', '@vvago', 'vale');
const valeBin = join(valePackageDir, 'bin', process.platform === 'win32' ? 'vale.exe' : 'vale');

async function ensureVale() {
  try {
    await access(valeBin);
  } catch {
    await run(process.execPath, [join(valePackageDir, 'index.js')], { stdio: 'inherit' });
  }
}

await ensureVale();

const child = spawn(valeBin, process.argv.slice(2), { stdio: 'inherit' });
child.on('exit', (code) => {
  process.exit(code ?? 1);
});
