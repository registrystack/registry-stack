import { spawn } from 'node:child_process';

import { resolveVale } from './vale-binary.mjs';

const valeBin = await resolveVale();

const child = spawn(valeBin, process.argv.slice(2), { stdio: 'inherit' });
child.on('exit', (code) => {
  process.exit(code ?? 1);
});
