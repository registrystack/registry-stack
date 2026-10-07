import assert from 'node:assert/strict';
import { execFile, spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import test from 'node:test';
import { setTimeout as sleep } from 'node:timers/promises';
import { promisify } from 'node:util';

import { groupAlive, stopGroup } from './background.mjs';

const execFileAsync = promisify(execFile);

// Fork a child that leads a process group of its own and exits at once, print
// its pid, and reap it only after reading a line. Until then the group holds
// one exited, unreaped process: Python reaps no child it is not asked to.
const HOLD_UNREAPED = `
import os, sys
child = os.fork()
if child == 0:
    os.setpgid(0, 0)
    os._exit(0)
print(child, flush=True)
sys.stdin.readline()
os.waitpid(child, 0)
print("reaped", flush=True)
sys.stdin.readline()
`;

// Wait until ps reports the process as exited but not yet reaped.
async function untilUnreaped(pid) {
  for (;;) {
    const { stdout } = await execFileAsync('ps', ['-o', 'stat=', '-p', String(pid)]);
    if (stdout.trim().startsWith('Z')) return;
    await sleep(10);
  }
}

test('a group whose processes have exited has ended, before and after they are reaped', { timeout: 30_000 }, async () => {
  const holder = spawn('python3', ['-c', HOLD_UNREAPED], { stdio: ['pipe', 'pipe', 'inherit'] });
  const closed = new Promise((resolvePromise) => holder.on('close', resolvePromise));
  const lines = createInterface({ input: holder.stdout })[Symbol.asyncIterator]();
  try {
    const group = Number((await lines.next()).value);
    await untilUnreaped(group);
    if (process.platform === 'darwin') {
      // Darwin answers EPERM for a group whose processes are all exited and
      // unreaped, which is the state a stopped background fence is in until
      // the journey's shell reaps it.
      assert.equal(groupAlive(group), false);
      await stopGroup(group);
    } else {
      // Linux reports such a group as present until the reap, so only the
      // probe answering at all is common to both kernels.
      assert.doesNotThrow(() => groupAlive(group));
    }
    holder.stdin.write('\n');
    assert.equal((await lines.next()).value, 'reaped');
    assert.equal(groupAlive(group), false);
    await stopGroup(group);
  } finally {
    holder.stdin.end();
    await closed;
  }
});
