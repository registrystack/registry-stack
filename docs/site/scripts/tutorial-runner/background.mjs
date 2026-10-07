#!/usr/bin/env node
// The command a page leaves running in another terminal (test-background).
//
// The journey script starts a background fence in its own process group and
// records `<group> <output file>` in a state file. This helper then waits for
// the fence's ready URL to answer with success, or stops the group the state
// file names:
//
//   background.mjs ready <url> <state file>   wait until the URL answers 2xx
//   background.mjs stop <state file>          stop the group, show its output
//
// A fence whose group ends before its URL answers, or that does not answer
// within READY_TIMEOUT_MS, fails the wait. A group that has already ended by
// the time stop is called fails too: a background command promises to keep
// running until it is stopped, so one that exited on its own is a failure
// even though it answered while it was up.

import { readFile, writeFile } from 'node:fs/promises';
import { setTimeout as sleep } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';

const READY_TIMEOUT_MS = 60_000;
const STOP_GRACE_MS = 10_000;

// Send a signal to every process of a group this runner started; signal 0
// only probes it. Returns whether the group still had a process to send to.
//
// Darwin answers EPERM for a group whose remaining processes have exited but
// are not yet reaped by their parent, where Linux answers success until the
// reap and ESRCH after it. An exited process runs nothing and holds no port,
// so that group has ended. EPERM cannot mean a running process the runner may
// not signal: every group it signals is one it started, whose processes run
// as its own user.
export function signalGroup(group, signal) {
  try {
    process.kill(-group, signal);
    return true;
  } catch (error) {
    if (error.code === 'ESRCH' || error.code === 'EPERM') return false;
    throw error;
  }
}

export function groupAlive(group) {
  return signalGroup(group, 0);
}

// Send TERM to the process group, and KILL once the grace period has passed.
// Returns once no process of the group is left, so a port it held is free.
export async function stopGroup(group) {
  if (!signalGroup(group, 'SIGTERM')) return;
  const deadline = Date.now() + STOP_GRACE_MS;
  while (groupAlive(group)) {
    if (Date.now() > deadline) {
      signalGroup(group, 'SIGKILL');
      while (groupAlive(group)) await sleep(50);
      return;
    }
    await sleep(50);
  }
}

async function readState(stateFile) {
  let text;
  try {
    text = (await readFile(stateFile, 'utf8')).trim();
  } catch (error) {
    if (error.code === 'ENOENT') return undefined;
    throw error;
  }
  if (text === '') return undefined;
  const [group, output] = text.split('\t');
  return { group: Number(group), output };
}

async function ready(url, stateFile) {
  const { group } = await readState(stateFile);
  const deadline = Date.now() + READY_TIMEOUT_MS;
  for (;;) {
    // The group is checked first, so a service that already held the port
    // cannot answer for a command that has ended.
    if (!groupAlive(group)) {
      console.error(`the command ended before ${url} answered`);
      return 1;
    }
    try {
      const response = await fetch(url, { signal: AbortSignal.timeout(2000) });
      await response.body?.cancel();
      if (response.ok && groupAlive(group)) return 0;
    } catch {
      // Not answering yet: the command may still be starting.
    }
    if (Date.now() > deadline) {
      console.error(`${url} did not answer within ${READY_TIMEOUT_MS / 1000} seconds`);
      return 1;
    }
    await sleep(100);
  }
}

async function stop(stateFile) {
  const state = await readState(stateFile);
  if (!state) return 0;
  // Checked before stopping it, so a group that already ended on its own is
  // told apart from one this call is the one to stop.
  const alreadyEnded = !groupAlive(state.group);
  await stopGroup(state.group);
  const output = await readFile(state.output, 'utf8');
  await writeFile(stateFile, '');
  if (alreadyEnded) {
    console.error(`the background command had already exited, although it must keep running until it is stopped${output === '' ? '' : '; it printed:'}`);
    process.stdout.write(output);
    return 1;
  }
  console.log(`\nstopped the background command${output === '' ? '' : ', which printed:'}`);
  process.stdout.write(output);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [command, ...args] = process.argv.slice(2);
  if (command === 'ready' && args.length === 2) process.exit(await ready(...args));
  if (command === 'stop' && args.length === 1) process.exit(await stop(...args));
  console.error('usage: background.mjs ready <url> <state file> | stop <state file>');
  process.exit(2);
}
