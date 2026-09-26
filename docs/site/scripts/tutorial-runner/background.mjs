#!/usr/bin/env node
// The command a page leaves running in another terminal (test-background).
//
// The journey script starts a background fence in its own process group and
// records `<group> <output file>` in a state file. This helper then waits for
// the fence's ready URL, or stops the group the state file names:
//
//   background.mjs ready <url> <state file>   wait until the URL answers
//   background.mjs stop <state file>          stop the group, show its output
//
// A fence whose group ends before its URL answers, or that does not answer
// within READY_TIMEOUT_MS, fails the wait.

import { readFile, writeFile } from 'node:fs/promises';
import { setTimeout as sleep } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';

const READY_TIMEOUT_MS = 60_000;
const STOP_GRACE_MS = 10_000;

export function groupAlive(group) {
  try {
    process.kill(-group, 0);
    return true;
  } catch (error) {
    if (error.code === 'ESRCH') return false;
    throw error;
  }
}

// Send TERM to the process group, and KILL once the grace period has passed.
// Returns once no process of the group is left, so a port it held is free.
export async function stopGroup(group) {
  if (!groupAlive(group)) return;
  process.kill(-group, 'SIGTERM');
  const deadline = Date.now() + STOP_GRACE_MS;
  while (groupAlive(group)) {
    if (Date.now() > deadline) {
      process.kill(-group, 'SIGKILL');
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
    try {
      await fetch(url, { signal: AbortSignal.timeout(2000) });
      return 0;
    } catch {
      // Not answering yet: the command may still be starting.
    }
    if (!groupAlive(group)) {
      console.error(`the command ended before ${url} answered`);
      return 1;
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
  await stopGroup(state.group);
  const output = await readFile(state.output, 'utf8');
  console.log(`\nstopped the background command${output === '' ? '' : ', which printed:'}`);
  process.stdout.write(output);
  await writeFile(stateFile, '');
  return 0;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [command, ...args] = process.argv.slice(2);
  if (command === 'ready' && args.length === 2) process.exit(await ready(...args));
  if (command === 'stop' && args.length === 1) process.exit(await stop(...args));
  console.error('usage: background.mjs ready <url> <state file> | stop <state file>');
  process.exit(2);
}
