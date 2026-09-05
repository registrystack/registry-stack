// Shared transient-failure retry for the network-facing `git fetch` used by
// scripts that pin a product repo at a commit ref via a shallow clone
// (sync-repo-docs.mjs, fetch-openapi.mjs). `git init`, `remote add`, and
// `checkout` stay local to each caller: they run against the already-created
// destination directory and never touch the network, so a transient failure
// there would not describe a flaky connection.

import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

import { withRetry } from './retry.mjs';

const run = promisify(execFile);

const TRANSIENT_GIT_ERROR_CODES = new Set([
  'EAGAIN',
  'ECONNREFUSED',
  'ECONNRESET',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'EPIPE',
  'ETIMEDOUT',
]);

const TRANSIENT_GIT_STDERR_PATTERN = new RegExp(
  [
    'could not resolve host',
    'could not read from remote repository',
    "couldn't connect to server",
    'connection (?:reset|refused|timed out)',
    'the remote end hung up unexpectedly',
    'early eof',
    'rpc failed',
    'unable to access',
    "unable to create '.*index\\.lock'",
    'operation timed out',
    'temporary failure in name resolution',
    'transfer closed with .* bytes remaining',
  ].join('|'),
  'i',
);

function stderrOf(error) {
  return Buffer.isBuffer(error?.stderr) ? error.stderr.toString('utf8') : String(error?.stderr ?? '');
}

export function isTransientGitFetchFailure(error) {
  if (typeof error?.code === 'string' && TRANSIENT_GIT_ERROR_CODES.has(error.code)) return true;
  return TRANSIENT_GIT_STDERR_PATTERN.test(stderrOf(error));
}

// Shallow-fetch a single pinned ref from `origin` into the already
// initialized repository at `cwd`. Retries a bounded number of times with
// backoff, but only for a failure that looks transient; a real content
// problem (missing ref, bad path, auth) still fails on the first attempt, and
// the final error is always the underlying git exec error (its stderr
// carried in both `.stderr` and, per Node's own child_process formatting,
// `.message`).
export async function fetchRefWithRetry(ref, cwd, { execFileImpl = run, wait, attempts } = {}) {
  return withRetry(
    () => execFileImpl('git', ['fetch', '--quiet', '--depth', '1', 'origin', ref], { cwd }),
    { isTransient: isTransientGitFetchFailure, wait, attempts },
  );
}
