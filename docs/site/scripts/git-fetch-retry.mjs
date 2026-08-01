// Bounded retry-with-backoff for the network git fetches performed while
// building the docs (scripts/sync-repo-docs.mjs, scripts/fetch-openapi.mjs).
// Both scripts shallow-clone dozens of pinned refs from product repos during
// `npm run generate`, which `npm run check` runs first. A single dropped
// connection among those clones otherwise fails the whole `check` pipeline,
// and the default execFile rejection swallows git's real stderr behind a bare
// "Command failed: git fetch ..." message. This wraps just the network fetch
// step (never the surrounding init/remote-add/checkout) with a small number
// of attempts and a linear backoff, and on exhausted attempts throws an error
// that carries git's real stderr, bounded so a runaway stream cannot flood
// the log.
//
// Retries are unconditional: git's stderr text for a permanent failure (an
// unknown ref) and a transient one (a dropped connection) is not reliably
// distinguishable across git versions and transports, so this does not try
// to classify errors before retrying. A permanent failure just costs one
// extra bounded backoff before it fails loudly with the real message.

const DEFAULT_ATTEMPTS = 3;
const DEFAULT_BACKOFF_MS = 1000;
const DEFAULT_STDERR_LIMIT = 4000;

function defaultSleep(ms) {
  return new Promise((resolveSleep) => setTimeout(resolveSleep, ms));
}

// Extract git's real stderr from a failed execFile-style error, bounded to
// `limit` characters so a pathological stream cannot flood the log.
function boundedStderr(error, limit) {
  const raw = Buffer.isBuffer(error?.stderr)
    ? error.stderr.toString('utf8')
    : String(error?.stderr ?? '');
  const text = raw.trim() || error?.message || String(error);
  if (text.length <= limit) return text;
  const omitted = text.length - limit;
  return `${text.slice(0, limit)}\n... [truncated ${omitted} more character(s)]`;
}

// Run `operation` (a single network git command), retrying on failure up to
// `attempts` times total with a linear backoff between attempts (`sleep` is a
// test seam only; production callers should leave it at its default). Throws
// an Error labeled with `label` whose message carries the last failure's
// real, bounded stderr.
export async function retryGitFetch(label, operation, {
  attempts = DEFAULT_ATTEMPTS,
  backoffMs = DEFAULT_BACKOFF_MS,
  stderrLimit = DEFAULT_STDERR_LIMIT,
  sleep = defaultSleep,
} = {}) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await operation();
    } catch (error) {
      lastError = error;
      if (attempt < attempts) {
        console.warn(
          `warning: ${label}: attempt ${attempt}/${attempts} failed, retrying: ` +
            boundedStderr(error, stderrLimit),
        );
        await sleep(backoffMs * attempt);
      }
    }
  }
  throw new Error(`${label}: failed after ${attempts} attempts: ${boundedStderr(lastError, stderrLimit)}`);
}
