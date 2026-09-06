// Small bounded-retry helper for a flaky network boundary (a shallow git
// fetch, an HTTPS bundle download). Retries only a caller-classified
// transient failure, with doubling backoff between attempts. A non-transient
// failure, or a transient failure that persists past the bound, is rethrown
// unchanged so the caller's own diagnostic (e.g. git's stderr, an HTTP
// status) still reaches the operator.

async function defaultWait(delayMs) {
  await new Promise((resolveWait) => setTimeout(resolveWait, delayMs));
}

export async function withRetry(action, {
  attempts = 3,
  baseDelayMs = 200,
  isTransient,
  wait = defaultWait,
} = {}) {
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      return await action();
    } catch (error) {
      if (attempt === attempts || !isTransient(error)) throw error;
      await wait(baseDelayMs * 2 ** (attempt - 1));
    }
  }
}
