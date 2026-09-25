# Registry Platform Rate Limit

`registry-platform-ratelimit` is the shared Registry Stack implementation of
in-memory keyed rate limiting. It carries no product vocabulary: a caller
presents an opaque key, never raw caller-controlled text, and gets back
admission or a refusal.

Two independent primitives live here:

- `TokenBucketLimiter` is a smooth per-key request budget with burst.
  `requests_per_minute` refills a per-key bucket of size `burst`, and
  `check(key, cost)` charges a caller-declared number of tokens, atomically: a
  refused check consumes no partial tokens. A refusal carries a `retry_after`
  duration computed from the bucket's own state, so a caller can set an HTTP
  `Retry-After` header without guessing.
- `FixedWindowCounter` is a per-key ceiling over a rolling window, for budgets
  that should reset in one step rather than refill smoothly (a failed-attempt
  counter, for example). `check(key)` answers the current budget without
  recording anything; `record(key)` records one occurrence and refuses once
  the window's count exceeds `limit`.

Both primitives are process-local: they track keys in memory only, not across
replicas, so a deployment with more than one replica gets independent budgets
per replica. Both cap the number of distinct keys they will track at
`MAX_TRACKED_KEYS` (100,000) and prune stale entries before admitting a new
key past that cap, so an unbounded population of one-shot keys cannot grow
memory without bound. `tracked_key_count` on each type reports the current
tracked population, for a metrics gauge. A key must be non-empty, at most
`MAX_KEY_BYTES` (256) bytes, and free of whitespace; a caller derives it (an
audit pseudonym or similar) before presenting it here.

Registry Evidence is the first consumer, wrapping both primitives behind its
own `EvidenceRateLimiter` to keep its own configuration and error vocabulary
at its boundary. See `crates/registry-evidence/src/rate_limit.rs`.
