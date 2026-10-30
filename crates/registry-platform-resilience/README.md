# Registry Platform Resilience

`registry-platform-resilience` is the shared Registry Stack
implementation of in-process resilience primitives. It carries no
product vocabulary: no exchange, route, or error class. A caller that
retries failed calls computes its delays here, and a caller that guards
calls behind a breaker runs its state machine here.

Two independent primitives live here:

- [`redelivery::calculate_redelivery_delay`] shapes the delay between
  one retry and the next: the first delay is the caller's own, each
  later one the previous delay grown by the back-off multiplier, then
  varied by a caller-drawn collision-avoidance fraction, then capped at
  the caller's maximum. The primitive is a pure function; the retry
  decision, the draw, and the clock stay with the caller.
- [`circuit_breaker::CircuitBreaker`] is a process-local state machine
  over `Closed`, `Open`, and `HalfOpen`. It judges a fixed count-based
  window of recorded calls once the window holds the declared minimum:
  a failure rate, or a slow-call rate, at or above its threshold opens
  it. The move from open to half-open is lazy, on the first acquire
  whose wait has elapsed, so the breaker starts no task and holds no
  thread; a caller that declares an automatic transition observes the
  same admission behavior, because nothing outside the breaker can see
  a phase nobody asked about. A failing half-open trial reopens with a
  fresh wait; trials that all succeed close the breaker with a fresh
  window.

Everything here is process-local and in-memory: state is not shared
across replicas, and a deployment with more than one replica gets an
independent breaker per replica. The types are shared by reference and
synchronized internally; no method performs I/O.
