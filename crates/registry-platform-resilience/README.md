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
  it. With automatic transition disabled, an elapsed open wait becomes
  half-open on the next acquire. When enabled, passive `state()` observation
  also materializes that elapsed transition without admitting a trial.
  Both modes admit the first guarded call after the wait. The primitive
  has no transition events or half-open timeout, so deriving the phase
  when observed needs no timer task or thread. A failing half-open trial reopens with a
  fresh wait; trials that all succeed close the breaker with a fresh
  window. Admission hands the caller a
  [`circuit_breaker::BreakerPermit`]: the call's outcome is recorded
  through the permit, and a permit dropped unrecorded counts its call
  as failed, so a caller whose future is abandoned mid-call cannot
  strand a half-open breaker. Every phase change starts a new cycle and
  the permit carries its own, so an outcome, or an abandoned permit,
  from an earlier cycle lands nowhere: a slow call of the closed window
  can neither close nor fail a later recovery cycle. A caller may explicitly
  ignore a completed outcome through the permit: it contributes no failure
  or slow-call sample, and a half-open trial releases its slot for a
  replacement without counting as a successful trial.

Everything here is process-local and in-memory: state is not shared
across replicas, and a deployment with more than one replica gets an
independent breaker per replica. The types are shared by reference and
synchronized internally; no method performs I/O.
