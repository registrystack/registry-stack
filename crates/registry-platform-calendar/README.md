# Registry Platform Calendar

`registry-platform-calendar` is the shared Registry Stack implementation of
timezone-correct calendar evaluation. It takes calendar identifiers, named IANA
timezones, pinned holiday content, and bounded arithmetic, and returns exact
instants or intervals. It performs no input or output and holds no product
semantics, so the same evaluator serves any runtime that must derive a
commitment-bearing time from authored calendar content.

Two evaluators live here. The working-day evaluator shifts a date across
working weekdays and holidays to a local `dueTime`, as used by Registry
Casework clocks. The weekly-opening evaluator expands a bounded weekly pattern
into concrete half-open UTC intervals, with exception layering where a blocking
closure wins over an ordinary opening and an exceptional reopening requires
explicit authority, names the closure it reopens, and stays inside it.

A local time that falls in a daylight-saving gap or fold is an explicit error,
never a silent shift to the nearest instant, so no caller can derive an
invisible duplicate or shifted commitment. An interval that spans a transition
keeps its real elapsed length. Authored spans are bounded to ten years so
expansion cannot run away on mistyped effective dates.
