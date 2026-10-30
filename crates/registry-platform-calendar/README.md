# Registry Platform Calendar

`registry-platform-calendar` is the shared Registry Stack implementation of
timezone-correct calendar evaluation. It takes calendar identifiers, named IANA
timezones, pinned holiday content, and bounded arithmetic, and returns exact
instants or intervals. It performs no input or output and holds no product
semantics, so the same evaluator serves any runtime that must derive a
commitment-bearing time from authored calendar content.

Two evaluators live here. The working-day evaluator shifts a date across
working weekdays and holidays to a local due time, as used by Registry
Casework clocks. The weekly-opening evaluator expands a bounded weekly pattern
into concrete half-open UTC intervals, with exception layering where a blocking
closure wins over an ordinary opening and an exceptional reopening requires
explicit authority, names the closure it reopens, and stays inside it.

`local_date(now, timezone)` returns the calendar date at an instant in a named
IANA timezone. A product that answers "today" uses it so that one deployment
has one today, which changes at local midnight.

Daylight-saving transitions follow one rule per evaluator, with no knob. A
working-day deadline is a single calculated instant: a due time inside a gap
moves to the first instant after the gap, and a due time inside a fold takes
the earlier of its two instants, so a deadline authored once evaluates on every
date. An interval endpoint inside a gap or fold is an explicit error, never a
silent shift, so no caller can derive an invisible duplicate or shifted
capacity commitment. An interval that spans a transition keeps its real
elapsed length.

Interval ends may use `24:00` for the following local midnight. Starts remain
`00:00` through `23:59`. A `00:00` to `24:00` opening covers the actual local
date, including a 23-hour or 25-hour daylight-saving day. Consecutive full-day
openings join without a gap. Overnight hours can be expressed as an opening
ending at `24:00` and another on the following date starting at `00:00`;
holidays and dated closures retain their own local-date boundaries. Midnight
endpoints still reject a daylight-saving gap or fold instead of shifting it.

Refusals are neutral: they name the value, its limit, and the fix, and never a
caller's configuration keys. Each product attaches its own configuration
pointer to the refusal it reports. Authored spans are bounded to ten years so
expansion cannot run away on mistyped effective dates.
