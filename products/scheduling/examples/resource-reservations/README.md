# Named resource reservations

This backend example uses the ordinary appointment and hold contracts to
reserve a room for a caller-selected interval. It adds no separate booking
service. Generate a copy with
`schedulingctl init PROJECT --template resource-reservations`, or check and
replay this directory with the built `schedulingctl` executable:

```sh
schedulingctl check products/scheduling/examples/resource-reservations
schedulingctl test products/scheduling/examples/resource-reservations
schedulingctl explain products/scheduling/examples/resource-reservations
```

The fixture is an offline capacity proof. It does not exercise authentication,
database locking, HTTP transport, or notification delivery.

The offering sets `partyCounts: optional`. Its fixtures omit `party`: reserving
a room consumes one resource allocation without inventing a recipient or an
attendee. If an institution also needs occupant counts, callers can provide
them separately under the offering's limits.

`durationMinutes` always measures elapsed time. For a local calendar-day
reservation, resolve both local date boundaries in the location's IANA
timezone and submit their elapsed difference. The example's 1 November 2026
day in New York lasts 1,500 minutes. A spring transition day can last 1,380
minutes. There is no implicit conversion of a day to 1,440 minutes and no
silent adjustment of an ambiguous or nonexistent local endpoint. The hard
duration ceiling is 10,080 elapsed minutes; an offering may set a lower
minimum, maximum, and increment.

`00:00` to `24:00` openings join across adjacent local dates. A multi-day
interval must fit continuous published opening time, including any closures.
This offering requires the occupied interval, including 15 minutes of setup
and cleanup, to fit. All offerings reserve their buffers in the capacity
ledger, including those that retain the default service-interval opening
coverage. A five-minute hold remains five minutes regardless of the eventual
reservation length.

Named selection is opt-in. The offering's catalogue document publishes its
`pool`, which joins to each resource's `pool` in the resource catalogue.
Selecting `room-a` is a hard constraint and never silently substitutes
`room-b`. Omitting the selection retains fungible allocation.

The task grant authorizes service, location, and action. Within that authority,
the active offering controls eligible resources and permitted intervals. A
caller-supplied resource, duration, or external reference grants no authority.
The grant currently has no narrower per-task resource or interval restriction;
an institution must not treat a source-side preference as an enforced
Scheduling authorization limit. Pricing and beneficiary eligibility remain
with the source system.
