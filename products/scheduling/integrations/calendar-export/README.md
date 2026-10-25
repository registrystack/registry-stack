# On-demand iCalendar export

This maintained example exports a bounded snapshot of current Registry
Scheduling appointments as iCalendar. It is an adapter over
`registry-scheduling-client`, not a calendar service. It has no calendar write
credential, feed URL, subscription token, webhook receiver, recurrence model,
or background synchronization authority.

The projection follows [RFC 5545](https://www.rfc-editor.org/rfc/rfc5545.html):
each appointment is one `VEVENT`; `UID` is stable from Scheduling's runtime-minted
appointment UUID; `SEQUENCE` is the Scheduling revision; `DTSTAMP` is the
explicit export clock; `DTSTART` and `DTEND` are the current displayed interval
in UTC; and a cancelled appointment has `STATUS:CANCELLED`. Output uses CRLF
and folds UTF-8 content lines at 75 octets. A revision outside RFC 5545's signed
32-bit `INTEGER` range, a non-positive interval, or interval precision the
format cannot preserve is a hard error.

By default, an event contains only its stable identifier, revision, displayed
interval, state, a generic `Appointment` summary, and opaque busy-time status.
It contains no person name, contact, organizer, attendee, location, offering,
resource, channel, party count, party reference, external record reference,
manager selection, cancellation reason, description, or URL.

## Run an export

Build and run the example from the Registry Stack repository root. Supply the
bearer token through `REGISTRY_SCHEDULING_TOKEN` using the deployment's normal
secret injection. The command accepts no token argument and never puts a token
in a URL or diagnostic.

A personal export rereads each explicitly named appointment through the
owner-authorized detail route:

```sh
cargo run --locked -p registry-scheduling-client --example calendar-export -- \
  personal \
  --base-url https://scheduling.example.gov/ \
  --appointment 03f4f87d-82c1-4e89-9554-620118a560d0 \
  > appointments.ics
```

A staff export uses the separately authorized operational query. It requires
the current configured projection profile and a service, location, and time
interval:

```sh
cargo run --locked -p registry-scheduling-client --example calendar-export -- \
  staff \
  --base-url https://scheduling.example.gov/ \
  --service registry-update \
  --location north-counter \
  --start 2026-11-01T00:00:00Z \
  --end 2026-12-01T00:00:00Z \
  --profile calendar-export \
  > appointments.ics
```

The staff path requests at most 50 rows per page, follows at most 10 pages,
and accepts at most 500 source rows. Personal export accepts at most 500
appointment identifiers. Repeated rows count toward the limit. Repeated
appointment rows converge to the highest revision, while inconsistent rows at
the same revision are refused. Page, row, interval, and empty-result bounds
are errors, never silent truncation. The adapter buffers the complete export
before writing stdout, so a failed read or continuation cannot produce a
partial calendar file.

## Snapshot and importer limits

Every invocation fetches current state. It does not accept lifecycle signals,
so a delayed or duplicate create, reschedule, or cancellation signal cannot
overwrite a newer appointment during export. Create, reschedule, and cancel
therefore project to the same `UID` with a higher `SEQUENCE` and current state.

Scheduling supplies authoritative instants, and the adapter writes those
instants in UTC. It does not infer a civil time zone, emit `VTIMEZONE`, or
recalculate daylight-saving transitions. Calendar applications may display the
UTC interval in their configured local zone; an interval spanning a DST change
keeps its actual elapsed duration.

The saved `.ics` file is only a snapshot. Browser, proxy, filesystem, and
calendar-application caches can retain an older copy, and importing a later
snapshot is an action owned by the person or institution operating that
calendar. RFC identity and sequence fields support correlation, but calendar
applications vary in whether an import updates, duplicates, or ignores an
existing event. This adapter does not claim automatic importer convergence.
It does not infer recurrence from similar appointments.

The Rust tests check the RFC-required object structure, UTC instants,
cancellation state, stable identity, sequence progression, CRLF framing,
UTF-8 octet folding, deduplication, bounds, and default disclosure. A separate
standards-based consumer parse should remain in release evidence when one is
available; the repository currently carries no independent iCalendar parser,
so the in-repository tests alone do not prove third-party parser acceptance.
