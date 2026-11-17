# On-demand iCalendar export

A maintained example that exports a bounded snapshot of current Registry Scheduling appointments as
iCalendar. It is an adapter over `registry-scheduling-client`, not a calendar service. The source is
`crates/registry-scheduling-client/examples/calendar-export.rs`.

The projection, default disclosure, bounds, and importer limits are in
[Author a Scheduling policy](https://docs.registrystack.org/configure/scheduling/#export-appointments-as-icalendar).

## Run an export

Run the example from the Registry Stack repository root. Supply the bearer token through
`REGISTRY_SCHEDULING_TOKEN`; the command accepts no token argument.

```sh
cargo run --locked -p registry-scheduling-client --example calendar-export -- \
  personal \
  --base-url https://scheduling.example.gov/ \
  --appointment 03f4f87d-82c1-4e89-9554-620118a560d0 \
  > appointments.ics
```

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

`personal` rereads each named appointment through the owner-authorized detail route. `staff` uses
the separately authorized operational query and needs the configured projection profile.
