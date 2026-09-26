// SPDX-License-Identifier: Apache-2.0

//! The complete starter projects `schedulingctl init` writes.
//!
//! Each template is a working project: its policy passes the check with zero
//! findings and its fixtures replay all-Pass offline, which the tests prove
//! end to end.

/// The `standalone-exact-time` policy: a Bangkok counter with two
/// interchangeable stations, and a New York hall whose fold-day opening
/// spans the repeated hour with unambiguous endpoints.
const EXACT_TIME_POLICY: &str = r#"apiVersion: registry.registrystack.org/scheduling-policy-package/v1alpha1
kind: SchedulingPolicyPackage
scheduling:
  id: registry-updates
  version: 1
services:
  - id: registry-update
    label: Registry record update
offerings:
  - id: registry-update-30
    service: registry-update
    label: 30-minute counter update
    mode: exact-time
    location: bangkok-counter
    because: A 30-minute registry update at an interchangeable counter station.
    exactTime:
      durationMinutes: 30
      bufferBeforeMinutes: 5
      bufferAfterMinutes: 5
      leadTimeMinutes: 120
      horizonDays: 60
      pool: update-stations
      startIncrementMinutes: 30
      maxRecipients: 1
    cancellationCutoffMinutes: 240
    reminders:
      - minutesBefore: 1440
        because: One reminder the day before a counter update.
      - minutesBefore: 120
        because: A second reminder two hours before, when stations are scarce.
    duplicateActiveKey: subject
    requiresCapabilities: []
    prerequisites: []
  - id: fold-day-update-30
    service: registry-update
    label: 30-minute fold-day update
    mode: exact-time
    location: new-york-hall
    because: A 30-minute update at the hall, published across the autumn time change.
    exactTime:
      durationMinutes: 30
      bufferBeforeMinutes: 0
      bufferAfterMinutes: 0
      leadTimeMinutes: 1
      horizonDays: 3650
      pool: hall-stations
      startIncrementMinutes: 30
      maxRecipients: 1
    cancellationCutoffMinutes: 240
    requiresCapabilities: []
    prerequisites: []
holidaySets:
  - id: office-holidays
    revision: 1
    because: Public holidays observed by the registry offices.
    dates: []
openings:
  - id: bangkok-counter-hours
    location: bangkok-counter
    holidaySet: office-holidays
    weekdays: [mon, tue, wed, thu, fri]
    startTime: "09:00"
    endTime: "12:30"
    effectiveFrom: "2026-10-01"
    effectiveUntil: "2026-12-31"
    because: Counter opening hours reviewed by the office manager.
  - id: new-york-hall-hours
    location: new-york-hall
    holidaySet: office-holidays
    weekdays: [sun]
    startTime: "00:30"
    endTime: "02:30"
    effectiveFrom: "2026-11-01"
    effectiveUntil: "2026-11-01"
    because: Fold-day hours whose endpoints sit outside the repeated local hour.
holdPolicy:
  ttlMinutes: 5
  maxPerCaller: 3
  because: Holds are short because counter capacity is scarce.
"#;

/// The `standalone-exact-time` counter fixture: a first caller takes a
/// station, a same-key retry is refused, a second caller gets the other
/// station, and a fourth finds both busy.
const COUNTER_STATIONS_FIXTURE: &str = r#"apiVersion: registry.registrystack.org/scheduling-fixture/v1alpha1
kind: SchedulingFixture
name: counter-stations
now: 2026-10-05T00:00:00Z
facts:
  locations:
    - id: bangkok-counter
      timezone: Asia/Bangkok
  pools:
    - id: update-stations
      members:
        - resourceId: station-1
          capabilities: []
          available: true
        - resourceId: station-2
          capabilities: []
          available: true
initial: []
cases:
  - name: first-caller-takes-a-station
    request:
      offering: registry-update-30
      start: 2026-10-05T02:00:00Z
      party:
        recipients: 1
        attendees: 1
      duplicateKey: subject:one
      policyRevision: 1
      capabilities: []
      prerequisites: []
    expect:
      outcome: admitted
      units: 1
      resource: station-1
  - name: same-key-retry-is-refused
    request:
      offering: registry-update-30
      start: 2026-10-05T02:30:00Z
      party:
        recipients: 1
        attendees: 1
      duplicateKey: subject:one
      policyRevision: 1
      capabilities: []
      prerequisites: []
    expect:
      outcome: refused
      code: booking.duplicate-active
  - name: second-caller-gets-the-other-station
    request:
      offering: registry-update-30
      start: 2026-10-05T02:00:00Z
      party:
        recipients: 1
        attendees: 1
      duplicateKey: subject:two
      policyRevision: 1
      capabilities: []
      prerequisites: []
    expect:
      outcome: admitted
      units: 1
      resource: station-2
  - name: both-stations-busy-refuses-another-caller
    request:
      offering: registry-update-30
      start: 2026-10-05T02:00:00Z
      party:
        recipients: 1
        attendees: 1
      duplicateKey: subject:three
      policyRevision: 1
      capabilities: []
      prerequisites: []
    expect:
      outcome: refused
      code: capacity.exhausted
"#;

/// The `standalone-exact-time` fold-day fixture: the pre-opening closure
/// moves the start grid to 04:45Z, a booking on the moved grid is rescheduled
/// into the three-real-hour opening, the freed slot serves another caller,
/// and a wall-clock match the moved grid does not publish is refused.
const FOLD_DAY_REBOOKING_FIXTURE: &str = r#"apiVersion: registry.registrystack.org/scheduling-fixture/v1alpha1
kind: SchedulingFixture
name: fold-day-rebooking
now: 2026-11-01T04:00:00Z
# America/New_York falls back on 2026-11-01: local 01:30 occurs twice, and the
# 00:30-02:30 opening spans three real hours, [04:30Z, 07:30Z). The closure
# 00:15-00:45 has unambiguous endpoints in one offset and moves the opening
# start to 04:45Z, so the 30-minute grid anchors there: 04:45, 05:15, 05:45...
facts:
  locations:
    - id: new-york-hall
      timezone: America/New_York
  pools:
    - id: hall-stations
      members:
        - resourceId: hall-station-1
          capabilities: []
          available: true
  exceptions:
    - id: hall-prep
      location: new-york-hall
      kind: closure
      date: "2026-11-01"
      startTime: "00:15"
      endTime: "00:45"
initial: []
cases:
  - name: morning-booking-after-the-closure
    request:
      offering: fold-day-update-30
      start: 2026-11-01T05:15:00Z
      party:
        recipients: 1
        attendees: 1
      policyRevision: 1
      capabilities: []
      prerequisites: []
    expect:
      outcome: admitted
      units: 1
      resource: hall-station-1
  - name: reschedule-into-the-later-morning
    request:
      offering: fold-day-update-30
      start: 2026-11-01T06:45:00Z
      party:
        recipients: 1
        attendees: 1
      policyRevision: 1
      rescheduleOf: case:morning-booking-after-the-closure
      capabilities: []
      prerequisites: []
    expect:
      outcome: admitted
      units: 1
      resource: hall-station-1
  - name: the-freed-slot-serves-another-caller
    request:
      offering: fold-day-update-30
      start: 2026-11-01T05:15:00Z
      party:
        recipients: 1
        attendees: 1
      policyRevision: 1
      capabilities: []
      prerequisites: []
    expect:
      outcome: admitted
      units: 1
      resource: hall-station-1
  - name: a-wall-clock-match-off-the-moved-grid-is-not-served
    request:
      offering: fold-day-update-30
      start: 2026-11-01T06:30:00Z
      party:
        recipients: 1
        attendees: 1
      policyRevision: 1
      capabilities: []
      prerequisites: []
    expect:
      outcome: refused
      code: schedule.unpublished
"#;

/// Live environment records for the exact-time starter. They carry every
/// location and resource pool its policy references, plus the fold-day closure
/// the example explains and exercises.
const EXACT_TIME_RECORDS: &str = r#"locations:
  - id: bangkok-counter
    timezone: Asia/Bangkok
  - id: new-york-hall
    timezone: America/New_York
pools:
  - id: update-stations
    members:
      - resourceId: station-1
        capabilities: []
        available: true
      - resourceId: station-2
        capabilities: []
        available: true
  - id: hall-stations
    members:
      - resourceId: hall-station-1
        capabilities: []
        available: true
windows: []
exceptions:
  - id: hall-prep
    location: new-york-hall
    kind: closure
    date: "2026-11-01"
    startTime: "00:15"
    endTime: "00:45"
"#;

/// The `standalone-arrival-window` policy: a Saturday morning household block
/// with a public and an assisted subquota over a per-recipient units table,
/// and a Saturday afternoon block over a banded table that refuses a party
/// above its highest band instead of guessing what it costs.
const ARRIVAL_WINDOW_POLICY: &str = r#"apiVersion: registry.registrystack.org/scheduling-policy-package/v1alpha1
kind: SchedulingPolicyPackage
scheduling:
  id: household-days
  version: 3
services:
  - id: household-day
    label: Household registration day
offerings:
  - id: household-morning
    service: household-day
    label: Morning household block
    mode: arrival-window
    location: civic-hall
    because: Households arrive in a served morning block.
    arrival:
      window: household-morning-window
      leadTimeMinutes: 60
      horizonDays: 45
    cancellationCutoffMinutes: 1440
    requiresCapabilities: []
    prerequisites: []
  - id: household-afternoon
    service: household-day
    label: Afternoon household block
    mode: arrival-window
    location: civic-hall
    because: Larger households arrive in an afternoon block sized by party, not a flat headcount.
    arrival:
      window: household-afternoon-window
      leadTimeMinutes: 60
      horizonDays: 45
    cancellationCutoffMinutes: 1440
    requiresCapabilities: []
    prerequisites: []
holidaySets:
  - id: office-holidays
    revision: 1
    because: Public holidays observed by the registry office.
    dates: []
openings:
  - id: hall-hours
    location: civic-hall
    holidaySet: office-holidays
    weekdays: [sat]
    startTime: "08:00"
    endTime: "12:00"
    effectiveFrom: "2026-10-01"
    effectiveUntil: "2026-12-31"
    because: The hall opens on Saturday mornings.
  - id: hall-afternoon-hours
    location: civic-hall
    holidaySet: office-holidays
    weekdays: [sat]
    startTime: "13:00"
    endTime: "17:00"
    effectiveFrom: "2026-10-01"
    effectiveUntil: "2026-12-31"
    because: The hall reopens on Saturday afternoons for banded household visits.
holdPolicy:
  ttlMinutes: 10
  maxPerCaller: 2
  because: Households need a few minutes to gather documents.
"#;

/// The `standalone-arrival-window` fixture: the public subquota depletes
/// while the assisted channel still admits.
const HOUSEHOLD_MORNING_FIXTURE: &str = r#"apiVersion: registry.registrystack.org/scheduling-fixture/v1alpha1
kind: SchedulingFixture
name: household-morning
now: 2026-10-09T20:00:00Z
facts:
  locations:
    - id: civic-hall
      timezone: Asia/Bangkok
  windows:
    - id: household-morning-window
      revision: 2
      offering: household-morning
      location: civic-hall
      start: 2026-10-10T01:00:00Z
      end: 2026-10-10T03:00:00Z
      units: 3
      unitsPolicy:
        kind: perRecipient
        perRecipient: 1
        because: Each recipient consumes one serving slot.
      subquotas:
        - id: public-quota
          channel: public
          units: 2
          because: Most households book the public channel.
        - id: assisted-quota
          channel: assisted
          units: 1
          because: Assisted bookings hold a protected unit.
      because: The Saturday morning household block, sized for two officers.
initial: []
cases:
  - name: first-household-takes-the-public-quota
    request:
      offering: household-morning
      start: 2026-10-10T01:00:00Z
      party:
        recipients: 2
        attendees: 3
      channel: public
      policyRevision: 3
      windowRevision: 2
      capabilities: []
      prerequisites: []
    expect:
      outcome: admitted
      units: 2
  - name: next-public-household-finds-the-quota-spent
    request:
      offering: household-morning
      start: 2026-10-10T01:00:00Z
      party:
        recipients: 1
        attendees: 1
      channel: public
      policyRevision: 3
      windowRevision: 2
      capabilities: []
      prerequisites: []
    expect:
      outcome: refused
      code: capacity.exhausted
  - name: assisted-household-fits-the-protected-unit
    request:
      offering: household-morning
      start: 2026-10-10T01:00:00Z
      party:
        recipients: 1
        attendees: 1
      channel: assisted
      policyRevision: 3
      windowRevision: 2
      capabilities: []
      prerequisites: []
    expect:
      outcome: admitted
      units: 1
"#;

/// The `standalone-arrival-window` fixture: two households fit the banded
/// table's first two bands, and a household above the highest band is
/// refused instead of costed by a guess.
const HOUSEHOLD_AFTERNOON_FIXTURE: &str = r#"apiVersion: registry.registrystack.org/scheduling-fixture/v1alpha1
kind: SchedulingFixture
name: household-afternoon
now: 2026-10-09T20:00:00Z
facts:
  locations:
    - id: civic-hall
      timezone: Asia/Bangkok
  windows:
    - id: household-afternoon-window
      revision: 1
      offering: household-afternoon
      location: civic-hall
      start: 2026-10-10T07:00:00Z
      end: 2026-10-10T09:00:00Z
      units: 3
      unitsPolicy:
        kind: bandedTable
        input: serviceRecipientCount
        bands:
          - upTo: 4
            units: 1
            because: A household of up to four shares one officers' block.
          - upTo: 8
            units: 2
            because: A larger household of up to eight needs two officers' blocks.
        aboveHighestBand:
          policy: refuse
        because: A household above eight needs a scheduled outreach visit instead of a walk-in block.
      subquotas: []
      because: The Saturday afternoon household block, sized by party rather than a flat headcount.
initial: []
cases:
  - name: a-small-household-fits-the-first-band
    request:
      offering: household-afternoon
      start: 2026-10-10T07:00:00Z
      party:
        recipients: 3
        attendees: 3
      policyRevision: 3
      windowRevision: 1
      capabilities: []
      prerequisites: []
    expect:
      outcome: admitted
      units: 1
  - name: a-household-above-the-highest-band-is-refused
    request:
      offering: household-afternoon
      start: 2026-10-10T07:00:00Z
      party:
        recipients: 9
        attendees: 9
      policyRevision: 3
      windowRevision: 1
      capabilities: []
      prerequisites: []
    expect:
      outcome: refused
      code: party.capacity-inadequate
  - name: a-mid-size-household-fits-the-second-band
    request:
      offering: household-afternoon
      start: 2026-10-10T07:00:00Z
      party:
        recipients: 6
        attendees: 6
      policyRevision: 3
      windowRevision: 1
      capabilities: []
      prerequisites: []
    expect:
      outcome: admitted
      units: 2
"#;

/// Live environment records for the arrival-window starter. The policy names
/// each window by id; this operator document owns its concrete supply.
const ARRIVAL_WINDOW_RECORDS: &str = r#"locations:
  - id: civic-hall
    timezone: Asia/Bangkok
pools: []
windows:
  - id: household-morning-window
    revision: 2
    offering: household-morning
    location: civic-hall
    start: 2026-10-10T01:00:00Z
    end: 2026-10-10T03:00:00Z
    units: 3
    unitsPolicy:
      kind: perRecipient
      perRecipient: 1
      because: Each recipient consumes one serving slot.
    subquotas:
      - id: public-quota
        channel: public
        units: 2
        because: Most households book the public channel.
      - id: assisted-quota
        channel: assisted
        units: 1
        because: Assisted bookings hold a protected unit.
    because: The Saturday morning household block, sized for two officers.
  - id: household-afternoon-window
    revision: 1
    offering: household-afternoon
    location: civic-hall
    start: 2026-10-10T07:00:00Z
    end: 2026-10-10T09:00:00Z
    units: 3
    unitsPolicy:
      kind: bandedTable
      input: serviceRecipientCount
      bands:
        - upTo: 4
          units: 1
          because: A household of up to four shares one officers' block.
        - upTo: 8
          units: 2
          because: A larger household of up to eight needs two officers' blocks.
      aboveHighestBand:
        policy: refuse
      because: A household above eight needs a scheduled outreach visit instead of a walk-in block.
    subquotas: []
    because: The Saturday afternoon household block, sized by party rather than a flat headcount.
exceptions: []
"#;

/// The operator runtime configuration example every template writes beside
/// the authored policy. It names no project path, so one document serves every
/// template and the committed example can never drift from what an adopter
/// initializes; the absolute paths an operator replaces are placeholders.
pub(super) const RUNTIME_EXAMPLE: &str = r#"# A complete Scheduling runtime configuration: the document
# `scheduling serve --runtime-config` reads and `scheduling migrate` reads.
# Copy it to runtime.yaml, set every absolute path to this deployment's real
# location, and point the secret references at secrets the configured provider
# can resolve. Scheduling reads the authored policy at
# package.root/scheduling.yaml and refuses to start when that file is missing
# or does not pass its checks.
apiVersion: registry.registrystack.org/scheduling-runtime/v1alpha1
kind: SchedulingRuntimeConfig
package:
  # The selected package always contains the policy at scheduling.yaml; no
  # second selector can override it. Under
  # listener.tlsTermination: operator-controlled-upstream the directory must
  # also contain the scheduling.package.json manifest `schedulingctl package`
  # writes; development loopback may select an unpackaged project directory.
  root: /srv/registry-scheduling/package
listener:
  bind: 127.0.0.1:8105
  tlsTermination: development-loopback
  networkExposure: private-address
  # `operator-controlled-upstream` is the production value: the runtime itself
  # stays plaintext and an operator-managed TLS edge terminates transport in
  # front of it. `development-loopback` is direct plaintext, refused on any
  # non-loopback bind. `networkExposure: container-private` additionally
  # permits an unspecified bind for a listener kept on a private container
  # network.
secretProviders:
  file:
    # Every secret:file reference resolves under this root. A secret file must
    # be a regular file owned by the runtime user, with mode 0400 or 0600 and
    # exactly one hard link, carrying non-empty text of at most 64 KiB without
    # NUL bytes; `openssl rand -hex 32` generates the audit key.
    root: /run/secrets/registry-scheduling
  # Declare `environment: {}` to enable secret:env/NAME references. The
  # runtime does not fall back from one provider to another; every configured
  # reference must resolve under a provider declared here.
  # environment: {}
database:
  # The least-privilege service connection and the operator-run migration
  # connection, each a PostgreSQL URL held in the secret provider. The
  # runtime requires TLS on the database connection: it sets sslmode Require
  # and refuses a connection that cannot be verified.
  runtimeUrlRef: secret:file/runtime-database-url
  migrationUrlRef: secret:file/migration-database-url
  # The PEM bundle of the private CA in front of PostgreSQL, when the
  # deployment terminates database TLS with one.
  # trustedRootCertificateRef: secret:file/postgres-ca.pem
  # `testOnlyPlaintext: true` is the one plaintext escape, and only a build
  # carrying the `postgres-test` feature accepts it: a production build
  # refuses the setting at startup instead of opening an unencrypted
  # connection.
  # testOnlyPlaintext: true
authentication:
  oidc:
    issuer: https://identity.example.test/realms/registry
    audience: urn:example:scheduling
    # The claim carrying the accepted OAuth scopes. The default is
    # `registry_scopes` for deployments that omit this field; stock ThunderID
    # emits `scope`.
    scopeClaim: scope
    # The read scope defaults to `scheduling-read` and the explain scope to
    # `scheduling-explain`; the two must differ. `allowedClients` names the
    # client ids the runtime admits. Development loopback leaves it empty by
    # default, which admits every client the issuer verifies; behind
    # listener.tlsTermination: operator-controlled-upstream an empty or
    # absent list is a startup refusal, so a production deployment must name
    # the clients it admits.
    # allowedClients: [scheduling-booking-agent]
    # `assertionIssuers` maps a client id to the assertion authorities it may
    # exchange a subject token from. A deployment that performs no token
    # exchange leaves it empty; once a client is listed, a token it
    # exchanged is accepted only for one of that client's declared
    # authorities.
    # assertionIssuers:
    #   scheduling-booking-agent: [https://issuer.example.test/assertions]
    # Signing keys come from issuer discovery by default. Declare the static
    # alternative instead when the runtime cannot reach the issuer's discovery
    # document, when the deployment is air-gapped, or when a test issuer's
    # keys are pinned by hand. It does no rotation of its own: rolling a key
    # means replacing the referenced document and restarting Scheduling.
    # jwksSource:
    #   kind: static
    #   documentRef: secret:file/jwks.json
audit:
  # One single-writer destination. `file`, the default, appends to the
  # absolute path, rotates at rotateBytes (default 100 MiB), and deletes
  # rotated files after retainDays (default 90); `stdout` hands each entry to
  # the process supervisor and takes neither path nor the rotation keys.
  destination: file
  path: /var/lib/registry-scheduling/audit.ndjson
  hashKeyRef: secret:file/scheduling-audit-key
destinations: {}
  # Where due reminder intents are delivered as CloudEvents 1.0 events. An
  # absent reminders destination is a supported deployment: the intents stay
  # readable in the outbox and are marked local, never pretended delivered.
  # reminders:
  #   url: https://bus.example.test/scheduling-reminders
  #   bearerTokenRef: secret:file/reminder-bearer-token
  # URL observers declared under scheduling.yaml hooks bind here. The policy
  # carries no endpoint or secret, and retained work keeps this exact binding.
  # hooks:
  #   appointment-events:
  #     url: https://integration.example.test/scheduling-events
  #     hmacSha256KeyRef: secret:file/appointment-events-hmac
  #     attemptTimeoutMilliseconds: 5000
  #     maximumAttempts: 8
retention:
  # Attempt receipts/listing cursors and hook delivery payloads have separate
  # bounded lifetimes. Appointment, reminder, and history retention are
  # deferred; audit.retainDays bounds rotated audit files. Seven days is a
  # default, not a jurisdictional recommendation.
  attemptReceiptDays: 7
  hookPayloadDays: 7
"#;

/// The files one template writes, relative to the project directory, in
/// write order. The first entry is always the authored policy.
pub(super) fn template_files(template: &str) -> Option<Vec<(&'static str, &'static str)>> {
    match template {
        "standalone-exact-time" => Some(vec![
            ("scheduling.yaml", EXACT_TIME_POLICY),
            ("runtime.example.yaml", RUNTIME_EXAMPLE),
            ("records.yaml", EXACT_TIME_RECORDS),
            ("fixtures/counter-stations.yaml", COUNTER_STATIONS_FIXTURE),
            (
                "fixtures/fold-day-rebooking.yaml",
                FOLD_DAY_REBOOKING_FIXTURE,
            ),
        ]),
        "standalone-arrival-window" => Some(vec![
            ("scheduling.yaml", ARRIVAL_WINDOW_POLICY),
            ("runtime.example.yaml", RUNTIME_EXAMPLE),
            ("records.yaml", ARRIVAL_WINDOW_RECORDS),
            ("fixtures/household-morning.yaml", HOUSEHOLD_MORNING_FIXTURE),
            (
                "fixtures/household-afternoon.yaml",
                HOUSEHOLD_AFTERNOON_FIXTURE,
            ),
        ]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_scheduling_core::{
        parse_fixture_yaml, parse_policy_yaml, AboveHighestBand, CaseStatus, RequiredUnitsPolicy,
        SchedulingFacts, AUTHORED_POLICY_FILE, SCHEDULING_FIXTURE_API_VERSION,
        SCHEDULING_FIXTURE_KIND, SCHEDULING_POLICY_API_VERSION, SCHEDULING_POLICY_KIND,
    };

    const TEMPLATE_NAMES: [&str; 2] = ["standalone-exact-time", "standalone-arrival-window"];

    #[test]
    fn the_templates_are_exactly_the_two_standalone_projects() {
        for template in TEMPLATE_NAMES {
            assert!(template_files(template).is_some(), "{template}");
        }
        assert!(template_files("standalone-decision").is_none());
        assert!(template_files("").is_none());
    }

    #[test]
    fn every_template_carries_parseable_records_for_its_policy_references() {
        for template in TEMPLATE_NAMES {
            let files = template_files(template).unwrap();
            let policy = parse_policy_yaml(files[0].1).expect("the template policy parses");
            let records = files
                .iter()
                .find(|(relative, _)| *relative == "records.yaml")
                .expect("the template carries live environment records");
            let facts: SchedulingFacts =
                serde_norway::from_str(records.1).expect("the template records parse");
            for offering in &policy.offerings {
                assert!(
                    facts.location(&offering.location).is_some(),
                    "{template}: missing location {}",
                    offering.location
                );
                if let Some(exact_time) = &offering.exact_time {
                    assert!(
                        facts.pool(&exact_time.pool).is_some(),
                        "{template}: missing pool {}",
                        exact_time.pool
                    );
                }
            }
        }
    }

    #[test]
    fn every_template_policy_parses_and_checks_clean_with_pinned_names() {
        for template in TEMPLATE_NAMES {
            let files = template_files(template).unwrap();
            assert_eq!(files[0].0, AUTHORED_POLICY_FILE);
            let policy = parse_policy_yaml(files[0].1).expect("the template policy parses");
            assert_eq!(policy.api_version, SCHEDULING_POLICY_API_VERSION);
            assert_eq!(policy.kind, SCHEDULING_POLICY_KIND);
            let findings = policy.check();
            assert!(findings.is_empty(), "{template}: {findings:?}");
        }
    }

    #[test]
    fn every_template_fixture_parses_and_fits_its_policy() {
        for template in TEMPLATE_NAMES {
            let files = template_files(template).unwrap();
            let policy = parse_policy_yaml(files[0].1).expect("the template policy parses");
            for (relative, contents) in template_fixtures(&files) {
                let fixture = parse_fixture_yaml(contents).unwrap_or_else(|error| {
                    panic!("{relative}: the template fixture parses: {error}")
                });
                assert_eq!(fixture.api_version, SCHEDULING_FIXTURE_API_VERSION);
                assert_eq!(fixture.kind, SCHEDULING_FIXTURE_KIND);
                fixture
                    .check(&policy)
                    .expect("the template fixture fits its policy");
            }
        }
    }

    /// The acceptance proof for both templates: every fixture replays
    /// all-Pass against its own template policy.
    #[test]
    fn every_template_fixture_replays_all_pass() {
        for template in TEMPLATE_NAMES {
            let files = template_files(template).unwrap();
            let policy = parse_policy_yaml(files[0].1).expect("the template policy parses");
            for (relative, contents) in template_fixtures(&files) {
                let fixture = parse_fixture_yaml(contents).expect("the template fixture parses");
                let outcomes = fixture
                    .replay(&policy)
                    .unwrap_or_else(|error| panic!("{relative}: the fixture replays: {error}"));
                assert!(
                    outcomes
                        .iter()
                        .all(|outcome| outcome.status == CaseStatus::Pass),
                    "{template}/{relative}: {outcomes:?}"
                );
            }
        }
    }

    /// The template's replay fixtures, in write order. The runtime example is
    /// written beside the policy and is not a fixture.
    fn template_fixtures<'a>(
        files: &'a [(&'static str, &'static str)],
    ) -> Vec<(&'static str, &'a str)> {
        files
            .iter()
            .filter(|(relative, _)| {
                relative.starts_with("fixtures/") && relative.ends_with(".yaml")
            })
            .map(|(relative, contents)| (*relative, *contents))
            .collect()
    }

    /// The arrival-window template's second offering exists so an adopter has
    /// a working example of a banded units table that refuses a party above
    /// its highest band, rather than only the fixed per-recipient table the
    /// first offering demonstrates.
    #[test]
    fn the_arrival_window_template_demonstrates_a_banded_table_refusing_above_its_highest_band() {
        let files = template_files("standalone-arrival-window").unwrap();
        let policy = parse_policy_yaml(
            files
                .iter()
                .find(|(path, _)| *path == "scheduling.yaml")
                .expect("the policy file exists")
                .1,
        )
        .expect("the template policy parses");
        let records: registry_scheduling_core::SchedulingFacts = serde_norway::from_str(
            files
                .iter()
                .find(|(path, _)| *path == "records.yaml")
                .expect("the records file exists")
                .1,
        )
        .expect("the template records parse");
        let window = records
            .windows
            .iter()
            .find(|window| window.id == "household-afternoon-window")
            .expect("the afternoon window is published");
        assert!(
            matches!(
                window.units_policy,
                RequiredUnitsPolicy::BandedTable {
                    above_highest_band: AboveHighestBand::Refuse,
                    ..
                }
            ),
            "{:?}",
            window.units_policy
        );

        let (relative, contents) = template_fixtures(&files)
            .into_iter()
            .find(|(relative, _)| relative.contains("household-afternoon"))
            .expect("the afternoon fixture ships with the template");
        let fixture = parse_fixture_yaml(contents).expect("the template fixture parses");
        let outcomes = fixture
            .replay(&policy)
            .unwrap_or_else(|error| panic!("{relative}: the fixture replays: {error}"));
        assert!(
            outcomes
                .iter()
                .all(|outcome| outcome.status == CaseStatus::Pass),
            "{outcomes:?}"
        );
        let refused = outcomes
            .iter()
            .find(|outcome| outcome.name.contains("above-the-highest-band"))
            .expect("a case exercises the above-highest-band refusal");
        assert!(
            refused
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("party.capacity-inadequate")),
            "{refused:?}"
        );
    }

    #[test]
    fn the_exact_time_template_carries_the_example_and_both_fixtures() {
        let files = template_files("standalone-exact-time").unwrap();
        let names: Vec<&str> = files.into_iter().map(|(relative, _)| relative).collect();
        assert_eq!(
            names,
            vec![
                "scheduling.yaml",
                "runtime.example.yaml",
                "records.yaml",
                "fixtures/counter-stations.yaml",
                "fixtures/fold-day-rebooking.yaml",
            ]
        );
    }
}
