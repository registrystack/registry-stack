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
windows: []
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

/// The `standalone-arrival-window` policy: a Saturday household block with a
/// public and an assisted subquota over a per-recipient units table.
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
    leftover: becomes-walk-in
    because: The Saturday morning household block, sized for two officers.
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

/// The files one template writes, relative to the project directory, in
/// write order. The first entry is always the authored policy.
pub(super) fn template_files(template: &str) -> Option<Vec<(&'static str, &'static str)>> {
    match template {
        "standalone-exact-time" => Some(vec![
            ("scheduling.yaml", EXACT_TIME_POLICY),
            ("fixtures/counter-stations.yaml", COUNTER_STATIONS_FIXTURE),
            (
                "fixtures/fold-day-rebooking.yaml",
                FOLD_DAY_REBOOKING_FIXTURE,
            ),
        ]),
        "standalone-arrival-window" => Some(vec![
            ("scheduling.yaml", ARRIVAL_WINDOW_POLICY),
            ("fixtures/household-morning.yaml", HOUSEHOLD_MORNING_FIXTURE),
        ]),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_scheduling_core::{
        parse_fixture_yaml, parse_policy_yaml, CaseStatus, AUTHORED_POLICY_FILE,
        SCHEDULING_FIXTURE_API_VERSION, SCHEDULING_FIXTURE_KIND, SCHEDULING_POLICY_API_VERSION,
        SCHEDULING_POLICY_KIND,
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
            for (relative, contents) in &files[1..] {
                assert!(
                    relative.starts_with("fixtures/") && relative.ends_with(".yaml"),
                    "{relative}"
                );
                let fixture = parse_fixture_yaml(contents).expect("the template fixture parses");
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
            for (relative, contents) in &files[1..] {
                let fixture = parse_fixture_yaml(contents).expect("the template fixture parses");
                let outcomes = fixture.replay(&policy).expect("the fixture replays");
                assert!(
                    outcomes
                        .iter()
                        .all(|outcome| outcome.status == CaseStatus::Pass),
                    "{template}/{relative}: {outcomes:?}"
                );
            }
        }
    }

    #[test]
    fn the_exact_time_template_carries_both_counter_and_fold_fixtures() {
        let files = template_files("standalone-exact-time").unwrap();
        let names: Vec<&str> = files.into_iter().map(|(relative, _)| relative).collect();
        assert_eq!(
            names,
            vec![
                "scheduling.yaml",
                "fixtures/counter-stations.yaml",
                "fixtures/fold-day-rebooking.yaml",
            ]
        );
    }
}
