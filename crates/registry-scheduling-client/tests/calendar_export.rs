// SPDX-License-Identifier: Apache-2.0

use chrono::{DateTime, TimeZone as _, Utc};
use registry_scheduling_client::{
    render_icalendar, AppointmentDocument, AppointmentStateDocument, AttendanceDocument,
    AttendanceState, BearerToken, CalendarEvent, CalendarExportError, ExternalReference,
    ManagerSelection, OperationalAppointmentDocument, PartyCounts, PartyReference,
    PartyReferenceRole, SchedulingAuth, SchedulingClient, SchedulingClientConfig,
    MAXIMUM_CALENDAR_EVENTS,
};
use url::Url;

fn instant(value: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(value)
        .expect("fixture instant")
        .with_timezone(&Utc)
}

fn appointment() -> AppointmentDocument {
    AppointmentDocument {
        attendance: None,
        allocations: Vec::new(),
        appointment_id: "03f4f87d-82c1-4e89-9554-620118a560d0".to_owned(),
        offering: "private-offering".to_owned(),
        start: instant("2026-03-29T01:30:00+01:00"),
        end: instant("2026-03-29T04:00:00+02:00"),
        resource: Some("private-resource".to_owned()),
        units: 1,
        party: Some(PartyCounts {
            recipients: 1,
            attendees: 2,
        }),
        manager: Some(ManagerSelection::SchedulingManager),
        party_references: vec![PartyReference {
            role: PartyReferenceRole::Beneficiary,
            reference: ExternalReference {
                product: "registry-breg".to_owned(),
                record_type: "person".to_owned(),
                identifier: "private-party-reference".to_owned(),
            },
        }],
        channel: Some("private-channel".to_owned()),
        revision: 7,
        state: AppointmentStateDocument::Confirmed,
        policy_revision: 4,
        created_at: instant("2026-03-01T09:00:00Z"),
        cancelled_at: None,
        external_references: vec![ExternalReference {
            product: "registry-casework".to_owned(),
            record_type: "case".to_owned(),
            identifier: "private-reference".to_owned(),
        }],
    }
}

fn operational() -> OperationalAppointmentDocument {
    OperationalAppointmentDocument {
        attendance: None,
        appointment_id: "03f4f87d-82c1-4e89-9554-620118a560d0".to_owned(),
        revision: 7,
        service: "private-service".to_owned(),
        location: "private-location".to_owned(),
        offering: "private-offering".to_owned(),
        state: AppointmentStateDocument::Confirmed,
        displayed_start: instant("2026-03-29T00:30:00Z"),
        displayed_end: instant("2026-03-29T02:00:00Z"),
        occupied_start: Some(instant("2026-03-29T00:15:00Z")),
        occupied_end: Some(instant("2026-03-29T02:15:00Z")),
        resource: Some("private-resource".to_owned()),
        units: Some(1),
        party: Some(PartyCounts {
            recipients: 1,
            attendees: 2,
        }),
        allocations: None,
        external_references: vec![ExternalReference {
            product: "registry-casework".to_owned(),
            record_type: "case".to_owned(),
            identifier: "private-reference".to_owned(),
        }],
    }
}

#[test]
fn current_lifecycle_revisions_keep_one_uid_and_advance_sequence() {
    let confirmed = CalendarEvent::try_from(&appointment()).expect("confirmed event");
    let mut cancelled_document = appointment();
    cancelled_document.revision = 8;
    cancelled_document.state = AppointmentStateDocument::Cancelled;
    cancelled_document.cancelled_at = Some(instant("2026-03-20T09:00:00Z"));
    let cancelled = CalendarEvent::try_from(&cancelled_document).expect("cancelled event");

    let confirmed_calendar = render_icalendar(
        [confirmed],
        Utc.with_ymd_and_hms(2026, 3, 20, 10, 0, 0).unwrap(),
    )
    .expect("confirmed calendar");
    let cancelled_calendar = render_icalendar(
        [cancelled],
        Utc.with_ymd_and_hms(2026, 3, 20, 11, 0, 0).unwrap(),
    )
    .expect("cancelled calendar");

    let uid = "UID:03f4f87d-82c1-4e89-9554-620118a560d0@appointments.scheduling.registrystack.org";
    assert!(confirmed_calendar.replace("\r\n ", "").contains(uid));
    assert!(cancelled_calendar.replace("\r\n ", "").contains(uid));
    assert!(confirmed_calendar.contains("SEQUENCE:7\r\n"));
    assert!(cancelled_calendar.contains("SEQUENCE:8\r\n"));
    assert!(confirmed_calendar.contains("STATUS:CONFIRMED\r\n"));
    assert!(cancelled_calendar.contains("STATUS:CANCELLED\r\n"));
}

#[test]
fn output_uses_the_authoritative_displayed_interval_in_utc() {
    let calendar = render_icalendar(
        [CalendarEvent::try_from(&appointment()).expect("event")],
        instant("2026-03-20T10:00:00Z"),
    )
    .expect("calendar");

    // The source interval crosses a European DST offset change. Exporting
    // instants in UTC makes the elapsed 90 minutes unambiguous.
    assert!(calendar.contains("DTSTART:20260329T003000Z\r\n"));
    assert!(calendar.contains("DTEND:20260329T020000Z\r\n"));
    assert!(calendar.contains("DTSTAMP:20260320T100000Z\r\n"));

    let operational_calendar = render_icalendar(
        [CalendarEvent::try_from(&operational()).expect("operational event")],
        instant("2026-03-20T10:00:00Z"),
    )
    .expect("operational calendar");
    assert!(operational_calendar.contains("DTSTART:20260329T003000Z\r\n"));
    assert!(operational_calendar.contains("DTEND:20260329T020000Z\r\n"));
    assert!(!operational_calendar.contains("20260329T001500Z"));
}

#[test]
fn default_projection_omits_private_and_operational_details() {
    let mut source = appointment();
    source.attendance = Some(AttendanceDocument {
        appointment_id: source.appointment_id.clone(),
        appointment_revision: source.revision,
        revision: 47,
        state: AttendanceState::NoShow,
        observed_at: instant("2026-03-20T09:13:17Z"),
        recorded_at: instant("2026-03-20T09:14:18Z"),
    });
    let calendar = render_icalendar(
        [CalendarEvent::try_from(&source).expect("event")],
        instant("2026-03-20T10:00:00Z"),
    )
    .expect("calendar");

    for absent in [
        "private-offering",
        "private-resource",
        "private-channel",
        "private-party-reference",
        "private-reference",
        "schedulingManager",
        "registry-casework",
        "no-show",
        "attendanceRevision",
        "20260320T091317Z",
        "20260320T091418Z",
        "ATTENDEE",
        "CONTACT",
        "DESCRIPTION",
        "LOCATION",
        "ORGANIZER",
        "RESOURCES",
        "URL:",
    ] {
        assert!(
            !calendar.contains(absent),
            "unexpected disclosure: {absent}"
        );
    }
    assert!(calendar.contains("SUMMARY:Appointment\r\n"));
}

#[test]
fn duplicate_rows_converge_to_the_highest_revision() {
    let old = CalendarEvent::try_from(&appointment()).expect("old event");
    let mut current_document = appointment();
    current_document.revision = 8;
    current_document.start = instant("2026-03-30T08:00:00Z");
    current_document.end = instant("2026-03-30T08:30:00Z");
    let current = CalendarEvent::try_from(&current_document).expect("current event");

    // Repeating an old row after the current row models an overlapping page
    // or delayed read. The newest Scheduling revision remains authoritative.
    let calendar = render_icalendar(
        [old, current.clone(), current],
        instant("2026-03-20T10:00:00Z"),
    )
    .expect("calendar");

    assert_eq!(calendar.matches("BEGIN:VEVENT").count(), 1);
    assert!(calendar.contains("SEQUENCE:8\r\n"));
    assert!(calendar.contains("DTSTART:20260330T080000Z\r\n"));
}

#[test]
fn conflicting_rows_at_one_revision_are_refused() {
    let first = CalendarEvent::try_from(&appointment()).expect("first event");
    let mut conflicting_document = appointment();
    conflicting_document.end = instant("2026-03-29T03:00:00Z");
    let conflicting = CalendarEvent::try_from(&conflicting_document).expect("conflicting event");

    assert_eq!(
        render_icalendar([first, conflicting], instant("2026-03-20T10:00:00Z")),
        Err(CalendarExportError::ConflictingRevision)
    );
}

#[test]
fn event_count_is_a_hard_error_instead_of_truncation() {
    let event = CalendarEvent::try_from(&appointment()).expect("event");
    let events = std::iter::repeat_n(event, MAXIMUM_CALENDAR_EVENTS + 1);
    assert_eq!(
        render_icalendar(events, instant("2026-03-20T10:00:00Z")),
        Err(CalendarExportError::TooManyEvents)
    );
}

#[test]
fn invalid_intervals_and_unrepresentable_revisions_are_refused() {
    let mut invalid_interval = appointment();
    invalid_interval.end = invalid_interval.start;
    assert_eq!(
        CalendarEvent::try_from(&invalid_interval),
        Err(CalendarExportError::InvalidInterval)
    );

    let mut excessive_revision = appointment();
    excessive_revision.revision = i32::MAX as u64 + 1;
    assert_eq!(
        CalendarEvent::try_from(&excessive_revision),
        Err(CalendarExportError::RevisionOutOfRange)
    );

    let mut subsecond_interval = appointment();
    subsecond_interval.start += chrono::Duration::milliseconds(1);
    assert_eq!(
        CalendarEvent::try_from(&subsecond_interval),
        Err(CalendarExportError::SubsecondPrecisionUnsupported)
    );

    assert_eq!(
        render_icalendar([], instant("2026-03-20T10:00:00Z")),
        Err(CalendarExportError::NoEvents)
    );

    let mut unsafe_identifier = appointment();
    unsafe_identifier.appointment_id = "appointment\r\ninjected".to_owned();
    assert_eq!(
        CalendarEvent::try_from(&unsafe_identifier),
        Err(CalendarExportError::InvalidIdentifier)
    );
}

#[test]
fn content_lines_use_crlf_and_fold_on_utf8_octet_boundaries() {
    let mut document = appointment();
    document.appointment_id = format!("{}éé", "a".repeat(70));
    let calendar = render_icalendar(
        [CalendarEvent::try_from(&document).expect("event")],
        instant("2026-03-20T10:00:00Z"),
    )
    .expect("calendar");

    assert!(!calendar.replace("\r\n", "").contains('\n'));
    assert!(calendar
        .split("\r\n")
        .filter(|line| !line.is_empty())
        .all(|line| line.len() <= 75));
    assert!(calendar.is_char_boundary(calendar.len()));
    let unfolded = calendar.replace("\r\n ", "");
    assert!(unfolded.contains(&format!(
        "UID:{}éé@appointments.scheduling.registrystack.org",
        "a".repeat(70)
    )));
}

#[tokio::test]
async fn owner_authorized_current_detail_is_the_export_source() {
    use axum::http::{HeaderMap, HeaderValue, StatusCode};
    use axum::routing::get;
    use axum::Router;

    const CURRENT_DETAIL: &str = r#"{
        "appointmentId":"03f4f87d-82c1-4e89-9554-620118a560d0",
        "offering":"not-exported",
        "start":"2026-03-30T08:00:00Z",
        "end":"2026-03-30T08:30:00Z",
        "resource":"not-exported",
        "units":1,
        "channel":null,
        "revision":9,
        "state":"cancelled",
        "policyRevision":4,
        "createdAt":"2026-03-01T09:00:00Z",
        "cancelledAt":"2026-03-20T09:00:00Z",
        "externalReferences":[]
    }"#;

    async fn current_detail(headers: HeaderMap) -> (StatusCode, HeaderMap, &'static str) {
        assert_eq!(
            headers.get("authorization"),
            Some(&HeaderValue::from_static("Bearer synthetic-calendar-token"))
        );
        let mut response_headers = HeaderMap::new();
        response_headers.insert("content-type", HeaderValue::from_static("application/json"));
        response_headers.insert(
            "traceparent",
            HeaderValue::from_static("00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"),
        );
        (StatusCode::OK, response_headers, CURRENT_DETAIL)
    }

    serde_json::from_str::<AppointmentDocument>(CURRENT_DETAIL).expect("fixture appointment JSON");

    let app = Router::new().route(
        "/v1/appointments/03f4f87d-82c1-4e89-9554-620118a560d0",
        get(current_detail),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });
    let client = SchedulingClient::new(SchedulingClientConfig::new(
        Url::parse(&format!("http://{address}/")).expect("fixture URL"),
    ))
    .expect("client");
    let token = BearerToken::new("synthetic-calendar-token").expect("synthetic token");

    let current = client
        .get_appointment(
            SchedulingAuth::new(&token),
            "03f4f87d-82c1-4e89-9554-620118a560d0",
        )
        .await
        .expect("current appointment");
    let calendar = render_icalendar(
        [CalendarEvent::try_from(&current.value).expect("calendar event")],
        instant("2026-03-20T10:00:00Z"),
    )
    .expect("calendar");

    assert!(calendar.contains("SEQUENCE:9\r\n"));
    assert!(calendar.contains("STATUS:CANCELLED\r\n"));
    assert!(!calendar.contains("not-exported"));
    server.abort();
}
