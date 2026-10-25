// SPDX-License-Identifier: Apache-2.0

//! On-demand, bounded iCalendar export over Registry Scheduling's public client.

use std::collections::BTreeSet;
use std::env;
use std::error::Error;
use std::fmt;

use chrono::{DateTime, Utc};
use registry_scheduling_client::{
    render_icalendar, BearerToken, CalendarEvent, OperationalAppointmentQuery,
    OperationalTimeBasis, SchedulingAuth, SchedulingClient, SchedulingClientConfig,
    MAXIMUM_CALENDAR_EVENTS,
};
use url::Url;

const TOKEN_ENVIRONMENT_VARIABLE: &str = "REGISTRY_SCHEDULING_TOKEN";
const OPERATIONAL_PAGE_SIZE: usize = 50;
const MAXIMUM_OPERATIONAL_PAGES: usize = 10;

#[derive(Debug)]
struct CliError(&'static str);

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for CliError {}

enum ExportMode {
    Personal {
        appointment_ids: Vec<String>,
    },
    Staff {
        service: String,
        location: String,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        profile: String,
    },
}

struct Arguments {
    base_url: Url,
    mode: ExportMode,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let arguments = parse_arguments()?;
    let token_text = env::var(TOKEN_ENVIRONMENT_VARIABLE)
        .map_err(|_| CliError("REGISTRY_SCHEDULING_TOKEN is required"))?;
    let token = BearerToken::new(token_text)?;
    let client = SchedulingClient::new(SchedulingClientConfig::new(arguments.base_url))?;

    // Build the whole snapshot before touching stdout. Any failed read,
    // continuation, bound check, or projection therefore produces no partial
    // calendar that a caller could mistake for a complete export.
    let events = match arguments.mode {
        ExportMode::Personal { appointment_ids } => {
            collect_personal(&client, &token, appointment_ids).await?
        }
        ExportMode::Staff {
            service,
            location,
            start,
            end,
            profile,
        } => collect_staff(&client, &token, service, location, start, end, profile).await?,
    };
    let calendar = render_icalendar(events, Utc::now())?;
    print!("{calendar}");
    Ok(())
}

async fn collect_personal(
    client: &SchedulingClient,
    token: &BearerToken,
    appointment_ids: Vec<String>,
) -> Result<Vec<CalendarEvent>, Box<dyn Error>> {
    if appointment_ids.is_empty() {
        return Err(CliError("personal export requires at least one --appointment").into());
    }
    if appointment_ids.len() > MAXIMUM_CALENDAR_EVENTS {
        return Err(CliError("personal export exceeds the appointment bound").into());
    }

    let mut events = Vec::with_capacity(appointment_ids.len());
    for appointment_id in appointment_ids {
        let current = client
            .get_appointment(SchedulingAuth::new(token), &appointment_id)
            .await?;
        events.push(CalendarEvent::try_from(&current.value)?);
    }
    Ok(events)
}

async fn collect_staff(
    client: &SchedulingClient,
    token: &BearerToken,
    service: String,
    location: String,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    profile: String,
) -> Result<Vec<CalendarEvent>, Box<dyn Error>> {
    if end <= start {
        return Err(CliError("staff export interval must have a positive duration").into());
    }

    let mut cursor = None;
    let mut seen_cursors = BTreeSet::new();
    let mut events = Vec::new();
    for page_number in 0..MAXIMUM_OPERATIONAL_PAGES {
        let query = OperationalAppointmentQuery {
            service: service.clone(),
            location: location.clone(),
            start,
            end,
            time_basis: OperationalTimeBasis::Displayed,
            offering: None,
            state: None,
            resource: None,
            external_reference: None,
            profile: Some(profile.clone()),
            cursor: cursor.clone(),
            limit: Some(OPERATIONAL_PAGE_SIZE),
        };
        let page = client
            .list_operational_appointments(SchedulingAuth::new(token), &query)
            .await?
            .value;
        if events.len().saturating_add(page.items.len()) > MAXIMUM_CALENDAR_EVENTS {
            return Err(CliError("staff export exceeds the appointment bound").into());
        }
        for document in &page.items {
            events.push(CalendarEvent::try_from(document)?);
        }

        let Some(next_cursor) = page.next_cursor else {
            return Ok(events);
        };
        if page_number + 1 == MAXIMUM_OPERATIONAL_PAGES {
            return Err(CliError("staff export exceeds the page bound").into());
        }
        if !seen_cursors.insert(next_cursor.clone()) {
            return Err(CliError("staff export received a repeated cursor").into());
        }
        cursor = Some(next_cursor);
    }
    unreachable!("the page loop returns or refuses at its explicit bound")
}

fn parse_arguments() -> Result<Arguments, CliError> {
    let mut values = env::args().skip(1);
    let mode = values.next().ok_or(CliError(usage()))?;
    if mode == "--help" || mode == "-h" {
        return Err(CliError(usage()));
    }

    let mut base_url = None;
    let mut appointment_ids = Vec::new();
    let mut service = None;
    let mut location = None;
    let mut start = None;
    let mut end = None;
    let mut profile = None;
    while let Some(flag) = values.next() {
        let value = values
            .next()
            .ok_or(CliError("every option requires a value"))?;
        match flag.as_str() {
            "--base-url" => {
                base_url = Some(
                    Url::parse(&value)
                        .map_err(|_| CliError("--base-url must be an absolute URL"))?,
                );
            }
            "--appointment" => appointment_ids.push(value),
            "--service" => service = Some(value),
            "--location" => location = Some(value),
            "--start" => start = Some(parse_instant(&value, "--start must be RFC 3339")?),
            "--end" => end = Some(parse_instant(&value, "--end must be RFC 3339")?),
            "--profile" => profile = Some(value),
            _ => return Err(CliError("unknown calendar-export option")),
        }
    }

    let base_url = base_url.ok_or(CliError("--base-url is required"))?;
    let mode = match mode.as_str() {
        "personal" => {
            if service.is_some()
                || location.is_some()
                || start.is_some()
                || end.is_some()
                || profile.is_some()
            {
                return Err(CliError(
                    "staff selectors are not valid for personal export",
                ));
            }
            ExportMode::Personal { appointment_ids }
        }
        "staff" => {
            if !appointment_ids.is_empty() {
                return Err(CliError("--appointment is not valid for staff export"));
            }
            ExportMode::Staff {
                service: service.ok_or(CliError("staff export requires --service"))?,
                location: location.ok_or(CliError("staff export requires --location"))?,
                start: start.ok_or(CliError("staff export requires --start"))?,
                end: end.ok_or(CliError("staff export requires --end"))?,
                profile: profile.ok_or(CliError("staff export requires --profile"))?,
            }
        }
        _ => return Err(CliError(usage())),
    };
    Ok(Arguments { base_url, mode })
}

fn parse_instant(value: &str, error: &'static str) -> Result<DateTime<Utc>, CliError> {
    DateTime::parse_from_rfc3339(value)
        .map(|parsed| parsed.with_timezone(&Utc))
        .map_err(|_| CliError(error))
}

const fn usage() -> &'static str {
    "usage: calendar-export personal --base-url URL --appointment ID [--appointment ID ...]\n       calendar-export staff --base-url URL --service ID --location ID --start RFC3339 --end RFC3339 --profile ID\nREGISTRY_SCHEDULING_TOKEN supplies the bearer token"
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use axum::extract::State;
    use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
    use axum::routing::get;
    use axum::Router;
    use registry_scheduling_client::{AppointmentStateDocument, OperationalAppointmentDocument};

    use super::*;

    #[derive(Clone, Copy)]
    enum FixtureMode {
        Personal,
        StaffCurrent,
        PageOverflow,
        RowOverflow,
    }

    #[derive(Clone)]
    struct Fixture {
        calls: Arc<AtomicUsize>,
        mode: FixtureMode,
    }

    async fn fixture_response(
        State(fixture): State<Fixture>,
        headers: HeaderMap,
        uri: Uri,
    ) -> (StatusCode, HeaderMap, String) {
        assert_eq!(
            headers.get("authorization"),
            Some(&HeaderValue::from_static("Bearer synthetic-example-token"))
        );
        let call = fixture.calls.fetch_add(1, Ordering::SeqCst);
        let body = match fixture.mode {
            FixtureMode::Personal => serde_json::json!({
                "appointmentId": "03f4f87d-82c1-4e89-9554-620118a560d0",
                "offering": "not-exported",
                "start": "2026-11-03T08:00:00Z",
                "end": "2026-11-03T08:30:00Z",
                "resource": "not-exported",
                "units": 1,
                "party": { "recipients": 1, "attendees": 2 },
                "manager": "schedulingManager",
                "partyReferences": [{
                    "role": "beneficiary",
                    "reference": {
                        "product": "registry-breg",
                        "recordType": "person",
                        "identifier": "not-exported"
                    }
                }],
                "channel": null,
                "revision": 9,
                "state": "cancelled",
                "policyRevision": 4,
                "createdAt": "2026-11-01T09:00:00Z",
                "cancelledAt": "2026-11-02T09:00:00Z",
                "externalReferences": []
            }),
            FixtureMode::StaffCurrent => {
                let query = query(&uri);
                assert_eq!(
                    query.get("service").map(String::as_str),
                    Some("registry-update")
                );
                assert_eq!(
                    query.get("location").map(String::as_str),
                    Some("north-counter")
                );
                assert_eq!(
                    query.get("profile").map(String::as_str),
                    Some("calendar-export")
                );
                assert_eq!(
                    query.get("timeBasis").map(String::as_str),
                    Some("displayed")
                );
                assert_eq!(query.get("limit").map(String::as_str), Some("50"));
                match call {
                    0 => serde_json::json!({
                        "items": [operational(7, AppointmentStateDocument::Confirmed)],
                        "nextCursor": "page-2"
                    }),
                    1 => {
                        assert_eq!(query.get("cursor").map(String::as_str), Some("page-2"));
                        serde_json::json!({
                            "items": [operational(8, AppointmentStateDocument::Cancelled)],
                            "nextCursor": null
                        })
                    }
                    _ => panic!("unexpected staff page"),
                }
            }
            FixtureMode::PageOverflow => serde_json::json!({
                "items": [],
                "nextCursor": format!("page-{}", call + 2)
            }),
            FixtureMode::RowOverflow => serde_json::json!({
                "items": vec![operational(1, AppointmentStateDocument::Confirmed); MAXIMUM_CALENDAR_EVENTS + 1],
                "nextCursor": null
            }),
        };
        let mut response_headers = HeaderMap::new();
        response_headers.insert("content-type", HeaderValue::from_static("application/json"));
        response_headers.insert(
            "traceparent",
            HeaderValue::from_static("00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"),
        );
        (StatusCode::OK, response_headers, body.to_string())
    }

    fn operational(
        revision: u64,
        state: AppointmentStateDocument,
    ) -> OperationalAppointmentDocument {
        OperationalAppointmentDocument {
            attendance: None,
            appointment_id: "03f4f87d-82c1-4e89-9554-620118a560d0".to_owned(),
            revision,
            service: "registry-update".to_owned(),
            location: "north-counter".to_owned(),
            offering: "not-exported".to_owned(),
            state,
            displayed_start: instant("2026-11-03T08:00:00Z"),
            displayed_end: instant("2026-11-03T08:30:00Z"),
            occupied_start: None,
            occupied_end: None,
            resource: Some("not-exported".to_owned()),
            units: Some(1),
            party: Some(registry_scheduling_client::PartyCounts {
                recipients: 1,
                attendees: 2,
            }),
            allocations: None,
            external_references: Vec::new(),
        }
    }

    fn instant(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .expect("fixture instant")
            .with_timezone(&Utc)
    }

    fn query(uri: &Uri) -> std::collections::BTreeMap<String, String> {
        url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
            .into_owned()
            .collect()
    }

    async fn fixture_client(mode: FixtureMode) -> (SchedulingClient, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let fixture = Fixture {
            calls: calls.clone(),
            mode,
        };
        let app = Router::new()
            .route("/v1/appointments/{appointment_id}", get(fixture_response))
            .route("/v1/operational/appointments", get(fixture_response))
            .with_state(fixture);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fixture");
        let address = listener.local_addr().expect("fixture address");
        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve fixture");
        });
        let client = SchedulingClient::new(SchedulingClientConfig::new(
            Url::parse(&format!("http://{address}/")).expect("fixture URL"),
        ))
        .expect("client");
        (client, calls)
    }

    fn token() -> BearerToken {
        BearerToken::new("synthetic-example-token").expect("synthetic token")
    }

    async fn staff_request(
        client: &SchedulingClient,
        token: &BearerToken,
    ) -> Result<Vec<CalendarEvent>, Box<dyn Error>> {
        collect_staff(
            client,
            token,
            "registry-update".to_owned(),
            "north-counter".to_owned(),
            instant("2026-11-01T00:00:00Z"),
            instant("2026-12-01T00:00:00Z"),
            "calendar-export".to_owned(),
        )
        .await
    }

    #[tokio::test]
    async fn personal_mode_rereads_current_owner_detail_before_projection() {
        let (client, calls) = fixture_client(FixtureMode::Personal).await;
        let events = collect_personal(
            &client,
            &token(),
            vec!["03f4f87d-82c1-4e89-9554-620118a560d0".to_owned()],
        )
        .await
        .expect("personal events");
        let calendar =
            render_icalendar(events, instant("2026-11-02T10:00:00Z")).expect("personal calendar");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(calendar.contains("SEQUENCE:9\r\n"));
        assert!(calendar.contains("STATUS:CANCELLED\r\n"));
        assert!(!calendar.contains("not-exported"));
    }

    #[tokio::test]
    async fn staff_mode_follows_bounded_current_profile_pages() {
        let (client, calls) = fixture_client(FixtureMode::StaffCurrent).await;
        let events = collect_staff(
            &client,
            &token(),
            "registry-update".to_owned(),
            "north-counter".to_owned(),
            instant("2026-11-01T00:00:00Z"),
            instant("2026-12-01T00:00:00Z"),
            "calendar-export".to_owned(),
        )
        .await
        .expect("staff events");
        let calendar =
            render_icalendar(events, instant("2026-11-02T10:00:00Z")).expect("staff calendar");

        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(calendar.matches("BEGIN:VEVENT").count(), 1);
        assert!(calendar.contains("SEQUENCE:8\r\n"));
        assert!(calendar.contains("STATUS:CANCELLED\r\n"));
        assert!(!calendar.contains("not-exported"));
    }

    #[tokio::test]
    async fn staff_mode_refuses_page_and_row_overflow() {
        let (page_client, page_calls) = fixture_client(FixtureMode::PageOverflow).await;
        let page_token = token();
        let page_error = staff_request(&page_client, &page_token)
            .await
            .expect_err("page overflow must fail");
        assert_eq!(
            page_error.to_string(),
            "staff export exceeds the page bound"
        );
        assert_eq!(page_calls.load(Ordering::SeqCst), MAXIMUM_OPERATIONAL_PAGES);

        let (row_client, row_calls) = fixture_client(FixtureMode::RowOverflow).await;
        let row_token = token();
        let row_error = staff_request(&row_client, &row_token)
            .await
            .expect_err("row overflow must fail");
        assert_eq!(
            row_error.to_string(),
            "staff export exceeds the appointment bound"
        );
        assert_eq!(row_calls.load(Ordering::SeqCst), 1);
    }
}
