// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use chrono::{DateTime, SecondsFormat, Utc};
use registry_platform_httpsec::{response_trace_id, ProblemDocument};
use registry_platform_httputil::client::{
    build_client, read_failure_kind, send_failure_kind, OutboundOptions, ServiceBaseUrl,
};
use registry_platform_httputil::{
    read_bounded, url::append_path_segments, validate_response_headers,
};
use registry_scheduling_core::{
    type_uri, AdmissionRequest, AppointmentDocument, AppointmentHistoryEntryDocument,
    AvailabilityEntry, CancelAppointmentRequest, CreateAppointmentRequest, ExplainDocument,
    HoldDocument, LocationDocument, OfferingDocument, PageDocument, ProblemCode,
    RescheduleAppointmentRequest, ResourceDocument, SchedulingServiceDocument, ServiceDocument,
    APPOINTMENTS_PATH, AVAILABILITY_EXPLAIN_PATH, AVAILABILITY_PATH, CURSOR_QUERY_PARAMETER,
    HOLDS_PATH, IDEMPOTENCY_KEY_HEADER, LIMIT_QUERY_PARAMETER, LOCATIONS_PATH,
    MAXIMUM_IDEMPOTENCY_KEY_BYTES, OFFERINGS_PATH, RESOURCES_PATH, SCHEDULING_PATH, SERVICES_PATH,
};
use reqwest::header::{HeaderName, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use reqwest::{RequestBuilder, Response, StatusCode, Url};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::{
    SchedulingAuth, SchedulingClientConfig, SchedulingClientError, SchedulingComplete,
    SchedulingProtocolFailure,
};

const JSON_MEDIA_TYPE: &str = "application/json";
const PROBLEM_MEDIA_TYPE: &str = "application/problem+json";
const MAXIMUM_PROBLEM_BYTES: u64 = 8 * 1024;
const MAXIMUM_CURSOR_BYTES: usize = 4096;
const MAXIMUM_IDENTIFIER_BYTES: usize = 128;
const OFFERING_QUERY_PARAMETER: &str = "offering";
const START_QUERY_PARAMETER: &str = "start";
const END_QUERY_PARAMETER: &str = "end";

pub struct SchedulingClient {
    http: reqwest::Client,
    base_url: ServiceBaseUrl,
    max_response_bytes: u64,
}

impl fmt::Debug for SchedulingClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SchedulingClient")
            .field("base_url", &"<validated service URL>")
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

impl SchedulingClient {
    pub fn new(config: SchedulingClientConfig) -> Result<Self, SchedulingClientError> {
        let base_url = config.validate()?;
        let http = build_client(OutboundOptions {
            request_timeout: config.request_timeout,
            connect_timeout: config.connect_timeout,
            user_agent: config.user_agent.as_deref(),
            trusted_root_certificates: config.trusted_root_certificates.as_deref(),
        })
        .map_err(|_| SchedulingClientError::configuration("the HTTP client could not be built"))?;
        Ok(Self {
            http,
            base_url,
            max_response_bytes: config.max_response_bytes,
        })
    }

    /// Which deployment and which policy this service answers with.
    pub async fn get_scheduling(
        &self,
        auth: SchedulingAuth<'_>,
    ) -> Result<SchedulingComplete<SchedulingServiceDocument>, SchedulingClientError> {
        self.get_json(&auth, SCHEDULING_PATH, &[]).await
    }

    pub async fn list_services(
        &self,
        auth: SchedulingAuth<'_>,
        cursor: Option<&str>,
    ) -> Result<SchedulingComplete<PageDocument<ServiceDocument>>, SchedulingClientError> {
        validate_cursor(cursor)?;
        self.get_json(&auth, SERVICES_PATH, &cursor_query(cursor))
            .await
    }

    pub async fn list_offerings(
        &self,
        auth: SchedulingAuth<'_>,
        cursor: Option<&str>,
    ) -> Result<SchedulingComplete<PageDocument<OfferingDocument>>, SchedulingClientError> {
        validate_cursor(cursor)?;
        self.get_json(&auth, OFFERINGS_PATH, &cursor_query(cursor))
            .await
    }

    /// Bounded availability. Exact-time offerings answer in grid slots and
    /// arrival-window offerings in windows; `start` and `end` bound the
    /// searched interval, `cursor` and `limit` bound the page.
    pub async fn availability(
        &self,
        auth: SchedulingAuth<'_>,
        offering: &str,
        start: Option<DateTime<Utc>>,
        end: Option<DateTime<Utc>>,
        cursor: Option<&str>,
        limit: Option<u32>,
    ) -> Result<SchedulingComplete<PageDocument<AvailabilityEntry>>, SchedulingClientError> {
        validate_availability(offering, start, end, cursor, limit)?;
        let mut query: Vec<(&str, String)> = Vec::new();
        query.push((OFFERING_QUERY_PARAMETER, offering.to_owned()));
        if let Some(start) = start {
            query.push((START_QUERY_PARAMETER, rfc3339(start)));
        }
        if let Some(end) = end {
            query.push((END_QUERY_PARAMETER, rfc3339(end)));
        }
        if let Some(cursor) = cursor {
            query.push((CURSOR_QUERY_PARAMETER, cursor.to_owned()));
        }
        if let Some(limit) = limit {
            query.push((LIMIT_QUERY_PARAMETER, limit.to_string()));
        }
        let request = self.authorized(
            self.http
                .get(self.url_from_constant(AVAILABILITY_PATH)?)
                .query(&query),
            &auth,
        );
        self.send_json(request, StatusCode::OK).await
    }

    /// The separately authorized explanation of one refused start.
    pub async fn explain(
        &self,
        auth: SchedulingAuth<'_>,
        offering: &str,
        start: DateTime<Utc>,
    ) -> Result<SchedulingComplete<ExplainDocument>, SchedulingClientError> {
        if offering.is_empty() {
            return Err(SchedulingClientError::invalid_request(
                "the offering selector is invalid",
            ));
        }
        let query = [
            (OFFERING_QUERY_PARAMETER, offering.to_owned()),
            (START_QUERY_PARAMETER, rfc3339(start)),
        ];
        let request = self.authorized(
            self.http
                .get(self.url_from_constant(AVAILABILITY_EXPLAIN_PATH)?)
                .query(&query),
            &auth,
        );
        self.send_json(request, StatusCode::OK).await
    }

    /// Reserve an admission instead of committing it. The request body is
    /// the same admission ask a direct create carries.
    pub async fn create_hold(
        &self,
        auth: SchedulingAuth<'_>,
        idempotency_key: &str,
        request: &AdmissionRequest,
    ) -> Result<SchedulingComplete<HoldDocument>, SchedulingClientError> {
        self.post_json(
            &auth,
            HOLDS_PATH,
            idempotency_key,
            request,
            StatusCode::CREATED,
        )
        .await
    }

    /// Give a hold's capacity back. The hold identifier is opaque and is
    /// never invented here: it comes from a minted hold document.
    pub async fn release_hold(
        &self,
        auth: SchedulingAuth<'_>,
        hold_id: &str,
    ) -> Result<SchedulingComplete<()>, SchedulingClientError> {
        validate_identifier(hold_id, "the hold identifier is invalid")?;
        let url = self.url_from_constant(&format!("{HOLDS_PATH}/{hold_id}"))?;
        let request = self.authorized(self.http.delete(url), &auth);
        self.send_empty(request, StatusCode::NO_CONTENT).await
    }

    /// Confirm a hold or create an appointment directly; the two request
    /// shapes are mutually exclusive by the core's own contract.
    pub async fn create_appointment(
        &self,
        auth: SchedulingAuth<'_>,
        idempotency_key: &str,
        request: &CreateAppointmentRequest,
    ) -> Result<SchedulingComplete<AppointmentDocument>, SchedulingClientError> {
        self.post_json(
            &auth,
            APPOINTMENTS_PATH,
            idempotency_key,
            request,
            StatusCode::CREATED,
        )
        .await
    }

    pub async fn get_appointment(
        &self,
        auth: SchedulingAuth<'_>,
        appointment_id: &str,
    ) -> Result<SchedulingComplete<AppointmentDocument>, SchedulingClientError> {
        validate_identifier(appointment_id, "the appointment identifier is invalid")?;
        self.get_json(&auth, &format!("{APPOINTMENTS_PATH}/{appointment_id}"), &[])
            .await
    }

    pub async fn reschedule_appointment(
        &self,
        auth: SchedulingAuth<'_>,
        appointment_id: &str,
        idempotency_key: &str,
        request: &RescheduleAppointmentRequest,
    ) -> Result<SchedulingComplete<AppointmentDocument>, SchedulingClientError> {
        validate_identifier(appointment_id, "the appointment identifier is invalid")?;
        self.post_json(
            &auth,
            &format!("{APPOINTMENTS_PATH}/{appointment_id}/reschedule"),
            idempotency_key,
            request,
            StatusCode::OK,
        )
        .await
    }

    pub async fn cancel_appointment(
        &self,
        auth: SchedulingAuth<'_>,
        appointment_id: &str,
        idempotency_key: &str,
        request: &CancelAppointmentRequest,
    ) -> Result<SchedulingComplete<AppointmentDocument>, SchedulingClientError> {
        validate_identifier(appointment_id, "the appointment identifier is invalid")?;
        self.post_json(
            &auth,
            &format!("{APPOINTMENTS_PATH}/{appointment_id}/cancel"),
            idempotency_key,
            request,
            StatusCode::OK,
        )
        .await
    }

    pub async fn appointment_history(
        &self,
        auth: SchedulingAuth<'_>,
        appointment_id: &str,
        cursor: Option<&str>,
    ) -> Result<
        SchedulingComplete<PageDocument<AppointmentHistoryEntryDocument>>,
        SchedulingClientError,
    > {
        validate_identifier(appointment_id, "the appointment identifier is invalid")?;
        validate_cursor(cursor)?;
        self.get_json(
            &auth,
            &format!("{APPOINTMENTS_PATH}/{appointment_id}/history"),
            &cursor_query(cursor),
        )
        .await
    }

    pub async fn list_resources(
        &self,
        auth: SchedulingAuth<'_>,
        cursor: Option<&str>,
    ) -> Result<SchedulingComplete<PageDocument<ResourceDocument>>, SchedulingClientError> {
        validate_cursor(cursor)?;
        self.get_json(&auth, RESOURCES_PATH, &cursor_query(cursor))
            .await
    }

    pub async fn list_locations(
        &self,
        auth: SchedulingAuth<'_>,
        cursor: Option<&str>,
    ) -> Result<SchedulingComplete<PageDocument<LocationDocument>>, SchedulingClientError> {
        validate_cursor(cursor)?;
        self.get_json(&auth, LOCATIONS_PATH, &cursor_query(cursor))
            .await
    }

    async fn get_json<T: DeserializeOwned>(
        &self,
        auth: &SchedulingAuth<'_>,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<SchedulingComplete<T>, SchedulingClientError> {
        let request = self.authorized(
            self.http.get(self.url_from_constant(path)?).query(query),
            auth,
        );
        self.send_json(request, StatusCode::OK).await
    }

    async fn post_json<T: DeserializeOwned, B: Serialize + ?Sized>(
        &self,
        auth: &SchedulingAuth<'_>,
        path: &str,
        idempotency_key: &str,
        body: &B,
        expected_status: StatusCode,
    ) -> Result<SchedulingComplete<T>, SchedulingClientError> {
        validate_idempotency_key(idempotency_key)?;
        let request = self
            .authorized(
                self.http.post(self.url_from_constant(path)?).json(body),
                auth,
            )
            .header(
                HeaderName::from_static(IDEMPOTENCY_KEY_HEADER),
                HeaderValue::from_str(idempotency_key).map_err(|_| {
                    SchedulingClientError::invalid_request("the idempotency key is invalid")
                })?,
            );
        self.send_json(request, expected_status).await
    }

    fn authorized(&self, request: RequestBuilder, auth: &SchedulingAuth<'_>) -> RequestBuilder {
        request
            .header(AUTHORIZATION, auth.token.authorization_header_value())
            .header(ACCEPT, JSON_MEDIA_TYPE)
    }

    fn url_from_constant(&self, path: &str) -> Result<Url, SchedulingClientError> {
        let segments = path.trim_start_matches('/').split('/').collect::<Vec<_>>();
        append_path_segments(self.base_url.as_url(), &segments)
            .map_err(|_| SchedulingClientError::invalid_request("a route identifier is invalid"))
    }

    async fn send_json<T: DeserializeOwned>(
        &self,
        request: RequestBuilder,
        expected_status: StatusCode,
    ) -> Result<SchedulingComplete<T>, SchedulingClientError> {
        let response = self.send(request).await?;
        let status = response.status();
        if status != expected_status {
            return Err(self.problem_or_status(response).await);
        }
        let trace_id = response_trace(status, response.headers())?;
        if !exact_media_type(response.headers(), JSON_MEDIA_TYPE) {
            return Err(protocol(
                status,
                SchedulingProtocolFailure::MediaType,
                Some(trace_id),
            ));
        }
        let body = read_bounded(response, self.max_response_bytes)
            .await
            .map_err(|error| SchedulingClientError::Transport {
                kind: read_failure_kind(&error),
            })?;
        let value = serde_json::from_slice(&body).map_err(|_| {
            protocol(
                status,
                SchedulingProtocolFailure::Body,
                Some(trace_id.clone()),
            )
        })?;
        Ok(SchedulingComplete { value, trace_id })
    }

    async fn send_empty(
        &self,
        request: RequestBuilder,
        expected_status: StatusCode,
    ) -> Result<SchedulingComplete<()>, SchedulingClientError> {
        let response = self.send(request).await?;
        let status = response.status();
        if status != expected_status {
            return Err(self.problem_or_status(response).await);
        }
        let trace_id = response_trace(status, response.headers())?;
        let body =
            read_bounded(response, 1)
                .await
                .map_err(|error| SchedulingClientError::Transport {
                    kind: read_failure_kind(&error),
                })?;
        if !body.is_empty() {
            return Err(protocol(
                status,
                SchedulingProtocolFailure::Body,
                Some(trace_id),
            ));
        }
        Ok(SchedulingComplete {
            value: (),
            trace_id,
        })
    }

    async fn send(&self, request: RequestBuilder) -> Result<Response, SchedulingClientError> {
        let response = request
            .send()
            .await
            .map_err(|error| SchedulingClientError::Transport {
                kind: send_failure_kind(&error),
            })?;
        validate_response_headers(response.headers()).map_err(|_| {
            protocol(
                response.status(),
                SchedulingProtocolFailure::HeaderBounds,
                None,
            )
        })?;
        Ok(response)
    }

    async fn problem_or_status(&self, response: Response) -> SchedulingClientError {
        let status = response.status();
        let trace = response_trace(status, response.headers()).ok();
        if !exact_media_type(response.headers(), PROBLEM_MEDIA_TYPE) {
            return protocol(status, SchedulingProtocolFailure::Status, trace);
        }
        let body = match read_bounded(response, MAXIMUM_PROBLEM_BYTES).await {
            Ok(value) => value,
            Err(error) => {
                return SchedulingClientError::Transport {
                    kind: read_failure_kind(&error),
                }
            }
        };
        let document = match ProblemDocument::parse_exact(&body, MAXIMUM_PROBLEM_BYTES as usize) {
            Ok(value) => value,
            Err(_) => return protocol(status, SchedulingProtocolFailure::Problem, trace),
        };
        domain_problem(status, trace.as_deref(), &document)
    }
}

/// Decide between a typed domain problem and a protocol failure.
///
/// A domain problem requires every one of these to hold: the document's
/// status equals the response status, the code is in the closed vocabulary
/// and pins that same status, the response trace header matches the
/// document's trace identifier, and the type URI, title, and detail equal
/// the pinned definition. Any mismatch, and any code outside the closed
/// vocabulary (a platform-owned transport problem carrying a different type
/// base, for example), is the edge talking: a protocol failure, never a
/// domain problem.
pub(crate) fn domain_problem(
    status: StatusCode,
    header_trace: Option<&str>,
    document: &ProblemDocument,
) -> SchedulingClientError {
    let trace_id = header_trace.map(str::to_owned);
    let Some(code) = ProblemCode::from_code(&document.code) else {
        return protocol(status, SchedulingProtocolFailure::Problem, trace_id);
    };
    if document.status != status.as_u16()
        || code.http_status() != status.as_u16()
        || header_trace != Some(document.trace_id.as_str())
        || document.type_uri != type_uri(code.code())
        || document.title != code.title()
        || document.detail != code.detail()
    {
        return protocol(status, SchedulingProtocolFailure::Problem, trace_id);
    }
    SchedulingClientError::Problem {
        status: status.as_u16(),
        code,
        trace_id,
    }
}

fn response_trace(
    status: StatusCode,
    headers: &reqwest::header::HeaderMap,
) -> Result<String, SchedulingClientError> {
    response_trace_id(headers)
        .map(|value| value.as_str().to_owned())
        .map_err(|_| protocol(status, SchedulingProtocolFailure::TraceContext, None))
}

fn exact_media_type(headers: &reqwest::header::HeaderMap, expected: &str) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    matches!(
        (values.next(), values.next()),
        (Some(value), None) if value.as_bytes() == expected.as_bytes()
    )
}

fn protocol(
    status: StatusCode,
    failure: SchedulingProtocolFailure,
    trace_id: Option<String>,
) -> SchedulingClientError {
    SchedulingClientError::Protocol {
        status: status.as_u16(),
        failure,
        trace_id,
    }
}

fn cursor_query(cursor: Option<&str>) -> Vec<(&'static str, &str)> {
    cursor
        .map(|value| vec![(CURSOR_QUERY_PARAMETER, value)])
        .unwrap_or_default()
}

fn rfc3339(instant: DateTime<Utc>) -> String {
    instant.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

fn validate_idempotency_key(idempotency_key: &str) -> Result<(), SchedulingClientError> {
    if idempotency_key.is_empty()
        || idempotency_key.len() > MAXIMUM_IDEMPOTENCY_KEY_BYTES
        || !idempotency_key.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(SchedulingClientError::invalid_request(
            "the idempotency key is invalid",
        ));
    }
    Ok(())
}

fn validate_cursor(cursor: Option<&str>) -> Result<(), SchedulingClientError> {
    if cursor.is_some_and(|value| value.is_empty() || value.len() > MAXIMUM_CURSOR_BYTES) {
        return Err(SchedulingClientError::invalid_request(
            "the cursor is invalid",
        ));
    }
    Ok(())
}

/// A route identifier is an opaque string a minted document carried, so it is
/// validated as a whole before it becomes a path segment: anything that would
/// split into several segments, or leave the segment alphabet the runtime's
/// own identifiers live in, is a caller defect, never a silent detour to a
/// different route.
fn validate_identifier(
    identifier: &str,
    reason: &'static str,
) -> Result<(), SchedulingClientError> {
    if identifier.is_empty()
        || identifier.len() > MAXIMUM_IDENTIFIER_BYTES
        || !identifier
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(SchedulingClientError::invalid_request(reason));
    }
    Ok(())
}

fn validate_availability(
    offering: &str,
    start: Option<DateTime<Utc>>,
    end: Option<DateTime<Utc>>,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> Result<(), SchedulingClientError> {
    if offering.is_empty() {
        return Err(SchedulingClientError::invalid_request(
            "the offering selector is invalid",
        ));
    }
    validate_cursor(cursor)?;
    if limit.is_some_and(|value| value == 0) {
        return Err(SchedulingClientError::invalid_request(
            "the page size is outside the accepted range",
        ));
    }
    if let (Some(start), Some(end)) = (start, end) {
        if end <= start {
            return Err(SchedulingClientError::invalid_request(
                "the availability interval ends before it starts",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    #[test]
    fn idempotency_keys_are_bounded_before_io() {
        assert!(validate_idempotency_key("hold-7").is_ok());
        assert!(validate_idempotency_key(&"x".repeat(MAXIMUM_IDEMPOTENCY_KEY_BYTES)).is_ok());
        assert!(validate_idempotency_key("").is_err());
        assert!(validate_idempotency_key(&"x".repeat(MAXIMUM_IDEMPOTENCY_KEY_BYTES + 1)).is_err());
        assert!(validate_idempotency_key("line\nbreak").is_err());
    }

    #[test]
    fn cursors_are_bounded_before_io() {
        assert!(validate_cursor(None).is_ok());
        assert!(validate_cursor(Some("opaque-cursor")).is_ok());
        assert!(validate_cursor(Some("")).is_err());
        assert!(validate_cursor(Some(&"x".repeat(MAXIMUM_CURSOR_BYTES + 1))).is_err());
    }

    #[test]
    fn route_identifiers_stay_one_path_segment() {
        let reason = "the appointment identifier is invalid";
        let uuid = "0199d0e0-8f2a-7c3b-9d4e-5f6a7b8c9d0e";
        assert!(validate_identifier(uuid, reason).is_ok());
        assert!(validate_identifier("appt-1", reason).is_ok());
        assert!(validate_identifier("claim_appt.1", reason).is_ok());
        for foreign in [
            "",
            "appt/1",
            "appt?x",
            "appt#y",
            "appt%2F1",
            "space id",
            "../appt",
            &"x".repeat(MAXIMUM_IDENTIFIER_BYTES + 1),
        ] {
            assert!(
                validate_identifier(foreign, reason).is_err(),
                "{foreign:?} must be refused"
            );
        }
    }

    #[test]
    fn availability_selectors_are_validated_before_io() {
        let start = Utc.with_ymd_and_hms(2026, 10, 5, 2, 0, 0).unwrap();
        let end = Utc.with_ymd_and_hms(2026, 10, 5, 2, 30, 0).unwrap();
        assert!(validate_availability(
            "registry-update-30",
            Some(start),
            Some(end),
            None,
            Some(25)
        )
        .is_ok());
        assert!(validate_availability("", None, None, None, None).is_err());
        assert!(validate_availability("registry-update-30", None, None, Some(""), None).is_err());
        assert!(validate_availability("registry-update-30", None, None, None, Some(0)).is_err());
        assert!(
            validate_availability("registry-update-30", Some(end), Some(start), None, None)
                .is_err()
        );
    }

    /// Times render exactly as the runtime answers them: UTC instants with
    /// no sub-second part carry the `Z` designator, and a sub-second part
    /// keeps its precision instead of being truncated.
    #[test]
    fn query_instants_render_as_whole_second_rfc3339() {
        let whole = Utc.with_ymd_and_hms(2026, 10, 5, 2, 0, 0).unwrap();
        assert_eq!(rfc3339(whole), "2026-10-05T02:00:00Z");
        let precise = Utc.with_ymd_and_hms(2026, 10, 5, 2, 0, 0).unwrap()
            + chrono::Duration::milliseconds(250);
        assert_eq!(rfc3339(precise), "2026-10-05T02:00:00.250Z");
    }
}
