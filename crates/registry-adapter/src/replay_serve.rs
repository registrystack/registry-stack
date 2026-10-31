// SPDX-License-Identifier: Apache-2.0

//! The replay runner: serving a recorded exchange through the facade's
//! own request path, the way the fixture suites replay a pack against
//! its recorded sends (`products/adapter/CONCEPT.md` section 14). This
//! is the facade half of replay: it reads the transcript the engine's
//! write capability recorded (`engine::replay`) and answers through
//! the facade's request machinery, so it names facade modules and
//! carries no engine boundary claim.

use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use registry_adapter_core::{
    AdapterFixture, AdapterPack, AdapterProfile, AdapterProject, ErrorClass, HttpMethod,
    RecordedHeaders,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::engine::component::rest::continuation::{
    filter_digest, ContinuationCodec, CursorBinding, CursorKey, CursorTtl,
};
use crate::engine::replay::{
    ReplayCursorNonce, ReplayFailure, ReplayTranscript, ReplayWriteCapability, ReplayWriteContext,
    REPLAY_CURSOR_CLOCK_SECONDS, REPLAY_CURSOR_ISSUER, REPLAY_CURSOR_KEY_BYTE,
    REPLAY_CURSOR_SUBJECT, REPLAY_DEPLOYMENT,
};

use crate::engine::exchange::{
    Exchange, CONTINUATION_PROPERTY, FILTERS_PROPERTY, NEXT_CONTINUATION_PROPERTY, PAGE_SIZE_HEADER,
};
use crate::engine::load::{compile_authored_with, EndpointCompilation, LoadError};
use crate::engine::route::{run_route_with_profile, RouteContext, RouteFailure};

/// The rendered facade result of one actual offline route execution.
#[derive(Debug, PartialEq)]
pub struct ReplayFacade {
    pub status: u16,
    pub headers: RecordedHeaders,
    pub body: Option<Value>,
    pub problem_class: Option<ErrorClass>,
    pub problem_code: Option<String>,
    /// Replay exercises the idempotent-consumer control path in memory. It
    /// never claims PostgreSQL durability or exact-response custody.
    pub write_durability: ReplayDurability,
}

/// What fixture replay proves about write durability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplayDurability {
    NotApplicable,
    Simulated,
}

/// Why the runtime could not execute and render one fixture entry.
#[derive(Debug)]
pub enum ReplayRunFailure {
    Transcript(ReplayFailure),
    Load(LoadError),
    Unserved {
        reason_code: &'static str,
        reason: String,
    },
    Operation,
    Request,
    Route(RouteFailure),
    Render,
    WriteCapability,
}

impl fmt::Display for ReplayRunFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Transcript(fault) => return fault.fmt(formatter),
            Self::Load(_) => "the authored runtime state could not compile",
            Self::Unserved {
                reason_code,
                reason,
            } => return write!(formatter, "{reason_code}: {reason}"),
            Self::Operation => "the fixture operation is not served by the authored runtime",
            Self::Request => "the recorded facade request is not valid for its operation",
            Self::Route(_) => "the route failed before its facade result could be rendered",
            Self::Render => "the facade envelope could not be rendered",
            Self::WriteCapability => "the replay write capability was not exercised as declared",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for ReplayRunFailure {}

impl From<ReplayFailure> for ReplayRunFailure {
    fn from(failure: ReplayFailure) -> Self {
        Self::Transcript(failure)
    }
}

impl From<LoadError> for ReplayRunFailure {
    fn from(failure: LoadError) -> Self {
        Self::Load(failure)
    }
}

/// Execute one fixture entry through the actual route interpreter and render
/// its facade response. This API constructs no live destination policy, TLS
/// client, runtime credential, database, listener, or journal.
pub async fn run(
    project: &AdapterProject,
    profile: &AdapterProfile,
    pack: &AdapterPack,
    pack_directory: &Path,
    fixture: &AdapterFixture,
    entry_index: usize,
) -> Result<ReplayFacade, ReplayRunFailure> {
    let entry = fixture
        .entries
        .get(entry_index)
        .ok_or(ReplayFailure::EntryMissing)?;
    let transcript = Arc::new(ReplayTranscript::new(fixture, entry_index)?);
    let authored = compile_authored_with(
        project,
        profile,
        pack,
        pack_directory,
        REPLAY_DEPLOYMENT,
        true,
        |endpoint| {
            if !transcript.records_endpoint(endpoint.id.as_str()) {
                return Ok(EndpointCompilation::Absent);
            }
            crate::engine::egress::EndpointEgress::compile_replay(endpoint, Arc::clone(&transcript))
                .map(|egress| EndpointCompilation::Served(Box::new(egress)))
                .map_err(|fault| LoadError::Runtime(fault.to_string()))
        },
    )?;
    let operation = authored
        .served
        .iter()
        .find(|operation| operation.operation == entry.facade_request.operation.as_str())
        .ok_or_else(|| {
            project
                .bindings
                .iter()
                .find(|binding| {
                    binding.operation.as_str() == entry.facade_request.operation.as_str()
                })
                .and_then(|binding| {
                    authored
                        .unserved
                        .iter()
                        .find(|unserved| unserved.binding == binding.id.as_str())
                })
                .map_or(ReplayRunFailure::Operation, |unserved| {
                    ReplayRunFailure::Unserved {
                        reason_code: unserved.reason_code,
                        reason: unserved.reason.clone(),
                    }
                })
        })?;
    let parameters = path_parameters(&operation.method_path, &entry.facade_request.path)
        .ok_or(ReplayRunFailure::Request)?;
    let record_type = parameters
        .get(&operation.record_type_parameter)
        .cloned()
        .ok_or(ReplayRunFailure::Request)?;
    if record_type != operation.record_type {
        return Err(ReplayRunFailure::Request);
    }
    let mut record_id = operation
        .record_id_parameter
        .as_ref()
        .and_then(|name| parameters.get(name))
        .cloned()
        .unwrap_or_default();
    let declared = profile
        .operations
        .get(operation.operation.as_str())
        .ok_or(ReplayRunFailure::Operation)?;
    let is_write = !declared.is_read();
    let mut filters = serde_json::Map::new();
    let mut page_size = None;
    let mut request_cursor = None;
    let mut write_record = None;
    if matches!(operation.method, HttpMethod::Post | HttpMethod::Put) {
        let body = entry
            .facade_request
            .body
            .as_ref()
            .map(|body| body.as_value())
            .ok_or(ReplayRunFailure::Request)?;
        if is_write {
            let template = declared
                .request_envelope
                .as_ref()
                .ok_or(ReplayRunFailure::Request)?;
            let captured = crate::facade::capture_write_record(template.text(), body)
                .map_err(|_| ReplayRunFailure::Request)?;
            crate::facade::validate_write_record(operation, &captured, &record_id)
                .map_err(|_| ReplayRunFailure::Request)?;
            if let Some(id) = captured.record_id {
                record_id = id;
            }
            write_record = Some(captured.record);
        } else {
            let captured = operation
                .request_template
                .as_ref()
                .ok_or(ReplayRunFailure::Request)?
                .capture(body, &operation.filters)
                .map_err(|_| ReplayRunFailure::Request)?;
            if let Some(id) = captured.record_id {
                record_id = id;
            }
            filters = captured.filters.unwrap_or_default();
            page_size = captured.page_size;
            request_cursor = captured.cursor;
        }
    } else {
        let inputs = crate::facade::query_inputs(operation, entry.facade_request.query.as_deref())
            .map_err(|_| ReplayRunFailure::Request)?;
        request_cursor = inputs.cursor;
        page_size = inputs.page_size;
        filters = inputs.filters;
    }

    if !is_write {
        crate::facade::require_declared_filters(
            operation,
            &crate::facade::RequestInputs {
                cursor: request_cursor.clone(),
                page_size,
                filters: filters.clone(),
            },
        )
        .map_err(|_| ReplayRunFailure::Request)?;
    }

    let cursor_filters = if let Some(pagination) = &operation.pagination {
        let digest = filter_digest(
            &serde_json::json!({"recordType": record_type, "filters": filters}),
            0,
        )
        .map_err(|_| ReplayRunFailure::Request)?;
        let carried = if let Some(cursor) = request_cursor.as_deref() {
            let opened = replay_cursor_codec()?
                .open(
                    cursor,
                    &replay_cursor_binding(operation, digest),
                    replay_cursor_time(),
                )
                .map_err(|_| ReplayRunFailure::Request)?;
            let (carried_size, continuation) =
                crate::facade::unwrap_continuation(opened).ok_or(ReplayRunFailure::Request)?;
            Some((carried_size, continuation))
        } else {
            None
        };
        let carried_size = carried.as_ref().map(|(size, _)| *size);
        page_size = Some(resolve_page_size(pagination, page_size, carried_size)?);
        Some((digest, carried.map(|(_, continuation)| continuation)))
    } else {
        None
    };

    let mut exchange = Exchange::new("fixture-replay-request".to_owned());
    if let Some(record) = write_record {
        exchange.message.body = record;
    }
    if !filters.is_empty() {
        exchange.set_property(FILTERS_PROPERTY, Value::Object(filters));
    }
    if let Some(continuation) = cursor_filters
        .as_ref()
        .and_then(|(_, continuation)| continuation.clone())
    {
        exchange.set_property(CONTINUATION_PROPERTY, continuation);
    }
    if let Some(size) = page_size {
        exchange
            .message
            .set_header(PAGE_SIZE_HEADER, serde_json::json!(size));
    }
    exchange
        .message
        .set_header("recordType", Value::String(record_type.clone()));
    exchange
        .message
        .set_header("recordId", Value::String(record_id));

    let replay_write = if is_write {
        let key = entry
            .facade_request
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("idempotency-key"))
            .map(|(_, value)| value.as_str())
            .ok_or(ReplayRunFailure::Request)?;
        exchange
            .message
            .set_header("Idempotency-Key", Value::String(key.to_owned()));
        let write = ReplayWriteContext::new(ReplayWriteCapability(()));
        exchange
            .install_replay_write(write.clone())
            .map_err(|_| ReplayRunFailure::WriteCapability)?;
        Some(write)
    } else {
        None
    };
    let resolver = SecretResolver::new(
        [SecretProvider::File],
        "/registry-adapter-fixture-replay-no-secrets",
    )
    .map_err(|_| ReplayRunFailure::Request)?;
    let context = RouteContext {
        endpoints: &authored.endpoints,
        scripts: &authored.scripts,
        resolver: &resolver,
        resilience: &operation.resilience,
        routes: &authored.routes,
        code_maps: Arc::clone(&authored.code_maps),
        maximum_upstream_calls: operation.maximum_upstream_calls,
        job: crate::engine::job_sources::JobPageState::default(),
    };
    let outcome = run_route_with_profile(&context, profile, &operation.steps, exchange).await;
    transcript.finish()?;
    let durability = if is_write {
        ReplayDurability::Simulated
    } else {
        ReplayDurability::NotApplicable
    };
    if let Some(write) = &replay_write {
        if !write.was_claimed().await {
            return Err(ReplayRunFailure::WriteCapability);
        }
        if write.is_unsupported_incomplete().await {
            let class = ErrorClass::FacadeConflict;
            let problem = registry_adapter_core::resolve_problem(profile, class)
                .ok_or(ReplayRunFailure::Render)?;
            return facade_result(
                crate::facade::facade_problem(
                    crate::facade::Problems {
                        profile,
                        envelope: &authored.problem_envelope,
                    },
                    class,
                    StatusCode::CONFLICT,
                    &record_type,
                    "fixture-replay-request",
                ),
                Some(class),
                Some(problem.code.as_str().to_owned()),
                durability,
            )
            .await;
        }
    }
    match outcome.result {
        Ok(done) => {
            let next_cursor = match (cursor_filters, page_size) {
                (Some((filters, _)), Some(page_size)) => {
                    let wrapped = done
                        .property(NEXT_CONTINUATION_PROPERTY)
                        .filter(|value| !value.is_null())
                        .map(|continuation| {
                            crate::facade::wrap_continuation(continuation, page_size)
                        });
                    replay_cursor_codec()?
                        .seal_replay(
                            replay_cursor_nonce(fixture, entry_index),
                            wrapped.as_ref(),
                            &replay_cursor_binding(operation, filters),
                            replay_cursor_time(),
                        )
                        .map_err(|_| ReplayRunFailure::Render)?
                }
                _ => None,
            };
            let slots = match crate::facade::disclosed_slots(
                operation,
                &done.message.body,
                page_size,
                &record_type,
                "fixture-replay-request",
            ) {
                Ok(slots) => slots,
                Err(_) => {
                    return replay_problem(
                        profile,
                        &authored.problem_envelope,
                        RouteFailure::of(ErrorClass::DisclosureViolation),
                        &record_type,
                        durability,
                    )
                    .await;
                }
            };
            let body = crate::facade::render_success(
                operation,
                slots,
                next_cursor,
                &record_type,
                "fixture-replay-request",
            )
            .map_err(|_| ReplayRunFailure::Render)?;
            let status = profile
                .operations
                .get(operation.operation.as_str())
                .and_then(|operation| u16::try_from(operation.success_status.get()).ok())
                .and_then(|status| StatusCode::from_u16(status).ok())
                .ok_or(ReplayRunFailure::Render)?;
            facade_result(
                crate::facade::json_response(status, &body),
                None,
                None,
                durability,
            )
            .await
        }
        Err(failure) => {
            replay_problem(
                profile,
                &authored.problem_envelope,
                failure,
                &record_type,
                durability,
            )
            .await
        }
    }
}

async fn replay_problem(
    profile: &AdapterProfile,
    envelope: &crate::engine::envelope::CompiledEnvelope,
    failure: RouteFailure,
    record_type: &str,
    durability: ReplayDurability,
) -> Result<ReplayFacade, ReplayRunFailure> {
    let failure = crate::facade::enforce_problem_data(profile, failure);
    let problem = registry_adapter_core::resolve_problem(profile, failure.class)
        .ok_or(ReplayRunFailure::Render)?;
    facade_result(
        crate::facade::route_problem(
            crate::facade::Problems { profile, envelope },
            &failure,
            record_type,
            "fixture-replay-request",
        ),
        Some(failure.class),
        Some(problem.code.as_str().to_owned()),
        durability,
    )
    .await
}

fn resolve_page_size(
    pagination: &crate::engine::load::ServedPagination,
    supplied: Option<u64>,
    carried: Option<u64>,
) -> Result<u64, ReplayRunFailure> {
    if supplied.is_some_and(|size| {
        !(pagination.page_size_minimum..=pagination.page_size_maximum).contains(&size)
    }) {
        return Err(ReplayRunFailure::Request);
    }
    match (supplied, carried) {
        (Some(supplied), Some(carried)) if supplied != carried => Err(ReplayRunFailure::Request),
        (Some(size), _) | (None, Some(size)) => Ok(size),
        (None, None) => pagination
            .page_size_default
            .ok_or(ReplayRunFailure::Request),
    }
}

fn replay_cursor_codec() -> Result<ContinuationCodec, ReplayRunFailure> {
    let key = CursorKey::new(Zeroizing::new(vec![
        REPLAY_CURSOR_KEY_BYTE;
        crate::engine::component::rest::continuation::CURSOR_KEY_BYTES
    ]))
    .map_err(|_| ReplayRunFailure::Render)?;
    Ok(ContinuationCodec::new(key, None, CursorTtl::default()))
}

fn replay_cursor_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(REPLAY_CURSOR_CLOCK_SECONDS)
}

fn replay_cursor_binding<'a>(
    operation: &'a crate::engine::load::ServedOperation,
    filters: crate::engine::component::rest::continuation::FilterDigest,
) -> CursorBinding<'a> {
    CursorBinding {
        operation: &operation.operation,
        binding_id: &operation.binding,
        issuer: REPLAY_CURSOR_ISSUER,
        subject: REPLAY_CURSOR_SUBJECT,
        deployment: REPLAY_DEPLOYMENT,
        filters,
    }
}

fn replay_cursor_nonce(fixture: &AdapterFixture, entry_index: usize) -> ReplayCursorNonce {
    replay_cursor_nonce_for(fixture.id.as_str(), entry_index)
}

fn replay_cursor_nonce_for(fixture_id: &str, entry_index: usize) -> ReplayCursorNonce {
    let mut digest = Sha256::new();
    digest.update(b"registry-adapter/fixture-replay/cursor-nonce/v1");
    digest.update(fixture_id.as_bytes());
    digest.update((entry_index as u64).to_be_bytes());
    let digest = digest.finalize();
    let mut nonce = [0_u8; 24];
    nonce.copy_from_slice(&digest[..24]);
    ReplayCursorNonce(nonce)
}

fn path_parameters(template: &str, path: &str) -> Option<BTreeMap<String, String>> {
    let template: Vec<_> = template.trim_matches('/').split('/').collect();
    let path: Vec<_> = path.trim_matches('/').split('/').collect();
    if template.len() != path.len() {
        return None;
    }
    let mut parameters = BTreeMap::new();
    for (expected, actual) in template.into_iter().zip(path) {
        if let Some(name) = expected
            .strip_prefix('{')
            .and_then(|name| name.strip_suffix('}'))
        {
            let actual = decode_path_parameter(actual)?;
            if actual.is_empty() || parameters.insert(name.to_owned(), actual).is_some() {
                return None;
            }
        } else if expected != actual {
            return None;
        }
    }
    Some(parameters)
}

fn decode_path_parameter(segment: &str) -> Option<String> {
    let bytes = segment.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let high = hex_digit(bytes.get(index + 1).copied()?)?;
        let low = hex_digit(bytes.get(index + 2).copied()?)?;
        decoded.push((high << 4) | low);
        index += 3;
    }
    String::from_utf8(decoded).ok()
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

async fn facade_result(
    response: axum::response::Response,
    problem_class: Option<ErrorClass>,
    problem_code: Option<String>,
    write_durability: ReplayDurability,
) -> Result<ReplayFacade, ReplayRunFailure> {
    let (parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, registry_adapter_core::MAXIMUM_RESPONSE_BYTES as usize)
        .await
        .map_err(|_| ReplayRunFailure::Render)?;
    let body = if bytes.is_empty() {
        None
    } else {
        Some(serde_json::from_slice(&bytes).map_err(|_| ReplayRunFailure::Render)?)
    };
    let mut headers = RecordedHeaders::new();
    for (name, value) in &parts.headers {
        let value = value.to_str().map_err(|_| ReplayRunFailure::Render)?;
        if headers
            .insert(name.as_str().to_owned(), value.to_owned())
            .is_some()
        {
            return Err(ReplayRunFailure::Render);
        }
    }
    Ok(ReplayFacade {
        status: parts.status.as_u16(),
        headers,
        body,
        problem_class,
        problem_code,
        write_durability,
    })
}

#[cfg(test)]
mod tests {
    use registry_adapter_core::ReplayMismatch;
    use registry_adapter_core::{HttpMethod, RecordedBody};

    use super::*;

    fn fixture(upstream: serde_json::Value) -> AdapterFixture {
        serde_json::from_value(serde_json::json!({
            "id": "fixture",
            "pack": "pack",
            "upstreamVersion": "1",
            "provenance": {"type": "documented", "reference": "test"},
            "intercepts": [
                {"type": "endpoint", "endpoint": "api"},
                {"type": "token-endpoint", "endpoint": "api"}
            ],
            "entries": [{
                "facadeRequest": {
                    "operation": "read",
                    "path": "/records"
                },
                "upstream": upstream,
                "expected": {"type": "response", "status": 200}
            }]
        }))
        .expect("fixture")
    }

    fn data_exchange(path: &str) -> serde_json::Value {
        serde_json::json!({
            "request": {
                "endpoint": "api",
                "method": "GET",
                "path": path,
                "query": "page=1",
                "headers": {"accept": "application/json", "x-trace": "fixture"}
            },
            "response": {"status": 200, "body": {"records": []}}
        })
    }

    #[test]
    fn matches_the_complete_ordered_data_send_and_finishes() {
        let fixture = fixture(serde_json::json!([data_exchange("/v1/records")]));
        let transcript = ReplayTranscript::new(&fixture, 0).expect("transcript");

        let response = transcript
            .answer_data(
                "api",
                HttpMethod::Get,
                "/v1/records",
                Some("page=1"),
                None,
                &[("Accept", "application/json"), ("X-Trace", "fixture")],
            )
            .expect("answer");

        assert_eq!(response.status.get(), 200);
        assert_eq!(
            response.body.as_ref().map(RecordedBody::as_value),
            Some(&serde_json::json!({"records": []}))
        );
        assert_eq!(transcript.finish(), Ok(()));
    }

    #[test]
    fn refuses_header_reordering_even_when_members_match() {
        let fixture = fixture(serde_json::json!([data_exchange("/v1/records")]));
        let transcript = ReplayTranscript::new(&fixture, 0).expect("transcript");

        let failure = transcript
            .answer_data(
                "api",
                HttpMethod::Get,
                "/v1/records",
                Some("page=1"),
                None,
                &[("x-trace", "fixture"), ("accept", "application/json")],
            )
            .expect_err("header order must match");

        assert_eq!(failure, ReplayFailure::HeaderOrder);
        assert_eq!(transcript.finish(), Err(ReplayFailure::HeaderOrder));
    }

    #[test]
    fn token_send_matches_without_a_secret_header_or_body() {
        let fixture = fixture(serde_json::json!([{
            "request": {
                "endpoint": "api",
                "tokenRequest": true,
                "method": "POST",
                "path": "/oauth/token"
            },
            "response": {
                "status": 200,
                "body": {"access_token": "synthetic-fixture-token"}
            }
        }]));
        let transcript = ReplayTranscript::new(&fixture, 0).expect("transcript");

        let response = transcript
            .answer_token("api", HttpMethod::Post, "/oauth/token")
            .expect("token answer");

        assert_eq!(
            response.body.as_ref().map(RecordedBody::as_value),
            Some(&serde_json::json!({"access_token": "synthetic-fixture-token"}))
        );
        assert_eq!(transcript.finish(), Ok(()));
    }

    #[test]
    fn fails_visibly_for_excess_and_leftover_sends() {
        let fixture = fixture(serde_json::json!([
            data_exchange("/one"),
            data_exchange("/two")
        ]));
        let transcript = ReplayTranscript::new(&fixture, 0).expect("transcript");
        transcript
            .answer_data(
                "api",
                HttpMethod::Get,
                "/one",
                Some("page=1"),
                None,
                &[("accept", "application/json"), ("x-trace", "fixture")],
            )
            .expect("first answer");
        assert_eq!(transcript.finish(), Err(ReplayFailure::Leftover));

        transcript
            .answer_data(
                "api",
                HttpMethod::Get,
                "/two",
                Some("page=1"),
                None,
                &[("accept", "application/json"), ("x-trace", "fixture")],
            )
            .expect("second answer");
        assert_eq!(transcript.finish(), Ok(()));
        assert_eq!(
            transcript.answer_data("api", HttpMethod::Get, "/three", None, None, &[]),
            Err(ReplayFailure::Send(ReplayMismatch::Exhausted))
        );
    }

    #[test]
    fn an_unserved_operation_names_its_stable_reason() {
        let failure = ReplayRunFailure::Unserved {
            reason_code: "adapter.operation.route-unsupported",
            reason: "the route uses an unsupported shape".to_owned(),
        };
        assert_eq!(
            failure.to_string(),
            "adapter.operation.route-unsupported: the route uses an unsupported shape"
        );
    }

    #[test]
    fn replay_uses_the_facade_page_default_and_bounds() {
        let pagination = crate::engine::load::ServedPagination {
            cursor_parameter: "cursor".to_owned(),
            page_size_parameter: "pageSize".to_owned(),
            page_size_minimum: 1,
            page_size_maximum: 100,
            page_size_default: Some(20),
        };
        assert_eq!(resolve_page_size(&pagination, None, None).unwrap(), 20);
        assert_eq!(resolve_page_size(&pagination, Some(5), None).unwrap(), 5);
        assert_eq!(resolve_page_size(&pagination, None, Some(5)).unwrap(), 5);
        assert!(matches!(
            resolve_page_size(&pagination, Some(101), None),
            Err(ReplayRunFailure::Request)
        ));
    }

    #[test]
    fn replay_decodes_facade_path_parameters_like_the_http_router() {
        let parameters = path_parameters(
            "/v1/records/{type}/{recordId}",
            "/v1/records/person/not%20an%20id",
        )
        .expect("the path matches");
        assert_eq!(parameters["recordId"], "not an id");
    }

    #[test]
    fn replay_nonce_seals_stable_bytes_that_the_production_codec_opens() {
        let codec = ContinuationCodec::new(
            CursorKey::new(Zeroizing::new(vec![0x52; 32])).expect("the fixed key is valid"),
            None,
            CursorTtl::default(),
        );
        let filters = filter_digest(&serde_json::json!({"recordType":"person","filters":{}}), 0)
            .expect("the fixed filters are canonical");
        let binding = CursorBinding {
            operation: "records-search",
            binding_id: "search-person",
            issuer: "https://fixture-replay.invalid",
            subject: "synthetic-fixture-caller",
            deployment: "fixture-replay-v1",
            filters,
        };
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let wrapped = serde_json::json!({"c": 2, "s": 5});
        let token = codec
            .seal_replay(ReplayCursorNonce([0xA5; 24]), Some(&wrapped), &binding, now)
            .expect("replay sealing succeeds")
            .expect("a continuation produces a token");
        assert_eq!(
            token,
            "AaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpcuXcsXmdcdWb2JVdLvZyzRGLUO0Vm6bQvkUiwrZPocm-Vj2rDA"
        );
        assert_eq!(
            codec
                .open(&token, &binding, now)
                .expect("the actual codec opens it"),
            wrapped
        );
    }

    #[test]
    fn maintained_page_cursor_goldens_are_exact_wire_bytes() {
        let token = |fixture_id: &str,
                     operation: &str,
                     binding_id: &str,
                     record_type: &str,
                     page_size: u64| {
            let filters = filter_digest(
                &serde_json::json!({"recordType":record_type,"filters":{}}),
                0,
            )
            .expect("the maintained inputs are canonical");
            let binding = CursorBinding {
                operation,
                binding_id,
                issuer: REPLAY_CURSOR_ISSUER,
                subject: REPLAY_CURSOR_SUBJECT,
                deployment: REPLAY_DEPLOYMENT,
                filters,
            };
            let wrapped = crate::facade::wrap_continuation(&serde_json::json!(2), page_size);
            replay_cursor_codec()
                .expect("the replay codec builds")
                .seal_replay(
                    replay_cursor_nonce_for(fixture_id, 0),
                    Some(&wrapped),
                    &binding,
                    replay_cursor_time(),
                )
                .expect("the golden seals")
                .expect("the continuation produces a cursor")
        };
        let actual = [
            token(
                "dhis2-tracker-search-page",
                "records-search",
                "person-search",
                "person",
                5,
            ),
            token(
                "dhis2-govstack-list-page",
                "records-list",
                "person-list",
                "persons",
                5,
            ),
            token(
                "opencrvs-events-search-page",
                "records-search",
                "birth-search",
                "birth",
                2,
            ),
            {
                let filters = filter_digest(
                    &serde_json::json!({
                        "recordType": "benefit_case",
                        "filters": {"status": "open"}
                    }),
                    0,
                )
                .expect("the GraphQL inputs are canonical");
                let binding = CursorBinding {
                    operation: "cases-find",
                    binding_id: "benefit-case-find",
                    issuer: REPLAY_CURSOR_ISSUER,
                    subject: REPLAY_CURSOR_SUBJECT,
                    deployment: REPLAY_DEPLOYMENT,
                    filters,
                };
                let wrapped =
                    crate::facade::wrap_continuation(&serde_json::json!("Y3Vyc29yOjUw"), 50);
                replay_cursor_codec()
                    .expect("the replay codec builds")
                    .seal_replay(
                        replay_cursor_nonce_for("graphql-cases-find-first-page", 0),
                        Some(&wrapped),
                        &binding,
                        replay_cursor_time(),
                    )
                    .expect("the GraphQL golden seals")
                    .expect("the continuation produces a cursor")
            },
        ];
        assert_eq!(
            actual,
            [
                "AZ-QW0He7xnlzHwsY_MoY3HaOSJkEzSnOof3k1fkUIdttZLapuyZGtNI5kAyIbnII4JOiV4s8Vy3tCHfbuY",
                "AR-iZNpifiCYGwbA8XWnBD1HATcvY6QeFMv0_bOd6shPCQFv50lXtHVRfDJUS5U-4TkNEh04LeFioTgVJLo",
                "AaW8rI1CvWK9y53Ni6oLOJeDjcl5fBVpQyicqzLMqPodcjKcJsY6mPbB0--gjsJEkxENyrX6bQqqqmFk1ag",
                "AQGTVIRecXOAHQpErfOzhEknm-j2T4eSa5osZDxhcPxbjL4ZWsi_fwuEmekmwe3pJzk7HzaQ5NkeOQEeGBtmPJ2tSNzFv1vbYu21rA",
            ]
        );
    }
}
