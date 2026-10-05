// SPDX-License-Identifier: Apache-2.0
//! Governed, disclosure-controlled count datasets over the ordinary read policy.

use super::*;
use crate::audit::{
    begin_statistics_pre_io_audit, record_http_refusal_audit, statistics_terminal_entry,
    HttpRefusalAudit, PreIoAudit, PreIoAuditKind, ReadTerminalAudit, RefusalHttpMethod,
    StatisticsTerminalAudit, TerminalAudit, TerminalAuditOutcome,
};
use crate::correlation::{statistics_problem, RequestDeadline};
use crate::cursor::{
    CursorBinding, CursorContinuation, CursorError, CursorQuery, CursorQueryScope,
};
use crate::model::{CompiledStatisticalDataset, HttpMethod};
use crate::postgres::{
    StatisticsLiveRequest, StatisticsPublishRequest, StatisticsReleaseListCursor,
    StatisticsReleaseListRequest, StatisticsReleaseRefusal, StatisticsReleaseSelection,
    StatisticsSeriesRequest, StatisticsServiceError, StatisticsVersionReadRequest,
    StatisticsWithdrawalRequest,
};
use crate::problem::ProblemCode;
use crate::statistics::{
    canonical_document, document_csv, ReleaseStatus, StatisticsDocument, WithdrawalReason,
};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::time::Duration;

// Keep database work inside the outer HTTP budget while leaving time to
// construct and enqueue its terminal audit response.
const STATISTICS_TERMINAL_AUDIT_RESERVE: Duration = Duration::from_millis(500);

fn statistics_work_deadline(
    now: tokio::time::Instant,
    outer: tokio::time::Instant,
) -> tokio::time::Instant {
    outer
        .checked_sub(STATISTICS_TERMINAL_AUDIT_RESERVE)
        .unwrap_or(now)
        .max(now)
        .min(outer)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Kind {
    Live,
    List,
    Series,
    Latest,
    Version,
    Publish,
    Withdraw,
}
impl Kind {
    fn name(self) -> &'static str {
        match self {
            Self::Live => "read_live",
            Self::List => "list_releases",
            Self::Series => "read_released_series",
            Self::Latest => "read_latest_release",
            Self::Version => "read_release_version",
            Self::Publish => "publish_release",
            Self::Withdraw => "withdraw_release",
        }
    }
    fn method(self) -> HttpMethod {
        if matches!(self, Self::Publish | Self::Withdraw) {
            HttpMethod::Post
        } else {
            HttpMethod::Get
        }
    }
}
#[derive(Clone)]
struct Route {
    dataset: String,
    kind: Kind,
}
impl Route {
    fn id(&self) -> String {
        format!("statistics.{}.{}", self.dataset, self.kind.name())
    }
}

pub(super) fn routes(service: &HttpService) -> Router<Arc<HttpService>> {
    let mut app = Router::new();
    for dataset in service.registry.statistical_datasets().values() {
        let root = format!("/v1/statistics/{}", dataset.id);
        if !dataset.live_profiles.is_empty() {
            app = app.route(
                &format!("{root}:live"),
                get(dispatch).layer(Extension(Route {
                    dataset: dataset.id.clone(),
                    kind: Kind::Live,
                })),
            );
        }
        if dataset.releases.is_some() {
            for (suffix, kind) in [
                ("/releases", Kind::List),
                ("/releases:series", Kind::Series),
                ("/releases/{period}", Kind::Latest),
                ("/releases/{period}/versions/{version}", Kind::Version),
                ("/releases/{period}/versions", Kind::Publish),
                (
                    "/releases/{period}/versions/{version}/withdrawal",
                    Kind::Withdraw,
                ),
            ] {
                let method = if kind.method() == HttpMethod::Post {
                    post(dispatch)
                } else {
                    get(dispatch)
                };
                app = app.route(
                    &format!("{root}{suffix}"),
                    method.layer(Extension(Route {
                        dataset: dataset.id.clone(),
                        kind,
                    })),
                );
            }
        }
    }
    app
}

/// Authorize one explicit profile, preserving ordinary list context for source reads.
fn authorize(
    service: &HttpService,
    dataset: &CompiledStatisticalDataset,
    kind: Kind,
    claims: &VerifiedRequestClaims,
    selected: Option<&str>,
) -> Option<AuthorizedRequestContext> {
    claims.principal()?;
    let eligible = |id: &str| match kind {
        Kind::Live => dataset.live_profiles.contains(id),
        Kind::Publish | Kind::Withdraw => {
            dataset.releases.as_ref().is_some_and(|r| r.publisher == id)
        }
        _ => dataset.releases.as_ref().is_some_and(|r| {
            r.publisher == id || r.readers.contains(id) || dataset.live_profiles.contains(id)
        }),
    };
    let configured_default = dataset
        .access_profiles
        .iter()
        .find(|(id, profile)| eligible(id) && profile.default)
        .map(|(id, _)| id.as_str());
    let mut profiles = dataset.access_profiles.keys().filter(|id| eligible(id));
    let only = profiles.next();
    let default = only.filter(|_| profiles.next().is_none());
    let selected = selected
        .or(configured_default)
        .or_else(|| default.map(String::as_str))?;
    if !eligible(selected) {
        return None;
    }
    if matches!(kind, Kind::Live | Kind::Publish | Kind::Withdraw) {
        let route = service.registry.routes().routes.iter().find(|route| {
            route.entity_id == dataset.unit_entity_id
                && route.operation == Operation::List
                && read_path_for_route(service, route).is_none()
        })?;
        let mut options = QueryOptions::default();
        options.parsed.access_profile = Some(selected.to_owned());
        return Some(authorize_route(service, route, claims, &options)?.context);
    }
    let profile = dataset.access_profiles.get(selected)?;
    let boundaries = authorize_profile_claims(profile, claims).ok()?;
    Some(
        AuthorizedRequestContext::new(
            claims.principal().map(str::to_owned),
            claims.purpose().map(str::to_owned),
            selected.to_owned(),
            boundaries,
        )
        .with_task_grant(task_grant_binding(profile, claims).ok()?)
        .with_grant_audit(claims)
        .with_recipients(claims),
    )
}

/// Extract only the selector needed for admission. Full validation follows
/// authorization, so malformed options cannot reveal an inaccessible dataset.
fn admission_profile(raw: Option<&str>) -> Option<String> {
    let raw = raw.filter(|raw| raw.len() <= MAX_RAW_QUERY_BYTES)?;
    raw.split('&')
        .filter_map(|pair| pair.split_once('='))
        .find_map(|(name, value)| {
            (percent_decode(name).ok().as_deref() == Some("accessProfile"))
                .then(|| percent_decode(value).ok())
                .flatten()
        })
}

#[derive(Default)]
struct Options {
    values: BTreeMap<String, String>,
}
impl Options {
    fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }
    fn parse(raw: Option<&str>, kind: Kind) -> Result<Self, &'static str> {
        let mut result = Self::default();
        let Some(raw) = raw else { return Ok(result) };
        if raw.is_empty() || raw.len() > MAX_RAW_QUERY_BYTES {
            return Err("query");
        }
        for pair in raw.split('&') {
            let (name, value) = pair.split_once('=').ok_or("query")?;
            let name = percent_decode(name).map_err(|_| "query")?;
            let value = percent_decode(value).map_err(|_| "query")?;
            let key = match name.as_str() {
                "accessProfile" => "accessProfile",
                "from" => "from",
                "to" => "to",
                "status" => "status",
                "$top" => "$top",
                "$skiptoken" => "$skiptoken",
                _ => return Err("query"),
            };
            let allowed = key == "accessProfile"
                || match kind {
                    Kind::Live => matches!(key, "from" | "to"),
                    Kind::Series => matches!(key, "from" | "to" | "status"),
                    Kind::List => matches!(key, "$top" | "$skiptoken"),
                    Kind::Latest => key == "status",
                    _ => false,
                };
            if !allowed || value.is_empty() || result.values.insert(name, value).is_some() {
                return Err(key);
            }
        }
        Ok(result)
    }
    fn selection(&self) -> Result<StatisticsReleaseSelection, &'static str> {
        match self.get("status") {
            None => Ok(StatisticsReleaseSelection::Any),
            Some("final") => Ok(StatisticsReleaseSelection::Final),
            _ => Err("status"),
        }
    }
    fn limit(&self) -> Result<u16, &'static str> {
        let Some(raw) = self.get("$top") else {
            return Ok(50);
        };
        let n = raw.parse::<u16>().map_err(|_| "$top")?;
        if !(1..=100).contains(&n) || n.to_string() != raw {
            return Err("$top");
        };
        Ok(n)
    }
}

async fn refusal(
    service: &HttpService,
    route: &Route,
    claims: &VerifiedRequestClaims,
    selected: Option<&str>,
    correlation: &RequestCorrelation,
    response: Response,
) -> Response {
    let selected = selected.filter(|id| {
        service
            .registry
            .statistical_datasets()
            .get(&route.dataset)
            .is_some_and(|d| d.access_profiles.contains_key(*id))
    });
    refusal_for_operation(
        service,
        claims,
        selected,
        correlation,
        response,
        route.kind.method().into(),
        &route.id(),
    )
    .await
}

async fn refusal_for_operation(
    service: &HttpService,
    claims: &VerifiedRequestClaims,
    selected: Option<&str>,
    correlation: &RequestCorrelation,
    response: Response,
    method: RefusalHttpMethod,
    operation_id: &str,
) -> Response {
    if claims.principal().is_none() {
        return anonymous_refusal(response, AnonymousRefusalReason::ReadConcealed);
    }
    let Some(backend) = &service.statistics else {
        return unavailable();
    };
    if record_http_refusal_audit(
        backend.audit(),
        backend.expected(),
        HttpRefusalAudit {
            grant: crate::audit::GrantAuditContext::from_claims(claims),
            method,
            operation_id,
            target_record: None,
            action_id: None,
            principal: claims.principal(),
            selected_access_profile: selected,
            purpose_present: claims.purpose().is_some(),
            correlation,
        },
    )
    .await
    .is_err()
    {
        return unavailable();
    }
    response
}

#[allow(clippy::too_many_arguments)] // Axum extractors are the HTTP contract.
async fn dispatch(
    State(service): State<Arc<HttpService>>,
    Extension(route): Extension<Route>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    deadline: Option<Extension<RequestDeadline>>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    Path(path): Path<HashMap<String, String>>,
    body: Body,
) -> Response {
    let claims = claims
        .map(|Extension(c)| c)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let Some(dataset) = service.registry.statistical_datasets().get(&route.dataset) else {
        // Unknown IDs are caller input, so refusal auditing uses the fixed route kind.
        return refusal(
            &service,
            &Route {
                dataset: String::new(),
                kind: route.kind,
            },
            &claims,
            None,
            &correlation,
            concealed(),
        )
        .await;
    };
    let selected = admission_profile(raw.as_deref());
    let Some(context) = authorize(&service, dataset, route.kind, &claims, selected.as_deref())
    else {
        return refusal(
            &service,
            &route,
            &claims,
            selected.as_deref(),
            &correlation,
            concealed(),
        )
        .await;
    };
    let options = match Options::parse(raw.as_deref(), route.kind) {
        Ok(v) => v,
        Err(field) => {
            return refusal(
                &service,
                &route,
                &claims,
                Some(context.selected_profile()),
                &correlation,
                statistics_invalid_query_at(field),
            )
            .await;
        }
    };
    let Some(backend) = &service.statistics else {
        return unavailable();
    };
    let attempt = begin_statistics_pre_io_audit(
        backend.audit(),
        backend.expected(),
        &context,
        PreIoAudit {
            kind: PreIoAuditKind::Attempt,
            method: route.kind.method(),
            operation_id: &route.id(),
            target_record: None,
            refusal_reason: None,
            correlation: &correlation,
        },
    )
    .await;
    let Ok(_attempt) = attempt else {
        return unavailable();
    };
    let now = chrono::Utc::now();
    let deadline = statistics_work_deadline(
        tokio::time::Instant::now(),
        deadline
            .map(|Extension(d)| d.0)
            .unwrap_or_else(|| tokio::time::Instant::now() + Duration::from_secs(10))
            .min(tokio::time::Instant::now() + Duration::from_secs(30)),
    );
    let period = path.get("period").map(String::as_str);
    let version = path
        .get("version")
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|v| *v > 0 && path.get("version") == Some(&v.to_string()));
    let mut lifecycle = None;
    let mut commit_unresolved = false;
    let result = if deadline <= tokio::time::Instant::now() {
        Err(service_problem(StatisticsServiceError::Timeout))
    } else {
        execute(
            &service,
            &route,
            &context,
            &options,
            period,
            version,
            &headers,
            body,
            deadline,
            now,
            &mut lifecycle,
            &mut commit_unresolved,
        )
        .await
    };
    let (response, count) = match result {
        Ok(v) => v,
        Err(response) => (response, 0),
    };
    // An unresolved commit proves neither a commit nor a refusal, so no
    // terminal entry is appended: the attempt's drop answers it `unfinished`.
    if commit_unresolved {
        return response;
    }
    let success = response.status().is_success();
    let hasher = backend.audit().profile().key_hasher();
    let principal = context
        .principal()
        .map(|p| {
            hasher.audit_reference_hash("breg-principal-v1", &backend.expected().activation_id, p)
        })
        .transpose();
    let Ok(principal) = principal else {
        return unavailable();
    };
    let query_reference = service
        .cursors
        .binding_digest(
            b"breg-statistical-query-v1",
            &json!({
                "from": options.get("from"),
                "to": options.get("to"),
                "status": options.get("status"),
            }),
        )
        .ok();
    let row_boundary_reference = service
        .cursors
        .binding_digest(b"breg-statistical-boundary-v1", &boundary_value(&context))
        .ok();
    let entry = statistics_terminal_entry(
        backend.audit().profile(),
        StatisticsTerminalAudit {
            read: ReadTerminalAudit {
                terminal: TerminalAudit {
                    grant: context.grant_audit().cloned(),
                    outcome: if success {
                        if route.kind.method() == HttpMethod::Post {
                            if lifecycle.as_ref().is_some_and(|l: &Lifecycle| l.replayed) {
                                TerminalAuditOutcome::Replayed
                            } else {
                                TerminalAuditOutcome::Committed
                            }
                        } else {
                            TerminalAuditOutcome::Returned
                        }
                    } else {
                        TerminalAuditOutcome::Refused
                    },
                    method: route.kind.method(),
                    operation_id: route.id(),
                    entity_id: None,
                    action_id: None,
                    package_revision: backend.expected().activation_id.clone(),
                    selected_access_profile: context.selected_profile().to_owned(),
                    purpose_present: context.purpose().is_some(),
                    principal_reference: principal,
                    record_reference: None,
                    record_revision: None,
                    result_count: Some(count),
                    field_set_reference: None,
                    correlation: correlation.clone(),
                },
                query_reference,
                row_boundary_reference,
            },
            dataset_id: &route.dataset,
            period_code: period,
            version: lifecycle
                .as_ref()
                .map(|l| l.header.version as i64)
                .or(version),
            status: lifecycle.as_ref().map(|l| match l.header.status {
                ReleaseStatus::Provisional => "provisional",
                ReleaseStatus::Final => "final",
            }),
            content_digest: lifecycle
                .as_ref()
                .and_then(|l| l.header.content_digest.as_deref()),
        },
    );
    let Ok(entry) = entry else {
        return unavailable();
    };
    if backend.audit().append(entry).await.is_err() {
        return unavailable();
    };
    response
}

struct Lifecycle {
    header: crate::statistics::ReleaseVersionHeader,
    replayed: bool,
}
type HttpResult = Result<(Response, usize), Response>;
#[allow(clippy::too_many_arguments, clippy::result_large_err)] // HTTP errors carry their complete response.
async fn execute(
    service: &HttpService,
    route: &Route,
    context: &AuthorizedRequestContext,
    options: &Options,
    period: Option<&str>,
    version: Option<i64>,
    headers: &HeaderMap,
    body: Body,
    deadline: tokio::time::Instant,
    now: chrono::DateTime<chrono::Utc>,
    lifecycle: &mut Option<Lifecycle>,
    commit_unresolved: &mut bool,
) -> HttpResult {
    let backend = service.statistics.as_ref().ok_or_else(unavailable)?;
    let selection = options.selection().map_err(statistics_invalid_query_at)?;
    let csv =
        !matches!(route.kind, Kind::List | Kind::Publish | Kind::Withdraw) && negotiate(headers);
    let result = match route.kind {
        Kind::Live => backend
            .live(StatisticsLiveRequest {
                context,
                dataset_id: &route.dataset,
                from: options.get("from"),
                to: options.get("to"),
                today: now.date_naive(),
                deadline,
            })
            .await
            .map_err(service_problem)
            .and_then(|d| document_response(&d, csv)),
        Kind::Series => {
            let from = options
                .get("from")
                .ok_or_else(|| statistics_invalid_query_at("from"))?;
            let to = options
                .get("to")
                .ok_or_else(|| statistics_invalid_query_at("to"))?;
            backend
                .read_series(StatisticsSeriesRequest {
                    context,
                    dataset_id: &route.dataset,
                    from,
                    to,
                    selection,
                    today: now.date_naive(),
                    deadline,
                })
                .await
                .map_err(service_problem)
                .and_then(|d| document_response(&d, csv))
        }
        Kind::Latest | Kind::Version => {
            if route.kind == Kind::Version && version.is_none() {
                return Err(concealed());
            }
            let stored = backend
                .read_version(StatisticsVersionReadRequest {
                    context,
                    dataset_id: &route.dataset,
                    period_code: period.ok_or_else(concealed)?,
                    version,
                    selection,
                    deadline,
                })
                .await
                .map_err(service_problem)?;
            *lifecycle = Some(Lifecycle {
                header: stored.header.clone(),
                replayed: false,
            });
            let d: StatisticsDocument =
                serde_json::from_slice(&stored.bytes).map_err(|_| unavailable())?;
            if csv {
                document_response(&d, true)
            } else {
                Ok((
                    bytes_response(stored.bytes, "application/json", true),
                    d.cells.len(),
                ))
            }
        }
        Kind::List => {
            let limit = options.limit().map_err(statistics_invalid_query_at)?;
            let binding =
                listing_binding(service, route, context, limit).map_err(|_| unavailable())?;
            let after =
                if let Some(token) = options.get("$skiptoken") {
                    let continuation = service
                        .cursors
                        .open_after_authorization(token, now.timestamp() as u64, |_| {
                            Ok(binding.clone())
                        })
                        .map_err(|_| statistics_problem(ProblemCode::QueryCursorInvalid, None))?
                        .continuation;
                    Some(StatisticsReleaseListCursor {
                        period: continuation.sort_value.ok_or_else(|| {
                            statistics_problem(ProblemCode::QueryCursorInvalid, None)
                        })?,
                        version: continuation.last_record_id.parse::<u64>().map_err(|_| {
                            statistics_problem(ProblemCode::QueryCursorInvalid, None)
                        })?,
                    })
                } else {
                    None
                };
            let page = backend
                .list_releases(StatisticsReleaseListRequest {
                    context,
                    dataset_id: &route.dataset,
                    after,
                    limit,
                    deadline,
                })
                .await
                .map_err(service_problem)?;
            let token = if let Some(next) = &page.next {
                let query = CursorQuery {
                    projection: Vec::new(),
                    filter: None,
                    spatial: None,
                    order: None,
                    include_count: false,
                    page_size: limit,
                    temporal_instant: None,
                    scope: CursorQueryScope::Collection {},
                };
                let continuation = CursorContinuation {
                    last_record_id: next.version.to_string(),
                    sort_value: Some(next.period.clone()),
                };
                let p = service
                    .cursors
                    .new_payload(now.timestamp() as u64, binding, query, continuation)
                    .map_err(|_| unavailable())?;
                Some(service.cursors.encode(&p).map_err(|_| unavailable())?)
            } else {
                None
            };
            let n = 0; // Release headers disclose no statistical cells.
            let bytes=serde_json::to_vec(&json!({"items":page.items,"pageInfo":{"hasMore":page.has_more,"nextCursor":token}}))
                .map_err(|_|unavailable())?;
            Ok((bytes_response(bytes, "application/json", false), n))
        }
        Kind::Publish | Kind::Withdraw => {
            let key = single_header(headers, IDEMPOTENCY_KEY_HEADER)
                .filter(|k| valid_idempotency_key(k))
                .ok_or_else(invalid_idempotency_key)?;
            if !single_content_type(headers, "application/json") {
                return Err(unsupported_media_type());
            }
            let bytes = to_bytes(body, 4096).await.map_err(|_| invalid_request())?;
            let value = parse_json_strict(&bytes).map_err(|_| invalid_request())?;
            let canonical = registry_platform_canonical_json::canonicalize_json(&value)
                .map_err(|_| invalid_request())?;
            let digest: [u8; 32] = Sha256::digest(canonical).into();
            let object = value
                .as_object()
                .filter(|o| o.len() == 1)
                .ok_or_else(invalid_request)?;
            let period = period.ok_or_else(concealed)?;
            let held = if route.kind == Kind::Publish {
                let status = match object.get("status").and_then(Value::as_str) {
                    Some("provisional") => ReleaseStatus::Provisional,
                    Some("final") => ReleaseStatus::Final,
                    _ => return Err(invalid_request()),
                };
                backend
                    .publish(StatisticsPublishRequest {
                        context,
                        dataset_id: &route.dataset,
                        period_code: period,
                        status,
                        idempotency_key: key,
                        route_id: &route.id(),
                        canonical_request_digest: digest,
                        computed_at: now,
                        today: now.date_naive(),
                        deadline,
                    })
                    .await
            } else {
                let reason = match object.get("reason").and_then(Value::as_str) {
                    Some("computation-error") => WithdrawalReason::ComputationError,
                    Some("source-data-error") => WithdrawalReason::SourceDataError,
                    Some("disclosure-risk") => WithdrawalReason::DisclosureRisk,
                    _ => return Err(invalid_request()),
                };
                backend
                    .withdraw(StatisticsWithdrawalRequest {
                        context,
                        dataset_id: &route.dataset,
                        period_code: period,
                        version: version.ok_or_else(concealed)?,
                        reason,
                        idempotency_key: key,
                        route_id: &route.id(),
                        canonical_request_digest: digest,
                        deadline,
                    })
                    .await
            }
            .map_err(|error| {
                *commit_unresolved = matches!(error, StatisticsServiceError::CommitUnresolved);
                service_problem(error)
            })?;
            let count = held.result_count;
            *lifecycle = Some(Lifecycle {
                header: held.header,
                replayed: held.replayed,
            });
            Ok((exact_mutation(&held.response, None, "", None), count))
        }
    };
    result
}

#[allow(clippy::result_large_err)] // HTTP errors carry their complete response.
fn document_response(document: &StatisticsDocument, csv: bool) -> HttpResult {
    let canonical = canonical_document(document).map_err(|_| unavailable())?;
    if canonical.len() > crate::compiler::MAX_STATISTICAL_RELEASE_DOCUMENT_BYTES {
        return Err(invalid_query());
    }
    let bytes = if csv {
        document_csv(document).map_err(|_| unavailable())?
    } else {
        canonical
    };
    if bytes.len() > crate::compiler::MAX_STATISTICAL_RELEASE_DOCUMENT_BYTES {
        return Err(invalid_query());
    }
    Ok((
        bytes_response(
            bytes,
            if csv {
                "text/csv; charset=utf-8"
            } else {
                "application/json"
            },
            true,
        ),
        document.cells.len(),
    ))
}
fn bytes_response(bytes: Vec<u8>, media: &'static str, digest: bool) -> Response {
    let mut builder = Response::builder()
        .status(200)
        .header(CONTENT_TYPE, media)
        .header(CACHE_CONTROL, "no-store")
        .header(VARY, "authorization, accept");
    if digest {
        builder = builder.header(
            "repr-digest",
            format!(
                "sha-256=:{}:",
                base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&bytes))
            ),
        );
    }
    builder
        .body(Body::from(bytes))
        .unwrap_or_else(|_| unavailable())
}
fn negotiate(headers: &HeaderMap) -> bool {
    let mut json_quality = (0_u16, 0_u8);
    let mut csv_quality = (0_u16, 0_u8);
    for value in headers
        .get_all(ACCEPT)
        .iter()
        .filter_map(|value| value.to_str().ok())
    {
        for item in value.split(',') {
            let mut parts = item.split(';');
            let media = parts.next().unwrap_or_default().trim();
            let quality = accept_quality(parts);
            if media.eq_ignore_ascii_case("text/csv") {
                csv_quality = csv_quality.max((quality, 3));
            } else if media.eq_ignore_ascii_case("application/json") {
                json_quality = json_quality.max((quality, 3));
            } else if media == "*/*" || media.eq_ignore_ascii_case("application/*") {
                json_quality = json_quality.max((quality, 1));
            }
        }
    }
    csv_quality.0 > 0 && csv_quality > json_quality
}
fn service_problem(error: StatisticsServiceError) -> Response {
    match error {
        StatisticsServiceError::Concealed => concealed(),
        StatisticsServiceError::QueryInvalid { field_path } => {
            statistics_invalid_query_at(field_path)
        }
        StatisticsServiceError::ReleaseRefused(reason) => statistics_problem(
            ProblemCode::StatisticalDatasetReleaseRefused,
            Some((
                "refusalCode",
                match reason {
                    StatisticsReleaseRefusal::PeriodNotEnded => "period-not-ended",
                    StatisticsReleaseRefusal::BeforeFirstPeriod => "before-first-period",
                    StatisticsReleaseRefusal::ProvisionalAfterFinal => "provisional-after-final",
                    StatisticsReleaseRefusal::AlreadyWithdrawn => "already-withdrawn",
                },
            )),
        ),
        StatisticsServiceError::VersionConflict => {
            statistics_problem(ProblemCode::StatisticalDatasetVersionConflict, None)
        }
        StatisticsServiceError::VersionWithdrawn { reason_code } => statistics_problem(
            ProblemCode::StatisticalDatasetVersionWithdrawn,
            Some((
                "reasonCode",
                match reason_code.as_str() {
                    "computation-error" => "computation-error",
                    "source-data-error" => "source-data-error",
                    "disclosure-risk" => "disclosure-risk",
                    _ => return unavailable(),
                },
            )),
        ),
        StatisticsServiceError::DomainViolation {
            dataset_id,
            dimension,
        } => {
            let code = ProblemCode::StatisticalDatasetDomainViolation;
            crate::correlation::problem_response_with_field_path(
                StatusCode::from_u16(code.status()).expect("catalogue status"),
                code.title(),
                code.description(),
                code.code(),
                format!("statisticalDatasets[id={dataset_id}].dimensions[id={dimension}]"),
            )
        }
        StatisticsServiceError::Timeout => statistics_problem(ProblemCode::RequestTimeout, None),
        StatisticsServiceError::IdempotencyConflict => {
            statistics_problem(ProblemCode::IdempotencyConflict, None)
        }
        StatisticsServiceError::Unavailable | StatisticsServiceError::CommitUnresolved => {
            unavailable()
        }
    }
}

fn listing_binding(
    service: &HttpService,
    route: &Route,
    context: &AuthorizedRequestContext,
    limit: u16,
) -> Result<CursorBinding, CursorError> {
    let digest = |domain, value: &Value| service.cursors.binding_digest(domain, value);
    let dataset = service
        .registry
        .statistical_datasets()
        .get(&route.dataset)
        .ok_or(CursorError::Mismatch)?;
    let reference = digest(
        b"breg-statistical-list-v1",
        &json!({"dataset":route.dataset,"definition":dataset.definition_digest}),
    )?;
    Ok(CursorBinding {
        package_revision: service.identity.package_revision.clone(),
        schema_fingerprint: service.identity.schema_fingerprint.clone(),
        registry_revision: service.registry.version().to_owned(),
        route_id: route.id(),
        query_operation_id: route.id(),
        query_kind: CompiledQueryKind::List,
        selected_profile: context.selected_profile().to_owned(),
        principal_reference: Some(digest(
            b"breg-statistical-caller-v1",
            &json!(context.principal()),
        )?),
        purpose_reference: Some(digest(
            b"breg-statistical-purpose-v1",
            &json!(context.purpose()),
        )?),
        row_boundary_reference: digest(
            b"breg-statistical-boundaries-v1",
            &boundary_value(context),
        )?,
        projection_reference: reference.clone(),
        query_reference: reference.clone(),
        sort_reference: reference.clone(),
        scope_reference: reference,
        spatial_reference: None,
        representation: CursorRepresentation::Json,
        adapter: CursorAdapter::Native,
        page_size: limit,
        include_count: false,
        temporal_instant: None,
        selected_fields: Vec::new(),
    })
}

fn boundary_value(context: &AuthorizedRequestContext) -> Value {
    json!(context.row_boundaries().iter().map(|b|json!({
        "field":b.field(),"operator":match b.operator(){RowBoundaryOperator::Equals=>"equals",RowBoundaryOperator::In=>"in"},
        "values":b.values(),
    })).collect::<Vec<_>>())
}

/// Caller-filtered metadata never adds an entity grant for release readers.
pub(super) fn metadata(
    service: &HttpService,
    claims: &VerifiedRequestClaims,
    options: &QueryOptions,
) -> Vec<Value> {
    service
        .registry
        .statistical_datasets()
        .values()
        .filter_map(|dataset| {
            let selected = options.access_profile().map(String::as_str);
            let context = authorize(service, dataset, Kind::List, claims, selected)
                .or_else(|| authorize(service, dataset, Kind::Live, claims, selected))?;
            crate::statistical_artifacts::statistical_dataset_metadata_entry(
                dataset,
                context.selected_profile(),
            )
        })
        .collect()
}

pub(super) fn append_openapi(
    service: &HttpService,
    claims: &VerifiedRequestClaims,
    options: &QueryOptions,
    paths: &mut Map<String, Value>,
    schemas: &mut Map<String, Value>,
) {
    let mut datasets = BTreeMap::new();
    for dataset in service.registry.statistical_datasets().values() {
        let selected = options.access_profile().map(String::as_str);
        let Some(context) = authorize(service, dataset, Kind::List, claims, selected)
            .or_else(|| authorize(service, dataset, Kind::Live, claims, selected))
        else {
            continue;
        };
        let profile = context.selected_profile();
        let mut dataset = dataset.clone();
        dataset.access_profiles.retain(|id, _| id == profile);
        dataset.live_profiles.retain(|id| id == profile);
        if let Some(releases) = &mut dataset.releases {
            releases.readers.retain(|id| id == profile);
            if releases.publisher != profile {
                releases.publisher.clear();
            }
        }
        datasets.insert(dataset.id.clone(), dataset);
    }
    crate::statistical_artifacts::append_statistics_openapi(
        paths,
        schemas,
        &datasets,
        service.registry.statistical_datasets(),
        true,
    );
}

pub(super) async fn unknown(
    service: &HttpService,
    claims: &VerifiedRequestClaims,
    correlation: &RequestCorrelation,
    method: &axum::http::Method,
) -> Response {
    refusal_for_operation(
        service,
        claims,
        None,
        correlation,
        concealed(),
        RefusalHttpMethod::from_request(method),
        "statistics.unknown",
    )
    .await
}

fn statistics_invalid_query_at(parameter: &'static str) -> Response {
    if crate::problem_location::is_query_parameter_location(parameter) {
        super::invalid_query_at(parameter)
    } else {
        invalid_query()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn work_deadline_reserves_terminal_audit_without_extending_short_budgets() {
        let now = tokio::time::Instant::now();
        let outer = now + Duration::from_secs(10);
        assert_eq!(
            statistics_work_deadline(now, outer),
            outer - Duration::from_millis(500)
        );
        for budget in [
            Duration::ZERO,
            Duration::from_millis(50),
            Duration::from_millis(500),
        ] {
            assert_eq!(statistics_work_deadline(now, now + budget), now);
        }
        let expired = now - Duration::from_secs(1);
        assert_eq!(statistics_work_deadline(now, expired), expired);
    }

    #[test]
    fn statistical_parameters_are_bounded_and_unknown_names_are_not_echoed() {
        for raw in [
            "from=2025-01&from=2025-02",
            "unknown=secret",
            "$filter=hidden",
            "from=%GG",
        ] {
            assert!(Options::parse(Some(raw), Kind::Live).is_err());
        }
        assert_eq!(
            Options::parse(Some("$top=0"), Kind::List)
                .ok()
                .unwrap()
                .limit(),
            Err("$top")
        );
        assert!(Options::parse(Some("status=final"), Kind::Live).is_err());
        for parameter in ["from", "to", "status"] {
            assert!(crate::problem_location::is_query_parameter_location(
                parameter
            ));
            assert_eq!(
                statistics_invalid_query_at(parameter).status(),
                StatusCode::BAD_REQUEST
            );
        }
        assert_eq!(
            statistics_invalid_query_at("query").status(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn statistical_accept_negotiation_respects_quality_and_zero_exclusion() {
        let headers = |accept: &str| {
            let mut h = HeaderMap::new();
            h.insert(ACCEPT, HeaderValue::from_str(accept).unwrap());
            h
        };
        assert!(negotiate(&headers("application/json;q=0.4,text/csv;q=0.8")));
        assert!(!negotiate(&headers("text/csv;q=0,application/json")));
        assert!(negotiate(&headers("TEXT/CSV;q=0.8,Application/JSON;q=0.4")));
        assert!(!negotiate(&headers("text/csv;q=0,application/json;q=0")));
        assert!(!negotiate(&headers("text/csv,application/json")));
        let mut repeated = headers("application/json;q=0.4");
        repeated.append(ACCEPT, HeaderValue::from_static("text/csv;q=0.8"));
        assert!(negotiate(&repeated));
        assert!(!negotiate(&headers("application/xml")));
        assert!(!negotiate(&HeaderMap::new()));
    }
}
