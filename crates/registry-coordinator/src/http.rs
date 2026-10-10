// SPDX-License-Identifier: Apache-2.0
//! Authenticated, bounded Coordinator service surface.
use crate::{
    access::{Action, Authenticator, Caller},
    deployment::{self, LoadedPackage},
    protocol::AdapterSet,
    runtime::RuntimeConfig,
    store::Store,
    PocError, Result,
};
use axum::{
    body::Bytes,
    extract::{
        rejection::{JsonRejection, PathRejection, QueryRejection},
        DefaultBodyLimit, FromRequest, Path, Query, State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{de::DeserializeOwned, Deserialize};
use serde_json::{json, Value};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{sync::Mutex, time::Instant};
use uuid::Uuid;

const BINDING_RECHECK_INTERVAL: Duration = Duration::from_secs(30);

// Only the deployment-wide live-binding scan is cached. Mutable activation,
// custody, audit and recovery gates remain fresh on every readiness request.
#[derive(Default)]
struct BindingReadiness(Mutex<Option<(Instant, bool)>>);

impl BindingReadiness {
    async fn check<F: Future<Output = Result<()>>>(&self, check: impl FnOnce() -> F) -> bool {
        // Coalesce concurrent probes into one inspection, including failures.
        let mut checked = self.0.lock().await;
        if let Some((until, ready)) = checked.as_ref() {
            if Instant::now() < *until {
                return *ready;
            }
        }
        let ready = check().await.is_ok();
        *checked = Some((Instant::now() + BINDING_RECHECK_INTERVAL, ready));
        ready
    }
}
#[derive(Clone)]
pub struct HttpState {
    pub store: Arc<Store>,
    pub recovery_only: bool,
    pub runtime: Arc<RuntimeConfig>,
    pub package: Arc<LoadedPackage>,
    pub authenticator: Arc<Authenticator>,
    pub adapters: Arc<dyn AdapterSet>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Start {
    flow: String,
    input: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reason {
    reason: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    #[serde(default = "limit")]
    limit: u32,
}
fn limit() -> u32 {
    20
}
pub fn router(state: HttpState) -> Router {
    let ready_state = state.clone();
    let ready_bindings = Arc::new(BindingReadiness::default());
    Router::new()
        .route("/health", get(|| async { Json(json!({"live":true})) }))
        .route(
            "/ready",
            get(move || ready(ready_state.clone(), ready_bindings.clone())),
        )
        .route("/v1/runs", post(start).get(list))
        .route("/v1/runs/{run}", get(status))
        .route("/v1/runs/{run}/inspect", get(inspect))
        .route("/v1/runs/{run}/retry-same", post(retry))
        .route("/v1/runs/{run}/cancel", post(cancel))
        .route("/v1/runs/{run}/reconcile", post(reconcile))
        .route("/v1/doctor", get(doctor))
        .route("/v1/restore-hold", post(hold))
        .route("/v1/release-restore-hold", post(release))
        .route("/v1/release-admission-hold", post(release_admission))
        .route("/v1/complete-execution-recovery", post(complete_execution))
        .route("/v1/retention", post(retain))
        .layer(DefaultBodyLimit::max(65_536))
        .layer(registry_platform_httpsec::request_body_limit(65_536))
        .layer(registry_platform_httpsec::security_headers(
            registry_platform_httpsec::CspBuilder::deny_by_default(),
        ))
        .with_state(state)
}
fn problem(error: PocError) -> Response {
    let status = match error.code.as_str() {
        "access.unauthenticated" => StatusCode::UNAUTHORIZED,
        "access.unavailable" => StatusCode::SERVICE_UNAVAILABLE,
        "access.denied" => StatusCode::FORBIDDEN,
        "request.content-type-invalid" => StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "run-absent" | "run-not-found" | "run.not_found" | "run.missing" => StatusCode::NOT_FOUND,
        "input-invalid" | "start-key-invalid" | "request.invalid" | "definition.input"
        | "reason-invalid" | "retention-invalid" => StatusCode::BAD_REQUEST,
        "store-unavailable"
        | "audit-unavailable"
        | "audit-unready"
        | "audit-response-unavailable" => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::CONFLICT,
    };
    let mut response=(status,Json(json!({"code":error.code,"message":error.message,"suggestedAction":error.suggested_action}))).into_response();
    response.headers_mut().insert(
        "cache-control",
        axum::http::HeaderValue::from_static("no-store"),
    );
    if status == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            axum::http::header::WWW_AUTHENTICATE,
            axum::http::HeaderValue::from_static("Bearer"),
        );
    }
    response
}
async fn caller(s: &HttpState, headers: &HeaderMap) -> Result<Caller> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            PocError::new(
                "access.unauthenticated",
                "a verified access token is required",
            )
        })?;
    let token = registry_platform_authcommon::parse_bearer_token(value).map_err(|_| {
        PocError::new(
            "access.unauthenticated",
            "a verified access token is required",
        )
    })?;
    s.authenticator.authenticate(token).await
}
async fn ready(s: HttpState, bindings: Arc<BindingReadiness>) -> Response {
    if !s.recovery_only
        && deployment::check(&s.store, &s.runtime, &s.package.digest)
            .await
            .is_ok()
        && s.store.is_ready().await.unwrap_or(false)
        && bindings
            .check(|| s.store.check_runtime_bindings(&s.runtime))
            .await
    {
        (StatusCode::OK, Json(json!({"ready":true}))).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"ready":false})),
        )
            .into_response()
    }
}

#[cfg(test)]
mod readiness_tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Notify;

    #[tokio::test(start_paused = true)]
    async fn live_binding_readiness_refreshes_success_and_failure_at_the_fixed_deadline() {
        let cache = BindingReadiness::default();
        let calls = AtomicUsize::new(0);
        assert!(
            cache
                .check(|| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Ok(()))
                })
                .await
        );
        tokio::time::advance(BINDING_RECHECK_INTERVAL - Duration::from_millis(1)).await;
        assert!(
            cache
                .check(|| async { panic!("successful inspection still valid") })
                .await
        );
        tokio::time::advance(Duration::from_millis(1)).await;
        assert!(
            !cache
                .check(|| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Err(PocError::new("live-binding-conflict", "test refusal")))
                })
                .await
        );
        assert!(
            !cache
                .check(|| async { panic!("failed inspection still cached") })
                .await
        );
        tokio::time::advance(BINDING_RECHECK_INTERVAL).await;
        assert!(
            cache
                .check(|| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Ok(()))
                })
                .await
        );
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn concurrent_readiness_probes_share_one_live_binding_inspection() {
        let cache = Arc::new(BindingReadiness::default());
        let calls = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let first = tokio::spawn({
            let (cache, calls, started, release) = (
                cache.clone(),
                calls.clone(),
                started.clone(),
                release.clone(),
            );
            async move {
                cache
                    .check(|| async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        started.notify_one();
                        release.notified().await;
                        Ok(())
                    })
                    .await
            }
        });
        started.notified().await;
        let mut others = tokio::task::JoinSet::new();
        for _ in 0..7 {
            let (cache, calls) = (cache.clone(), calls.clone());
            others.spawn(async move {
                cache
                    .check(|| async {
                        calls.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    })
                    .await
            });
        }
        release.notify_one();
        assert!(first.await.unwrap());
        while let Some(result) = others.join_next().await {
            assert!(result.unwrap());
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}

#[cfg(test)]
mod problem_tests {
    use super::*;

    #[test]
    fn only_credential_refusal_returns_a_bearer_challenge() {
        for (code, status, challenge) in [
            (
                "access.unauthenticated",
                StatusCode::UNAUTHORIZED,
                Some("Bearer"),
            ),
            ("access.denied", StatusCode::FORBIDDEN, None),
            ("access.unavailable", StatusCode::SERVICE_UNAVAILABLE, None),
            ("store-unavailable", StatusCode::SERVICE_UNAVAILABLE, None),
            ("request.invalid", StatusCode::BAD_REQUEST, None),
        ] {
            let response = problem(PocError::new(code, "synthetic boundary refusal"));
            assert_eq!(response.status(), status);
            assert_eq!(
                response
                    .headers()
                    .get(axum::http::header::WWW_AUTHENTICATE)
                    .map(|value| value.to_str().unwrap()),
                challenge
            );
            assert_eq!(response.headers()["cache-control"], "no-store");
        }
    }

    #[test]
    fn openapi_documents_challenges_only_on_authenticated_route_401s() {
        let document = openapi();
        for operation in document["paths"]
            .as_object()
            .unwrap()
            .values()
            .flat_map(|path| path.as_object().unwrap().values())
        {
            if operation.get("security").is_some() {
                assert_eq!(
                    operation["responses"]["401"]["headers"]["WWW-Authenticate"]["schema"]["const"],
                    "Bearer"
                );
                for status in ["400", "403", "404", "503"] {
                    assert!(operation["responses"][status]["headers"]
                        .get("WWW-Authenticate")
                        .is_none());
                }
            }
        }
    }
}
type BoundedBody = std::result::Result<Bytes, axum::extract::rejection::BytesRejection>;
fn request_body<T: DeserializeOwned>(body: BoundedBody) -> Result<T> {
    let bytes =
        body.map_err(|_| PocError::new("request.invalid", "supply a bounded JSON object"))?;
    let value = registry_platform_canonical_json::parse_json_strict(&bytes)
        .map_err(|_| PocError::new("request.invalid", "supply unambiguous bounded JSON"))?;
    serde_json::from_value(value)
        .map_err(|_| PocError::new("request.invalid", "supply the declared JSON object fields"))
}
// Preserve Axum's JSON media contract, but release its rejection only after
// caller authentication and action/ownership authorization have succeeded.
async fn json_body<T: DeserializeOwned>(headers: &HeaderMap, body: BoundedBody) -> Result<T> {
    let bytes =
        body.map_err(|_| PocError::new("request.invalid", "supply a bounded JSON object"))?;
    let mut request = axum::http::Request::new(axum::body::Body::from(bytes.clone()));
    *request.headers_mut() = headers.clone();
    if matches!(
        Json::<Value>::from_request(request, &()).await,
        Err(JsonRejection::MissingJsonContentType(_))
    ) {
        return Err(PocError::new(
            "request.content-type-invalid",
            "supply application/json or an application media type ending in +json",
        ));
    }
    request_body(Ok(bytes))
}
async fn start(State(s): State<HttpState>, headers: HeaderMap, body: BoundedBody) -> Response {
    let result = async {
        let c = caller(&s, &headers).await?;
        c.authorize(Action::Start, None)?;
        let body: Start = json_body(&headers, body).await?;
        c.authorize(Action::Start, Some(&body.flow))?;
        if s.recovery_only {
            return Err(PocError::new(
                "recovery-only",
                "admissions are disabled in recovery-only service mode",
            )
            .suggest("establish persistent recovery hold before resuming an ordinary service"));
        }
        if body.flow != s.package.definition.workflow.id {
            return Err(PocError::new(
                "access.denied",
                "the caller policy does not authorize this operation",
            ));
        }
        deployment::check(&s.store, &s.runtime, &s.package.digest).await?;
        let key = headers
            .get("idempotency-key")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| PocError::new("start-key-invalid", "supply Idempotency-Key"))?;
        let binding = s
            .runtime
            .binding_digest_for(&s.package.definition.workflow)?;
        let id = s
            .store
            .admit_runtime_owned(
                &s.package.definition,
                body.input,
                &c.actor,
                key,
                &binding,
                &s.runtime,
            )
            .await?;
        s.store.status_owned(id, &c.actor).await.and_then(|v| {
            serde_json::to_value(v)
                .map_err(|_| PocError::new("status-unavailable", "cannot encode status"))
        })
    }
    .await;
    answer(result)
}
type RunPath = std::result::Result<Path<String>, PathRejection>;
async fn run_caller(
    s: &HttpState,
    headers: &HeaderMap,
    run: RunPath,
    action: Action,
) -> Result<(Caller, Uuid)> {
    let c = caller(s, headers).await?;
    c.authorize(action, None)?;
    let Path(run) =
        run.map_err(|_| PocError::new("request.invalid", "supply a bounded UUID run identifier"))?;
    // Business parsing follows authentication and action policy. Preserve the
    // UUID forms accepted by the former typed extractor, within their bound.
    let run = if run.len() <= 45 {
        Uuid::parse_str(&run).ok()
    } else {
        None
    }
    .ok_or_else(|| PocError::new("request.invalid", "supply a bounded UUID run identifier"))?;
    let status = s.store.status_owned(run, &c.actor).await?;
    c.authorize(action, Some(&status.workflow_id))
        .map_err(|_| PocError::new("run-absent", "run was not found"))?;
    Ok((c, run))
}
fn answer(result: Result<Value>) -> Response {
    match result {
        Ok(v) => {
            let mut r = Json(v).into_response();
            r.headers_mut().insert(
                "cache-control",
                axum::http::HeaderValue::from_static("no-store"),
            );
            r
        }
        Err(e) => problem(e),
    }
}
fn encode(value: impl serde::Serialize) -> Result<Value> {
    serde_json::to_value(value)
        .map_err(|_| PocError::new("status-unavailable", "cannot encode protected result"))
}
async fn status(State(s): State<HttpState>, headers: HeaderMap, run: RunPath) -> Response {
    answer(
        async {
            let (c, run) = run_caller(&s, &headers, run, Action::Status).await?;
            encode(s.store.status_owned(run, &c.actor).await?)
        }
        .await,
    )
}
async fn list(
    State(s): State<HttpState>,
    headers: HeaderMap,
    query: std::result::Result<Query<List>, QueryRejection>,
) -> Response {
    answer(
        async {
            let c = caller(&s, &headers).await?;
            let flows = c.authorized_flows(Action::Status)?;
            let Query(q) = query.map_err(|_| {
                PocError::new("request.invalid", "supply the declared bounded list query")
            })?;
            if !(1..=100).contains(&q.limit) {
                return Err(PocError::new(
                    "request.invalid",
                    "limit must be between 1 and 100",
                ));
            }
            let runs = s.store.list_owned(q.limit, &c.actor, flows).await?;
            encode(json!({"runs": runs}))
        }
        .await,
    )
}
async fn binding(s: &HttpState, run: Uuid, c: &Caller) -> Result<String> {
    let definition = s.store.definition_owned(run, &c.actor).await?;
    s.runtime.binding_digest_for(&definition.workflow)
}
async fn inspect(State(s): State<HttpState>, headers: HeaderMap, run: RunPath) -> Response {
    answer(
        async {
            let (c, run) = run_caller(&s, &headers, run, Action::Inspect).await?;
            encode(
                s.store
                    .inspect_runtime_owned(run, &s.runtime, &c.actor)
                    .await?,
            )
        }
        .await,
    )
}
async fn retry(
    State(s): State<HttpState>,
    headers: HeaderMap,
    run: RunPath,
    body: BoundedBody,
) -> Response {
    answer(
        async {
            let (c, run) = run_caller(&s, &headers, run, Action::RetrySame).await?;
            let reason: Reason = json_body(&headers, body).await?;
            s.store
                .retry_same_owned(run, &binding(&s, run, &c).await?, &c.actor, &reason.reason)
                .await?;
            Ok(json!({"runId":run,"status":"retry-scheduled"}))
        }
        .await,
    )
}
async fn cancel(
    State(s): State<HttpState>,
    headers: HeaderMap,
    run: RunPath,
    body: BoundedBody,
) -> Response {
    answer(
        async {
            let (c, run) = run_caller(&s, &headers, run, Action::Cancel).await?;
            let reason: Reason = json_body(&headers, body).await?;
            encode(s.store.cancel_owned(run, &c.actor, &reason.reason).await?)
        }
        .await,
    )
}
async fn reconcile(
    State(s): State<HttpState>,
    headers: HeaderMap,
    run: RunPath,
    body: BoundedBody,
) -> Response {
    answer(
        async {
            let (c, run) = run_caller(&s, &headers, run, Action::Reconcile).await?;
            let reason: Reason = json_body(&headers, body).await?;
            encode(
                s.store
                    .reconcile_owned(
                        run,
                        &binding(&s, run, &c).await?,
                        &c.actor,
                        &reason.reason,
                        s.adapters.as_ref(),
                    )
                    .await?,
            )
        }
        .await,
    )
}
async fn doctor(State(s): State<HttpState>, headers: HeaderMap) -> Response {
    answer(
        async {
            let c = caller(&s, &headers).await?;
            c.authorize(Action::Doctor, None)?;
            let active = deployment::check_serving(&s.store, &s.runtime, &s.package.digest).await;
            let status = s.store.doctor().await?;
            Ok(json!({"activationReady":active.is_ok(),"state":status}))
        }
        .await,
    )
}
async fn hold(State(s): State<HttpState>, headers: HeaderMap, body: BoundedBody) -> Response {
    answer(
        async {
            let c = caller(&s, &headers).await?;
            c.authorize(Action::RestoreHold, None)?;
            let reason: Reason = json_body(&headers, body).await?;
            s.store.set_restore_hold(&c.actor, &reason.reason).await?;
            Ok(json!({"restoreHold":true}))
        }
        .await,
    )
}
async fn release(State(s): State<HttpState>, headers: HeaderMap, body: BoundedBody) -> Response {
    answer(
        async {
            let c = caller(&s, &headers).await?;
            c.authorize(Action::ReleaseRestoreHold, None)?;
            let reason: Reason = json_body(&headers, body).await?;
            s.store
                .release_restore_hold(&c.actor, &reason.reason)
                .await?;
            Ok(json!({"restoreHold":false}))
        }
        .await,
    )
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdmissionRelease {
    recovery_reference: String,
    admission_history_complete: bool,
    prior_deployment_fenced: bool,
}
async fn release_admission(
    State(s): State<HttpState>,
    headers: HeaderMap,
    body: BoundedBody,
) -> Response {
    answer(
        async {
            let c = caller(&s, &headers).await?;
            c.authorize(Action::ReleaseAdmissionHold, None)?;
            let body: AdmissionRelease = json_body(&headers, body).await?;
            s.store
                .release_admission_hold(
                    &c.actor,
                    &body.recovery_reference,
                    body.admission_history_complete,
                    body.prior_deployment_fenced,
                )
                .await?;
            Ok(json!({"admissionsHold":false}))
        }
        .await,
    )
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecutionRecovery {
    recovery_reference: String,
    execution_history_complete: bool,
    prior_deployment_fenced: bool,
}
async fn complete_execution(
    State(s): State<HttpState>,
    headers: HeaderMap,
    body: BoundedBody,
) -> Response {
    answer(
        async {
            let c = caller(&s, &headers).await?;
            c.authorize(Action::CompleteExecutionRecovery, None)?;
            let body: ExecutionRecovery = json_body(&headers, body).await?;
            s.store
                .complete_execution_recovery(
                    &c.actor,
                    &body.recovery_reference,
                    body.execution_history_complete,
                    body.prior_deployment_fenced,
                )
                .await?;
            Ok(json!({"executionRecoveryReviewed":true}))
        }
        .await,
    )
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Retain {
    before: chrono::DateTime<chrono::Utc>,
    limit: u32,
}
async fn retain(State(s): State<HttpState>, headers: HeaderMap, body: BoundedBody) -> Response {
    answer(
        async {
            let c = caller(&s, &headers).await?;
            c.authorize(Action::Retain, None)?;
            let body: Retain = json_body(&headers, body).await?;
            let count = s
                .store
                .retain_terminal(body.before, body.limit, &c.actor)
                .await?;
            Ok(json!({"erased":count}))
        }
        .await,
    )
}
pub fn openapi() -> Value {
    let run_param = json!({"name":"run","in":"path","required":true,"schema":{"type":"string","format":"uuid"}});
    let mut paths = serde_json::Map::new();
    let operations = [
        ("/v1/runs", "get", "listRuns", None, Some("RunList")),
        (
            "/v1/runs",
            "post",
            "startRun",
            Some("Start"),
            Some("RunStatus"),
        ),
        (
            "/v1/runs/{run}",
            "get",
            "runStatus",
            None,
            Some("RunStatus"),
        ),
        (
            "/v1/runs/{run}/inspect",
            "get",
            "inspectRun",
            None,
            Some("RunInspection"),
        ),
        (
            "/v1/runs/{run}/retry-same",
            "post",
            "retrySame",
            Some("Reason"),
            Some("RetryScheduled"),
        ),
        (
            "/v1/runs/{run}/cancel",
            "post",
            "cancelRun",
            Some("Reason"),
            Some("RunStatus"),
        ),
        (
            "/v1/runs/{run}/reconcile",
            "post",
            "reconcileRun",
            Some("Reason"),
            Some("RunInspection"),
        ),
        ("/v1/doctor", "get", "doctor", None, Some("Doctor")),
        (
            "/v1/restore-hold",
            "post",
            "restoreHold",
            Some("Reason"),
            Some("Hold"),
        ),
        (
            "/v1/release-restore-hold",
            "post",
            "releaseRestoreHold",
            Some("Reason"),
            Some("Hold"),
        ),
        (
            "/v1/release-admission-hold",
            "post",
            "releaseAdmissionHold",
            Some("AdmissionRelease"),
            Some("AdmissionHold"),
        ),
        (
            "/v1/complete-execution-recovery",
            "post",
            "completeExecutionRecovery",
            Some("ExecutionRecovery"),
            Some("ExecutionReviewed"),
        ),
        (
            "/v1/retention",
            "post",
            "retainTerminal",
            Some("Retention"),
            Some("Erased"),
        ),
    ];
    for (path, method, id, request, response) in operations {
        let mut op = json!({"operationId":id,"security":[{"bearer":[]}],"responses":{"200":{"description":"Authorized result","content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{}",response.unwrap_or("Problem"))}}}},"400":{"description":"Invalid bounded request"},"401":{"description":"Verified access token required"},"403":{"description":"Current caller policy refused"},"404":{"description":"Absent or unauthorized run"},"409":{"description":"State or recovery conflict"},"503":{"description":"Database, audit or verifier unavailable"}}});
        op["responses"]["401"]["headers"] = json!({"WWW-Authenticate":{
            "description":"Bearer authentication challenge for missing or refused credentials.",
            "schema":{"type":"string","const":"Bearer"}
        }});
        if method == "post" {
            op["responses"]["415"] =
                json!({"description":"JSON media type required after caller authorization"});
        }
        if path.contains("{run}") {
            op["parameters"] = json!([run_param.clone()]);
        }
        if id == "listRuns" {
            op["parameters"] = json!([{"name":"limit","in":"query","schema":{"type":"integer","minimum":1,"maximum":100,"default":20}}]);
        }
        if id == "startRun" {
            op["parameters"] = json!([{"name":"Idempotency-Key","in":"header","required":true,"schema":{"type":"string","minLength":1,"maxLength":256}}]);
        }
        if let Some(request) = request {
            op["requestBody"] = json!({"required":true,"content":{"application/json":{"schema":{"$ref":format!("#/components/schemas/{request}")}}}});
        }
        paths.entry(path.to_owned()).or_insert_with(|| json!({}))[method] = op;
    }
    for (path, key) in [("/health", "live"), ("/ready", "ready")] {
        paths.insert(path.into(),json!({"get":{"operationId":key,"responses":{"200":{"description":"Health result","content":{"application/json":{"schema":{"type":"object","required":[key],"properties":{key:{"type":"boolean"}}}}}},"503":{"description":"Deployment unavailable or in recovery hold"}}}}));
    }
    let nullable_text = json!({"type":["string","null"]});
    let date = json!({"type":"string","format":"date-time"});
    let operation_ids: Vec<_> = crate::operations::descriptors()
        .iter()
        .map(|operation| operation.id)
        .collect();
    let status = json!({"type":"object","required":["runId","workflowId","workflowVersion","definitionDigest","bindingDigest","step","state","admittedAt","deadlineAt","uncertain","restoreReviewRequired"],"properties":{"runId":{"type":"string","format":"uuid"},"workflowId":{"type":"string"},"workflowVersion":{"type":"string"},"definitionDigest":{"type":"string"},"bindingDigest":{"type":"string"},"step":{"type":"string"},"state":{"type":"string"},"outcome":nullable_text,"output":{},"failureCode":nullable_text,"admittedAt":date,"deadlineAt":date,"nextDueAt":{"type":["string","null"],"format":"date-time"},"uncertain":{"type":"boolean"},"restoreReviewRequired":{"type":"boolean"}}});
    let schemas = json!({
      "Start":{"type":"object","additionalProperties":false,"required":["flow","input"],"properties":{"flow":{"type":"string","minLength":1,"maxLength":128},"input":{}}},
      "Reason":{"type":"object","additionalProperties":false,"required":["reason"],"properties":{"reason":{"type":"string","minLength":1,"maxLength":256}}},
      "ExecutionRecovery":{"type":"object","additionalProperties":false,"required":["recoveryReference","executionHistoryComplete","priorDeploymentFenced"],"properties":{"recoveryReference":{"type":"string","minLength":1,"maxLength":256},"executionHistoryComplete":{"type":"boolean"},"priorDeploymentFenced":{"type":"boolean"}}},
      "ExecutionReviewed":{"type":"object","required":["executionRecoveryReviewed"],"properties":{"executionRecoveryReviewed":{"type":"boolean"}}},
      "AdmissionRelease":{"type":"object","additionalProperties":false,"required":["recoveryReference","admissionHistoryComplete","priorDeploymentFenced"],"properties":{"recoveryReference":{"type":"string","minLength":1,"maxLength":256},"admissionHistoryComplete":{"type":"boolean"},"priorDeploymentFenced":{"type":"boolean"}}},
      "AdmissionHold":{"type":"object","required":["admissionsHold"],"properties":{"admissionsHold":{"type":"boolean"}}},
      "Retention":{"type":"object","additionalProperties":false,"required":["before","limit"],"properties":{"before":{"type":"string","format":"date-time"},"limit":{"type":"integer","minimum":1,"maximum":100}}},
      "RunStatus":status,"RunList":{"type":"object","required":["runs"],"properties":{"runs":{"type":"array","maxItems":100,"items":{"$ref":"#/components/schemas/RunStatus"}}}},
      "StepStatus":{"type":"object","required":["step","state","generation","attempt","commandPrepared","uncertain","receiptExpired"],"properties":{"step":{"type":"string"},"state":{"type":"string"},"generation":{"type":"integer"},"attempt":{"type":"integer"},"nextDueAt":{"type":["string","null"],"format":"date-time"},"leaseExpiresAt":{"type":["string","null"],"format":"date-time"},"commandPrepared":{"type":"boolean"},"uncertain":{"type":"boolean"},"receiptExpired":{"type":"boolean"},"failureCode":{"type":["string","null"]}}},
      "OperationIdentity":{"type":"object","additionalProperties":false,"description":"Pinned public operation contract; does not establish current authority or receipt availability.","required":["id","version","product","effect","keyRequirement","requiresPreparation","recovery","readReceipt"],"properties":{"id":{"type":"string","enum":operation_ids},"version":{"type":"integer","minimum":1},"product":{"type":"string"},"effect":{"type":"string","enum":["read","mutation"]},"keyRequirement":{"type":"string","enum":["none","required"]},"requiresPreparation":{"type":"boolean"},"recovery":{"type":"string","enum":["read-again","same-command-and-receipt","same-command"]},"readReceipt":{"type":"boolean"}}},
      "RunInspection":{"type":"object","required":["run","steps","recovery"],"properties":{"run":{"$ref":"#/components/schemas/RunStatus"},"steps":{"type":"array","items":{"$ref":"#/components/schemas/StepStatus"}},"recovery":{"type":"object","required":["retryAllowed"],"properties":{"retryAllowed":{"type":"boolean"},"reason":{"type":["string","null"]},"operation":{"$ref":"#/components/schemas/OperationIdentity"}}}}},
      "Doctor":{"type":"object","required":["activationReady","state"],"properties":{"activationReady":{"type":"boolean"},"state":{"type":"object","required":["databaseId","schemaVersion","restoreHold","auditReady","admissionsHold","restoreReviewRequired","states","uncertain","terminalPayloads","oldestTerminalPayloadAt"],"properties":{"databaseId":{"type":"string"},"schemaVersion":{"type":"integer"},"restoreHold":{"type":"boolean"},"auditReady":{"type":"boolean"},"admissionsHold":{"type":"boolean"},"restoreReviewRequired":{"type":"integer","minimum":0},"states":{"type":"object","additionalProperties":{"type":"integer"}},"uncertain":{"type":"integer"},"oldestDueAt":{"type":["string","null"],"format":"date-time"},"terminalPayloads":{"type":"integer","minimum":0},"oldestTerminalPayloadAt":{"type":["string","null"],"format":"date-time"}}}}},
      "RetryScheduled":{"type":"object","required":["runId","status"],"properties":{"runId":{"type":"string","format":"uuid"},"status":{"const":"retry-scheduled"}}},
      "Hold":{"type":"object","required":["restoreHold"],"properties":{"restoreHold":{"type":"boolean"}}},"Erased":{"type":"object","required":["erased"],"properties":{"erased":{"type":"integer","minimum":0}}},
      "Problem":{"type":"object","required":["code","message"],"properties":{"code":{"type":"string"},"message":{"type":"string"},"suggestedAction":{"type":["string","null"]}}}
    });
    json!({"openapi":"3.1.0","info":{"title":"Registry Coordinator","version":env!("CARGO_PKG_VERSION")},"components":{"securitySchemes":{"bearer":{"type":"http","scheme":"bearer","bearerFormat":"JWT"}},"schemas":schemas},"paths":paths})
}
