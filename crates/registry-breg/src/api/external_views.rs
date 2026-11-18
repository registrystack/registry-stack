// SPDX-License-Identifier: Apache-2.0
//! Explicit external views, root refresh requests from a staff application's
//! service client, and the in-process refresh worker.

use super::*;
use crate::external_refresh_config::ResolvedExternalRefreshPlan;
use crate::external_views::{
    ExternalCardinality, ExternalFieldType, ExternalLinkPermissionSource, ExternalProjectionMode,
    ExternalViewSource,
};
use crate::query::{ComparisonOp, FilterExpr, FilterPredicate, Literal, OrderDirection};
use registry_platform_oidc::ActorKind;

const MAX_REFRESH_BODY_BYTES: usize = 4096;
/// How often the in-process worker looks for due or ready refresh plans.
const REFRESH_TICK: std::time::Duration = std::time::Duration::from_secs(5);
/// Each worker step runs under its own deadline.
const REFRESH_STEP_DEADLINE: std::time::Duration = std::time::Duration::from_secs(10);
/// A plan starts no new step once its turn has run this long, so one busy
/// plan cannot hold the others back for a whole tick.
const REFRESH_PLAN_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) struct ExternalViewRequest {
    pub(crate) context: AuthorizedRequestContext,
    pub(crate) correlation: RequestCorrelation,
    pub(crate) view: String,
    pub(crate) link: String,
    pub(crate) root: Option<Uuid>,
    pub(crate) query: ExternalQueryMode,
    pub(crate) deadline: tokio::time::Instant,
}

pub(crate) enum ExternalQueryMode {
    First(ExternalQuery),
    Continue(String),
}

#[derive(Clone, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ExternalQuery {
    pub(crate) equality: Option<ExternalEquality>,
    pub(crate) order: Option<ExternalOrder>,
    pub(crate) page_size: u16,
    pub(crate) include_count: bool,
}

#[derive(Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ExternalEquality {
    pub(crate) field: String,
    pub(crate) value: Value,
}

#[derive(Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ExternalOrder {
    pub(crate) field: String,
    pub(crate) descending: bool,
}

#[derive(Clone, Debug)]
pub(crate) enum ExternalViewError {
    Concealed,
    InvalidCursor,
    Incomplete,
    Unavailable,
    /// This projection cannot serve: its binding was refused, its grant has
    /// expired or its scope moved to another binding. Other views still serve.
    ProjectionUnavailable(String),
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ExternalSourceChange {
    pub(crate) projection: String,
    pub(crate) selector: String,
}

pub(crate) enum SourceChangeAdmission {
    Accepted,
    AtCapacity,
}

pub(crate) trait ExternalViewService: Send + Sync {
    fn read(
        &self,
        request: ExternalViewRequest,
    ) -> ServiceFuture<'_, Result<Value, ExternalViewError>>;

    /// Queue one admitted root for the in-process worker's next tick.
    fn request_root_refresh(
        &self,
        _request: ExternalViewRequest,
    ) -> ServiceFuture<'_, Result<SourceChangeAdmission, ExternalViewError>> {
        Box::pin(async { Err(ExternalViewError::Concealed) })
    }

    fn managed_plan(&self, _plan: &str) -> Option<&ResolvedExternalRefreshPlan> {
        None
    }

    /// The configured plans that are due or hold ready work now.
    fn runnable_managed_plans(&self) -> ServiceFuture<'_, Result<Vec<String>, ExternalViewError>> {
        Box::pin(async { Ok(Vec::new()) })
    }

    fn managed_step(
        &self,
        _plan: String,
        _request: ExternalViewRequest,
    ) -> ServiceFuture<'_, Result<Value, ExternalViewError>> {
        Box::pin(async { Err(ExternalViewError::Concealed) })
    }

    fn admit_source_change(
        &self,
        _plan: String,
        _claims: VerifiedRequestClaims,
        _correlation: RequestCorrelation,
        _deadline: tokio::time::Instant,
        _change: ExternalSourceChange,
    ) -> ServiceFuture<'_, Result<SourceChangeAdmission, ExternalViewError>> {
        Box::pin(async { Err(ExternalViewError::Concealed) })
    }
}

pub(super) fn routes(registry: &CompiledRegistry) -> Router<Arc<HttpService>> {
    let mut app = Router::new();
    if !registry.external_views().views.is_empty() {
        app = app
            .route("/v1/external-views/{view}/{link}/records", get(collection))
            .route(
                "/v1/external-views/{view}/{link}/records/{root}",
                get(detail),
            );
        if registry
            .external_views()
            .projections
            .values()
            .any(|projection| projection.mode == ExternalProjectionMode::Indexed)
        {
            app = app
                .route(
                    "/v1/external-views/{view}/{link}/records/{root}/refresh",
                    post(root_refresh),
                )
                .route(
                    "/v1/external-refresh-plans/{plan}/source-changes",
                    post(admit_source_change),
                );
        }
    }
    app
}

fn decode_refresh_body<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Option<T> {
    serde_json::from_value(parse_json_strict(bytes).ok()?).ok()
}

async fn refresh_body<T: serde::de::DeserializeOwned>(
    request: axum::extract::Request,
) -> Option<T> {
    if !single_content_type(request.headers(), "application/json")
        || request.uri().query().is_some()
    {
        return None;
    }
    let bytes = to_bytes(request.into_body(), MAX_REFRESH_BODY_BYTES)
        .await
        .ok()?;
    decode_refresh_body(&bytes)
}

fn root_context(
    service: &HttpService,
    view: &ExternalViewSource,
    operation: Operation,
    access_profile: Option<String>,
    claims: &VerifiedRequestClaims,
    headers: &HeaderMap,
) -> Option<AuthorizedRequestContext> {
    let route = service.registry.routes().routes.iter().find(|route| {
        route.entity_id == view.record_type.as_str()
            && route.operation == operation
            && read_path_for_route(service, route).is_none()
    })?;
    let mut options = QueryOptions::default();
    options.parsed.access_profile = access_profile;
    let authorised = authorize_route(service, route, claims, &options)?;
    let mut context = authorised.context;
    context
        .bind_access_attribution(authorised.response_entity, headers)
        .ok()?;
    Some(context)
}

fn refresh_deadline(
    deadline: Option<Extension<crate::correlation::RequestDeadline>>,
) -> tokio::time::Instant {
    deadline
        .map(|Extension(value)| value.0)
        .unwrap_or_else(|| tokio::time::Instant::now() + std::time::Duration::from_secs(10))
}

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// A queued request answers 202 with no body; a full queue answers 429 and
/// the caller retries later.
fn admission_response(result: Result<SourceChangeAdmission, ExternalViewError>) -> Response {
    no_store(match result {
        Ok(SourceChangeAdmission::Accepted) => StatusCode::ACCEPTED.into_response(),
        Ok(SourceChangeAdmission::AtCapacity) => (
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, "30")],
        )
            .into_response(),
        Err(error) => external_view_problem(error),
    })
}

/// One plan's turn in one worker tick: its step reports in order, and the
/// failure that ended the turn, if any.
pub(crate) struct ManagedRefreshTick {
    pub(crate) plan: String,
    pub(crate) steps: Vec<Value>,
    pub(crate) failure: Option<ExternalViewError>,
}

/// Run one worker tick: every configured refresh plan that is due or holds
/// ready work takes bounded steps as its configured worker identity. The
/// worker holds no bearer token; each plan's principal, requester client,
/// scopes, purpose and row claims come from the runtime file, and the plan's
/// access profile admits the root list exactly as it would a request.
#[cfg(all(test, feature = "postgres-test"))]
pub(crate) async fn managed_refresh_tick(service: &HttpService) -> Vec<ManagedRefreshTick> {
    refresh_tick(service, None).await.unwrap_or_default()
}

/// The in-process refresh worker. It ticks every five seconds until
/// shutdown, and a requested shutdown stops it between steps. A tick in which
/// every plan's turn completed records progress.
pub(crate) async fn run_managed_refresh(
    service: Arc<HttpService>,
    last_success: Arc<crate::metrics::LastSuccess>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) {
    let mut interval = tokio::time::interval(REFRESH_TICK);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            change = shutdown.changed() => {
                if change.is_err() || *shutdown.borrow() { return; }
            }
            _ = interval.tick() => {
                let ticks = refresh_tick(&service, Some(&shutdown)).await;
                if ticks.is_some_and(|ticks| ticks.iter().all(|tick| tick.failure.is_none())) {
                    last_success.record();
                }
            }
        }
    }
}

/// `None` when the plan state could not be read; that failure is logged.
async fn refresh_tick(
    service: &HttpService,
    shutdown: Option<&tokio::sync::watch::Receiver<bool>>,
) -> Option<Vec<ManagedRefreshTick>> {
    let Some(backend) = service.external_views.as_ref() else {
        return Some(Vec::new());
    };
    let plans = match backend.runnable_managed_plans().await {
        Ok(plans) => plans,
        Err(_) => {
            tracing::warn!(
                reason = "unavailable",
                "external refresh worker could not read its plans"
            );
            return None;
        }
    };
    let stopping = || shutdown.is_some_and(|shutdown| *shutdown.borrow());
    let mut ticks = Vec::with_capacity(plans.len());
    for id in plans {
        if stopping() {
            break;
        }
        let mut tick = ManagedRefreshTick {
            plan: id,
            steps: Vec::new(),
            failure: None,
        };
        let started = tokio::time::Instant::now();
        loop {
            let request = backend
                .managed_plan(&tick.plan)
                .ok_or(ExternalViewError::Concealed)
                .and_then(|plan| worker_request(service, plan));
            let result = match request {
                Ok(request) => backend.managed_step(tick.plan.clone(), request).await,
                Err(error) => {
                    tracing::warn!(
                        plan = %tick.plan,
                        reason = "worker-refused",
                        "external refresh plan's worker identity was not admitted"
                    );
                    Err(error)
                }
            };
            match result {
                Ok(step) => {
                    let more = step.get("moreWork") == Some(&Value::Bool(true));
                    tick.steps.push(step);
                    if !more || started.elapsed() >= REFRESH_PLAN_BUDGET || stopping() {
                        break;
                    }
                }
                Err(error) => {
                    tick.failure = Some(error);
                    break;
                }
            }
        }
        ticks.push(tick);
    }
    Some(ticks)
}

/// The plan's configured worker identity, admitted to its root list through
/// the plan's access profile as a request would be.
fn worker_request(
    service: &HttpService,
    plan: &ResolvedExternalRefreshPlan,
) -> Result<ExternalViewRequest, ExternalViewError> {
    let claims = plan
        .worker_claims()
        .map_err(|_| ExternalViewError::Concealed)?;
    let view = service
        .registry
        .external_views()
        .views
        .get(&plan.target.view)
        .ok_or(ExternalViewError::Concealed)?;
    let context = root_context(
        service,
        view,
        Operation::List,
        Some(plan.worker.access_profile.clone()),
        &claims,
        &HeaderMap::new(),
    )
    .ok_or(ExternalViewError::Concealed)?;
    Ok(ExternalViewRequest {
        context,
        correlation: RequestCorrelation::breg_created(),
        view: plan.target.view.clone(),
        link: plan.target.link.clone(),
        root: None,
        query: ExternalQueryMode::First(ExternalQuery {
            page_size: plan.page_size,
            ..ExternalQuery::default()
        }),
        deadline: tokio::time::Instant::now() + REFRESH_STEP_DEADLINE,
    })
}

async fn admit_source_change(
    State(service): State<Arc<HttpService>>,
    Authenticated(claims): Authenticated,
    Extension(correlation): Extension<RequestCorrelation>,
    deadline: Option<Extension<crate::correlation::RequestDeadline>>,
    Path(id): Path<String>,
    request: axum::extract::Request,
) -> Response {
    let Some(backend) = service.external_views.as_ref() else {
        return concealed();
    };
    let Some(plan) = backend.managed_plan(&id) else {
        return concealed();
    };
    let permits = |notifier: &crate::external_refresh_config::ResolvedExternalRefreshNotifier| {
        claims.actor_kind() == Some(ActorKind::Service)
            && claims.principal().is_some()
            && claims.requester_client() == Some(notifier.requester_client.as_str())
            && claims.has_scope(&notifier.required_scope)
    };
    if !plan.notifiers.values().any(permits) {
        return concealed();
    }
    let Some(change) = refresh_body::<ExternalSourceChange>(request).await else {
        return invalid_request();
    };
    if !plan.notifiers.get(&change.projection).is_some_and(permits) {
        return concealed();
    }
    if !service
        .registry
        .external_views()
        .projections
        .contains_key(&change.projection)
    {
        return concealed();
    }
    if !registry_adapter_core::projection_token_valid(&change.selector) {
        return invalid_request();
    }
    admission_response(
        backend
            .admit_source_change(id, claims, correlation, refresh_deadline(deadline), change)
            .await,
    )
}

struct ReadTarget {
    view: String,
    link: String,
    root: Option<String>,
    /// A root refresh request rather than a read.
    refresh: bool,
}

async fn collection(
    State(service): State<Arc<HttpService>>,
    Authenticated(claims): Authenticated,
    Extension(correlation): Extension<RequestCorrelation>,
    deadline: Option<Extension<crate::correlation::RequestDeadline>>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    Path((view, link)): Path<(String, String)>,
) -> Response {
    handle(
        &service,
        &claims,
        correlation,
        deadline,
        raw,
        &headers,
        ReadTarget {
            view,
            link,
            root: None,
            refresh: false,
        },
    )
    .await
}

async fn detail(
    State(service): State<Arc<HttpService>>,
    Authenticated(claims): Authenticated,
    Extension(correlation): Extension<RequestCorrelation>,
    deadline: Option<Extension<crate::correlation::RequestDeadline>>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    Path((view, link, root)): Path<(String, String, String)>,
) -> Response {
    handle(
        &service,
        &claims,
        correlation,
        deadline,
        raw,
        &headers,
        ReadTarget {
            view,
            link,
            root: Some(root),
            refresh: false,
        },
    )
    .await
}

/// Queue one root for the in-process worker. The caller is a staff
/// application's service client whose selected profile may Get the root and
/// holds `refreshExternalProjections` for the link's projection.
async fn root_refresh(
    State(service): State<Arc<HttpService>>,
    Authenticated(claims): Authenticated,
    Extension(correlation): Extension<RequestCorrelation>,
    deadline: Option<Extension<crate::correlation::RequestDeadline>>,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    Path((view, link, root)): Path<(String, String, String)>,
) -> Response {
    handle(
        &service,
        &claims,
        correlation,
        deadline,
        raw,
        &headers,
        ReadTarget {
            view,
            link,
            root: Some(root),
            refresh: true,
        },
    )
    .await
}

async fn handle(
    service: &HttpService,
    claims: &VerifiedRequestClaims,
    correlation: RequestCorrelation,
    deadline: Option<Extension<crate::correlation::RequestDeadline>>,
    raw: Option<String>,
    headers: &HeaderMap,
    target: ReadTarget,
) -> Response {
    let inventory = service.registry.external_views();
    let Some(view) = inventory.views.get(&target.view) else {
        return concealed();
    };
    let Some(link) = view
        .links
        .iter()
        .find(|link| link.id.as_str() == target.link)
    else {
        return concealed();
    };
    let Some(projection) = inventory.projections.get(link.projection.as_str()) else {
        return unavailable();
    };
    let is_detail = target.root.is_some();
    let root_operation = if is_detail {
        Operation::Get
    } else {
        Operation::List
    };
    let profile_selection = admission_profile(raw.as_deref());
    let Some(context) = root_context(
        service,
        view,
        root_operation,
        profile_selection.clone(),
        claims,
        headers,
    ) else {
        return concealed();
    };
    let profile = context.selected_profile();
    if context.purpose() != Some(projection.purpose.as_str()) {
        return concealed();
    }
    let grant = if target.refresh {
        let Some(ids) = inventory.refresh.get(profile) else {
            return concealed();
        };
        if projection.mode != ExternalProjectionMode::Indexed || !ids.contains(&projection.id) {
            return concealed();
        }
        None
    } else {
        let Some(grant) = inventory
            .grants
            .get(profile)
            .and_then(|views| views.get(&target.view))
            .and_then(|grant| grant.links.iter().find(|grant| grant.link == link.id))
        else {
            return concealed();
        };
        if !is_detail
            && (projection.mode != ExternalProjectionMode::Indexed
                || projection.cardinality != ExternalCardinality::One)
        {
            return concealed();
        }
        Some(grant)
    };
    let root = match target.root {
        Some(root) => match Uuid::parse_str(&root) {
            Ok(id) if id.hyphenated().to_string() == root => Some(id),
            _ => return concealed(),
        },
        None => None,
    };
    let options = match QueryOptions::parse(raw.as_deref(), true) {
        Ok(value) => value,
        Err(error) => return error.problem(),
    };
    if options.parsed.as_of.is_some() || options.parsed.access_profile != profile_selection {
        return invalid_query_at("query");
    }
    let Some(record_type) = inventory.record_types.get(projection.record_type.as_str()) else {
        return unavailable();
    };
    // A root refresh takes no query beyond the selected profile.
    let allows_query = projection.mode == ExternalProjectionMode::Indexed
        && !target.refresh
        && (!is_detail || projection.cardinality == ExternalCardinality::Many);
    let query = match plan_query(
        options.parsed.mode,
        grant,
        &record_type.fields,
        allows_query,
    ) {
        Ok(query) => query,
        Err(parameter) => return invalid_query_at(parameter),
    };
    let Some(backend) = &service.external_views else {
        return unavailable();
    };
    let request = ExternalViewRequest {
        context,
        correlation,
        view: target.view,
        link: target.link,
        root,
        query,
        deadline: refresh_deadline(deadline),
    };
    if target.refresh {
        return admission_response(backend.request_root_refresh(request).await);
    }
    no_store(match backend.read(request).await {
        Ok(value) => Json(value).into_response(),
        Err(error) => external_view_problem(error),
    })
}

fn external_view_problem(error: ExternalViewError) -> Response {
    match error {
        ExternalViewError::Concealed => concealed(),
        ExternalViewError::InvalidCursor => cursor_invalid(),
        ExternalViewError::Incomplete => fixed_problem(ProblemCode::ExternalViewIncomplete),
        ExternalViewError::Unavailable => unavailable(),
        ExternalViewError::ProjectionUnavailable(projection) => projection_unavailable(&projection),
    }
}

/// The backend reports this only after the caller's view and link grant was
/// admitted, so naming the compiled projection discloses no source value.
fn projection_unavailable(projection: &str) -> Response {
    let code = ProblemCode::SourceUnavailable;
    crate::correlation::problem_response_with_field_path(
        StatusCode::from_u16(code.status()).expect("problem catalogue status is valid"),
        code.title(),
        code.description(),
        code.code(),
        format!(
            "/externalProjections/{}",
            projection.replace('~', "~0").replace('/', "~1")
        ),
    )
}

fn plan_query(
    mode: strict_query::ParsedReadQueryMode,
    grant: Option<&ExternalLinkPermissionSource>,
    fields: &[crate::external_views::ExternalFieldSource],
    allows_query: bool,
) -> Result<ExternalQueryMode, &'static str> {
    let options = match mode {
        strict_query::ParsedReadQueryMode::SkipToken { token } if allows_query => {
            return Ok(ExternalQueryMode::Continue(token));
        }
        strict_query::ParsedReadQueryMode::SkipToken { .. } => return Err("$skiptoken"),
        strict_query::ParsedReadQueryMode::Query(options) => options,
    };
    if options.select.is_some() {
        return Err("$select");
    }
    if options.bbox.is_some() {
        return Err("bbox");
    }
    if options.top.is_some() && !allows_query {
        return Err("$top");
    }
    let page_size = u16::try_from(options.top.unwrap_or(50))
        .ok()
        .filter(|size| (1..=100).contains(size))
        .ok_or("$top")?;
    let equality = options
        .filter
        .map(|filter| {
            if !allows_query {
                return Err("$filter");
            }
            let FilterExpr::Predicate(FilterPredicate::Compare {
                field,
                op: ComparisonOp::Eq,
                literal,
            }) = filter
            else {
                return Err("$filter");
            };
            let id = registry_platform_yaml::LocalId::new(field.as_str()).map_err(|_| "$filter")?;
            if !grant.is_some_and(|grant| grant.filterable_fields.contains(&id)) {
                return Err("$filter");
            }
            let field_type = fields
                .iter()
                .find(|candidate| candidate.id == id)
                .map(|field| field.value_type)
                .ok_or("$filter")?;
            let value = literal_value(field_type, literal).ok_or("$filter")?;
            Ok(ExternalEquality {
                field: id.as_str().to_owned(),
                value,
            })
        })
        .transpose()?;
    let order = options
        .orderby
        .map(|order| {
            if !allows_query {
                return Err("$orderby");
            }
            let id = registry_platform_yaml::LocalId::new(order.field.as_str())
                .map_err(|_| "$orderby")?;
            if !grant.is_some_and(|grant| grant.sortable_fields.contains(&id)) {
                return Err("$orderby");
            }
            Ok(ExternalOrder {
                field: id.as_str().to_owned(),
                descending: order.direction == OrderDirection::Desc,
            })
        })
        .transpose()?;
    if options.count.is_some() && (!allows_query || !grant.is_some_and(|grant| grant.allow_count)) {
        return Err("$count");
    }
    Ok(ExternalQueryMode::First(ExternalQuery {
        equality,
        order,
        page_size,
        include_count: options.count.unwrap_or(false),
    }))
}

fn literal_value(field_type: ExternalFieldType, literal: Literal) -> Option<Value> {
    match (field_type, literal) {
        (_, Literal::Null) => Some(Value::Null),
        (ExternalFieldType::String, Literal::String(value)) if value.len() <= 4096 => {
            Some(Value::String(value))
        }
        (ExternalFieldType::Integer, Literal::Integer(value)) => {
            value.parse::<i64>().ok().map(Value::from)
        }
        (ExternalFieldType::Decimal, Literal::Decimal(value) | Literal::Integer(value)) => {
            Some(Value::String(value))
        }
        (ExternalFieldType::Boolean, Literal::Boolean(value)) => Some(Value::Bool(value)),
        (ExternalFieldType::Date, Literal::String(value)) => {
            chrono::NaiveDate::parse_from_str(&value, "%Y-%m-%d")
                .ok()
                .filter(|date| date.format("%Y-%m-%d").to_string() == value)
                .map(|_| Value::String(value))
        }
        (ExternalFieldType::Uuid, Literal::String(value)) => Uuid::parse_str(&value)
            .ok()
            .map(|id| Value::String(id.hyphenated().to_string())),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_refresh_config::tests::{admitted_holder_plan, example_registry};

    async fn body(response: Response) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap()
    }

    struct Ready;
    impl ReadinessProbe for Ready {
        fn is_ready(&self) -> ServiceFuture<'_, bool> {
            Box::pin(async { true })
        }
    }

    /// Worker admission reads no Record; every read is refused.
    struct NoRecords;
    impl RecordReadService for NoRecords {
        fn get(
            &self,
            _: RecordReadRequest,
        ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
            Box::pin(async { Err(ReadServiceError::Unavailable) })
        }
        fn list(
            &self,
            _: RecordReadRequest,
        ) -> ServiceFuture<'_, Result<HeldReadResponse, ReadServiceError>> {
            Box::pin(async { Err(ReadServiceError::Unavailable) })
        }
        fn lookup(
            &self,
            _: RecordReadRequest,
        ) -> ServiceFuture<'_, Result<Option<HeldReadResponse>, ReadServiceError>> {
            Box::pin(async { Err(ReadServiceError::Unavailable) })
        }
    }

    fn example_service() -> HttpService {
        HttpService::new(
            Arc::new(example_registry()),
            ReadRuntimeIdentity {
                package_revision: "package-revision".to_owned(),
                schema_fingerprint: "schema-fingerprint".to_owned(),
            },
            Arc::new(NoRecords),
            Arc::new(Ready),
            Arc::new(
                crate::cursor::CursorCodec::new(
                    zeroize::Zeroizing::new(vec![7; 32]),
                    std::time::Duration::from_secs(60),
                )
                .unwrap(),
            ),
        )
    }

    fn refused(service: &HttpService, plan: &ResolvedExternalRefreshPlan) -> bool {
        matches!(
            worker_request(service, plan),
            Err(ExternalViewError::Concealed)
        )
    }

    #[test]
    fn the_worker_is_admitted_to_its_root_list_as_its_plan_configures() {
        let service = example_service();
        let request = worker_request(&service, &admitted_holder_plan()).unwrap();
        assert_eq!(request.context.selected_profile(), "projection-refresh");
        assert_eq!(request.view, "licence-holder-indexed");
        assert_eq!(request.link, "holder");
        assert!(request.root.is_none());
    }

    #[test]
    fn a_worker_request_refuses_a_client_its_profile_does_not_admit() {
        let service = example_service();
        let mut plan = admitted_holder_plan();
        plan.worker.requester_client = "staff-app".to_owned();
        assert!(refused(&service, &plan));
    }

    #[test]
    fn a_worker_request_refuses_a_missing_or_wrong_row_claim() {
        let service = example_service();
        let mut two_values = admitted_holder_plan();
        two_values.worker.row_claims.insert(
            "jurisdiction".to_owned(),
            BTreeSet::from(["zone-a".to_owned(), "zone-b".to_owned()]),
        );
        assert!(refused(&service, &two_values), "two values for equals");
        let mut renamed = admitted_holder_plan();
        let values = renamed.worker.row_claims.remove("jurisdiction").unwrap();
        renamed
            .worker
            .row_claims
            .insert("region".to_owned(), values);
        assert!(
            refused(&service, &renamed),
            "a claim the boundary does not use"
        );
        let mut missing = admitted_holder_plan();
        missing.worker.row_claims.remove("jurisdiction");
        assert!(refused(&service, &missing), "no jurisdiction claim");
    }

    /// The worker always acts as a service. The example's `officer` profile
    /// lists the same root for the same purpose but admits only humans, so a
    /// worker copying its client and scope is refused on actor kind alone.
    #[test]
    fn a_worker_request_refuses_a_profile_for_another_actor_kind() {
        let service = example_service();
        let mut plan = admitted_holder_plan();
        plan.worker.access_profile = "officer".to_owned();
        plan.worker.requester_client = "officer".to_owned();
        plan.worker.required_scopes = BTreeSet::from(["registry:licensing:read".to_owned()]);
        let officer = &service.registry.entities()["licence"].access_profiles["officer"];
        assert_eq!(
            crate::api::authorize_profile_claims(officer, &plan.worker_claims().unwrap()).err(),
            Some("actor-kind-mismatched")
        );
        assert!(refused(&service, &plan));
    }

    #[tokio::test]
    async fn an_unavailable_projection_names_itself_and_other_failures_stay_generic() {
        let named = external_view_problem(ExternalViewError::ProjectionUnavailable(
            "person-indexed".to_owned(),
        ));
        assert_eq!(named.status(), StatusCode::SERVICE_UNAVAILABLE);
        let named = body(named).await;
        assert_eq!(named["code"], "source.unavailable");
        assert_eq!(named["fieldPath"], "/externalProjections/person-indexed");

        let generic = external_view_problem(ExternalViewError::Unavailable);
        assert_eq!(generic.status(), StatusCode::SERVICE_UNAVAILABLE);
        let generic = body(generic).await;
        assert_eq!(generic["code"], "source.unavailable");
        assert!(generic.get("fieldPath").is_none());
    }

    #[tokio::test]
    async fn incomplete_coverage_is_a_fixed_problem_with_its_own_code() {
        let response = external_view_problem(ExternalViewError::Incomplete);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            response.headers()[axum::http::header::CONTENT_TYPE],
            "application/problem+json"
        );
        let problem = body(response).await;
        assert_eq!(problem["code"], "external_view.incomplete");
        assert_eq!(
            problem["type"],
            "https://id.registrystack.org/problems/registry-breg/external_view/incomplete"
        );
        assert_eq!(problem["title"], "Service Unavailable");
        assert_eq!(problem["status"], 503);
        assert_eq!(
            problem["detail"],
            "The external view's indexed coverage is incomplete for this request."
        );
        let members = problem
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>();
        // The correlation layer adds traceId on the served route.
        assert_eq!(
            members,
            ["code", "detail", "status", "title", "type"].into()
        );
    }
}
