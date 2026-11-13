// SPDX-License-Identifier: Apache-2.0
//! Explicit external views and machine-only refresh over an authorised local root.

use super::*;
use crate::external_refresh_config::ResolvedExternalRefreshPlan;
use crate::external_views::{
    ExternalCardinality, ExternalFieldType, ExternalLinkPermissionSource, ExternalProjectionMode,
    ExternalViewSource,
};
use crate::query::{ComparisonOp, FilterExpr, FilterPredicate, Literal, OrderDirection};
use registry_platform_oidc::ActorKind;

const MAX_REFRESH_BODY_BYTES: usize = 4096;

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

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum RefreshMode {
    Projection,
    Labels,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ManagedRefreshStep {
    #[serde(default)]
    start_sweep: bool,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct ExternalRefreshHint {
    pub(crate) hint_id: String,
    pub(crate) projection: String,
    pub(crate) selector_scheme: String,
    pub(crate) selector: String,
}

pub(crate) enum HintAdmission {
    Accepted,
    Conflict,
    AtCapacity,
}

pub(crate) trait ExternalViewService: Send + Sync {
    fn read(
        &self,
        request: ExternalViewRequest,
    ) -> ServiceFuture<'_, Result<Value, ExternalViewError>>;
    fn refresh(
        &self,
        request: ExternalViewRequest,
        mode: RefreshMode,
    ) -> ServiceFuture<'_, Result<Value, ExternalViewError>>;

    fn managed_plan(&self, _plan: &str) -> Option<&ResolvedExternalRefreshPlan> {
        None
    }

    fn managed_step(
        &self,
        _plan: String,
        _request: ExternalViewRequest,
        _start_sweep: bool,
    ) -> ServiceFuture<'_, Result<Value, ExternalViewError>> {
        Box::pin(async { Err(ExternalViewError::Concealed) })
    }

    fn admit_hint(
        &self,
        _plan: String,
        _claims: VerifiedRequestClaims,
        _correlation: RequestCorrelation,
        _deadline: tokio::time::Instant,
        _hint: ExternalRefreshHint,
    ) -> ServiceFuture<'_, Result<HintAdmission, ExternalViewError>> {
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
            )
            .route("/v1/external-views/{view}/{link}/refresh", post(refresh))
            .route(
                "/v1/external-views/{view}/{link}/refresh-labels",
                post(refresh_labels),
            );
        if registry
            .external_views()
            .projections
            .values()
            .any(|projection| projection.mode == ExternalProjectionMode::Indexed)
        {
            app = app
                .route("/v1/external-refresh-plans/{plan}/step", post(managed_step))
                .route("/v1/external-refresh-plans/{plan}/hints", post(admit_hint));
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

fn verified_worker<'a>(
    claims: &VerifiedRequestClaims,
    principal_claim: &str,
    principal: &str,
    requester_client: &str,
    row_claims: impl IntoIterator<Item = (&'a str, &'a BTreeSet<String>)>,
) -> bool {
    claims.actor_kind() == Some(ActorKind::Service)
        && claims.principal_claim() == Some(principal_claim)
        && claims.principal() == Some(principal)
        && claims.requester_client() == Some(requester_client)
        && row_claims.into_iter().all(|(name, expected)| {
            claims
                .direct_claim(name)
                .is_some_and(|value| value.values() == *expected)
        })
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

async fn managed_step(
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
    let worker = &plan.worker;
    if !verified_worker(
        &claims,
        &worker.principal_claim,
        &worker.principal,
        &worker.requester_client,
        worker
            .row_claims
            .iter()
            .filter(|(name, _)| plan.target.target_claim_names.contains(*name))
            .map(|(name, values)| (name.as_str(), values)),
    ) || !worker
        .required_scopes
        .iter()
        .all(|scope| claims.has_scope(scope))
        || (!worker.required_purposes.is_empty()
            && !claims
                .purpose()
                .is_some_and(|purpose| worker.required_purposes.contains(purpose)))
    {
        return concealed();
    }
    let Some(view) = service
        .registry
        .external_views()
        .views
        .get(&plan.target.view)
    else {
        return concealed();
    };
    let Some(context) = root_context(
        &service,
        view,
        Operation::List,
        Some(worker.access_profile.clone()),
        &claims,
        request.headers(),
    ) else {
        return concealed();
    };
    let Some(body) = refresh_body::<ManagedRefreshStep>(request).await else {
        return invalid_request();
    };
    let result = backend
        .managed_step(
            id,
            ExternalViewRequest {
                context,
                correlation,
                view: plan.target.view.clone(),
                link: plan.target.link.clone(),
                root: None,
                query: ExternalQueryMode::First(ExternalQuery {
                    page_size: plan.page_size,
                    ..ExternalQuery::default()
                }),
                deadline: refresh_deadline(deadline),
            },
            body.start_sweep,
        )
        .await;
    no_store(match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => external_view_problem(error),
    })
}

async fn admit_hint(
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
    let Some(hint) = refresh_body::<ExternalRefreshHint>(request).await else {
        return invalid_request();
    };
    if !plan.notifiers.get(&hint.projection).is_some_and(permits) {
        return concealed();
    }
    let Some(projection) = service
        .registry
        .external_views()
        .projections
        .get(&hint.projection)
    else {
        return concealed();
    };
    if !valid_idempotency_key(&hint.hint_id)
        || projection.selector_scheme.as_str() != hint.selector_scheme
        || !registry_adapter_core::projection_token_valid(&hint.selector)
    {
        return invalid_request();
    }
    let result = backend
        .admit_hint(id, claims, correlation, refresh_deadline(deadline), hint)
        .await;
    no_store(match result {
        Ok(HintAdmission::Accepted) => StatusCode::ACCEPTED.into_response(),
        Ok(HintAdmission::Conflict) => fixed_problem(ProblemCode::IdempotencyConflict),
        Ok(HintAdmission::AtCapacity) => (
            StatusCode::TOO_MANY_REQUESTS,
            [(axum::http::header::RETRY_AFTER, "30")],
        )
            .into_response(),
        Err(error) => external_view_problem(error),
    })
}

struct ReadTarget {
    view: String,
    link: String,
    root: Option<String>,
    refresh: Option<RefreshMode>,
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
            refresh: None,
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
            refresh: None,
        },
    )
    .await
}

async fn refresh(
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
            refresh: Some(RefreshMode::Projection),
        },
    )
    .await
}

async fn refresh_labels(
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
            refresh: Some(RefreshMode::Labels),
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
    let grant = if let Some(mode) = target.refresh {
        let Some(ids) = inventory.refresh.get(profile) else {
            return concealed();
        };
        if projection.mode != ExternalProjectionMode::Indexed || !ids.contains(&projection.id) {
            return concealed();
        }
        if mode == RefreshMode::Labels
            && (projection.cardinality != ExternalCardinality::Many
                || !link
                    .label
                    .as_ref()
                    .is_some_and(|label| ids.contains(&label.projection)))
        {
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
    let allows_query = projection.mode == ExternalProjectionMode::Indexed
        && (!is_detail || projection.cardinality == ExternalCardinality::Many);
    let query = match plan_query(
        options.parsed.mode,
        grant,
        &record_type.fields,
        allows_query,
        target.refresh.is_some(),
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
    let result = if let Some(mode) = target.refresh {
        backend.refresh(request, mode).await
    } else {
        backend.read(request).await
    };
    no_store(match result {
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
    refresh: bool,
) -> Result<ExternalQueryMode, &'static str> {
    let options = match mode {
        strict_query::ParsedReadQueryMode::SkipToken { token } if allows_query || refresh => {
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
    if options.top.is_some() && !allows_query && !refresh {
        return Err("$top");
    }
    let page_size = u16::try_from(options.top.unwrap_or(50))
        .ok()
        .filter(|size| (1..=100).contains(size))
        .ok_or("$top")?;
    let equality = options
        .filter
        .map(|filter| {
            if !allows_query || refresh {
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
            if !allows_query || refresh {
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
    if options.count.is_some()
        && (!allows_query || refresh || !grant.is_some_and(|grant| grant.allow_count))
    {
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

    #[test]
    fn managed_worker_requires_the_verified_actor_and_exact_row_claim() {
        let claims = |tenant: &str, client: &str, kind| {
            VerifiedRequestClaims::authenticated(
                "registry_principal",
                "worker-principal",
                BTreeSet::from(["registry.refresh".to_owned()]),
                Some("consultation".to_owned()),
                BTreeMap::from([(
                    "tenant".to_owned(),
                    VerifiedClaimValue::direct_string(tenant).unwrap(),
                )]),
            )
            .unwrap()
            .with_contextual_authority(
                Some(kind),
                Some(client.to_owned()),
                None,
                None,
                BTreeMap::new(),
            )
            .unwrap()
        };
        let expected = BTreeSet::from(["allowed".to_owned()]);
        let permits = |claims: &VerifiedRequestClaims| {
            verified_worker(
                claims,
                "registry_principal",
                "worker-principal",
                "worker-client",
                [("tenant", &expected)],
            )
        };
        assert!(permits(&claims(
            "allowed",
            "worker-client",
            ActorKind::Service
        )));
        assert!(!permits(&claims(
            "outside",
            "worker-client",
            ActorKind::Service
        )));
        assert!(!permits(&claims(
            "allowed",
            "other-client",
            ActorKind::Service
        )));
        assert!(!permits(&claims(
            "allowed",
            "worker-client",
            ActorKind::Human
        )));
    }

    #[test]
    fn managed_step_body_is_closed_and_rejects_duplicate_instructions() {
        let parse = decode_refresh_body::<ManagedRefreshStep>;
        assert!(!parse(b"{}").unwrap().start_sweep);
        assert!(parse(br#"{"startSweep":true}"#).unwrap().start_sweep);
        assert!(parse(br#"{"scope":"outside"}"#).is_none());
        assert!(parse(br#"{"startSweep":true,"startSweep":false}"#).is_none());
    }

    async fn body(response: Response) -> Value {
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await.unwrap()).unwrap()
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
