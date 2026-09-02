// SPDX-License-Identifier: Apache-2.0
//! Admission for compiled immediate actions. Entity CRUD grants are not consulted.

#[cfg(test)]
#[path = "tests/immediate_action_tests.rs"]
mod tests;

use super::*;
use crate::data::{validate_field_value, FieldValue};
use crate::model::{
    ActionRouteKind, CompiledAction, CompiledActionRoute, CompiledActionTargetBinding,
};

pub(super) struct AuthorizedActionSurface<'a> {
    pub route: &'a CompiledActionRoute,
    pub action: &'a CompiledAction,
    pub context: AuthorizedActionContext,
}

pub(super) fn visible_actions<'a>(
    service: &'a HttpService,
    claims: &VerifiedRequestClaims,
    options: &QueryOptions,
) -> Vec<AuthorizedActionSurface<'a>> {
    service
        .registry
        .actions()
        .routes
        .iter()
        .filter_map(|route| authorize_action(service, route, claims, options))
        .collect()
}

pub(super) fn append_openapi(
    surfaces: &[AuthorizedActionSurface<'_>],
    paths: &mut Map<String, Value>,
    schemas: &mut Map<String, Value>,
) {
    use crate::artifacts::*;
    for surface in surfaces {
        let action = surface.action;
        let methods = paths
            .entry(surface.route.path.clone())
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .expect("compiled OpenAPI paths are objects");
        methods.insert(
            "post".to_owned(),
            openapi_action_operation(
                surface.route,
                action,
                OpenApiAccessProfiles::Selected(surface.context.selected_profile()),
            ),
        );
        match surface.route.kind {
            ActionRouteKind::Invoke => {
                schemas.insert(
                    openapi_action_input_schema_id(&action.id),
                    openapi_action_input_schema(action),
                );
                schemas.insert(
                    openapi_action_response_schema_id(&action.id),
                    openapi_action_response_schema(action, Some(surface.context.result_effects())),
                );
            }
            ActionRouteKind::TargetConditions => {
                schemas.insert(
                    openapi_action_condition_request_schema_id(&action.id),
                    openapi_action_condition_request_schema(action),
                );
                schemas.insert(
                    openapi_action_condition_response_schema_id(&action.id),
                    openapi_action_condition_response_schema(action),
                );
            }
        }
    }
}

pub(super) fn metadata(surfaces: &[AuthorizedActionSurface<'_>]) -> Value {
    Value::Array(
        surfaces
            .iter()
            .filter(|surface| surface.route.kind == ActionRouteKind::Invoke)
            .map(|surface| {
                crate::artifacts::public_action_metadata_entry(
                    surface.action,
                    Some(surface.context.selected_profile()),
                )
            })
            .collect(),
    )
}

fn authorize_action<'a>(
    service: &'a HttpService,
    route: &'a CompiledActionRoute,
    claims: &VerifiedRequestClaims,
    options: &QueryOptions,
) -> Option<AuthorizedActionSurface<'a>> {
    service.mutations.as_ref()?;
    let inventory = service.registry.actions();
    // A caller cannot construct an alternate path, operation or action under a
    // valid route identifier. Discovery and dispatch use this same inventory.
    if !inventory.routes.contains(route) || route.operation != Operation::Invoke {
        return None;
    }
    let access = inventory.access.iter().find(|entry| {
        entry.route_id == route.id
            && entry.action_id == route.action_id
            && entry.operation == route.operation
    })?;
    let selected = options
        .access_profile()
        .map(String::as_str)
        .unwrap_or(&access.default_profile_id);
    if !access.profile_ids.contains(selected)
        || !route.access_profiles.iter().any(|id| id == selected)
    {
        return None;
    }
    let action = inventory
        .actions
        .iter()
        .find(|action| action.id == route.action_id)?;
    let grant = action
        .grants
        .iter()
        .find(|grant| grant.profile_id == selected)?;
    if grant.anonymous
        || !grant.operations.contains(&Operation::Invoke)
        || grant.principal_claim.as_deref() != claims.principal_claim()
        || !grant
            .required_scopes
            .iter()
            .all(|scope| claims.has_scope(scope))
        || (!grant.required_purposes.is_empty()
            && !claims
                .purpose()
                .is_some_and(|purpose| grant.required_purposes.contains(purpose)))
    {
        return None;
    }
    let principal = claims.principal()?;
    let target_authority = grant
        .targets
        .iter()
        .map(|target| {
            Some((
                target.entity_id.clone(),
                verified_row_boundaries_from_sources(&target.row_boundaries, claims)?,
            ))
        })
        .collect::<Option<BTreeMap<_, _>>>()?;
    Some(AuthorizedActionSurface {
        route,
        action,
        context: AuthorizedActionContext::new(
            action.id.clone(),
            principal.to_owned(),
            claims.purpose().map(str::to_owned),
            selected.to_owned(),
            target_authority,
            grant.results.clone(),
        ),
    })
}

#[allow(clippy::too_many_arguments)] // Axum extractors are the HTTP contract.
pub(super) async fn dispatch(
    State(service): State<Arc<HttpService>>,
    Extension(route): Extension<CompiledActionRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    claims: Option<Extension<VerifiedRequestClaims>>,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed();
    };
    let claims = claims
        .map(|Extension(value)| value)
        .unwrap_or_else(VerifiedRequestClaims::anonymous);
    let (options, valid_options) = match QueryOptions::parse(raw_query.as_deref(), false) {
        Ok(options) => (options, true),
        Err(_) => (QueryOptions::default(), false),
    };
    let refusal =
        |response| action_refusal(mutations, &route, &claims, &options, &correlation, response);
    if !valid_options {
        return refusal(concealed()).await;
    }
    let Some(surface) = authorize_action(&service, &route, &claims, &options) else {
        return refusal(concealed()).await;
    };
    if !single_content_type(&headers, "application/json") {
        return refusal(unsupported_media_type()).await;
    }
    let idempotency_key = if route.kind == ActionRouteKind::Invoke {
        match single_header(&headers, "idempotency-key").filter(|key| valid_idempotency_key(key)) {
            Some(key) => Some(key),
            None => return refusal(invalid_request()).await,
        }
    } else {
        None
    };
    let Ok(body) = bounded_body_to(body, surface.action.maximum_snapshot_bytes as usize).await
    else {
        return refusal(invalid_request()).await;
    };
    let parsed = match parse_body(surface.action, route.kind, &body) {
        Ok(parsed) => parsed,
        Err(error) => return refusal(invalid_action_request(error)).await,
    };
    match route.kind {
        ActionRouteKind::Invoke => {
            let outcome = mutations
                .invoke_action(ImmediateActionInput {
                    route_id: &route.id,
                    action_id: &surface.action.id,
                    idempotency_key: idempotency_key.expect("invoke admission requires a key"),
                    context: &surface.context,
                    input: parsed.input,
                    preconditions: parsed.preconditions,
                    body_bytes: body.len(),
                    correlation: &correlation,
                })
                .await;
            match outcome {
                Ok(outcome) => {
                    let mut response = exact_mutation(outcome.response());
                    response
                        .headers_mut()
                        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
                    response
                }
                Err(error) => mutation_problem(error),
            }
        }
        ActionRouteKind::TargetConditions => {
            match mutations
                .action_target_conditions(ActionTargetConditionsInput {
                    route_id: &route.id,
                    action_id: &surface.action.id,
                    context: &surface.context,
                    input: parsed.input,
                    correlation: &correlation,
                })
                .await
            {
                Ok(response) => exact_non_record_no_store(response),
                Err(crate::mutation::MutationError::PreconditionFailed) => concealed(),
                Err(error) => mutation_problem(error),
            }
        }
    }
}

async fn action_refusal(
    mutations: &crate::postgres::PostgresRecordMutationService,
    route: &CompiledActionRoute,
    claims: &VerifiedRequestClaims,
    options: &QueryOptions,
    correlation: &RequestCorrelation,
    response: Response,
) -> Response {
    if claims.principal().is_none() {
        return anonymous_refusal(response, AnonymousRefusalReason::ActionRefused);
    }
    // Only a profile the compiled action route grants may reach the journal, so
    // an unknown caller-supplied value is recorded as absent.
    let selected_access_profile = match options.access_profile() {
        Some(profile) => route
            .access_profiles
            .iter()
            .any(|candidate| candidate == profile)
            .then_some(profile.as_str()),
        None => Some(route.default_access_profile.as_str()),
    };
    match mutations
        .record_action_refusal(
            &route.action_id,
            crate::audit::HttpRefusalAudit {
                method: route.method,
                operation_id: &route.id,
                target_record: None,
                action_id: None,
                principal: claims.principal(),
                selected_access_profile,
                purpose_present: claims.purpose().is_some(),
                correlation,
            },
        )
        .await
    {
        Ok(()) => response,
        Err(_) => mutation_problem(MutationError::Unavailable),
    }
}

struct ParsedActionBody {
    input: Map<String, Value>,
    preconditions: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ParseActionError {
    field_path: String,
}

impl ParseActionError {
    fn at(field_path: impl Into<String>) -> Self {
        Self {
            field_path: field_path.into(),
        }
    }
}

fn condition_inputs(action: &CompiledAction) -> BTreeSet<&str> {
    action
        .effects
        .iter()
        .filter_map(|effect| match &effect.target.binding {
            CompiledActionTargetBinding::Existing { input } => Some(input.as_str()),
            CompiledActionTargetBinding::Create => None,
        })
        .collect()
}

fn parse_body(
    action: &CompiledAction,
    kind: ActionRouteKind,
    bytes: &[u8],
) -> Result<ParsedActionBody, ParseActionError> {
    let value = parse_json_strict(bytes).map_err(|_| ParseActionError::at(""))?;
    let envelope = value.as_object().ok_or_else(|| ParseActionError::at(""))?;
    if envelope
        .keys()
        .any(|name| name != "input" && (name != "preconditions" || kind != ActionRouteKind::Invoke))
    {
        return Err(ParseActionError::at(""));
    }
    let wire_input = envelope
        .get("input")
        .and_then(Value::as_object)
        .ok_or_else(|| ParseActionError::at("/input"))?;
    let condition_inputs = condition_inputs(action);
    let accepted_inputs = action
        .inputs
        .iter()
        .filter(|input| {
            kind == ActionRouteKind::Invoke || condition_inputs.contains(input.id.as_str())
        })
        .collect::<Vec<_>>();
    let mut input = Map::new();
    for (name, value) in wire_input {
        let declared = action
            .inputs
            .iter()
            .find(|input| input.api_name == *name)
            .ok_or_else(|| ParseActionError::at("/input"))?;
        if !accepted_inputs.iter().any(|input| input.id == declared.id) {
            return Err(ParseActionError::at(json_pointer([
                "input",
                declared.api_name.as_str(),
            ])));
        }
        if !validate_field_value(FieldValue::Json(value), &declared.field_type) {
            return Err(ParseActionError::at(json_pointer([
                "input",
                declared.api_name.as_str(),
            ])));
        }
        input.insert(declared.id.clone(), value.clone());
    }
    if let Some(declared) = accepted_inputs.iter().find(|declared| {
        (declared.required
            || kind == ActionRouteKind::TargetConditions
            || condition_inputs.contains(declared.id.as_str()))
            && !input.contains_key(&declared.id)
    }) {
        return Err(ParseActionError::at(json_pointer([
            "input",
            declared.api_name.as_str(),
        ])));
    }
    let mut preconditions = BTreeMap::new();
    if kind == ActionRouteKind::Invoke {
        if let Some(value) = envelope.get("preconditions") {
            for (name, value) in value
                .as_object()
                .ok_or_else(|| ParseActionError::at("/preconditions"))?
            {
                let declared = action
                    .inputs
                    .iter()
                    .find(|input| input.api_name == *name)
                    .ok_or_else(|| ParseActionError::at("/preconditions"))?;
                if !condition_inputs.contains(declared.id.as_str()) {
                    return Err(ParseActionError::at(json_pointer([
                        "preconditions",
                        declared.api_name.as_str(),
                    ])));
                }
                let condition = value.as_object().ok_or_else(|| {
                    ParseActionError::at(json_pointer([
                        "preconditions",
                        declared.api_name.as_str(),
                    ]))
                })?;
                if condition.is_empty() {
                    return Err(ParseActionError::at(json_pointer([
                        "preconditions",
                        declared.api_name.as_str(),
                        "ifMatch",
                    ])));
                }
                if condition.len() != 1 {
                    return Err(ParseActionError::at(json_pointer([
                        "preconditions",
                        declared.api_name.as_str(),
                    ])));
                }
                let tag = condition
                    .get("ifMatch")
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        ParseActionError::at(json_pointer([
                            "preconditions",
                            declared.api_name.as_str(),
                        ]))
                    })?;
                if !valid_action_condition(tag) {
                    return Err(ParseActionError::at(json_pointer([
                        "preconditions",
                        declared.api_name.as_str(),
                        "ifMatch",
                    ])));
                }
                preconditions.insert(declared.id.clone(), tag.to_owned());
            }
        } else if !condition_inputs.is_empty() {
            return Err(ParseActionError::at("/preconditions"));
        }
        if let Some(input_id) = condition_inputs
            .iter()
            .find(|id| !preconditions.contains_key(**id))
        {
            let declared = action
                .inputs
                .iter()
                .find(|input| input.id == *input_id)
                .expect("condition input refers to compiled action input");
            return Err(ParseActionError::at(json_pointer([
                "preconditions",
                declared.api_name.as_str(),
            ])));
        }
    }
    Ok(ParsedActionBody {
        input,
        preconditions,
    })
}

fn valid_action_condition(value: &str) -> bool {
    // The action protocol carries an opaque strong condition, not an ordinary
    // record GET validator. Its binding is checked under current action authority.
    value.len() > 2
        && value.len() <= 256
        && value.starts_with('"')
        && value.ends_with('"')
        && value.as_bytes()[1..value.len() - 1]
            .iter()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x7e))
}

fn invalid_action_request(error: ParseActionError) -> Response {
    crate::correlation::problem_response_with_field_path(
        StatusCode::BAD_REQUEST,
        "urn:registry-server:problem:request.invalid",
        "Bad Request",
        "The request is invalid.",
        "request.invalid",
        error.field_path,
    )
}

fn json_pointer<const N: usize>(segments: [&str; N]) -> String {
    let mut pointer = String::new();
    for segment in segments {
        pointer.push('/');
        pointer.push_str(&json_pointer_segment(segment));
    }
    pointer
}

fn json_pointer_segment(segment: &str) -> String {
    segment.replace('~', "~0").replace('/', "~1")
}
