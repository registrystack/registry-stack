// SPDX-License-Identifier: Apache-2.0

//! First-class Proposal HTTP resources. Action start and lifecycle grants are
//! admitted independently; a business Record is never used as a Proposal.

use super::*;
use crate::model::{CompiledAction, CompiledActionExecution, CompiledProposalPermission,
    ProposalOperation};
use crate::postgres::{ProposalAuthority, ProposalAuthorityOperation, RowBoundaryContext};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ExecutorLease { pub job_id: Uuid, pub claim_token: Uuid }

pub(crate) struct ProposalMutationInput<'a> {
    pub action_id: &'a str,
    pub proposal_id: Option<Uuid>,
    pub operation: ProposalAuthorityOperation,
    pub authority: &'a ProposalAuthority,
    pub idempotency_key: &'a str,
    pub expected_etag: Option<&'a str>,
    pub input: Option<Map<String, Value>>,
    pub proposal_version: Option<u32>,
    pub effect_digest: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub executor_lease: Option<ExecutorLease>,
    pub correlation: &'a RequestCorrelation,
    pub human_identity: Option<&'a registry_review_client::HumanIdentity>,
    pub claims: &'a VerifiedRequestClaims,
}

#[derive(Default)]
pub(crate) struct ProposalListQuery {
    pub action: Option<String>,
    pub owner: Option<String>,
    pub state: Option<String>,
    pub target: Option<Uuid>,
    pub after: Option<Uuid>,
    pub limit: usize,
}

fn permission_matches(permission: &CompiledProposalPermission, claims: &VerifiedRequestClaims) -> bool {
    permission.principal_claim.as_deref() == claims.principal_claim()
        && permission.required_scopes.iter().all(|scope| claims.has_scope(scope))
        && (permission.required_purposes.is_empty()
            || claims.purpose().is_some_and(|purpose| permission.required_purposes.contains(purpose)))
        && actor_matches(permission.actor_kind, claims)
        && (permission.requester_clients.is_empty()
            || claims.requester_client().is_some_and(|client| permission.requester_clients.contains(client)))
}

fn actor_matches(expected: Option<crate::contract::ActorKindSource>, claims: &VerifiedRequestClaims) -> bool {
    use crate::contract::ActorKindSource;
    use registry_platform_oidc::ActorKind;
    if claims.actor_subject().is_some() && expected != Some(ActorKindSource::Agent) { return false; }
    match expected {
        None => true,
        Some(ActorKindSource::Human) => claims.actor_kind() == Some(ActorKind::Human),
        Some(ActorKindSource::Agent) => claims.actor_kind() == Some(ActorKind::Agent) && claims.actor_subject().is_some(),
        Some(ActorKindSource::Service) => claims.actor_kind() == Some(ActorKind::Service),
    }
}

fn boundaries(
    sources: &[crate::contract::RowBoundarySource], claims: &VerifiedRequestClaims,
) -> Option<Vec<RowBoundaryContext>> {
    verified_row_boundaries_from_sources(sources, claims)?.into_iter().map(|boundary| {
        match boundary.operator() {
            RowBoundaryOperator::Equals => Some(RowBoundaryContext::Equals {
                field: boundary.field().to_owned(), value: boundary.values().first()?.clone(),
            }),
            RowBoundaryOperator::In => Some(RowBoundaryContext::In {
                field: boundary.field().to_owned(), values: boundary.values().clone(),
            }),
        }
    }).collect()
}

pub(crate) fn authorize(
    registry: &CompiledRegistry, action: &CompiledAction, claims: &VerifiedRequestClaims,
    selected: Option<&str>, operation: ProposalAuthorityOperation,
) -> Option<ProposalAuthority> {
    let CompiledActionExecution::Proposal {proposal} = &action.execution else { return None; };
    if claims.grant().is_some() { return None; }
    let (profile, targets) = match operation {
        ProposalAuthorityOperation::Start => {
            let grant = action.permissions.iter().find(|grant| {
                selected.map_or(grant.default, |profile| profile == grant.profile_id)
                    && grant.operations.contains(&Operation::Start)
            })?;
            if grant.principal_claim.as_deref() != claims.principal_claim()
                || !grant.required_scopes.iter().all(|scope| claims.has_scope(scope))
                || (!grant.required_purposes.is_empty() && !claims.purpose().is_some_and(|p| grant.required_purposes.contains(p)))
                || !actor_matches(grant.actor_kind, claims)
                || (!grant.requester_clients.is_empty() && !claims.requester_client().is_some_and(|c| grant.requester_clients.contains(c))) {
                return None;
            }
            let targets = grant.targets.iter().map(|target| {
                Some((target.entity_id.clone(), boundaries(&target.row_boundaries, claims)?))
            }).collect::<Option<BTreeMap<_, _>>>()?;
            (grant.profile_id.as_str(), targets)
        }
        ProposalAuthorityOperation::Lifecycle(operation) => {
            let grant = proposal.permissions.iter().find(|grant| {
                selected.map_or(grant.default, |profile| profile == grant.profile_id)
                    && grant.operations.contains(&operation)
            })?;
            if !permission_matches(grant, claims) { return None; }
            let targets = grant.targets.iter().map(|target| {
                Some((target.entity_id.clone(), boundaries(&target.row_boundaries, claims)?))
            }).collect::<Option<BTreeMap<_, _>>>()?;
            (grant.profile_id.as_str(), targets)
        }
    };
    let mut authority = ProposalAuthority::for_compiled(registry, &action.id, operation,
        claims.principal()?, profile, claims.purpose(), targets).ok()?;
    authority.common = authority.common.with_grant_audit(crate::audit::GrantAuditContext::from_claims(claims));
    Some(authority)
}

fn selected_profile(raw: Option<&str>) -> Result<Option<String>, ()> {
    let options = QueryOptions::parse(raw, false).map_err(|_| ())?;
    Ok(options.access_profile().cloned())
}

fn parse_input(action: &CompiledAction, value: &Value) -> Result<Map<String, Value>, ()> {
    let supplied = value.as_object().ok_or(())?;
    let mut input = Map::new();
    for (name, value) in supplied {
        let declared = action.inputs.iter().find(|input| input.api_name == *name).ok_or(())?;
        if !crate::data::validate_field_value(crate::data::FieldValue::Json(value), &declared.field_type) {
            return Err(());
        }
        input.insert(declared.id.clone(), value.clone());
    }
    if action.inputs.iter().any(|declared| declared.required && !input.contains_key(&declared.id)) { return Err(()); }
    Ok(input)
}

fn json_response(value: Value, etag: Option<&str>) -> Response {
    let mut response = Json(value).into_response();
    response.headers_mut().insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Some(etag) = etag.and_then(|etag| HeaderValue::from_str(etag).ok()) {
        response.headers_mut().insert(ETAG, etag);
    }
    response
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn start(
    State(service): State<Arc<HttpService>>, Extension(route): Extension<CompiledActionRoute>,
    Extension(correlation): Extension<RequestCorrelation>, Authenticated(claims): Authenticated,
    RawQuery(raw_query): RawQuery, headers: HeaderMap, body: Body,
) -> Response {
    let Some(mutations) = &service.mutations else { return concealed(); };
    let Ok(selected) = selected_profile(raw_query.as_deref()) else { return concealed(); };
    let Some(action) = service.registry.actions().actions.iter().find(|action| action.id == route.action_id) else { return concealed(); };
    if route.operation != Operation::Start || route.path != action.route { return concealed(); }
    let Some(authority) = authorize(&service.registry, action, &claims, selected.as_deref(), ProposalAuthorityOperation::Start) else { return concealed(); };
    if !single_content_type(&headers, "application/json") { return unsupported_media_type(); }
    let Some(key) = single_header(&headers, "idempotency-key").filter(|key| valid_idempotency_key(key)) else { return missing_idempotency_key(); };
    let Ok(bytes) = bounded_body_to(body, action.maximum_snapshot_bytes as usize).await else { return invalid_request(); };
    let Ok(value) = parse_json_strict(&bytes) else { return invalid_request(); };
    let Some(envelope) = value.as_object().filter(|object| object.len() == 1) else { return invalid_request(); };
    let Some(raw_input) = envelope.get("input") else { return invalid_request(); };
    let Ok(input) = parse_input(action, raw_input) else { return invalid_request(); };
    match mutations.proposal_mutation(ProposalMutationInput {
        action_id: &action.id, proposal_id: None, operation: ProposalAuthorityOperation::Start,
        authority: &authority, idempotency_key: key, expected_etag: None,
        input: Some(input), proposal_version: None, effect_digest: None, reason: None,
        executor_lease: None, correlation: &correlation, human_identity: claims.human_identity(), claims: &claims,
    }).await {
        Ok(outcome) => exact_mutation(outcome.response(), None, "", service.field_encryption.as_deref()),
        Err(error) => mutation_problem(error),
    }
}

pub(super) async fn get(
    State(service): State<Arc<HttpService>>, Path(id): Path<String>,
    Authenticated(claims): Authenticated, RawQuery(raw_query): RawQuery,
) -> Response {
    let Some(mutations) = &service.mutations else { return concealed(); };
    let Ok(id) = Uuid::parse_str(&id) else { return concealed(); };
    let Ok(selected) = selected_profile(raw_query.as_deref()) else { return concealed(); };
    let action_id = match mutations.proposal_action_id(id).await { Ok(Some(id))=>id,Ok(None)=>return concealed(),Err(error)=>return mutation_problem(error) };
    let Some(action) = service.registry.actions().actions.iter().find(|a| a.id == action_id) else { return concealed(); };
    let Some(authority) = authorize(&service.registry,action,&claims,selected.as_deref(),ProposalAuthorityOperation::Lifecycle(ProposalOperation::Get)) else { return concealed(); };
    match mutations.proposal_document(id,&authority,&claims).await {
        Ok((value,etag))=>json_response(value,Some(&etag)),
        Err(MutationError::PreconditionFailed)=>concealed(),Err(error)=>mutation_problem(error),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn transition(
    State(service): State<Arc<HttpService>>, Path((id, operation)): Path<(String,String)>,
    Extension(correlation): Extension<RequestCorrelation>, Authenticated(claims): Authenticated,
    RawQuery(raw_query): RawQuery, headers: HeaderMap, body: Body,
) -> Response {
    let Some(mutations) = &service.mutations else { return concealed(); };
    let Ok(id) = Uuid::parse_str(&id) else { return concealed(); };
    let operation = match operation.as_str() {"submit"=>ProposalOperation::Submit,"revise"=>ProposalOperation::Revise,"cancel"=>ProposalOperation::Cancel,"apply"=>ProposalOperation::Apply,_=>return concealed()};
    let Ok(selected) = selected_profile(raw_query.as_deref()) else { return concealed(); };
    let action_id = match mutations.proposal_action_id(id).await {Ok(Some(id))=>id,Ok(None)=>return concealed(),Err(error)=>return mutation_problem(error)};
    let Some(action) = service.registry.actions().actions.iter().find(|a| a.id == action_id) else { return concealed(); };
    let Some(authority) = authorize(&service.registry,action,&claims,selected.as_deref(),ProposalAuthorityOperation::Lifecycle(operation)) else { return concealed(); };
    if !single_content_type(&headers,"application/json") {return unsupported_media_type();}
    let Some(key) = single_header(&headers,"idempotency-key").filter(|key|valid_idempotency_key(key)) else {return missing_idempotency_key();};
    let Some(etag) = single_header(&headers,"if-match").filter(|etag|valid_if_match(etag)) else {return precondition_required();};
    let Ok(bytes) = bounded_body_to(body,action.maximum_snapshot_bytes as usize).await else {return invalid_request();};
    let Ok(value) = parse_json_strict(&bytes) else {return invalid_request();};
    let Some(envelope) = value.as_object() else {return invalid_request();};
    let allowed = match operation {ProposalOperation::Revise=>vec!["input"],ProposalOperation::Apply=>vec!["proposalVersion","effectDigest","reason","executorLease"],_=>vec![]};
    if envelope.keys().any(|key|!allowed.contains(&key.as_str())) {return invalid_request();}
    let input = match envelope.get("input") {Some(value)=>match parse_input(action,value){Ok(input)=>Some(input),Err(_)=>return invalid_request()},None=>None};
    if operation == ProposalOperation::Revise && input.is_none() {return invalid_request();}
    let version = envelope.get("proposalVersion").and_then(Value::as_u64).and_then(|v|u32::try_from(v).ok()).filter(|v|*v>0);
    let digest = envelope.get("effectDigest").and_then(Value::as_str);
    if operation == ProposalOperation::Apply && (version.is_none() || digest.is_none()) {return invalid_request();}
    let reason = match envelope.get("reason") {Some(Value::String(reason)) if crate::proposal_workflow::valid_application_reason(reason)=>Some(reason.as_str()),None=>None,_=>return invalid_request()};
    let lease = match envelope.get("executorLease") {Some(value)=>match serde_json::from_value(value.clone()){Ok(lease)=>Some(lease),Err(_)=>return invalid_request()},None=>None};
    match mutations.proposal_mutation(ProposalMutationInput {
        action_id:&action.id,proposal_id:Some(id),operation:ProposalAuthorityOperation::Lifecycle(operation),
        authority:&authority,idempotency_key:key,expected_etag:Some(etag),input,
        proposal_version:version,effect_digest:digest,reason,executor_lease:lease,
        correlation:&correlation,human_identity:claims.human_identity(),claims:&claims,
    }).await {
        Ok(outcome)=>exact_mutation(outcome.response(),None,"",service.field_encryption.as_deref()),
        Err(error)=>mutation_problem(error),
    }
}

pub(super) async fn list(
    State(service): State<Arc<HttpService>>, Authenticated(claims): Authenticated,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let Some(mutations) = &service.mutations else {return concealed();};
    let mut selected = None;
    let mut query = ProposalListQuery {limit:50,..Default::default()};
    let mut seen = BTreeSet::new();
    if let Some(raw) = raw_query {
        if raw.len() > MAX_RAW_QUERY_BYTES {return concealed();}
        for pair in raw.split('&') {
            let Some((key,value))=pair.split_once('=') else {return concealed();};
            let (Ok(key),Ok(value))=(percent_decode(key),percent_decode(value)) else {return concealed();};
            if !seen.insert(key.clone()) {return concealed();}
            match key.as_str() {
                "accessProfile"=>selected=Some(value),"action"=>query.action=Some(value),
                "owner" if value=="caller"=>query.owner=Some(value),
                "state" if ["draft","submitted","applied","cancelled"].contains(&value.as_str())=>query.state=Some(value),
                "target"=>match Uuid::parse_str(&value){Ok(id)=>query.target=Some(id),Err(_)=>return concealed()},
                "cursor"=>match Uuid::parse_str(&value){Ok(id)=>query.after=Some(id),Err(_)=>return concealed()},
                "top"=>match value.parse::<usize>(){Ok(limit) if (1..=100).contains(&limit)=>query.limit=limit,_=>return concealed()},
                _=>return concealed(),
            }
        }
    }
    let authorities = service.registry.actions().actions.iter().filter_map(|action| {
        authorize(&service.registry,action,&claims,selected.as_deref(),ProposalAuthorityOperation::Lifecycle(ProposalOperation::List))
    }).collect::<Vec<_>>();
    if authorities.is_empty() {return concealed();}
    match mutations.list_proposals(&authorities,&query,&claims).await {
        Ok(value)=>json_response(value,None),Err(error)=>mutation_problem(error),
    }
}
