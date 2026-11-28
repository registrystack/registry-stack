// SPDX-License-Identifier: Apache-2.0

//! First-class Proposal HTTP resources. Action start and lifecycle grants are
//! admitted independently; a business Record is never used as a Proposal.

use super::*;
mod answers;
use crate::model::{
    CompiledAction, CompiledActionExecution, CompiledActionRoute, CompiledProposalPermission,
    CompiledRegistry, HttpMethod, ProposalOperation,
};
use crate::postgres::{ProposalAuthority, ProposalAuthorityOperation, RowBoundaryContext};
pub(super) use answers::answer;

pub(super) fn proposal_problem(error: MutationError) -> Response {
    match error {
        MutationError::AuthorizationRefused(check) => concealed(check),
        error => mutation_problem(error),
    }
}

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ExecutorLease {
    pub job_id: Uuid,
    pub claim_token: Uuid,
}

pub(crate) struct ProposalMutationInput<'a> {
    pub action_id: &'a str,
    pub proposal_id: Option<Uuid>,
    pub operation: ProposalAuthorityOperation,
    pub authority: &'a ProposalAuthority,
    pub idempotency_key: &'a str,
    pub expected_etag: Option<&'a str>,
    pub input: Option<Map<String, Value>>,
    pub submission_version: Option<u32>,
    pub effect_digest: Option<&'a str>,
    pub reason: Option<&'a str>,
    pub executor_lease: Option<ExecutorLease>,
    pub rebase_start_authority: Option<&'a ProposalAuthority>,
    pub attachment: Option<crate::attachment::AttachmentMutation>,
    pub answer: Option<crate::review_store::asks::AnswerMutation>,
    pub correlation: &'a RequestCorrelation,
    pub human_identity: Option<&'a registry_review_client::HumanIdentity>,
    pub claims: Option<&'a VerifiedRequestClaims>,
}

#[derive(Default)]
pub(crate) struct ProposalListQuery {
    pub action: Option<String>,
    pub owner: Option<String>,
    pub state: Option<String>,
    pub target: Option<Uuid>,
    pub turn: Option<String>,
    pub pending_manual_application: bool,
    pub after: Option<Uuid>,
    pub limit: usize,
}

pub(crate) struct ProposalRecordReadAuthority {
    pub fields: BTreeSet<String>,
    pub context: crate::postgres::ClaimContext,
}

#[derive(Clone, Copy)]
pub(crate) enum ReviewDocumentSource<'a> {
    Field(&'a str),
    Ask(Uuid),
}
pub(crate) struct ReviewContextDocumentRead<'a> {
    pub source: ReviewDocumentSource<'a>,
    pub effect_digest: &'a str,
    pub schema_digest: &'a str,
    pub records: &'a BTreeMap<String, ProposalRecordReadAuthority>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProposalTaskContextSubject {
    pub source: String,
    pub subject_type: String,
    pub id: String,
    pub version: String,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProposalTaskContextContract {
    pub id: String,
    pub revision: String,
    pub schema_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProposalTaskContextIdentity {
    pub action_id: String,
    pub subject: ProposalTaskContextSubject,
    pub contract: ProposalTaskContextContract,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ProposalTaskContextRequest {
    pub expected: ProposalTaskContextIdentity,
    pub request_id: Uuid,
    pub task_id: Uuid,
    pub task_revision: i64,
    pub policy: registry_review_protocol::PolicyBinding,
    pub purpose: String,
    pub fields: Vec<String>,
}

impl ProposalTaskContextRequest {
    fn valid(&self) -> bool {
        let unique = self.fields.iter().collect::<BTreeSet<_>>();
        registry_platform_yaml::LocalId::new(&self.expected.action_id).is_ok()
            && self.expected.subject.subject_type == "proposal"
            && Uuid::parse_str(&self.expected.subject.id).is_ok()
            && !self.expected.subject.source.is_empty()
            && self.expected.subject.source.len() <= 512
            && !self.expected.subject.source.chars().any(char::is_control)
            && !self.expected.subject.version.is_empty()
            && self.expected.subject.version.len() <= 128
            && !self.expected.subject.version.chars().any(char::is_control)
            && valid_digest(&self.expected.subject.digest)
            && self
                .expected
                .contract
                .id
                .starts_with("urn:registry:breg:review-context:")
            && self.expected.contract.id.len() <= 2048
            && !self.expected.contract.id.chars().any(char::is_control)
            && valid_digest(&self.expected.contract.revision)
            && valid_digest(&self.expected.contract.schema_digest)
            && !self.request_id.is_nil()
            && !self.task_id.is_nil()
            && self.task_revision >= 1
            && self.policy.check().is_ok()
            && !self.purpose.is_empty()
            && self.purpose.len() <= 128
            && !self.purpose.chars().any(char::is_control)
            && (1..=128).contains(&self.fields.len())
            && unique.len() == self.fields.len()
            && self
                .fields
                .iter()
                .all(|field| crate::logical_names::valid_api_name(field))
    }
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn permission_matches(
    permission: &CompiledProposalPermission,
    claims: &VerifiedRequestClaims,
    standing_own_draft: bool,
) -> Result<(), FailedCheck> {
    request_matches(
        permission.principal_claim.as_deref(),
        &permission.required_scopes,
        &permission.required_purposes,
        permission.actor_kind,
        &permission.requester_clients,
        claims,
        standing_own_draft,
    )
}

/// The checks a Proposal permission and an Action start grant share, in the
/// order they are made. The first that fails names itself.
fn request_matches(
    principal_claim: Option<&str>,
    required_scopes: &BTreeSet<String>,
    required_purposes: &BTreeSet<String>,
    actor_kind: Option<crate::contract::ActorKindSource>,
    requester_clients: &BTreeSet<String>,
    claims: &VerifiedRequestClaims,
    standing_own_draft: bool,
) -> Result<(), FailedCheck> {
    if principal_claim != claims.principal_claim() {
        return Err(FailedCheck::TokenClaims);
    }
    if !required_scopes.iter().all(|scope| claims.has_scope(scope)) {
        claims.declare_scope_refusal(required_scopes, None);
        return Err(FailedCheck::Scope);
    }
    if !required_purposes.is_empty()
        && !claims
            .purpose()
            .is_some_and(|purpose| required_purposes.contains(purpose))
    {
        return Err(FailedCheck::Purpose);
    }
    actor_matches(actor_kind, claims, standing_own_draft)?;
    if !requester_clients.is_empty()
        && !claims
            .requester_client()
            .is_some_and(|client| requester_clients.contains(client))
    {
        return Err(FailedCheck::RequesterClient);
    }
    Ok(())
}

fn actor_matches(
    expected: Option<crate::contract::ActorKindSource>,
    claims: &VerifiedRequestClaims,
    standing_own_draft: bool,
) -> Result<(), FailedCheck> {
    use crate::contract::ActorKindSource;
    use registry_platform_oidc::ActorKind;
    if claims.actor_subject().is_some() && expected != Some(ActorKindSource::Agent) {
        return Err(FailedCheck::Delegation);
    }
    let matches = match expected {
        None => true,
        Some(ActorKindSource::Human) => claims.actor_kind() == Some(ActorKind::Human),
        Some(ActorKindSource::Agent) => {
            claims.actor_kind() == Some(ActorKind::Agent)
                && (claims.actor_subject().is_some()
                    || claims.grant().is_some()
                    || standing_own_draft)
        }
        Some(ActorKindSource::Service) => claims.actor_kind() == Some(ActorKind::Service),
    };
    if matches {
        Ok(())
    } else {
        Err(FailedCheck::ActorKind)
    }
}

fn boundaries(
    sources: &[crate::contract::RowBoundarySource],
    claims: &VerifiedRequestClaims,
) -> Option<Vec<RowBoundaryContext>> {
    verified_row_boundaries_from_sources(sources, claims)?
        .into_iter()
        .map(|boundary| match boundary.operator() {
            RowBoundaryOperator::Equals => Some(RowBoundaryContext::Equals {
                field: boundary.field().to_owned(),
                value: boundary.values().first()?.clone(),
            }),
            RowBoundaryOperator::In => Some(RowBoundaryContext::In {
                field: boundary.field().to_owned(),
                values: boundary.values().clone(),
            }),
        })
        .collect()
}

pub(crate) fn external_recovery_actor_allowed(
    application: &crate::model::CompiledProposalApplication,
    claims: Option<&VerifiedRequestClaims>,
) -> bool {
    !application.is_automatic()
        || claims.is_some_and(|claims| {
            claims.actor_kind() == Some(registry_platform_oidc::ActorKind::Human)
        })
}

pub(crate) fn authorize(
    registry: &CompiledRegistry,
    action: &CompiledAction,
    claims: &VerifiedRequestClaims,
    selected: Option<&str>,
    operation: ProposalAuthorityOperation,
    proposal_id: Option<Uuid>,
) -> Option<ProposalAuthority> {
    authorize_checked(registry, action, claims, selected, operation, proposal_id).ok()
}

/// The admission of a Proposal operation. The refusal names the first check
/// that failed, for the operator only.
pub(crate) fn authorize_checked(
    registry: &CompiledRegistry,
    action: &CompiledAction,
    claims: &VerifiedRequestClaims,
    selected: Option<&str>,
    operation: ProposalAuthorityOperation,
    proposal_id: Option<Uuid>,
) -> Result<ProposalAuthority, FailedCheck> {
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        return Err(FailedCheck::Operation);
    };
    if matches!(
        operation,
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Apply | ProposalOperation::Retry)
    ) && !external_recovery_actor_allowed(&proposal.application, Some(claims))
    {
        return Err(FailedCheck::ActorKind);
    }
    let standing_agent = (claims.actor_subject().is_some()
        || claims.actor_kind() == Some(registry_platform_oidc::ActorKind::Agent))
        && claims.grant().is_none();
    if standing_agent
        && !matches!(
            operation,
            ProposalAuthorityOperation::Start
                | ProposalAuthorityOperation::Lifecycle(ProposalOperation::Edit)
                | ProposalAuthorityOperation::Lifecycle(ProposalOperation::GetReviewContext)
        )
    {
        return Err(FailedCheck::TaskGrantMissing);
    }
    let (profile, targets, task_source, profile_kind) = match operation {
        ProposalAuthorityOperation::Start => {
            let grant = action
                .permissions
                .iter()
                .find(|grant| {
                    selected.map_or(grant.default, |profile| profile == grant.profile_id)
                        && grant.operations.contains(&Operation::Start)
                })
                .ok_or(FailedCheck::AccessProfile)?;
            request_matches(
                grant.principal_claim.as_deref(),
                &grant.required_scopes,
                &grant.required_purposes,
                grant.actor_kind,
                &grant.requester_clients,
                claims,
                standing_agent,
            )?;
            let targets = grant
                .targets
                .iter()
                .map(|target| {
                    Some((
                        target.entity_id.clone(),
                        boundaries(&target.row_boundaries, claims)?,
                    ))
                })
                .collect::<Option<BTreeMap<_, _>>>()
                .ok_or(FailedCheck::RowBoundary)?;
            (
                grant.profile_id.as_str(),
                targets,
                grant.task_grant.as_ref(),
                grant.actor_kind,
            )
        }
        ProposalAuthorityOperation::Lifecycle(operation) => {
            let grant = proposal
                .permissions
                .iter()
                .find(|grant| {
                    selected.map_or(grant.default, |profile| profile == grant.profile_id)
                        && grant.operations.contains(&operation)
                })
                .ok_or(FailedCheck::AccessProfile)?;
            if standing_agent
                && operation == ProposalOperation::Edit
                && grant.ownership != Some(crate::model::ProposalOwnership::Caller)
            {
                return Err(FailedCheck::Operation);
            }
            // A standing agent edits only its caller-owned draft. The one
            // additional operation is current review-context disclosure, and
            // only a verified delegated actor may use it. CompiledRegistry is
            // also a public deserializable type, so retain the empty-client
            // refusal as a runtime defense for malformed compiled input.
            if standing_agent
                && operation == ProposalOperation::GetReviewContext
                && (claims.actor_subject().is_none() || grant.requester_clients.is_empty())
            {
                return Err(FailedCheck::Delegation);
            }
            permission_matches(grant, claims, standing_agent)?;
            if grant.review_authority.is_some()
                && (operation != ProposalOperation::GetReviewStatus
                    || claims.actor_kind() != Some(registry_platform_oidc::ActorKind::Service))
            {
                return Err(FailedCheck::ActorKind);
            }
            let targets = grant
                .targets
                .iter()
                .map(|target| {
                    Some((
                        target.entity_id.clone(),
                        boundaries(&target.row_boundaries, claims)?,
                    ))
                })
                .collect::<Option<BTreeMap<_, _>>>()
                .ok_or(FailedCheck::RowBoundary)?;
            (
                grant.profile_id.as_str(),
                targets,
                grant.task_grant.as_ref(),
                grant.actor_kind,
            )
        }
    };
    let mut authority = ProposalAuthority::for_compiled(
        registry,
        &action.id,
        operation,
        claims.principal().ok_or(FailedCheck::TokenClaims)?,
        profile,
        claims.purpose(),
        targets,
    )
    .map_err(|_| FailedCheck::Operation)?;
    authority.common = authority
        .common
        .with_audit_context(crate::audit::RequestAuditContext::from_claims(claims));
    // An applicant's answers and the files they cite reach human reviewers
    // only: a verified human caller, on a profile written for humans or for
    // any kind, acting for no one else and under no task grant. A delegated
    // actor, a standing or task-granted agent and a service never receive
    // them, whatever their grant says.
    authority.receives_review_answers = claims.actor_kind()
        == Some(registry_platform_oidc::ActorKind::Human)
        && claims.actor_subject().is_none()
        && claims.grant().is_none()
        && task_source.is_none()
        && matches!(
            profile_kind,
            None | Some(crate::contract::ActorKindSource::Human)
        );
    match (task_source, claims.grant()) {
        (None, None) => {}
        (Some(source), Some(grant)) => {
            let binding =
                bind_task_grant(&source.source_issuer, claims).map_err(|refusal| refusal.check)?;
            let bounds = grant
                .bounds()
                .breg_permissions()
                .ok_or(FailedCheck::TaskGrantScope)?;
            let operation_name = crate::mutation::proposal_operation_name(operation);
            let scope = match operation {
                ProposalAuthorityOperation::Start => {
                    let collection = format!("action:{}", action.id);
                    if !bounds.iter().any(|bound| {
                        bound.collection() == collection
                            && bound.operations().iter().any(|op| op == operation_name)
                    }) {
                        return Err(FailedCheck::TaskGrantScope);
                    }
                    None
                }
                ProposalAuthorityOperation::Lifecycle(_) => {
                    let scope = bounds
                        .iter()
                        .filter(|bound| bound.operations().iter().any(|op| op == operation_name))
                        .filter_map(|bound| {
                            let raw = bound.collection().strip_prefix("proposal:")?;
                            let id = Uuid::parse_str(raw).ok()?;
                            (id.to_string() == raw).then_some(id)
                        })
                        .collect::<BTreeSet<_>>();
                    if scope.is_empty() || proposal_id.is_some_and(|id| !scope.contains(&id)) {
                        return Err(FailedCheck::TaskGrantScope);
                    }
                    Some(scope)
                }
            };
            authority.common = authority
                .common
                .with_proposal_task_grant(binding.clone(), operation)
                .map_err(|_| FailedCheck::TaskGrantScope)?;
            authority.task_grant = Some(binding);
            authority.proposal_scope = scope;
        }
        (Some(_), None) => return Err(FailedCheck::TaskGrantMissing),
        (None, Some(_)) => return Err(FailedCheck::TaskGrantScope),
    }
    Ok(authority)
}

pub(super) fn selected_profile(raw: Option<&str>) -> Result<Option<String>, ()> {
    let options = QueryOptions::parse(raw, false).map_err(|_| ())?;
    Ok(options.access_profile().cloned())
}

fn review_status_options(raw: Option<&str>) -> Result<(Option<String>, bool), ()> {
    let Some(raw) = raw else {
        return Ok((None, false));
    };
    if raw.is_empty() || raw.len() > MAX_RAW_QUERY_BYTES {
        return Err(());
    }
    let mut ordinary = Vec::new();
    let mut include_progress = false;
    for pair in raw.split('&') {
        let (name, value) = pair.split_once('=').ok_or(())?;
        if percent_decode(name).map_err(|_| ())? == "include" {
            if include_progress || percent_decode(value).map_err(|_| ())? != "progress" {
                return Err(());
            }
            include_progress = true;
        } else {
            ordinary.push(pair);
        }
    }
    let ordinary = (!ordinary.is_empty()).then(|| ordinary.join("&"));
    Ok((selected_profile(ordinary.as_deref())?, include_progress))
}

fn parse_input(action: &CompiledAction, value: &Value) -> Result<Map<String, Value>, ()> {
    let supplied = value.as_object().ok_or(())?;
    let mut input = Map::new();
    for (name, value) in supplied {
        let declared = action
            .inputs
            .iter()
            .find(|input| input.api_name == *name)
            .ok_or(())?;
        if !(crate::data::validate_field_value(
            crate::data::FieldValue::Json(value),
            &declared.field_type,
        ) || value.is_null() && !declared.required && action.handler.is_some())
        {
            return Err(());
        }
        input.insert(declared.id.clone(), value.clone());
    }
    Ok(input)
}

pub(super) fn json_response(value: Value, etag: Option<&str>) -> Response {
    let mut response = Json(value).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .headers_mut()
        .insert(VARY, HeaderValue::from_static("authorization, accept"));
    if let Some(etag) = etag.and_then(|etag| HeaderValue::from_str(etag).ok()) {
        response.headers_mut().insert(ETAG, etag);
    }
    response
}

pub(super) async fn admitted_http_refusal(
    mutations: &crate::postgres::PostgresRecordMutationService,
    authority: &ProposalAuthority,
    method: HttpMethod,
    correlation: &RequestCorrelation,
    response: Response,
) -> Response {
    match mutations
        .record_proposal_http_refusal(authority, method, correlation)
        .await
    {
        Ok(()) => response,
        Err(_) => unavailable(),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn known_action_refusal(
    mutations: &crate::postgres::PostgresRecordMutationService,
    action: &CompiledAction,
    claims: &VerifiedRequestClaims,
    selected: Option<&str>,
    operation: ProposalAuthorityOperation,
    method: HttpMethod,
    correlation: &RequestCorrelation,
    check: FailedCheck,
) -> Response {
    let profile = selected.filter(|profile| match operation {
        ProposalAuthorityOperation::Start => action.permissions.iter().any(|grant| {
            grant.profile_id == *profile && grant.operations.contains(&Operation::Start)
        }),
        ProposalAuthorityOperation::Lifecycle(operation) => match &action.execution {
            CompiledActionExecution::Proposal { proposal } => proposal
                .permissions
                .iter()
                .any(|grant| grant.profile_id == *profile && grant.operations.contains(&operation)),
            _ => false,
        },
    });
    let operation_id = format!(
        "proposals.{}.{}",
        action.id,
        crate::mutation::proposal_operation_name(operation)
    );
    match mutations
        .record_action_refusal(
            &action.id,
            crate::audit::HttpRefusalAudit {
                refusal_reason: None,
                context: crate::audit::RequestAuditContext::from_claims(claims),
                method: method.into(),
                operation_id: &operation_id,
                target_record: None,
                action_id: Some(&action.id),
                principal: claims.principal(),
                selected_access_profile: profile,
                purpose_present: claims.purpose().is_some(),
                correlation,
            },
        )
        .await
    {
        Ok(()) => concealed(check),
        Err(_) => unavailable(),
    }
}

async fn audited_list_concealment(
    mutations: &crate::postgres::PostgresRecordMutationService,
    service: &HttpService,
    claims: &VerifiedRequestClaims,
    selected: Option<&str>,
    correlation: &RequestCorrelation,
    check: FailedCheck,
) -> Response {
    let selected_access_profile = selected.filter(|selected| {
        service.registry.actions().actions.iter().any(|action| {
            matches!(
                &action.execution,
                CompiledActionExecution::Proposal { proposal }
                    if proposal.permissions.iter().any(|permission| {
                        permission.profile_id == *selected
                            && permission.operations.contains(&ProposalOperation::List)
                    })
            )
        })
    });
    match mutations
        .record_refusal(crate::audit::HttpRefusalAudit {
            refusal_reason: None,
            context: crate::audit::RequestAuditContext::from_claims(claims),
            method: HttpMethod::Get.into(),
            operation_id: "proposals.list",
            target_record: None,
            action_id: None,
            principal: claims.principal(),
            selected_access_profile,
            purpose_present: claims.purpose().is_some(),
            correlation,
        })
        .await
    {
        Ok(()) => concealed(check),
        Err(_) => unavailable(),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn start(
    State(service): State<Arc<HttpService>>,
    Extension(route): Extension<CompiledActionRoute>,
    Extension(correlation): Extension<RequestCorrelation>,
    Authenticated(claims): Authenticated,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed(FailedCheck::Visibility);
    };
    let Ok(selected) = selected_profile(raw_query.as_deref()) else {
        return concealed(FailedCheck::Visibility);
    };
    let Some(action) = service
        .registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == route.action_id)
    else {
        return concealed(FailedCheck::Visibility);
    };
    if route.operation != Operation::Start || route.path != action.route {
        return concealed(FailedCheck::Visibility);
    }
    let authority = match authorize_checked(
        &service.registry,
        action,
        &claims,
        selected.as_deref(),
        ProposalAuthorityOperation::Start,
        None,
    ) {
        Ok(authority) => authority,
        Err(check) => {
            return known_action_refusal(
                mutations,
                action,
                &claims,
                selected.as_deref(),
                ProposalAuthorityOperation::Start,
                HttpMethod::Post,
                &correlation,
                check,
            )
            .await;
        }
    };
    if !single_content_type(&headers, "application/json") {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            unsupported_media_type(),
        )
        .await;
    }
    let Some(key) =
        single_header(&headers, "idempotency-key").filter(|key| valid_idempotency_key(key))
    else {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            missing_idempotency_key(),
        )
        .await;
    };
    let Ok(bytes) = bounded_body_to(body, action.maximum_snapshot_bytes as usize).await else {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            invalid_request(),
        )
        .await;
    };
    let Ok(value) = parse_json_strict(&bytes) else {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            invalid_request(),
        )
        .await;
    };
    let Some(envelope) = value.as_object().filter(|object| object.len() == 1) else {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            invalid_request(),
        )
        .await;
    };
    let Some(raw_input) = envelope.get("input") else {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            invalid_request(),
        )
        .await;
    };
    let Ok(input) = parse_input(action, raw_input) else {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            invalid_request(),
        )
        .await;
    };
    match mutations
        .proposal_mutation(ProposalMutationInput {
            action_id: &action.id,
            proposal_id: None,
            operation: ProposalAuthorityOperation::Start,
            authority: &authority,
            idempotency_key: key,
            expected_etag: None,
            input: Some(input),
            submission_version: None,
            effect_digest: None,
            reason: None,
            executor_lease: None,
            rebase_start_authority: None,
            attachment: None,
            answer: None,
            correlation: &correlation,
            human_identity: claims.human_identity(),
            claims: Some(&claims),
        })
        .await
    {
        Ok(outcome) => exact_mutation(
            outcome.response(),
            None,
            "",
            service.field_encryption.as_deref(),
        ),
        Err(error) => proposal_problem(error),
    }
}

pub(super) async fn get(
    State(service): State<Arc<HttpService>>,
    Path(id): Path<String>,
    Extension(correlation): Extension<RequestCorrelation>,
    Authenticated(claims): Authenticated,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed(FailedCheck::Visibility);
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return concealed(FailedCheck::Visibility);
    };
    let Ok(selected) = selected_profile(raw_query.as_deref()) else {
        return concealed(FailedCheck::Visibility);
    };
    let action_id = match mutations.proposal_action_id(id).await {
        Ok(Some(id)) => id,
        Ok(None) => return concealed(FailedCheck::Visibility),
        Err(error) => return proposal_problem(error),
    };
    let Some(action) = service
        .registry
        .actions()
        .actions
        .iter()
        .find(|a| a.id == action_id)
    else {
        return concealed(FailedCheck::Visibility);
    };
    let authority = match authorize_checked(
        &service.registry,
        action,
        &claims,
        selected.as_deref(),
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Get),
        Some(id),
    ) {
        Ok(authority) => authority,
        Err(check) => {
            return known_action_refusal(
                mutations,
                action,
                &claims,
                selected.as_deref(),
                ProposalAuthorityOperation::Lifecycle(ProposalOperation::Get),
                HttpMethod::Get,
                &correlation,
                check,
            )
            .await;
        }
    };
    match mutations
        .proposal_document(id, &authority, &claims, &correlation)
        .await
    {
        Ok((value, etag)) => json_response(value, Some(&etag)),
        Err(MutationError::PreconditionFailed) => concealed(FailedCheck::Visibility),
        Err(error) => proposal_problem(error),
    }
}

/// One exact submission, read under the Proposal's Get authority. A version
/// that is not canonical, never existed or is outside the caller's authority
/// is concealed like an unknown Proposal.
pub(super) async fn submission(
    State(service): State<Arc<HttpService>>,
    Path((id, version)): Path<(String, String)>,
    Extension(correlation): Extension<RequestCorrelation>,
    Authenticated(claims): Authenticated,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed(FailedCheck::Visibility);
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return concealed(FailedCheck::Visibility);
    };
    let Some(version) = version
        .parse::<u32>()
        .ok()
        .filter(|parsed| *parsed > 0 && parsed.to_string() == version)
    else {
        return concealed(FailedCheck::Visibility);
    };
    let Ok(selected) = selected_profile(raw_query.as_deref()) else {
        return concealed(FailedCheck::Visibility);
    };
    let action_id = match mutations.proposal_action_id(id).await {
        Ok(Some(id)) => id,
        Ok(None) => return concealed(FailedCheck::Visibility),
        Err(error) => return proposal_problem(error),
    };
    let Some(action) = service
        .registry
        .actions()
        .actions
        .iter()
        .find(|a| a.id == action_id)
    else {
        return concealed(FailedCheck::Visibility);
    };
    let authority = match authorize_checked(
        &service.registry,
        action,
        &claims,
        selected.as_deref(),
        ProposalAuthorityOperation::Lifecycle(ProposalOperation::Get),
        Some(id),
    ) {
        Ok(authority) => authority,
        Err(check) => {
            return known_action_refusal(
                mutations,
                action,
                &claims,
                selected.as_deref(),
                ProposalAuthorityOperation::Lifecycle(ProposalOperation::Get),
                HttpMethod::Get,
                &correlation,
                check,
            )
            .await;
        }
    };
    match mutations
        .proposal_submission_read(id, version, &authority, &correlation)
        .await
    {
        Ok(Some(value)) => json_response(value, None),
        Ok(None) => fixed_problem(ProblemCode::ProposalSubmissionExpired),
        Err(MutationError::PreconditionFailed) => concealed(FailedCheck::Visibility),
        Err(error) => proposal_problem(error),
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn transition(
    State(service): State<Arc<HttpService>>,
    Path((id, operation)): Path<(String, String)>,
    Extension(correlation): Extension<RequestCorrelation>,
    Authenticated(claims): Authenticated,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed(FailedCheck::Visibility);
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return concealed(FailedCheck::Visibility);
    };
    let operation = match operation.as_str() {
        "edit" => ProposalOperation::Edit,
        "submit" => ProposalOperation::Submit,
        "revise" => ProposalOperation::Revise,
        "cancel" => ProposalOperation::Cancel,
        "apply" => ProposalOperation::Apply,
        "rebase" => ProposalOperation::Rebase,
        "retry" => ProposalOperation::Retry,
        _ => return concealed(FailedCheck::Operation),
    };
    let Ok(selected) = selected_profile(raw_query.as_deref()) else {
        return concealed(FailedCheck::Visibility);
    };
    let action_id = match mutations.proposal_action_id(id).await {
        Ok(Some(id)) => id,
        Ok(None) => return concealed(FailedCheck::Visibility),
        Err(error) => return proposal_problem(error),
    };
    let Some(action) = service
        .registry
        .actions()
        .actions
        .iter()
        .find(|a| a.id == action_id)
    else {
        return concealed(FailedCheck::Visibility);
    };
    let authority = match authorize_checked(
        &service.registry,
        action,
        &claims,
        selected.as_deref(),
        ProposalAuthorityOperation::Lifecycle(operation),
        Some(id),
    ) {
        Ok(authority) => authority,
        Err(check) => {
            return known_action_refusal(
                mutations,
                action,
                &claims,
                selected.as_deref(),
                ProposalAuthorityOperation::Lifecycle(operation),
                HttpMethod::Post,
                &correlation,
                check,
            )
            .await;
        }
    };
    let rebase_start_authority = if operation == ProposalOperation::Rebase {
        match authorize_checked(
            &service.registry,
            action,
            &claims,
            selected.as_deref(),
            ProposalAuthorityOperation::Start,
            None,
        ) {
            Ok(authority) => Some(authority),
            Err(check) => {
                return admitted_http_refusal(
                    mutations,
                    &authority,
                    HttpMethod::Post,
                    &correlation,
                    concealed(check),
                )
                .await;
            }
        }
    } else {
        None
    };
    if !single_content_type(&headers, "application/json") {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            unsupported_media_type(),
        )
        .await;
    }
    let Some(key) =
        single_header(&headers, "idempotency-key").filter(|key| valid_idempotency_key(key))
    else {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            missing_idempotency_key(),
        )
        .await;
    };
    let Some(etag) = single_header(&headers, "if-match").filter(|etag| valid_if_match(etag)) else {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            precondition_required(),
        )
        .await;
    };
    let Ok(bytes) = bounded_body_to(body, action.maximum_snapshot_bytes as usize).await else {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            invalid_request(),
        )
        .await;
    };
    let Ok(value) = parse_json_strict(&bytes) else {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            invalid_request(),
        )
        .await;
    };
    let Some(envelope) = value.as_object() else {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            invalid_request(),
        )
        .await;
    };
    let allowed = match operation {
        ProposalOperation::Edit | ProposalOperation::Revise | ProposalOperation::Rebase => {
            vec!["input"]
        }
        ProposalOperation::Apply => vec!["submissionVersion", "effectDigest", "reason"],
        _ => vec![],
    };
    if envelope.keys().any(|key| !allowed.contains(&key.as_str())) {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            invalid_request(),
        )
        .await;
    }
    let input = match envelope.get("input") {
        Some(value) => match parse_input(action, value) {
            Ok(input) => Some(input),
            Err(_) => {
                return admitted_http_refusal(
                    mutations,
                    &authority,
                    HttpMethod::Post,
                    &correlation,
                    invalid_request(),
                )
                .await;
            }
        },
        None => None,
    };
    if matches!(
        operation,
        ProposalOperation::Edit | ProposalOperation::Rebase
    ) && input.is_none()
    {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            invalid_request(),
        )
        .await;
    }
    let version = envelope
        .get("submissionVersion")
        .and_then(Value::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v > 0);
    let digest = envelope.get("effectDigest").and_then(Value::as_str);
    if operation == ProposalOperation::Apply && (version.is_none() || digest.is_none()) {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            invalid_request(),
        )
        .await;
    }
    let reason = match envelope.get("reason") {
        Some(Value::String(reason))
            if crate::proposal_workflow::valid_application_reason(reason) =>
        {
            Some(reason.as_str())
        }
        None => None,
        _ => {
            return admitted_http_refusal(
                mutations,
                &authority,
                HttpMethod::Post,
                &correlation,
                invalid_request(),
            )
            .await;
        }
    };
    match mutations
        .proposal_mutation(ProposalMutationInput {
            action_id: &action.id,
            proposal_id: Some(id),
            operation: ProposalAuthorityOperation::Lifecycle(operation),
            authority: &authority,
            idempotency_key: key,
            expected_etag: Some(etag),
            input,
            submission_version: version,
            effect_digest: digest,
            reason,
            executor_lease: None,
            rebase_start_authority: rebase_start_authority.as_ref(),
            attachment: None,
            answer: None,
            correlation: &correlation,
            human_identity: claims.human_identity(),
            claims: Some(&claims),
        })
        .await
    {
        Ok(outcome) => exact_mutation(
            outcome.response(),
            None,
            "",
            service.field_encryption.as_deref(),
        ),
        Err(MutationError::ProposalGuardFailed(failure)) => {
            guard_failure_response(
                &service,
                &authority,
                &claims,
                &headers,
                &correlation,
                *failure,
            )
            .await
        }
        Err(error) => proposal_problem(error),
    }
}

/// A failed field commit guard is named only when the selected profile could
/// itself read the guard field and the target Record through the ordinary GET
/// path and the guard still fails against that disclosed value, exactly the
/// disclosure rule of an immediate Action. Every other case, including a Record
/// that changed or moved out of the profile's boundaries since the transaction
/// rolled back, keeps the generic precondition refusal without a response
/// `RefusalNote` (while still counting under `action-guard` for the operator),
/// so development posture cannot turn the concealed cause into an existence
/// oracle.
async fn guard_failure_response(
    service: &HttpService,
    authority: &ProposalAuthority,
    claims: &VerifiedRequestClaims,
    headers: &HeaderMap,
    correlation: &RequestCorrelation,
    failure: crate::mutation::ProposalGuardFailure,
) -> Response {
    let concealed_guard = || {
        crate::correlation::record_refusal_check(FailedCheck::ActionGuard, correlation);
        mutation_problem(MutationError::PreconditionFailed)
    };
    let guard = &failure.guard;
    let (Some(entity), Some(boundaries)) = (
        service.registry.entities().get(&guard.entity_id),
        authority.targets.get(&guard.entity_id),
    ) else {
        return concealed_guard();
    };
    let observed = super::actions::availability::observe_target(
        service,
        authority.common.access_profile(),
        claims,
        headers,
        entity,
        &failure.record_id.to_string(),
        &BTreeSet::from([guard.field.clone()]),
        boundaries,
        correlation,
    )
    .await;
    let Ok(Some(observed)) = observed else {
        return concealed_guard();
    };
    let is_timestamp = entity.fields.get(&guard.field).is_some_and(|field| {
        matches!(
            field.field_type,
            crate::contract::FieldTypeSource::Timestamp
        )
    });
    if crate::commit_guard::guard_matches(
        guard,
        &failure.input,
        &observed.current,
        &service.registry,
        time::OffsetDateTime::now_utc(),
        is_timestamp,
    ) {
        return concealed_guard();
    }
    crate::correlation::note_refusal(
        crate::correlation::action_guard_failure_response(
            guard.reason.clone(),
            guard.label.clone(),
        ),
        FailedCheck::ActionGuard,
    )
}

/// Batch transport only: every item retains the scalar context read's current
/// authorization, Record disclosure, transaction, and paired audit admission.
pub(super) async fn review_context_batch(
    State(service): State<Arc<HttpService>>,
    Extension(correlation): Extension<RequestCorrelation>,
    Authenticated(claims): Authenticated,
    RawQuery(raw): RawQuery,
) -> Response {
    let Some(raw) = raw.filter(|raw| raw.len() <= MAX_RAW_QUERY_BYTES) else {
        return concealed(FailedCheck::Visibility);
    };
    let mut ids = None;
    let mut profile = Vec::new();
    for pair in raw.split('&') {
        let Some((key, value)) = pair.split_once('=') else {
            return concealed(FailedCheck::Visibility);
        };
        let Ok(key) = percent_decode(key) else {
            return concealed(FailedCheck::Visibility);
        };
        if key == "ids" {
            if ids.is_some() {
                return concealed(FailedCheck::Visibility);
            }
            let Ok(value) = percent_decode(value) else {
                return concealed(FailedCheck::Visibility);
            };
            ids = Some(value);
        } else {
            profile.push(pair);
        }
    }
    let Some(ids) = ids else {
        return concealed(FailedCheck::Visibility);
    };
    let ids = ids.split(',').collect::<Vec<_>>();
    let mut distinct = BTreeSet::new();
    if ids.is_empty()
        || ids.len() > 100
        || ids.iter().any(|id| {
            !matches!(Uuid::parse_str(id), Ok(value) if !value.is_nil() && value.to_string() == *id)
                || !distinct.insert(*id)
        })
    {
        return concealed(FailedCheck::Visibility);
    }
    let profile = Some(profile.join("&"));
    if selected_profile(profile.as_deref()).is_err() {
        return concealed(FailedCheck::Visibility);
    }
    // Bound the aggregate independently of each Proposal's configured context.
    let mut remaining = 8 * 1024 * 1024 - 64 * 1024;
    let mut items = Vec::with_capacity(ids.len());
    let mut concealed_items = Vec::new();
    for id in ids {
        let response = review_read(
            service.clone(),
            id.to_owned(),
            claims.clone(),
            profile.clone(),
            ProposalOperation::GetReviewContext,
            ReviewAnswers::Omitted,
            correlation.clone(),
        )
        .await;
        match response.status() {
            StatusCode::OK => {
                let Ok(bytes) = bounded_body_to(response.into_body(), remaining).await else {
                    return unavailable();
                };
                remaining -= bytes.len();
                let Ok(context) = serde_json::from_slice::<Value>(&bytes) else {
                    return unavailable();
                };
                items.push(json!({"id":id,"status":"visible","context":context}));
            }
            StatusCode::NOT_FOUND => {
                concealed_items.push(response);
                items.push(json!({"id":id,"status":"concealed"}));
            }
            _ => return response,
        }
    }
    // The batch answers 200, so each concealed item records its own refusal.
    // They are recorded only once the batch answers, so a batch that ends with
    // another answer counts nothing the caller did not see.
    for response in &concealed_items {
        crate::correlation::record_noted_refusal(response, &correlation);
    }
    json_response(json!({"items":items}), None)
}

pub(super) async fn review_context(
    State(service): State<Arc<HttpService>>,
    Path(id): Path<String>,
    Extension(correlation): Extension<RequestCorrelation>,
    Authenticated(claims): Authenticated,
    RawQuery(raw): RawQuery,
) -> Response {
    review_read(
        service,
        id,
        claims,
        raw,
        ProposalOperation::GetReviewContext,
        ReviewAnswers::Served,
        correlation,
    )
    .await
}

pub(super) async fn review_status(
    State(service): State<Arc<HttpService>>,
    Path(id): Path<String>,
    Extension(correlation): Extension<RequestCorrelation>,
    Authenticated(claims): Authenticated,
    RawQuery(raw): RawQuery,
) -> Response {
    review_read(
        service,
        id,
        claims,
        raw,
        ProposalOperation::GetReviewStatus,
        ReviewAnswers::Omitted,
        correlation,
    )
    .await
}

pub(super) async fn task_grant_context(
    State(service): State<Arc<HttpService>>,
    Path(id): Path<String>,
    Extension(correlation): Extension<RequestCorrelation>,
    Authenticated(claims): Authenticated,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed(FailedCheck::Visibility);
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return concealed(FailedCheck::Visibility);
    };
    let Ok(selected) = selected_profile(raw.as_deref()) else {
        return concealed(FailedCheck::Visibility);
    };
    let action_id = match mutations.proposal_action_id(id).await {
        Ok(Some(id)) => id,
        Ok(None) => return concealed(FailedCheck::Visibility),
        Err(error) => return proposal_problem(error),
    };
    let Some(action) = service
        .registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == action_id)
    else {
        return concealed(FailedCheck::Visibility);
    };
    let operation = ProposalOperation::GetTaskGrantContext;
    let authority = match authorize_checked(
        &service.registry,
        action,
        &claims,
        selected.as_deref(),
        ProposalAuthorityOperation::Lifecycle(operation),
        Some(id),
    ) {
        Ok(authority) => authority,
        Err(check) => {
            return known_action_refusal(
                mutations,
                action,
                &claims,
                selected.as_deref(),
                ProposalAuthorityOperation::Lifecycle(operation),
                HttpMethod::Post,
                &correlation,
                check,
            )
            .await;
        }
    };
    if !single_content_type(&headers, "application/json") {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            unsupported_media_type(),
        )
        .await;
    }
    let Ok(bytes) = bounded_body_to(body, MAX_MUTATION_BODY_BYTES).await else {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            invalid_request(),
        )
        .await;
    };
    let Ok(value) = parse_json_strict(&bytes) else {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            invalid_request(),
        )
        .await;
    };
    let Ok(request) = serde_json::from_value::<ProposalTaskContextRequest>(value) else {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            invalid_request(),
        )
        .await;
    };
    if !request.valid()
        || request.expected.action_id != action.id
        || request.expected.subject.id != id.to_string()
    {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            concealed(FailedCheck::Visibility),
        )
        .await;
    }
    let selected_fields = request.fields.iter().cloned().collect::<BTreeSet<_>>();
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        return concealed(FailedCheck::Operation);
    };
    let granted = proposal.permissions.iter().find(|permission| {
        permission.profile_id == authority.common.access_profile()
            && permission.operations.contains(&operation)
    });
    if !granted.is_some_and(|permission| {
        !selected_fields.is_empty()
            && selected_fields.is_subset(&permission.readable_context_fields)
    }) {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            concealed(FailedCheck::Disclosure),
        )
        .await;
    }
    let Some(records) = review_record_authorities(
        &service.registry,
        action,
        &claims,
        &authority,
        operation,
        Some(&selected_fields),
    ) else {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Post,
            &correlation,
            concealed(FailedCheck::Visibility),
        )
        .await;
    };
    match mutations
        .proposal_task_context_read(
            id,
            &authority,
            &records,
            &request,
            &selected_fields,
            &correlation,
        )
        .await
    {
        Ok((proposal, etag)) => {
            let mut response =
                json_response(json!({"request":request,"proposal":proposal}), Some(&etag));
            response.headers_mut().insert(
                axum::http::header::CACHE_CONTROL,
                axum::http::HeaderValue::from_static("no-store"),
            );
            response
        }
        Err(MutationError::PreconditionFailed) => concealed(FailedCheck::Visibility),
        Err(error) => proposal_problem(error),
    }
}

/// Whether a review read may carry applicant answers. The batch inbox read
/// shows none, so it neither serves nor audits them; only the single-Proposal
/// review-context read does, and then only to a human reviewer.
#[derive(Clone, Copy, Eq, PartialEq)]
enum ReviewAnswers {
    Served,
    Omitted,
}

#[allow(clippy::too_many_arguments)]
async fn review_read(
    service: Arc<HttpService>,
    id: String,
    claims: VerifiedRequestClaims,
    raw: Option<String>,
    operation: ProposalOperation,
    answers: ReviewAnswers,
    correlation: RequestCorrelation,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed(FailedCheck::Visibility);
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return concealed(FailedCheck::Visibility);
    };
    let Ok((selected, include_progress)) = (if operation == ProposalOperation::GetReviewStatus {
        review_status_options(raw.as_deref())
    } else {
        selected_profile(raw.as_deref()).map(|selected| (selected, false))
    }) else {
        return concealed(FailedCheck::Visibility);
    };
    let action_id = match mutations.proposal_action_id(id).await {
        Ok(Some(id)) => id,
        Ok(None) => return concealed(FailedCheck::Visibility),
        Err(error) => return proposal_problem(error),
    };
    let Some(action) = service
        .registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == action_id)
    else {
        return concealed(FailedCheck::Visibility);
    };
    let mut authority = match authorize_checked(
        &service.registry,
        action,
        &claims,
        selected.as_deref(),
        ProposalAuthorityOperation::Lifecycle(operation),
        Some(id),
    ) {
        Ok(authority) => authority,
        Err(check) => {
            return known_action_refusal(
                mutations,
                action,
                &claims,
                selected.as_deref(),
                ProposalAuthorityOperation::Lifecycle(operation),
                HttpMethod::Get,
                &correlation,
                check,
            )
            .await;
        }
    };
    if answers == ReviewAnswers::Omitted {
        authority.receives_review_answers = false;
    }
    let records = review_record_authorities(
        &service.registry,
        action,
        &claims,
        &authority,
        operation,
        None,
    );
    let Some(records) = records else {
        return admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Get,
            &correlation,
            concealed(FailedCheck::Visibility),
        )
        .await;
    };
    match mutations
        .proposal_review_read(id, &authority, &records, include_progress, &correlation)
        .await
    {
        Ok((value, etag)) => json_response(value, etag.as_deref()),
        Err(MutationError::PreconditionFailed) => concealed(FailedCheck::Visibility),
        Err(error) => proposal_problem(error),
    }
}

/// The complete context's ordinary Record authority is shared by JSON display
/// and document downloads. A saved link must not bypass current disclosure.
pub(crate) fn review_record_authorities(
    registry: &CompiledRegistry,
    action: &CompiledAction,
    claims: &VerifiedRequestClaims,
    authority: &ProposalAuthority,
    operation: ProposalOperation,
    selected_fields: Option<&BTreeSet<String>>,
) -> Option<BTreeMap<String, ProposalRecordReadAuthority>> {
    let mut records = BTreeMap::new();
    if matches!(
        operation,
        ProposalOperation::GetReviewContext | ProposalOperation::GetTaskGrantContext
    ) {
        let CompiledActionExecution::Proposal { proposal } = &action.execution else {
            return None;
        };
        let Some(mapping) = &proposal.review_context else {
            return None;
        };
        for (field, source) in &mapping.fields {
            if selected_fields.is_some_and(|selected| !selected.contains(field)) {
                continue;
            }
            use crate::contract::ProposalContextValueSource;
            let target = match source {
                ProposalContextValueSource::Input { .. }
                | ProposalContextValueSource::Additions { .. }
                | ProposalContextValueSource::Document { .. } => continue,
                ProposalContextValueSource::Record { input, .. } => {
                    let input = action
                        .inputs
                        .iter()
                        .find(|declared| declared.id == *input)?;
                    let crate::contract::FieldTypeSource::Reference { target, .. } =
                        &input.field_type
                    else {
                        return None;
                    };
                    target
                }
                ProposalContextValueSource::Changes { record_type, .. } => record_type,
            };
            let entity = registry.entities().get(target)?;
            let profile = entity
                .access_profiles
                .get(authority.common.access_profile())?;
            if !profile.operations.contains(&Operation::Get)
                || authorize_profile_claims(profile, claims).is_err()
            {
                return None;
            }
            let Ok(task_grant) = task_grant_binding(profile, claims) else {
                return None;
            };
            let row_boundaries = boundaries(&profile.row_boundaries, claims)?;
            let Ok(mut context) = crate::postgres::ClaimContext::for_compiled(
                registry,
                target,
                claims.principal().map(str::to_owned),
                authority.common.access_profile(),
                claims.purpose().map(str::to_owned),
                row_boundaries,
            )
            .and_then(|context| context.with_recipients(claims.recipients().clone())) else {
                return None;
            };
            if let Some(binding) = task_grant {
                let Ok(bound) = context.with_task_grant(binding) else {
                    return None;
                };
                context = bound;
            }
            records.insert(
                target.clone(),
                ProposalRecordReadAuthority {
                    fields: profile.readable_fields.iter().cloned().collect(),
                    context,
                },
            );
        }
    }
    Some(records)
}

pub(super) async fn list(
    State(service): State<Arc<HttpService>>,
    Extension(correlation): Extension<RequestCorrelation>,
    Authenticated(claims): Authenticated,
    RawQuery(raw_query): RawQuery,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed(FailedCheck::Visibility);
    };
    let selected = match proposal_list_admission_profile(raw_query.as_deref()) {
        Ok(selected) => selected,
        Err(()) => {
            return audited_list_concealment(
                mutations,
                &service,
                &claims,
                None,
                &correlation,
                FailedCheck::AccessProfile,
            )
            .await;
        }
    };
    // When no Proposal action admits the caller, the first Proposal action's
    // refusal names the check. A registry with none refuses on the profile.
    let mut first_refusal = None;
    let mut authorities = Vec::new();
    for action in &service.registry.actions().actions {
        match authorize_checked(
            &service.registry,
            action,
            &claims,
            selected.as_deref(),
            ProposalAuthorityOperation::Lifecycle(ProposalOperation::List),
            None,
        ) {
            Ok(authority) => authorities.push(authority),
            Err(check) if matches!(action.execution, CompiledActionExecution::Proposal { .. }) => {
                first_refusal.get_or_insert(check);
            }
            Err(_) => {}
        }
    }
    if authorities.is_empty() {
        return audited_list_concealment(
            mutations,
            &service,
            &claims,
            selected.as_deref(),
            &correlation,
            first_refusal.unwrap_or(FailedCheck::AccessProfile),
        )
        .await;
    }
    let query = match parse_proposal_list_query(raw_query.as_deref()) {
        Ok(query) => query,
        Err(QueryParseError::InvalidAt("top")) => {
            return invalid_query_at_with_detail(
                "top",
                "The Proposal list takes `limit` for its page size; `top` is not accepted.",
            );
        }
        Err(QueryParseError::Invalid) => return invalid_query_at("query"),
        Err(error) => return error.problem(),
    };
    match mutations
        .list_proposals(&authorities, &query, &claims, &correlation)
        .await
    {
        Ok(value) => json_response(value, None),
        Err(error) => proposal_problem(error),
    }
}

fn proposal_list_admission_profile(raw: Option<&str>) -> Result<Option<String>, ()> {
    let Some(raw) = raw else { return Ok(None) };
    if raw.len() > MAX_RAW_QUERY_BYTES {
        return Err(());
    }
    let mut selected = None;
    for pair in raw.split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            if percent_decode(pair).ok().as_deref() == Some("accessProfile") {
                return Err(());
            }
            continue;
        };
        let Ok(name) = percent_decode(name) else {
            continue;
        };
        if name != "accessProfile" {
            continue;
        }
        let value = percent_decode(value).map_err(|_| ())?;
        if !strict_query::valid_config_identifier(&value) || selected.replace(value).is_some() {
            return Err(());
        }
    }
    Ok(selected)
}

fn proposal_list_parameter(name: &str) -> Option<&'static str> {
    match name {
        "accessProfile" => Some("accessProfile"),
        "action" => Some("action"),
        "owner" => Some("owner"),
        "state" => Some("state"),
        "turn" => Some("turn"),
        "pendingManualApplication" => Some("pendingManualApplication"),
        "target" => Some("target"),
        "cursor" => Some("cursor"),
        "limit" => Some("limit"),
        "top" => Some("top"),
        _ => None,
    }
}

fn proposal_list_error(name: &str) -> QueryParseError {
    proposal_list_parameter(name).map_or(QueryParseError::Invalid, QueryParseError::InvalidAt)
}

fn parse_proposal_list_query(raw: Option<&str>) -> Result<ProposalListQuery, QueryParseError> {
    let mut query = ProposalListQuery {
        limit: 50,
        ..Default::default()
    };
    let Some(raw) = raw else { return Ok(query) };
    if raw.is_empty() || raw.len() > MAX_RAW_QUERY_BYTES {
        return Err(QueryParseError::Invalid);
    }
    let mut seen = BTreeSet::new();
    for pair in raw.split('&') {
        let (name, value) = pair.split_once('=').ok_or(QueryParseError::Invalid)?;
        let name = percent_decode(name).map_err(|_| QueryParseError::Invalid)?;
        let value = percent_decode(value).map_err(|_| proposal_list_error(&name))?;
        if !seen.insert(name.clone()) {
            return Err(proposal_list_error(&name));
        }
        match name.as_str() {
            "accessProfile" => {
                if !strict_query::valid_config_identifier(&value) {
                    return Err(QueryParseError::InvalidAt("accessProfile"));
                }
            }
            "action" => query.action = Some(value),
            "owner" if value == "caller" => query.owner = Some(value),
            "state"
                if ["draft", "submitted", "applied", "cancelled", "rejected"]
                    .contains(&value.as_str()) =>
            {
                query.state = Some(value)
            }
            "turn" if ["party", "official", "nobody"].contains(&value.as_str()) => {
                query.turn = Some(value)
            }
            "pendingManualApplication" if value == "true" || value == "false" => {
                query.pending_manual_application = value == "true";
            }
            "target" => {
                query.target = Some(
                    Uuid::parse_str(&value).map_err(|_| QueryParseError::InvalidAt("target"))?,
                );
            }
            "cursor" => {
                query.after = Some(
                    Uuid::parse_str(&value).map_err(|_| QueryParseError::InvalidAt("cursor"))?,
                );
            }
            "limit" => {
                query.limit = value
                    .parse::<usize>()
                    .ok()
                    .filter(|limit| (1..=100).contains(limit))
                    .ok_or(QueryParseError::InvalidAt("limit"))?;
            }
            "top" => return Err(QueryParseError::InvalidAt("top")),
            _ if proposal_list_parameter(&name).is_some() => {
                return Err(proposal_list_error(&name));
            }
            _ => return Err(QueryParseError::Invalid),
        }
    }
    Ok(query)
}
