// SPDX-License-Identifier: Apache-2.0

//! Engine-owned Proposal slots. Get and Edit have explicit, separate byte grants.
use super::*;
use crate::model::{CompiledActionExecution, HttpMethod, ProposalOperation};
use crate::postgres::{ProposalAuthority, ProposalAuthorityOperation};

pub(super) fn routes(_service: &HttpService) -> Router<Arc<HttpService>> {
    Router::new().route(
        "/v1/proposals/{proposal_id}/attachments/{slot_id}",
        get(download).patch(upload).delete(remove),
    )
}

#[allow(clippy::too_many_arguments)]
async fn upload(
    State(service): State<Arc<HttpService>>,
    Path((id, slot)): Path<(String, String)>,
    Extension(correlation): Extension<RequestCorrelation>,
    Authenticated(claims): Authenticated,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    mutate(
        service,
        id,
        slot,
        correlation,
        claims,
        raw,
        headers,
        body,
        false,
    )
    .await
}
#[allow(clippy::too_many_arguments)]
async fn remove(
    State(service): State<Arc<HttpService>>,
    Path((id, slot)): Path<(String, String)>,
    Extension(correlation): Extension<RequestCorrelation>,
    Authenticated(claims): Authenticated,
    RawQuery(raw): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    mutate(
        service,
        id,
        slot,
        correlation,
        claims,
        raw,
        headers,
        body,
        true,
    )
    .await
}

async fn authorize(
    service: &HttpService,
    id: Uuid,
    slot: &str,
    claims: &VerifiedRequestClaims,
    selected: Option<&str>,
    operation: ProposalOperation,
) -> Result<(String, ProposalAuthority), MutationError> {
    let mutations = service
        .mutations
        .as_ref()
        .ok_or(MutationError::PreconditionFailed)?;
    let action_id = mutations
        .proposal_action_id(id)
        .await?
        .ok_or(MutationError::PreconditionFailed)?;
    let action = service
        .registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == action_id)
        .ok_or(MutationError::PreconditionFailed)?;
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        return Err(MutationError::PreconditionFailed);
    };
    let authority = super::proposals::authorize(
        &service.registry,
        action,
        claims,
        selected,
        ProposalAuthorityOperation::Lifecycle(operation),
        Some(id),
    )
    .ok_or(MutationError::PreconditionFailed)?;
    let grant = proposal
        .permissions
        .iter()
        .find(|grant| {
            grant.profile_id == authority.common.access_profile()
                && grant.operations.contains(&operation)
        })
        .ok_or(MutationError::PreconditionFailed)?;
    let allowed = if operation == ProposalOperation::Get {
        &grant.readable_attachments
    } else {
        &grant.writable_attachments
    };
    if !proposal.attachments.contains_key(slot) || !allowed.contains(slot) {
        return Err(MutationError::PreconditionFailed);
    }
    Ok((action_id, authority))
}

#[allow(clippy::too_many_arguments)]
async fn mutate(
    service: Arc<HttpService>,
    id: String,
    slot: String,
    correlation: RequestCorrelation,
    claims: VerifiedRequestClaims,
    raw: Option<String>,
    headers: HeaderMap,
    body: Body,
    removal: bool,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed();
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return concealed();
    };
    let Ok(selected) = super::proposals::selected_profile(raw.as_deref()) else {
        return concealed();
    };
    let (action_id, authority) = match authorize(
        &service,
        id,
        &slot,
        &claims,
        selected.as_deref(),
        ProposalOperation::Edit,
    )
    .await
    {
        Ok(value) => value,
        Err(MutationError::PreconditionFailed) => return concealed(),
        Err(error) => return mutation_problem(error),
    };
    let Some(key) =
        single_header(&headers, "idempotency-key").filter(|key| valid_idempotency_key(key))
    else {
        return super::proposals::admitted_http_refusal(
            mutations,
            &authority,
            if removal {
                HttpMethod::Delete
            } else {
                HttpMethod::Patch
            },
            &correlation,
            missing_idempotency_key(),
        )
        .await;
    };
    let Some(etag) = single_header(&headers, "if-match").filter(|etag| valid_if_match(etag)) else {
        return super::proposals::admitted_http_refusal(
            mutations,
            &authority,
            if removal {
                HttpMethod::Delete
            } else {
                HttpMethod::Patch
            },
            &correlation,
            precondition_required(),
        )
        .await;
    };
    let action = service
        .registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == action_id)
        .expect("admitted Action");
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        return concealed();
    };
    let definition = &proposal.attachments[&slot];
    let (content_type, bytes) = if removal {
        if !to_bytes(body, 0).await.is_ok_and(|bytes| bytes.is_empty()) {
            return super::proposals::admitted_http_refusal(
                mutations,
                &authority,
                if removal {
                    HttpMethod::Delete
                } else {
                    HttpMethod::Patch
                },
                &correlation,
                invalid_request(),
            )
            .await;
        }
        (None, None)
    } else {
        let Some(content_type) = single_header(&headers, CONTENT_TYPE.as_str()).filter(|value| {
            definition
                .content_types
                .iter()
                .any(|allowed| allowed == value)
        }) else {
            return super::proposals::admitted_http_refusal(
                mutations,
                &authority,
                if removal {
                    HttpMethod::Delete
                } else {
                    HttpMethod::Patch
                },
                &correlation,
                unsupported_media_type(),
            )
            .await;
        };
        let Ok(bytes) = bounded_body_to(body, definition.maximum_bytes as usize).await else {
            return super::proposals::admitted_http_refusal(
                mutations,
                &authority,
                if removal {
                    HttpMethod::Delete
                } else {
                    HttpMethod::Patch
                },
                &correlation,
                invalid_request(),
            )
            .await;
        };
        if bytes.is_empty() {
            return super::proposals::admitted_http_refusal(
                mutations,
                &authority,
                if removal {
                    HttpMethod::Delete
                } else {
                    HttpMethod::Patch
                },
                &correlation,
                invalid_request(),
            )
            .await;
        }
        (Some(content_type.to_owned()), Some(bytes.to_vec()))
    };
    let input = super::proposals::ProposalMutationInput {
        action_id: &action_id,
        proposal_id: Some(id),
        operation: ProposalAuthorityOperation::Lifecycle(ProposalOperation::Edit),
        authority: &authority,
        idempotency_key: key,
        expected_etag: Some(etag),
        input: None,
        submission_version: None,
        effect_digest: None,
        reason: None,
        executor_lease: None,
        rebase_start_authority: None,
        attachment: Some(crate::attachment::AttachmentMutation {
            slot_id: slot,
            content_type,
            bytes,
        }),
        correlation: &correlation,
        human_identity: claims.human_identity(),
        claims: Some(&claims),
    };
    match mutations.proposal_mutation(input).await {
        Ok(outcome) => exact_mutation(
            outcome.response(),
            None,
            "",
            service.field_encryption.as_deref(),
        ),
        Err(MutationError::PreconditionFailed) => precondition_failed(),
        Err(error) => mutation_problem(error),
    }
}

async fn download(
    State(service): State<Arc<HttpService>>,
    Path((id, slot)): Path<(String, String)>,
    Extension(correlation): Extension<RequestCorrelation>,
    Authenticated(claims): Authenticated,
    RawQuery(raw): RawQuery,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed();
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return concealed();
    };
    let Ok((selected, version)) = parse_download_query(raw.as_deref()) else {
        return concealed();
    };
    let (_, authority) = match authorize(
        &service,
        id,
        &slot,
        &claims,
        selected.as_deref(),
        ProposalOperation::Get,
    )
    .await
    {
        Ok(value) => value,
        Err(MutationError::PreconditionFailed) => return concealed(),
        Err(error) => return mutation_problem(error),
    };
    match mutations
        .proposal_attachment_download(id, version, &slot, &authority, &correlation)
        .await
    {
        Ok((content_type, bytes)) => Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, content_type)
            .header(
                "content-disposition",
                crate::attachment::DOWNLOAD_CONTENT_DISPOSITION,
            )
            .header("x-content-type-options", "nosniff")
            .header(CACHE_CONTROL, "no-store")
            .header(VARY, "authorization")
            .body(Body::from(bytes))
            .unwrap_or_else(|_| unavailable()),
        Err(MutationError::PreconditionFailed) => concealed(),
        Err(error) => mutation_problem(error),
    }
}

fn parse_download_query(raw: Option<&str>) -> Result<(Option<String>, u32), QueryParseError> {
    let raw = raw.ok_or(QueryParseError::Invalid)?;
    if raw.len() > MAX_RAW_QUERY_BYTES {
        return Err(QueryParseError::Invalid);
    }
    let mut version = None;
    let mut selected = None;
    for pair in raw.split('&') {
        let (name, value) = pair.split_once('=').ok_or(QueryParseError::Invalid)?;
        let (name, value) = (percent_decode(name)?, percent_decode(value)?);
        match name.as_str() {
            "submissionVersion" => {
                let parsed = value.parse::<u32>().map_err(|_| QueryParseError::Invalid)?;
                if parsed == 0 || parsed.to_string() != value || version.replace(parsed).is_some() {
                    return Err(QueryParseError::Invalid);
                }
            }
            "accessProfile" if selected.is_none() && !value.is_empty() => selected = Some(value),
            _ => return Err(QueryParseError::Invalid),
        }
    }
    Ok((selected, version.ok_or(QueryParseError::Invalid)?))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn download_requires_one_canonical_submission_version() {
        for invalid in [
            "",
            "accessProfile=owner",
            "submissionVersion=0",
            "submissionVersion=01",
            "submissionVersion=1&submissionVersion=2",
            "submissionVersion=1&%73ubmissionVersion=2",
            "submissionVersion=4294967296",
            "submissionVersion=1&$select=id",
        ] {
            assert!(parse_download_query(Some(invalid)).is_err(), "{invalid}");
        }
        assert_eq!(
            parse_download_query(Some("submissionVersion=2&accessProfile=owner"))
                .unwrap()
                .1,
            2
        );
    }
}
