// SPDX-License-Identifier: Apache-2.0

//! Engine-owned Proposal slots. Get and Edit have explicit, separate byte grants.
use super::proposals::ReviewDocumentSource;
use super::*;
use crate::model::{CompiledActionExecution, HttpMethod, ProposalOperation};
use crate::postgres::{ProposalAuthority, ProposalAuthorityOperation};

pub(super) fn routes(_service: &HttpService) -> Router<Arc<HttpService>> {
    Router::new()
        .route(
            "/v1/proposals/{proposal_id}/attachments/{slot_id}",
            get(download).patch(upload).delete(remove),
        )
        .route(
            "/v1/proposals/{proposal_id}/additions/{file_id}",
            get(download_addition).post(add),
        )
}

async fn add(
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
        true,
    )
    .await
}

fn mutation_method(removal: bool, addition: bool) -> HttpMethod {
    if addition {
        HttpMethod::Post
    } else if removal {
        HttpMethod::Delete
    } else {
        HttpMethod::Patch
    }
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
        false,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn authorize(
    service: &HttpService,
    id: Uuid,
    slot: &str,
    claims: &VerifiedRequestClaims,
    selected: Option<&str>,
    operation: ProposalOperation,
    context_source: Option<ReviewDocumentSource<'_>>,
    addition: bool,
    method: HttpMethod,
    correlation: &RequestCorrelation,
) -> Result<(String, ProposalAuthority), Response> {
    let mutations = service
        .mutations
        .as_ref()
        .ok_or_else(|| concealed(FailedCheck::Visibility))?;
    let action_id = mutations
        .proposal_action_id(id)
        .await
        .map_err(super::proposals::proposal_problem)?
        .ok_or_else(|| concealed(FailedCheck::Visibility))?;
    let action = service
        .registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == action_id)
        .ok_or_else(|| concealed(FailedCheck::Visibility))?;
    let CompiledActionExecution::Proposal { proposal } = &action.execution else {
        return Err(concealed(FailedCheck::Operation));
    };
    let authority = match super::proposals::authorize_checked(
        &service.registry,
        action,
        claims,
        selected,
        ProposalAuthorityOperation::Lifecycle(operation),
        Some(id),
    ) {
        Ok(authority) => authority,
        Err(check) => {
            return Err(super::proposals::known_action_refusal(
                mutations,
                action,
                claims,
                selected,
                ProposalAuthorityOperation::Lifecycle(operation),
                method,
                correlation,
                check,
            )
            .await);
        }
    };
    let grant = proposal.permissions.iter().find(|grant| {
        grant.profile_id == authority.common.access_profile()
            && grant.operations.contains(&operation)
    });
    let allowed = grant.is_some_and(|grant| match operation {
        ProposalOperation::Get => grant.readable_attachments.contains(slot),
        ProposalOperation::GetReviewContext => match context_source {
            // A file an answer cites is admitted in place of the authored
            // additions field, so the caller's readable context fields do not
            // apply to it. Only a human reviewer receives answers, so only a
            // human reviewer is admitted here.
            Some(ReviewDocumentSource::Ask(_)) => addition && authority.receives_review_answers,
            Some(ReviewDocumentSource::Field(field)) => {
                grant.readable_context_fields.contains(field)
                    && match proposal
                        .review_context
                        .as_ref()
                        .and_then(|context| context.fields.get(field))
                    {
                        Some(crate::contract::ProposalContextValueSource::Document {
                            slot: mapped,
                        }) => !addition && mapped == slot,
                        Some(crate::contract::ProposalContextValueSource::Additions {
                            slot: mapped,
                        }) => addition && mapped == slot,
                        _ => false,
                    }
            }
            None => false,
        },
        ProposalOperation::Edit | ProposalOperation::Add => {
            grant.writable_attachments.contains(slot)
        }
        _ => false,
    });
    let declared = if addition {
        proposal
            .additions
            .as_ref()
            .is_some_and(|definition| definition.id == slot)
    } else {
        proposal.attachments.contains_key(slot)
    };
    if !declared || !allowed {
        return Err(super::proposals::admitted_http_refusal(
            mutations,
            &authority,
            method,
            correlation,
            concealed(FailedCheck::Operation),
        )
        .await);
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
    addition: bool,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed(FailedCheck::Visibility);
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return concealed(FailedCheck::Visibility);
    };
    let Ok(selected) = super::proposals::selected_profile(raw.as_deref()) else {
        return concealed(FailedCheck::Visibility);
    };
    let (action_id, authority) = match authorize(
        &service,
        id,
        &slot,
        &claims,
        selected.as_deref(),
        if addition {
            ProposalOperation::Add
        } else {
            ProposalOperation::Edit
        },
        None,
        addition,
        mutation_method(removal, addition),
        &correlation,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
    };
    let Some(key) =
        single_header(&headers, "idempotency-key").filter(|key| valid_idempotency_key(key))
    else {
        return super::proposals::admitted_http_refusal(
            mutations,
            &authority,
            mutation_method(removal, addition),
            &correlation,
            missing_idempotency_key(),
        )
        .await;
    };
    let Some(etag) = single_header(&headers, "if-match").filter(|etag| valid_if_match(etag)) else {
        return super::proposals::admitted_http_refusal(
            mutations,
            &authority,
            mutation_method(removal, addition),
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
        return concealed(FailedCheck::Operation);
    };
    let (content_types, maximum_bytes) = if addition {
        let definition = proposal.additions.as_ref().expect("admitted addition slot");
        (&definition.content_types, definition.maximum_bytes)
    } else {
        let definition = &proposal.attachments[&slot];
        (&definition.content_types, definition.maximum_bytes)
    };
    let (content_type, bytes) = if removal {
        if !to_bytes(body, 0).await.is_ok_and(|bytes| bytes.is_empty()) {
            return super::proposals::admitted_http_refusal(
                mutations,
                &authority,
                mutation_method(removal, addition),
                &correlation,
                invalid_request(),
            )
            .await;
        }
        (None, None)
    } else {
        let Some(content_type) = single_header(&headers, CONTENT_TYPE.as_str())
            .filter(|value| content_types.iter().any(|allowed| allowed == value))
        else {
            return super::proposals::admitted_http_refusal(
                mutations,
                &authority,
                mutation_method(removal, addition),
                &correlation,
                fixed_problem(ProblemCode::AttachmentContentType),
            )
            .await;
        };
        let bytes = match super::actions::read_action_body(body, maximum_bytes as usize).await {
            Ok(bytes) => bytes,
            Err(error) => {
                let problem = if matches!(error, super::actions::ActionBodyError::TooLarge) {
                    fixed_problem(ProblemCode::AttachmentTooLarge)
                } else {
                    invalid_request()
                };
                return super::proposals::admitted_http_refusal(
                    mutations,
                    &authority,
                    mutation_method(removal, addition),
                    &correlation,
                    problem,
                )
                .await;
            }
        };
        (Some(content_type.to_owned()), Some(bytes))
    };
    let input = super::proposals::ProposalMutationInput {
        action_id: &action_id,
        proposal_id: Some(id),
        operation: ProposalAuthorityOperation::Lifecycle(if addition {
            ProposalOperation::Add
        } else {
            ProposalOperation::Edit
        }),
        authority: &authority,
        idempotency_key: key,
        expected_etag: Some(etag),
        input: None,
        submission_version: None,
        effect_digest: None,
        reason: None,
        executor_lease: None,
        rebase_start_authority: None,
        answer: None,
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
        Err(error) => super::proposals::proposal_problem(error),
    }
}

async fn download(
    State(service): State<Arc<HttpService>>,
    Path((id, slot)): Path<(String, String)>,
    Extension(correlation): Extension<RequestCorrelation>,
    Authenticated(claims): Authenticated,
    RawQuery(raw): RawQuery,
) -> Response {
    download_file(service, id, slot, correlation, claims, raw, false).await
}

async fn download_addition(
    State(service): State<Arc<HttpService>>,
    Path((id, file)): Path<(String, String)>,
    Extension(correlation): Extension<RequestCorrelation>,
    Authenticated(claims): Authenticated,
    RawQuery(raw): RawQuery,
) -> Response {
    download_file(service, id, file, correlation, claims, raw, true).await
}

async fn download_file(
    service: Arc<HttpService>,
    id: String,
    mut slot: String,
    correlation: RequestCorrelation,
    claims: VerifiedRequestClaims,
    raw: Option<String>,
    addition: bool,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed(FailedCheck::Visibility);
    };
    let Ok(id) = Uuid::parse_str(&id) else {
        return concealed(FailedCheck::Visibility);
    };
    let addition_id = if addition {
        let Ok(file) = Uuid::parse_str(&slot) else {
            return concealed(FailedCheck::Visibility);
        };
        let action_id = match mutations.proposal_action_id(id).await {
            Ok(Some(action)) => action,
            Ok(None) => return concealed(FailedCheck::Visibility),
            Err(error) => return super::proposals::proposal_problem(error),
        };
        let Some(definition) = service
            .registry
            .actions()
            .actions
            .iter()
            .find(|action| action.id == action_id)
            .and_then(|action| match &action.execution {
                CompiledActionExecution::Proposal { proposal } => proposal.additions.as_ref(),
                _ => None,
            })
        else {
            return concealed(FailedCheck::Visibility);
        };
        slot = definition.id.clone();
        Some(file)
    } else {
        None
    };
    let Ok(query) = parse_download_query(raw.as_deref()) else {
        return concealed(FailedCheck::Visibility);
    };
    let (field, operation) = match &query.review {
        Some(review) => (Some(review.source()), ProposalOperation::GetReviewContext),
        None => (None, ProposalOperation::Get),
    };
    let (action_id, authority) = match authorize(
        &service,
        id,
        &slot,
        &claims,
        query.selected.as_deref(),
        operation,
        field,
        addition,
        HttpMethod::Get,
        &correlation,
    )
    .await
    {
        Ok(value) => value,
        Err(response) => return response,
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
    let Some(records) = super::proposals::review_record_authorities(
        &service.registry,
        action,
        &claims,
        &authority,
        operation,
        None,
    ) else {
        return super::proposals::admitted_http_refusal(
            mutations,
            &authority,
            HttpMethod::Get,
            &correlation,
            concealed(FailedCheck::Visibility),
        )
        .await;
    };
    let review = query
        .review
        .as_ref()
        .map(|review| super::proposals::ReviewContextDocumentRead {
            source: review.source(),
            effect_digest: &review.effect_digest,
            schema_digest: &review.schema_digest,
            records: &records,
        });
    match mutations
        .proposal_attachment_download(
            id,
            query.version,
            &slot,
            addition_id,
            &authority,
            review.as_ref(),
            &correlation,
        )
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
        Err(MutationError::PreconditionFailed) => concealed(FailedCheck::Visibility),
        Err(error) => super::proposals::proposal_problem(error),
    }
}

#[derive(Debug)]
struct AttachmentDownloadQuery {
    selected: Option<String>,
    version: u32,
    review: Option<ReviewDownloadQuery>,
}
#[derive(Debug)]
enum ReviewDownloadSelector {
    Field(String),
    Ask(Uuid),
}
#[derive(Debug)]
struct ReviewDownloadQuery {
    selector: ReviewDownloadSelector,
    effect_digest: String,
    schema_digest: String,
}

impl ReviewDownloadQuery {
    fn source(&self) -> ReviewDocumentSource<'_> {
        match &self.selector {
            ReviewDownloadSelector::Field(field) => ReviewDocumentSource::Field(field),
            ReviewDownloadSelector::Ask(ask) => ReviewDocumentSource::Ask(*ask),
        }
    }
}

fn parse_download_query(raw: Option<&str>) -> Result<AttachmentDownloadQuery, QueryParseError> {
    let raw = raw.ok_or(QueryParseError::Invalid)?;
    if raw.len() > MAX_RAW_QUERY_BYTES {
        return Err(QueryParseError::Invalid);
    }
    let mut version = None;
    let mut selected = None;
    let mut field = None;
    let mut ask = None;
    let mut effect_digest = None;
    let mut schema_digest = None;
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
            "accessProfile"
                if selected.is_none() && registry_platform_yaml::LocalId::new(&value).is_ok() =>
            {
                selected = Some(value)
            }
            "reviewContextField"
                if field.is_none() && crate::logical_names::valid_api_name(&value) =>
            {
                field = Some(value)
            }
            "reviewAskId" if ask.is_none() => {
                let id = Uuid::parse_str(&value).map_err(|_| QueryParseError::Invalid)?;
                if id.is_nil() || id.to_string() != value {
                    return Err(QueryParseError::Invalid);
                }
                ask = Some(id);
            }
            "effectDigest"
                if effect_digest.is_none()
                    && registry_platform_yaml::Digest::new(&value).is_ok() =>
            {
                effect_digest = Some(value)
            }
            "contextSchemaDigest"
                if schema_digest.is_none()
                    && registry_platform_yaml::Digest::new(&value).is_ok() =>
            {
                schema_digest = Some(value)
            }
            _ => return Err(QueryParseError::Invalid),
        }
    }
    let review = match (field, ask, effect_digest, schema_digest) {
        (None, None, None, None) => None,
        (Some(field), None, Some(effect_digest), Some(schema_digest)) => {
            Some(ReviewDownloadQuery {
                selector: ReviewDownloadSelector::Field(field),
                effect_digest,
                schema_digest,
            })
        }
        (None, Some(ask), Some(effect_digest), Some(schema_digest)) => Some(ReviewDownloadQuery {
            selector: ReviewDownloadSelector::Ask(ask),
            effect_digest,
            schema_digest,
        }),
        _ => return Err(QueryParseError::Invalid),
    };
    Ok(AttachmentDownloadQuery {
        selected,
        version: version.ok_or(QueryParseError::Invalid)?,
        review,
    })
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
                .version,
            2
        );
    }

    #[test]
    fn review_document_query_is_complete_closed_and_exclusive() {
        let valid = format!("submissionVersion=1&reviewContextField=supportingDocument&effectDigest=sha256%3A{}&contextSchemaDigest=sha256%3A{}&accessProfile=reviewer_one", "a".repeat(64), "b".repeat(64));
        let parsed = parse_download_query(Some(&valid)).unwrap();
        assert!(
            matches!(parsed.review.unwrap().selector,ReviewDownloadSelector::Field(field) if field=="supportingDocument")
        );
        for invalid in [
            "submissionVersion=1&reviewContextField=supportingDocument".to_owned(),
            valid.replace("effectDigest=", "unknown="),
            valid.replace("submissionVersion=1", "submissionVersion=01"),
            valid.replace(
                "reviewContextField=supportingDocument",
                "reviewContextField=bad-field",
            ),
            valid.replace("sha256%3A", "sha256%3Ax"),
            format!("{valid}&%72eviewContextField=supportingDocument"),
            format!("{valid}&effectDigest=sha256%3A{}", "a".repeat(64)),
            format!("{valid}&contextSchemaDigest=sha256%3A{}", "b".repeat(64)),
            format!("{valid}&accessProfile=owner"),
        ] {
            assert!(parse_download_query(Some(&invalid)).is_err(), "{invalid}");
        }
    }
}
