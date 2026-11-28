// SPDX-License-Identifier: Apache-2.0
//! Applicant answers use the same admission, ETag and receipt boundary as other commands.
use super::*;
use crate::review_store::asks::{AnswerBody, AnswerMutation};

#[allow(clippy::too_many_arguments)]
pub(in crate::api) async fn answer(
    State(service): State<Arc<HttpService>>,
    Path((id, ask)): Path<(String, String)>,
    Extension(correlation): Extension<RequestCorrelation>,
    Authenticated(claims): Authenticated,
    RawQuery(raw_query): RawQuery,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let Some(mutations) = &service.mutations else {
        return concealed(FailedCheck::Visibility);
    };
    let (Ok(id), Ok(ask_id)) = (Uuid::parse_str(&id), Uuid::parse_str(&ask)) else {
        return concealed(FailedCheck::Visibility);
    };
    if id.is_nil() || ask_id.is_nil() {
        return concealed(FailedCheck::Visibility);
    }
    let Ok(selected) = selected_profile(raw_query.as_deref()) else {
        return concealed(FailedCheck::Visibility);
    };
    let action_id = match mutations.proposal_action_id(id).await {
        Ok(Some(action)) => action,
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
    let operation = ProposalAuthorityOperation::Lifecycle(ProposalOperation::Answer);
    let authority = match authorize_checked(
        &service.registry,
        action,
        &claims,
        selected.as_deref(),
        operation,
        Some(id),
    ) {
        Ok(authority) => authority,
        Err(check) => {
            return known_action_refusal(
                mutations,
                action,
                &claims,
                selected.as_deref(),
                operation,
                HttpMethod::Post,
                &correlation,
                check,
            )
            .await
        }
    };
    let refusal = async {
        if !single_content_type(&headers, "application/json") {
            return Err(unsupported_media_type());
        }
        let key = single_header(&headers, "idempotency-key")
            .filter(|key| valid_idempotency_key(key))
            .ok_or_else(missing_idempotency_key)?;
        let etag = single_header(&headers, "if-match")
            .filter(|etag| valid_if_match(etag))
            .ok_or_else(precondition_required)?;
        let bytes = bounded_body_to(body, 16_384)
            .await
            .map_err(|_| invalid_request())?;
        let value = parse_json_strict(&bytes).map_err(|_| invalid_request())?;
        if value.get("text").is_some_and(Value::is_null) {
            return Err(proposal_problem(MutationError::InvalidRequestAt(
                crate::problem_location::RequestLocation::proposal_answer_text(),
            )));
        }
        let answer: AnswerBody = serde_json::from_value(value).map_err(|_| invalid_request())?;
        Ok((key, etag, answer))
    }
    .await;
    let (key, etag, body) = match refusal {
        Ok(values) => values,
        Err(response) => {
            return admitted_http_refusal(
                mutations,
                &authority,
                HttpMethod::Post,
                &correlation,
                response,
            )
            .await
        }
    };
    match mutations
        .proposal_mutation(ProposalMutationInput {
            action_id: &action.id,
            proposal_id: Some(id),
            operation,
            authority: &authority,
            idempotency_key: key,
            expected_etag: Some(etag),
            input: None,
            submission_version: None,
            effect_digest: None,
            reason: None,
            executor_lease: None,
            rebase_start_authority: None,
            attachment: None,
            answer: Some(AnswerMutation { ask_id, body }),
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
