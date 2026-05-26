// SPDX-License-Identifier: Apache-2.0
//! HTTP-layer issuance helper: Accept negotiation + VC issuance.
//!
//! Protected handlers use this helper for aggregate and entity-record
//! credential issuance. The shape is the same in both places:
//!
//! 1. Build the normal plain JSON response.
//! 2. Ask [`crate::provenance::negotiate`] whether the caller opted in
//!    with `Accept: application/vc+jwt`.
//! 3. If yes (and provenance is enabled), build the typed claim subject
//!    via the matching `crate::provenance::claim` builder, hand it to
//!    [`crate::provenance::ProvenanceState::issue`], and return a 200
//!    response with `Content-Type: application/vc+jwt` and the compact
//!    JWS as the body. Attach [`crate::audit::ProvenanceIssuanceExt`] so
//!    the audit middleware emits a `provenance.vc.issued` event.
//! 4. If no (no opt-in, or provenance disabled / absent), return the
//!    plain JSON response unchanged. This keeps non-VC callers on the
//!    same response contract.
//!
//! The helper is `pub(crate)` because it is an implementation detail of
//! the api module; nothing outside `src/api` should call it directly.

use std::sync::Arc;

use axum::http::{header, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use time::OffsetDateTime;

use crate::audit::ProvenanceIssuanceExt;
use crate::config::Config;
use crate::error::{Error, ProvenanceError};
use crate::provenance::claim::{
    aggregate_result_subject, entity_record_subject, AggregateResultInput, EntityRecordInput,
};
use crate::provenance::publicschema::PublicSchemaVcRegistry;
use crate::provenance::{
    negotiate, ClaimType, IssuanceContext, IssueError, NegotiationOutcome, ProvenanceState,
    VcCredentialProfile,
};

/// Media type emitted on a signed VC response. The audit / observability
/// layer uses this as the only signal that a response carried a VC.
const VC_JWT_CONTENT_TYPE: HeaderValue = HeaderValue::from_static("application/vc+jwt");

/// Decide whether the caller asked for a signed VC and the gateway is
/// allowed to issue one (provenance present + enabled + accepted media
/// type listed). Returns the live [`ProvenanceState`] handle when all
/// conditions hold; `None` when the plain JSON path should run
/// instead.
pub(crate) fn signed_vc_requested<'a>(
    state: Option<&'a Arc<ProvenanceState>>,
    headers: &HeaderMap,
) -> Option<&'a Arc<ProvenanceState>> {
    let state = state?;
    if !state.is_enabled() {
        return None;
    }
    match negotiate(headers, &state.config().accepted_media_types) {
        NegotiationOutcome::SignedVc => Some(state),
        NegotiationOutcome::PlainJson => None,
    }
}

/// Build the canonical subject URI for an entity row, used as both the
/// VC `credentialSubject.id` and JWT `sub`.
pub(crate) fn entity_subject_uri(config: &Config, dataset: &str, entity: &str, id: &str) -> String {
    let base = config.catalog.base_url.trim_end_matches('/');
    format!("{base}/datasets/{dataset}/{entity}/{id}")
}

/// Build the canonical subject URI for an aggregate result, used as the
/// VC `credentialSubject.id`. The aggregate's URL is the public route
/// the gateway exposes.
pub(crate) fn aggregate_subject_uri(config: &Config, dataset: &str, aggregate_id: &str) -> String {
    let base = config.catalog.base_url.trim_end_matches('/');
    format!("{base}/datasets/{dataset}/aggregates/{aggregate_id}")
}

/// Common path: hand a built `credentialSubject` to the orchestrator,
/// wrap the resulting compact JWS in an HTTP response, and attach the
/// `ProvenanceIssuanceExt` so audit picks it up.
fn issue_response(
    state: &ProvenanceState,
    claim_type: ClaimType,
    subject_uri: String,
    credential_subject: Value,
    profile: Option<VcCredentialProfile>,
) -> Response {
    let issued_at = OffsetDateTime::now_utc();
    let signed = match state.issue_with_profile(
        IssuanceContext {
            claim_type,
            subject_uri: subject_uri.clone(),
            credential_subject,
            issued_at,
        },
        profile,
    ) {
        Ok(signed) => signed,
        Err(err) => return issue_error_to_response(err),
    };
    let mut response = signed.compact_jws.clone().into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, VC_JWT_CONTENT_TYPE);
    response.extensions_mut().insert(ProvenanceIssuanceExt {
        iss: signed.issuer_did,
        kid: signed.verification_method_id,
        jti: signed.jti,
        claim_type: signed.credential_type,
        subject: subject_uri,
        iat: signed.iat,
        nbf: signed.nbf,
        exp: signed.exp,
    });
    response
}

fn issue_error_to_response(err: IssueError) -> Response {
    let error = match err {
        IssueError::SignerUnavailable => Error::from(ProvenanceError::SignerUnavailable),
        IssueError::IssuanceFailed => Error::from(ProvenanceError::IssuanceFailed),
    };
    error.into_response()
}

/// Inputs for [`maybe_issue_aggregate_result`]. Carrying them in a
/// struct keeps the helper signature short and lets the handler build
/// the values once before deciding on the negotiation outcome.
#[derive(Debug, Clone)]
pub(crate) struct AggregateIssuanceArgs<'a> {
    pub dataset: &'a str,
    pub aggregate_id: &'a str,
    pub group_by: Vec<String>,
    pub indicators: Vec<String>,
    pub rows: Vec<Value>,
    pub suppressed_rows: u64,
    pub min_cell_size: u64,
    pub computed_at_rfc3339: String,
    pub as_of_rfc3339: Option<String>,
}

/// Issue an `AggregateResult` VC. Same opt-in contract as
/// [`maybe_issue_aggregate_result`].
pub(crate) fn maybe_issue_aggregate_result(
    state: Option<&Arc<ProvenanceState>>,
    config: Option<&Arc<Config>>,
    headers: &HeaderMap,
    plain_response: Response,
    args: AggregateIssuanceArgs<'_>,
) -> Response {
    let Some(state) = signed_vc_requested(state, headers) else {
        return plain_response;
    };
    let Some(config) = config else {
        return plain_response;
    };
    let subject_uri = aggregate_subject_uri(config, args.dataset, args.aggregate_id);
    let subject = aggregate_result_subject(&AggregateResultInput {
        subject_uri: subject_uri.clone(),
        dataset: args.dataset.to_string(),
        aggregate_id: args.aggregate_id.to_string(),
        aggregate_url: subject_uri.clone(),
        group_by: args.group_by,
        indicators: args.indicators,
        rows: args.rows,
        suppressed_rows: args.suppressed_rows,
        min_cell_size: args.min_cell_size,
        computed_at_rfc3339: args.computed_at_rfc3339,
        as_of_rfc3339: args.as_of_rfc3339,
    });
    issue_response(
        state,
        ClaimType::AggregateResult,
        subject_uri,
        subject,
        None,
    )
}

/// Issue an `EntityRecord` VC. Same opt-in contract as
/// [`maybe_issue_aggregate_result`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn maybe_issue_entity_record(
    state: Option<&Arc<ProvenanceState>>,
    config: Option<&Arc<Config>>,
    publicschema: Option<&Arc<PublicSchemaVcRegistry>>,
    headers: &HeaderMap,
    plain_response: Response,
    dataset: &str,
    entity: &str,
    subject_id: &str,
    record: Value,
    expansions: Vec<String>,
    as_of_rfc3339: String,
) -> Response {
    let Some(state) = signed_vc_requested(state, headers) else {
        return plain_response;
    };
    let Some(config) = config else {
        return plain_response;
    };
    let subject_uri = entity_subject_uri(config, dataset, entity, subject_id);
    if let Some(publicschema) = publicschema {
        match publicschema.mapped_entity_credential(dataset, entity, &subject_uri, record.clone()) {
            Ok(Some(mapped)) => {
                return issue_response(
                    state,
                    ClaimType::EntityRecord,
                    subject_uri,
                    mapped.credential_subject,
                    Some(VcCredentialProfile {
                        credential_type: mapped.credential_type,
                        context_url: mapped.context_url,
                        schema_url: mapped.schema_url,
                    }),
                );
            }
            Ok(None) => {}
            Err(err) => {
                tracing::error!(error = %err, "publicschema.issuance_failed");
                return issue_error_to_response(IssueError::IssuanceFailed);
            }
        }
    }
    let subject = entity_record_subject(&EntityRecordInput {
        subject_uri: subject_uri.clone(),
        dataset: dataset.to_string(),
        entity: entity.to_string(),
        subject_id: subject_id.to_string(),
        record,
        expansions,
        as_of_rfc3339,
    });
    issue_response(state, ClaimType::EntityRecord, subject_uri, subject, None)
}

/// Build an RFC 3339 string for "now" in UTC. Helper kept here so the
/// callers don't need to import `time::format_description` themselves.
#[must_use]
pub(crate) fn now_rfc3339() -> String {
    use time::format_description::well_known::Rfc3339;
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| String::new())
}
