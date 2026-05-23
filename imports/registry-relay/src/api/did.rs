// SPDX-License-Identifier: Apache-2.0
//! Public, unauthenticated `/.well-known/did.json` route.
//!
//! Gateway-mode deployments self-publish their DID Document at this
//! path so consumers can resolve `did:web:<host>` to a verification
//! method and verify VC signatures. Delegated-mode deployments return
//! `404` here: the ministry hosts its own DID Document.
//!
//! The document is built from
//! `crate::provenance::did_web::build_did_document` and the active
//! signer's public JWK. Retired keys stay in `verificationMethod`
//! until their last issued credential has expired; a key is removed
//! when `now > retired_after + max_validity + clock_skew_grace`
//! (spec §7, §13.4). `max_validity` is the longest claim-validity
//! window across all claim types; `clock_skew_grace` is 5 minutes.

use std::sync::Arc;
use std::time::Duration;

use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Router};
use time::OffsetDateTime;

use crate::error::{Error, ProvenanceError};
use crate::provenance::did_web::{build_did_document, VerificationMethodEntry};
use crate::provenance::{IssuerMode, ProvenanceState};

const APPLICATION_DID_JSON: HeaderValue = HeaderValue::from_static("application/did+json");
const CACHE_CONTROL_5M: HeaderValue = HeaderValue::from_static("public, max-age=300");

/// Grace window added to `max_validity` before a retired key is dropped
/// from the DID Document. Accounts for clock skew between the issuer
/// and verifiers (spec §7 default: 300 s).
const CLOCK_SKEW_GRACE: Duration = Duration::from_secs(300);

pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route("/.well-known/did.json", get(serve_did_document))
}

async fn serve_did_document(state: Option<Extension<Arc<ProvenanceState>>>) -> Response {
    let Some(Extension(state)) = state else {
        return Error::from(ProvenanceError::DidDocumentUnavailable).into_response();
    };
    let now = (state.clock)();
    serve_did_document_at(&state, now)
}

/// Inner, clock-injectable handler. The public axum handler passes
/// `OffsetDateTime::now_utc()`; tests pass a pinned instant.
fn serve_did_document_at(state: &ProvenanceState, now: OffsetDateTime) -> Response {
    let cfg = state.config();
    if cfg.mode != IssuerMode::Gateway {
        return Error::from(ProvenanceError::DidDocumentUnavailable).into_response();
    }
    let active = VerificationMethodEntry {
        id: cfg.verification_method_id.clone(),
        controller: cfg.issuer_did.clone(),
        public_jwk: cfg.signer.public_jwk(),
    };

    // Compute the longest validity window across all claim types so that
    // any credential signed by the retired key can still be verified
    // before we remove the key from the DID Document (spec §13.4).
    let cv = &cfg.claim_validity;
    let max_validity = cv.aggregate_result.max(cv.entity_record);

    // A retired key stays in `verificationMethod` while
    // `now <= retired_after + max_validity + clock_skew_grace`.
    // Once `now` passes that cutoff the key drops out deterministically.
    let grace =
        time::Duration::try_from(max_validity + CLOCK_SKEW_GRACE).unwrap_or(time::Duration::MAX);

    let retired: Vec<VerificationMethodEntry> = cfg
        .retired_keys
        .iter()
        .filter(|entry| {
            entry
                .retired_after
                .checked_add(grace)
                .map(|cutoff| now <= cutoff)
                .unwrap_or(false)
        })
        .map(|entry| VerificationMethodEntry {
            id: entry.verification_method_id.clone(),
            controller: cfg.issuer_did.clone(),
            public_jwk: entry.public_jwk.clone(),
        })
        .collect();

    let doc = build_did_document(&cfg.issuer_did, &active, &retired);
    let body = match serde_json::to_vec(&doc) {
        Ok(bytes) => bytes,
        Err(_) => return Error::from(ProvenanceError::IssuanceFailed).into_response(),
    };

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, APPLICATION_DID_JSON);
    headers.insert(header::CACHE_CONTROL, CACHE_CONTROL_5M);
    (StatusCode::OK, headers, body).into_response()
}
