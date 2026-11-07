//! The handlers of the OpenID4VCI Draft 13 compatibility profile.
//!
//! See [`crate::draft13`] for what the profile is and how it differs from the
//! 1.0 Final profile on the wire. These handlers reuse the 1.0 profile's offer
//! store, offer authorization, proof validation and Evidence client; what they
//! add is the Draft 13 request and response shapes, a `c_nonce` bound to the
//! access token it is delivered with, and a catalog generation of their own, so
//! that no code, token, or nonce of one profile is usable in the other.

use axum::{
    extract::{Extension, Form, State},
    routing::{get, post},
};
use serde::Deserialize;

use super::*;
use crate::draft13::{
    credential_issuer, issuer_metadata as draft13_metadata, CREDENTIAL_PATH, ISSUER_METADATA_PATH,
    OFFERS_PATH, TOKEN_PATH,
};

/// Register the profile's routes beside the 1.0 profile's.
pub(super) fn routes(router: Router<Arc<DeliveryService>>) -> Router<Arc<DeliveryService>> {
    router
        .route(
            ISSUER_METADATA_PATH,
            get(issuer_metadata).head(unknown_route),
        )
        .route(OFFERS_PATH, post(create_offer))
        .route(TOKEN_PATH, post(token))
        .route(CREDENTIAL_PATH, post(credential))
}

/// The plain JSON issuer metadata, derived from authenticated Evidence
/// discovery like the 1.0 document.
async fn issuer_metadata(State(service): State<Arc<DeliveryService>>) -> Response {
    match service.issuer.catalog().await {
        Ok(catalog) => value_response(StatusCode::OK, &draft13_metadata(&catalog, &service.config)),
        Err(error) => issuance_response(&service, &error),
    }
}

async fn create_offer(
    State(service): State<Arc<DeliveryService>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    create_offer_for(Profile::Draft13, service, headers, body).await
}

/// Exchange a pre-authorized code for an access token and the `c_nonce` the
/// wallet's proof must carry.
///
/// The `c_nonce` is bound to the access token it is delivered with, so it
/// proves freshness for that one exchange and opens no other, and a nonce from
/// the 1.0 nonce endpoint is not one.
async fn token(
    State(service): State<Arc<DeliveryService>>,
    Extension(stage): Extension<RequestStage>,
    Form(request): Form<TokenRequest>,
) -> Response {
    let access_token = match redeem_code(Profile::Draft13, &service, &stage, request).await {
        Ok(access_token) => access_token,
        Err(response) => return response,
    };
    service.metrics.record_outcome(Outcome::NonceMinted);
    value_response(
        StatusCode::OK,
        &json!({
            "access_token": access_token.as_str(),
            "token_type": "bearer",
            "expires_in": service.config.store.access_token_lifetime_seconds,
            "c_nonce": service.nonces.mint_bound(&access_token, service.now()),
            "c_nonce_expires_in": service.config.store.nonce_lifetime_seconds,
        }),
    )
}

/// What a wallet sends to collect its credential: the format and type it
/// wants, and one proof.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRequest {
    format: String,
    vct: String,
    proof: ProofObject,
}

/// The proof object. Members of other proof types are not read: a proof type
/// this profile does not accept is refused by name, not by shape.
#[derive(Deserialize)]
struct ProofObject {
    proof_type: String,
    #[serde(default)]
    jwt: String,
}

/// Issue one credential for one proof.
///
/// The access token is claimed before any proof is looked at, exactly as in
/// the 1.0 profile: a wallet gets one attempt per authorization, and every
/// refusal after the claim is terminal for the exchange. A refused proof
/// therefore carries no fresh `c_nonce`, because the token a fresh nonce would
/// be bound to is already spent.
async fn credential(
    State(service): State<Arc<DeliveryService>>,
    Extension(stage): Extension<RequestStage>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let Some(access_token) = bearer_credential(&headers) else {
        return unauthorized("a bearer access token is required");
    };
    let access_token = Zeroizing::new(access_token.to_owned());
    stage.mark_claiming_token();
    let prepared = match service
        .store
        .claim_access_token(
            &access_token,
            Profile::Draft13.generation(&service),
            service.now(),
        )
        .await
    {
        Ok(prepared) => prepared,
        Err(StoreError::Unknown) => {
            service.metrics.record_outcome(Outcome::TokenClaimRefused);
            return unauthorized("the access token cannot be used");
        }
        Err(error) => return store_response(&service, &error, Outcome::TokenClaimRefused),
    };
    service.metrics.record_outcome(Outcome::TokenClaimed);

    let delivery_audit = match service
        .audit
        .begin_credential_delivery(prepared.exchange_id())
        .await
    {
        Ok(audit) => audit,
        Err(_) => return credential_audit_unavailable_response(),
    };
    refresh_store_entries_in_background(&service);

    let refused = |error: &'static str, description: &'static str| {
        service.metrics.record_outcome(Outcome::ProofRefused);
        problem(StatusCode::BAD_REQUEST, error, description)
    };

    let Ok(body) = std::str::from_utf8(&body) else {
        return audited_credential_response(
            delivery_audit,
            CredentialDeliveryOutcome::ProofRefused,
            refused(
                "invalid_credential_request",
                "the credential request is not a document this service accepts",
            ),
        )
        .await;
    };
    let Ok(document) = serde_json::from_str::<Value>(body) else {
        return audited_credential_response(
            delivery_audit,
            CredentialDeliveryOutcome::ProofRefused,
            refused(
                "invalid_credential_request",
                "the credential request is not a document this service accepts",
            ),
        )
        .await;
    };
    if document.get("proofs").is_some() {
        return audited_credential_response(
            delivery_audit,
            CredentialDeliveryOutcome::ProofRefused,
            refused(
                "invalid_credential_request",
                "this profile accepts one `proof`; the plural `proofs` member is not accepted",
            ),
        )
        .await;
    }
    let Ok(request) = serde_json::from_value::<CredentialRequest>(document) else {
        return audited_credential_response(
            delivery_audit,
            CredentialDeliveryOutcome::ProofRefused,
            refused(
                "invalid_credential_request",
                "the credential request must carry exactly `format`, `vct` and `proof`",
            ),
        )
        .await;
    };
    if request.format != crate::CREDENTIAL_FORMAT {
        return audited_credential_response(
            delivery_audit,
            CredentialDeliveryOutcome::ProofRefused,
            refused(
                "unsupported_credential_format",
                "this profile delivers `dc+sd-jwt` credentials only",
            ),
        )
        .await;
    }
    let Ok(offered) = serde_json::from_str::<OfferedRequest>(prepared.body()) else {
        return audited_credential_response(
            delivery_audit,
            CredentialDeliveryOutcome::InternalError,
            problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "the recorded offer could not be read",
            ),
        )
        .await;
    };
    // The type is the one the offer was created for, so a token cannot be
    // spent on a different credential than the one the adopter authorized.
    if request.vct != offered.evidence_type {
        return audited_credential_response(
            delivery_audit,
            CredentialDeliveryOutcome::ProofRefused,
            refused(
                "unsupported_credential_type",
                "the credential type is not the one this token was issued for",
            ),
        )
        .await;
    }
    if request.proof.proof_type != "jwt" {
        return audited_credential_response(
            delivery_audit,
            CredentialDeliveryOutcome::ProofRefused,
            refused("invalid_proof", "this profile accepts a `jwt` proof only"),
        )
        .await;
    }

    let audience = credential_issuer(&service.config);
    let key = match holder_key_from_proof_with(&service, &request.proof.jwt, &audience, |nonce| {
        service
            .nonces
            .verify_bound(nonce, &access_token, service.now())
    }) {
        Ok(key) => key,
        Err(refusal) => {
            tracing::warn!(
                target: "registry_evidence_oid4vci::service",
                error = refusal.error,
                reason = %refusal.description,
                "draft 13 proof refused"
            );
            service.metrics.record_outcome(match refusal.nonce_outcome {
                Some(outcome) => outcome,
                None => Outcome::ProofRefused,
            });
            // Draft 13 has no `invalid_nonce`: an unusable nonce is an
            // unusable proof.
            return audited_credential_response(
                delivery_audit,
                CredentialDeliveryOutcome::ProofRefused,
                problem(
                    StatusCode::BAD_REQUEST,
                    "invalid_proof",
                    refusal.description,
                ),
            )
            .await;
        }
    };
    if holder_thumbprint(&key).is_err() {
        return audited_credential_response(
            delivery_audit,
            CredentialDeliveryOutcome::ProofRefused,
            refused(
                "invalid_proof",
                "the proof presented a key this service cannot forward",
            ),
        )
        .await;
    }

    let credentials = match service.issuer.issue(offered.into_spec(vec![key])).await {
        Ok(credentials) => credentials,
        Err(error) => {
            let outcome = credential_issuance_audit_outcome(&error);
            return audited_credential_response(
                delivery_audit,
                outcome,
                credential_issuance_response(&service, &error),
            )
            .await;
        }
    };
    // One key was proved, so one credential must come back. Anything else is
    // an answer this profile cannot express, and none of it is released.
    let mut credentials = credentials;
    let credential = match (credentials.pop(), credentials.is_empty()) {
        (Some(credential), true) => credential,
        _ => {
            let error = IssuanceError::Malformed;
            return audited_credential_response(
                delivery_audit,
                credential_issuance_audit_outcome(&error),
                credential_issuance_response(&service, &error),
            )
            .await;
        }
    };
    service.metrics.record_outcome(Outcome::CredentialIssued);

    if delivery_audit
        .finish(CredentialDeliveryOutcome::Released)
        .await
        .is_err()
    {
        return credential_audit_unavailable_response();
    }

    // What Evidence signed, passed on byte for byte.
    value_response(StatusCode::OK, &json!({"credential": credential}))
}
