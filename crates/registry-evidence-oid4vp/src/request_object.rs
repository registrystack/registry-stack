//! The signed authorization request object a wallet fetches from
//! `request_uri` (OpenID4VP 1.0 section 5.10; JWT-secured request, RFC 9101).

use registry_platform_crypto::jws::{sign_compact_jws, JwsError};
use serde_json::{json, Map, Value};

use crate::{
    client_identifier::RequestIdentity,
    config::PolicyConfig,
    policy::{client_metadata, dcql_query},
    session::Session,
};

/// The media type of a served request object (RFC 9101 section 10.2; OpenID4VP
/// 1.0 section 5.10).
pub const CONTENT_TYPE: &str = "application/oauth-authz-req+jwt";

/// The `typ` header of a request object (OpenID4VP 1.0 section 5, RFC 9101).
pub const TYP: &str = "oauth-authz-req+jwt";

/// The `aud` of a signed request when the wallet publishes no metadata
/// (OpenID4VP 1.0 section 5.8, Static Discovery Metadata).
pub const AUDIENCE: &str = "https://self-issued.me/v2";

/// Why a request object could not be produced.
#[derive(Debug, thiserror::Error)]
pub enum RequestObjectError {
    #[error("the request object could not be signed")]
    Signing(#[from] JwsError),
    #[error("the request object payload could not be encoded")]
    Encoding(#[from] serde_json::Error),
}

/// The request object claims for `session` at time `now`.
///
/// `exp` is the session's expiry: a wallet cannot present against a request
/// the service would no longer accept a response to.
#[must_use]
pub fn claims(
    identity: &RequestIdentity,
    session: &Session,
    policy: &PolicyConfig,
    now: u64,
) -> Value {
    json!({
        // 5.2 / 5.9.3: the prefixed Client Identifier.
        "client_id": identity.client_id(),
        // 5.6: the Authorization Response carries a vp_token.
        "response_type": "vp_token",
        // 8.3.1: an encrypted response posted to the response_uri.
        "response_mode": "direct_post.jwt",
        // 8.2: where the wallet posts. Under x509_san_dns the host must match
        // the certificate SAN (5.9.3); under a pre-registered client the wallet
        // matches it against the URIs registered for the client.
        "response_uri": session.response_uri,
        // 5.2: bound to the credential's key binding proof.
        "nonce": session.nonce,
        "state": session.state,
        // 5.1.
        "dcql_query": dcql_query(policy),
        "client_metadata": client_metadata(policy, session.encryption_key.public_jwk()),
        // 5.8.
        "aud": AUDIENCE,
        "iat": now,
        "exp": session.expires_at,
    })
}

/// Sign request object `claims`. An X.509 identity adds its certificate chain
/// to the `x5c` header; an Ed25519 identity adds nothing, and the wallet finds
/// its key by the `kid` the signer writes.
pub async fn sign(
    identity: &RequestIdentity,
    claims: &Value,
) -> Result<String, RequestObjectError> {
    let payload = serde_json::to_vec(claims)?;
    let mut header = Map::new();
    header.insert("typ".to_owned(), Value::from(TYP));
    if let Some(x5c) = identity.x5c() {
        // 5.9.3: the certificate chain, leaf first, in the x5c header.
        header.insert("x5c".to_owned(), json!(x5c));
    }
    Ok(sign_compact_jws(header, &payload, identity.signer()).await?)
}
