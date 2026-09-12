//! Proof that the offer boundary is a resource server for standards-based
//! access tokens, including one issued by the pinned stock local issuer.
//!
//! The adopter-facing offer endpoint is the only authorization boundary this
//! service has. Focused cases use a deterministic signer to vary one claim at a
//! time. The ignored exact gate provisions the installed pinned issuer, obtains
//! a token with `private_key_jwt`, and verifies it against the issuer's own
//! public key snapshot.
//!
//! Nothing here touches the client half of the process. This service's own token
//! client identity has no part in any decision below, which is the separation
//! [`registry_evidence_oid4vci::authorizer`] exists to keep.

use std::{
    collections::BTreeMap, net::TcpListener, os::unix::fs::PermissionsExt as _, path::PathBuf,
    sync::Arc,
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_evidence_client::{PrivateKeyJwt, PrivateKeyJwtConfig, TokenProvider};
use registry_evidence_oid4vci::{
    authorizer::{verifier_profile, AuthorizationError, MintResourceServer, OfferAuthorizer},
    config::{AccessTokenAlgorithm, OfferAuthorizationConfig},
};
use registry_platform_crypto::{sign, PrivateJwk, PublicJwk};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier};
use registry_thunderid_tooling::{
    container::Session,
    description::SessionIdentity,
    local::{self, TypedLocalClient},
    render,
    version::ThunderIdPin,
};
use serde_json::{json, Value};

const FIXTURE_ISSUER: &str = "https://issuer.example.org";
const OFFER_AUDIENCE: &str = "https://delivery.example.org";
const CLIENT_ID: &str = "offer-caller";
const PRINCIPAL: &str = "urn:example:offer-caller";

/// Deterministic P-256 material for the token signing key, so the access token
/// this test verifies is ES256 signed exactly as a deployment's would be.
fn signing_key_pair(seed: u8) -> (Value, Value) {
    let scalar = [seed; 32];
    let signing = p256::ecdsa::SigningKey::from_slice(&scalar).expect("a valid P-256 scalar");
    let encoded = signing.verifying_key().to_encoded_point(false);
    let x = URL_SAFE_NO_PAD.encode(encoded.x().expect("an uncompressed point has x"));
    let y = URL_SAFE_NO_PAD.encode(encoded.y().expect("an uncompressed point has y"));
    let bare = PublicJwk::parse(
        &json!({"kty": "EC", "crv": "P-256", "alg": "ES256", "x": x, "y": y}).to_string(),
    )
    .expect("the public JWK parses");
    let kid = bare.jkt().expect("the thumbprint computes");
    (
        json!({"kty": "EC", "crv": "P-256", "alg": "ES256", "kid": kid, "x": x, "y": y}),
        json!({"kty": "EC", "crv": "P-256", "alg": "ES256", "kid": kid, "x": x, "y": y,
               "d": URL_SAFE_NO_PAD.encode(scalar)}),
    )
}

/// The offer boundary, built over the profile and a trusted key snapshot.
fn resource_server(config: &OfferAuthorizationConfig, key_set: &Value) -> MintResourceServer {
    let parsed: jsonwebtoken::jwk::JwkSet =
        serde_json::from_value(key_set.clone()).expect("the issuer publishes a parsable key set");
    let fetcher = Arc::new(JwksFetcher::new_static(
        parsed,
        JwksFetcherConfig::defaults(),
    ));
    MintResourceServer::new(Arc::new(TokenVerifier::new(
        verifier_profile(config),
        fetcher,
    )))
    .with_required_scopes(config.required_scopes.clone().unwrap_or_default())
}

fn offer_config(
    issuer: &str,
    audience: &str,
    algorithm: AccessTokenAlgorithm,
) -> OfferAuthorizationConfig {
    OfferAuthorizationConfig {
        issuer: issuer.to_owned(),
        jwks_uri: format!("{issuer}/oauth2/jwks"),
        audiences: vec![audience.to_owned()],
        algorithms: vec![algorithm],
        authorized_clients: Vec::new(),
        required_scopes: None,
        maximum_token_lifetime_seconds: 900,
    }
}

/// The required-scope gate: a correctly signed, audience-matching token whose
/// scope set omits the configured offer permission authorizes nothing.
#[tokio::test]
async fn a_token_without_the_required_offer_scope_is_refused() {
    let (issued, key_set) = signed_offer_fixture(json!({"scope":"offers:read"}));
    let mut config = offer_config(FIXTURE_ISSUER, OFFER_AUDIENCE, AccessTokenAlgorithm::ES256);
    config.required_scopes = Some(vec!["oid4vci:offer".to_owned()]);
    assert_eq!(
        resource_server(&config, &key_set).authorize(&issued).await,
        Err(AuthorizationError::Refused),
        "a correctly signed audience-matching token with no offer scope authorized an offer"
    );

    let (signing_public, signing_document) = signing_key_pair(7);
    let private =
        PrivateJwk::parse(&signing_document.to_string()).expect("the fixture signing key parses");
    let kid = signing_public["kid"].as_str().expect("the key has an id");
    let now = chrono::Utc::now().timestamp();
    let header = json!({"alg": "ES256", "typ": "at+jwt", "kid": kid});
    let claims = json!({
        "iss": FIXTURE_ISSUER,
        "aud": OFFER_AUDIENCE,
        "sub": PRINCIPAL,
        "iat": now,
        "exp": now + 300,
        "scope": "oid4vci:offer offers:read",
    });
    let encode =
        |value: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("serializes"));
    let signing_input = format!("{}.{}", encode(&header), encode(&claims));
    let signature = sign(signing_input.as_bytes(), &private).expect("the fixture signs");
    let fixture = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature));

    let key_set = json!({"keys": [signing_public]});
    resource_server(&config, &key_set)
        .authorize(&fixture)
        .await
        .expect("a token carrying the required offer scope authorizes an offer");
}

fn signed_offer_fixture(extra: Value) -> (String, Value) {
    let (signing_public, signing_document) = signing_key_pair(7);
    let private =
        PrivateJwk::parse(&signing_document.to_string()).expect("the fixture signing key parses");
    let kid = signing_public["kid"].as_str().expect("the key has an id");
    let now = chrono::Utc::now().timestamp();
    let header = json!({"alg": "ES256", "typ": "at+jwt", "kid": kid});
    let mut claims = json!({
        "iss": FIXTURE_ISSUER,
        "aud": OFFER_AUDIENCE,
        "sub": PRINCIPAL,
        "iat": now,
        "exp": now + 300,
        "scope": "oid4vci:offer",
    });
    claims
        .as_object_mut()
        .expect("claims are an object")
        .extend(
            extra
                .as_object()
                .expect("extra claims are an object")
                .clone(),
        );
    let encode =
        |value: &Value| URL_SAFE_NO_PAD.encode(serde_json::to_vec(value).expect("serializes"));
    let signing_input = format!("{}.{}", encode(&header), encode(&claims));
    let signature = sign(signing_input.as_bytes(), &private).expect("the fixture signs");
    (
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature)),
        json!({"keys": [signing_public]}),
    )
}

#[tokio::test]
async fn task_bound_and_partial_grants_cannot_create_deferred_wallet_offers() {
    let now = chrono::Utc::now().timestamp();
    let (task_bound, keys) = signed_offer_fixture(json!({
        "registry_actor_kind":"agent",
        "registry_grant_id":"grant-a",
        "registry_grant_authority":"authority-a",
        "registry_grant_source_issuer":"https://casework.example",
        "registry_grant_client":"offer-caller",
        "registry_grant_resource":OFFER_AUDIENCE,
        "registry_purpose":"credential-delivery",
        "registry_grant_exp":now + 300,
        "registry_grant_bounds":{"type":"evidence","requirement":"urn:example:requirement"}
    }));
    let config = {
        let mut config = offer_config(FIXTURE_ISSUER, OFFER_AUDIENCE, AccessTokenAlgorithm::ES256);
        config.required_scopes = Some(vec!["oid4vci:offer".to_owned()]);
        config
    };
    assert_eq!(
        resource_server(&config, &keys).authorize(&task_bound).await,
        Err(AuthorizationError::Refused)
    );

    let (partial, keys) = signed_offer_fixture(json!({"registry_grant_id":"grant-a"}));
    assert_eq!(
        resource_server(&config, &keys).authorize(&partial).await,
        Err(AuthorizationError::Refused)
    );
}

#[tokio::test]
async fn an_ordinary_service_offer_with_purpose_but_no_grant_remains_supported() {
    let (ordinary, keys) = signed_offer_fixture(json!({
        "registry_actor_kind":"service",
        "registry_purpose":"credential-delivery"
    }));
    let mut config = offer_config(FIXTURE_ISSUER, OFFER_AUDIENCE, AccessTokenAlgorithm::ES256);
    config.required_scopes = Some(vec!["oid4vci:offer".to_owned()]);
    resource_server(&config, &keys)
        .authorize(&ordinary)
        .await
        .expect("an ordinary service offer remains supported");
}

#[tokio::test]
async fn a_token_issued_for_another_resource_server_is_refused() {
    let (token, key_set) = signed_offer_fixture(json!({}));
    // The same correctly signed token, presented to a deployment that answers to a
    // different audience. An adopter's token for another resource server is
    // not an offer authorization here.
    assert_eq!(
        resource_server(
            &offer_config(
                FIXTURE_ISSUER,
                "https://elsewhere.example.org",
                AccessTokenAlgorithm::ES256
            ),
            &key_set
        )
        .authorize(&token)
        .await,
        Err(AuthorizationError::Refused)
    );
}

#[tokio::test]
async fn a_token_this_issuer_did_not_sign_is_refused() {
    let (token, key_set) = signed_offer_fixture(json!({}));
    let config = offer_config(FIXTURE_ISSUER, OFFER_AUDIENCE, AccessTokenAlgorithm::ES256);
    let server = resource_server(&config, &key_set);

    // A token whose signature was replaced, presented otherwise unchanged.
    let mut parts: Vec<&str> = token.split('.').collect();
    parts.pop();
    let forged = format!("{}.{}", parts.join("."), URL_SAFE_NO_PAD.encode([0_u8; 64]));
    assert_eq!(
        server.authorize(&forged).await,
        Err(AuthorizationError::Refused)
    );
    assert_eq!(
        server.authorize("not-a-token").await,
        Err(AuthorizationError::Refused)
    );
    assert_eq!(server.authorize("").await, Err(AuthorizationError::Missing));
}

struct OwnedStockSession {
    label: String,
    id: String,
    port: u16,
    state_root: PathBuf,
    image: String,
    docker: PathBuf,
}

impl Drop for OwnedStockSession {
    fn drop(&mut self) {
        let session = Session {
            label: &self.label,
            id: &self.id,
            port: self.port,
            state_root: &self.state_root,
            image: &self.image,
        };
        let _ = local::stop(&session, &self.docker);
    }
}

fn installed_or_env(variable: &str, binary: &str) -> PathBuf {
    if let Some(path) = std::env::var_os(variable) {
        return PathBuf::from(path);
    }
    std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default())
        .map(|directory| directory.join(binary))
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| panic!("set {variable} for the exact stock-issuer gate"))
}

/// Replacement acceptance for the former in-process supporting-issuer fixture. This gate
/// uses the installed pinned issuer, its native private-key-JWT registration,
/// its real token endpoint, and the exact public RS256 keys it served.
#[test]
#[ignore = "exact gate: starts the pinned stock issuer container"]
fn stock_issuer_service_token_authorizes_the_offer_boundary() {
    let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve issuer port");
    let port = reservation.local_addr().expect("issuer address").port();
    let issuer = format!("http://127.0.0.1:{port}");
    let directory = tempfile::tempdir().expect("private stock issuer state");
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700))
        .expect("issuer state is owner-only");
    let state_root = directory.path().join("issuer");
    let label = format!("oid4vci-offer-{port}");
    let id = format!("oid4vci-offer-session-{port}");
    let (public, private) = signing_key_pair(11);
    let description = local::typed_local_description(
        SessionIdentity {
            label: label.clone(),
            id: id.clone(),
        },
        port,
        state_root.clone(),
        OFFER_AUDIENCE.to_owned(),
        vec![TypedLocalClient {
            client_id: CLIENT_ID.to_owned(),
            public_jwks: json!({"keys":[public]}).to_string(),
            claims: BTreeMap::from([
                ("registry_actor_kind".to_owned(), json!("service")),
                ("registry_purpose".to_owned(), json!("credential-delivery")),
            ]),
            scopes: vec!["oid4vci:offer".to_owned()],
            allow_human_fixture: false,
        }],
    )
    .expect("the stock issuer description is valid");
    render::render(&description).expect("the stock issuer resources render");
    let pin = ThunderIdPin::load().expect("the maintained stock issuer pin loads");
    let docker = installed_or_env("DOCKER_BIN", "docker");
    let session = Session {
        label: &label,
        id: &id,
        port,
        state_root: &state_root,
        image: &pin.image,
    };
    drop(reservation);
    let keys =
        local::start(&session, &docker, &mut || false).expect("the pinned stock issuer starts");
    let _owned = OwnedStockSession {
        label,
        id,
        port,
        state_root,
        image: pin.image,
        docker,
    };

    let private = PrivateJwk::parse(&private.to_string()).expect("the client key parses");
    let provider = PrivateKeyJwt::new(
        PrivateKeyJwtConfig::new(
            format!("{issuer}/oauth2/token")
                .parse()
                .expect("the token endpoint parses"),
            CLIENT_ID,
            private,
        )
        .with_audience(issuer.clone())
        .with_resource(OFFER_AUDIENCE)
        .with_scopes(["oid4vci:offer".to_owned()]),
    )
    .expect("the private-key-JWT client is valid");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("the HTTP runtime builds");
    let issued = runtime
        .block_on(provider.bearer_token())
        .expect("the stock issuer issues an offer token");
    let authorization = issued.authorization_header_value();
    let compact = authorization
        .to_str()
        .expect("the issued token is header-safe")
        .strip_prefix("Bearer ")
        .expect("the provider uses the bearer scheme");
    let config = offer_config(&issuer, OFFER_AUDIENCE, AccessTokenAlgorithm::RS256);
    let authorized = runtime
        .block_on(resource_server(&config, &keys).authorize(compact))
        .expect("the offer boundary accepts the stock issuer token");
    assert_eq!(authorized.client.as_deref(), Some(CLIENT_ID));
    assert!(authorized.subject.is_some());
}
