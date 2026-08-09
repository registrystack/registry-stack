//! The delivery service and its HTTP boundary.
//!
//! Two entry points, and the difference between them is the whole point of
//! having both: [`DeliveryService::check`] validates everything a serving
//! process needs and takes nothing, while [`serve`] binds the configured
//! listener. An operator can therefore validate an edited configuration on the
//! host that is already serving the old one.
//!
//! # The two identities
//!
//! [`OFFERS_PATH`] is the authorization boundary of this service. It is a
//! resource server for tokens an authorization server issued, verified through
//! [`crate::authorizer`]. Everything this service asks Evidence for goes out
//! under its own client identity, through [`crate::issuer`]. The two are
//! configured by separate documents, built by separate constructors, and share
//! no code path, so neither can be used to reach the other.
//!
//! # What the wallet-facing routes never do
//!
//! No route here signs a credential, and no state held here can. A credential
//! is whatever Evidence returned, passed on byte for byte, and the only key
//! this process holds is the one that authenticates it to the authorization
//! server. A holder's private key stays with the holder: a proof presents a
//! public key, the key is read out of the validated proof, and the type it is
//! read into has no member a private one could be written to.

use std::{
    future::{Future, IntoFuture},
    io,
    net::SocketAddr,
    sync::Arc,
    time::Duration,
};

use axum::{
    body::Body,
    extract::{DefaultBodyLimit, Form, State},
    http::{
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, PRAGMA, WWW_AUTHENTICATE},
        HeaderMap, HeaderValue, Request, StatusCode,
    },
    middleware::{from_fn, from_fn_with_state, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use registry_evidence_client::{HolderPublicKey, MAXIMUM_HOLDER_KEYS};
use registry_platform_crypto::PublicJwk;
use registry_platform_sdjwt::{validate_oid4vci_proof_jwt, Oid4vciProofPolicy};
use serde::Deserialize;
use serde_json::{json, Value};
use thiserror::Error;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

use crate::{
    authorizer::{AuthorizationError, MintResourceServer, OfferAuthorizer},
    config::DeliveryConfig,
    issuer::{CredentialIssuer, EvidenceIssuer, IssuanceError},
    metadata::authorization_server_metadata,
    offer::{
        credential_offer, credential_offer_uri, generate_secret, generate_transaction_code,
        offered_request, OfferError, OfferedRequest, RequestedSubject,
    },
    secretfile::{read_owner_only, SecretFileError},
    store::{NonceError, NonceMinter, OfferStore, PreparedRequest, StoreError},
};

pub const HEALTH_PATH: &str = "/health";
pub const READY_PATH: &str = "/ready";
pub const ISSUER_METADATA_PATH: &str = "/.well-known/openid-credential-issuer";
pub const AUTHORIZATION_SERVER_METADATA_PATH: &str = "/.well-known/oauth-authorization-server";
pub const OFFERS_PATH: &str = "/offers";
pub const TOKEN_PATH: &str = "/token";
pub const NONCE_PATH: &str = "/nonce";
pub const CREDENTIAL_PATH: &str = "/credential";

const JSON_MEDIA_TYPE: &str = "application/json";

/// The longest proof JWT this service will look at, and the longest payload
/// inside one. A proof carries one public key and three claims, so anything
/// larger is refused before it is parsed rather than after.
const MAXIMUM_PROOF_BYTES: usize = 8_192;
const MAXIMUM_PROOF_PAYLOAD_BYTES: usize = 2_048;

/// How old a wallet's proof may be, and how far ahead of this clock it may be
/// dated. The nonce already bounds the exchange; this bounds the proof itself.
const PROOF_MAX_AGE: Duration = Duration::from_secs(300);
const PROOF_MAX_FUTURE_SKEW: Duration = Duration::from_secs(60);

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("the Mint client key cannot be used: {0}")]
    ClientKey(#[from] SecretFileError),
    #[error("the outbound credential client cannot be built: {0}")]
    Issuer(#[from] IssuanceError),
}

/// Everything a serving process holds.
///
/// One immutable configuration, the bounded offer state, and the two halves of
/// the process: the resource server that authorizes offers and the client that
/// asks Evidence for credentials. There is no signing key for credentials here
/// and no holder key.
pub struct DeliveryService {
    config: DeliveryConfig,
    store: OfferStore,
    nonces: NonceMinter,
    authorizer: Arc<dyn OfferAuthorizer>,
    issuer: Arc<dyn CredentialIssuer>,
}

impl std::fmt::Debug for DeliveryService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DeliveryService")
            .field("credentialIssuer", &self.config.credential_issuer)
            .field("clientId", &self.config.mint.client_id)
            .field("offers", &self.store.len())
            .finish_non_exhaustive()
    }
}

impl DeliveryService {
    /// Load everything a serving process needs, taking the client key.
    ///
    /// The key is read here, handed to the outbound client that authenticates
    /// with it, and dropped. Nothing else in the process keeps a copy, and the
    /// offer boundary is built from its own document without seeing it.
    pub fn load(config: DeliveryConfig) -> Result<Self, ServiceError> {
        let client_key = read_owner_only(&config.mint.private_key_file)?;
        let authorizer = Arc::new(MintResourceServer::from_config(
            &config.offers,
            config.validation_mode,
        ));
        let issuer = Arc::new(EvidenceIssuer::new(&config, &client_key)?);
        Ok(Self::with_halves(config, authorizer, issuer))
    }

    /// Assemble a service over an already built resource server and issuer.
    #[must_use]
    pub fn with_halves(
        config: DeliveryConfig,
        authorizer: Arc<dyn OfferAuthorizer>,
        issuer: Arc<dyn CredentialIssuer>,
    ) -> Self {
        let store = OfferStore::new(&config.store);
        let nonces = NonceMinter::new(config.store.nonce_lifetime_seconds);
        Self {
            config,
            store,
            nonces,
            authorizer,
            issuer,
        }
    }

    /// Validate a configuration without taking what a serving process holds.
    ///
    /// Everything [`DeliveryService::load`] does, and no socket. The loaded key
    /// is dropped, and zeroized, before this returns.
    pub fn check(config: &DeliveryConfig) -> Result<(), ServiceError> {
        let client_key = read_owner_only(&config.mint.private_key_file)?;
        EvidenceIssuer::new(config, &client_key)?;
        Ok(())
    }

    #[must_use]
    pub fn config(&self) -> &DeliveryConfig {
        &self.config
    }
}

/// Build the router over an already loaded service.
///
/// Both fallbacks answer, so an unknown route is a refusal and never an empty
/// success. The configured body limit applies to every route: none of these
/// requests is large, and a wallet that sends a large one is refused before it
/// is parsed. The configured timeout applies to every route as well, and it
/// bounds the whole request, so a body that arrives a byte at a time is bounded
/// by the same limit as a handler that waits on a slow source.
pub fn build_app(service: Arc<DeliveryService>) -> Router {
    let body_limit = service.config.listener.maximum_request_bytes as usize;
    let request_timeout =
        Duration::from_millis(service.config.listener.request_timeout_milliseconds);
    let routes = Router::new()
        .route(HEALTH_PATH, get(health))
        .route(READY_PATH, get(ready))
        .route(ISSUER_METADATA_PATH, get(issuer_metadata))
        .route(
            AUTHORIZATION_SERVER_METADATA_PATH,
            get(authorization_server),
        )
        .route(OFFERS_PATH, post(create_offer))
        .route(TOKEN_PATH, post(token))
        .route(NONCE_PATH, post(nonce))
        .route(CREDENTIAL_PATH, post(credential))
        .fallback(unknown_route)
        .method_not_allowed_fallback(unknown_route)
        .with_state(service);
    routes
        .layer(DefaultBodyLimit::max(body_limit))
        .layer(from_fn_with_state(
            request_timeout,
            refuse_a_stalled_request,
        ))
        .layer(from_fn(add_no_store))
}

/// Bind the configured listener and serve until `shutdown` resolves.
pub async fn serve<F>(service: Arc<DeliveryService>, shutdown: F) -> io::Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let bind_ip = service
        .config
        .listener
        .bind_address()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let address = SocketAddr::new(bind_ip, service.config.listener.port);
    let listener = TcpListener::bind(address).await?;
    tracing::info!(
        target: "registry_evidence_oid4vci::service",
        credential_issuer = %service.config.credential_issuer,
        "delivery service listening"
    );
    let app = build_app(service);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .into_future()
        .await
}

async fn health() -> Response {
    json_response(StatusCode::OK, br#"{"status":"ok"}"#.to_vec())
}

/// Readiness tracks what the process holds. What the two outbound sources are
/// doing is not part of it: a delivery front end that reported itself unready
/// because a remote deployment was slow would take itself out of service for a
/// fault it does not have.
async fn ready() -> Response {
    json_response(StatusCode::OK, br#"{"status":"ready"}"#.to_vec())
}

/// The published issuer metadata.
///
/// Every entry is derived from what Evidence publishes. When discovery cannot
/// be read, this answers that the metadata is unavailable rather than serving a
/// stale or empty catalog as though it were the answer.
async fn issuer_metadata(State(service): State<Arc<DeliveryService>>) -> Response {
    match service.issuer.catalog().await {
        Ok(catalog) => value_response(StatusCode::OK, &catalog.issuer_metadata(&service.config)),
        Err(error) => issuance_response(&error),
    }
}

/// The authorization server metadata for the only grant this service supports.
async fn authorization_server(State(service): State<Arc<DeliveryService>>) -> Response {
    value_response(
        StatusCode::OK,
        &authorization_server_metadata(&service.config),
    )
}

/// What an adopter sends to create an offer.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OfferRequest {
    credential_configuration_id: String,
    subjects: Vec<RequestedSubject>,
    /// Whether the person redeeming the offer must also present a transaction
    /// code. The code is generated here and returned once, to the adopter, over
    /// the channel it authorized on.
    #[serde(default)]
    transaction_code: bool,
}

/// Create one offer, against a request the adopter is authorized to make.
///
/// This is the authorization boundary of the service. Everything after it is
/// reached with the secrets created here and with nothing else.
async fn create_offer(
    State(service): State<Arc<DeliveryService>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let authorized = match authorize_offer(&service, &headers).await {
        Ok(authorized) => authorized,
        Err(response) => return response,
    };

    let Ok(request) = serde_json::from_str::<OfferRequest>(&body) else {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the offer request is not a document this service accepts",
        );
    };

    let catalog = match service.issuer.catalog().await {
        Ok(catalog) => catalog,
        Err(error) => return issuance_response(&error),
    };
    // An identifier this catalog does not carry is one Evidence does not
    // publish as holder-bound. Refusing it here is what keeps an
    // audience-scoped assertion from being laundered into a wallet credential.
    let Some(configuration) = catalog.get(&request.credential_configuration_id) else {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "the credential configuration is not offered by this deployment",
        );
    };
    let offered = match offered_request(
        configuration,
        &catalog.issued_by,
        &catalog.provided_by,
        catalog.assurance_profile,
        request.subjects,
    ) {
        Ok(offered) => offered,
        Err(OfferError::UnknownConfiguration) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "the credential configuration is not offered by this deployment",
            )
        }
        Err(_) => {
            return problem(
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "the offered subjects do not match the credential configuration",
            )
        }
    };
    let Ok(body) = serde_json::to_string(&offered) else {
        return problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "the offer could not be recorded",
        );
    };
    let body = Zeroizing::new(body);

    let code = generate_secret();
    let transaction_code = request.transaction_code.then(generate_transaction_code);
    let prepared = PreparedRequest::new(&request.credential_configuration_id, &body);
    if let Err(error) = service.store.remember_offer(
        &code,
        transaction_code.as_ref().map(|code| code.as_str()),
        prepared,
        now(),
    ) {
        return store_response(&error);
    }

    tracing::info!(
        target: "registry_evidence_oid4vci::service",
        client = authorized.client.as_deref().unwrap_or("unnamed"),
        credential_configuration_id = %request.credential_configuration_id,
        "offer created"
    );

    let offer = credential_offer(
        &service.config.credential_issuer,
        &request.credential_configuration_id,
        &code,
        transaction_code.is_some(),
    );
    let mut answer = json!({
        "credentialOffer": offer,
        "credentialOfferUri": credential_offer_uri(&offer),
        "expiresIn": service.config.store.offer_lifetime_seconds,
    });
    if let Some(transaction_code) = transaction_code.as_ref() {
        // Returned once, to the caller that was authorized to create the offer.
        // It is never logged and never stored in a form that can be read back.
        answer["transactionCode"] = json!(transaction_code.as_str());
    }
    value_response(StatusCode::CREATED, &answer)
}

/// What a wallet sends to redeem a pre-authorized code.
///
/// Deliberately without a `Debug` derive: both members are secrets, and a
/// derived rendering is the usual way one reaches a log.
#[derive(Deserialize)]
struct TokenRequest {
    grant_type: String,
    #[serde(rename = "pre-authorized_code", default)]
    pre_authorized_code: String,
    #[serde(default)]
    tx_code: Option<String>,
}

/// Exchange a pre-authorized code for an access token.
///
/// The response carries no nonce. A wallet asks for one at [`NONCE_PATH`],
/// which is where a nonce this service can recompute comes from.
async fn token(
    State(service): State<Arc<DeliveryService>>,
    Form(request): Form<TokenRequest>,
) -> Response {
    if request.grant_type != crate::PRE_AUTHORIZED_CODE_GRANT_TYPE {
        return problem(
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            "this service supports the pre-authorized code grant only",
        );
    }
    let code = Zeroizing::new(request.pre_authorized_code);
    let transaction_code = request.tx_code.map(Zeroizing::new);
    let access_token = generate_secret();
    // Redeeming and binding are one step. A refusal between them would spend
    // the offer and leave the wallet a retryable answer it can never act on.
    if let Err(error) = service.store.redeem_offer_for_access_token(
        &code,
        transaction_code.as_ref().map(|code| code.as_str()),
        &access_token,
        now(),
    ) {
        return store_response(&error);
    }
    value_response(
        StatusCode::OK,
        &json!({
            "access_token": access_token.as_str(),
            "token_type": "Bearer",
            "expires_in": service.config.store.access_token_lifetime_seconds,
        }),
    )
}

/// Mint a nonce for the credential request that follows.
///
/// The endpoint requires no authorization, which is what OpenID4VCI 1.0 says
/// and is also the only shape that cannot be used as an oracle: nothing here
/// looks anything up, so nothing here can report whether a credential exists.
/// Nothing about the caller is read either, so the nonce is a freshness
/// challenge rather than a second authorization: it is a keyed tag over its own
/// expiry, and a proof echoing it is bounded by the single-use access token the
/// credential request must also present.
async fn nonce(State(service): State<Arc<DeliveryService>>) -> Response {
    value_response(
        StatusCode::OK,
        &json!({"c_nonce": service.nonces.mint(now())}),
    )
}

/// What a wallet sends to collect its credentials.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialRequest {
    credential_configuration_id: String,
    proofs: CredentialProofs,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialProofs {
    jwt: Vec<String>,
}

/// Issue one credential per proof, as one Evidence request.
///
/// The access token is claimed before any proof is looked at. A wallet
/// therefore gets one attempt per authorization, which is what keeps this from
/// being a place to try proofs against a live token until one is accepted.
async fn credential(
    State(service): State<Arc<DeliveryService>>,
    headers: HeaderMap,
    body: String,
) -> Response {
    let Some(access_token) = bearer_credential(&headers) else {
        return unauthorized("a bearer access token is required");
    };
    let access_token = Zeroizing::new(access_token.to_owned());
    let prepared = match service.store.claim_access_token(&access_token, now()) {
        Ok(prepared) => prepared,
        Err(StoreError::Unknown) => return unauthorized("the access token cannot be used"),
        Err(error) => return store_response(&error),
    };
    service.store.sweep(now());

    let Ok(request) = serde_json::from_str::<CredentialRequest>(&body) else {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid_credential_request",
            "the credential request is not a document this service accepts",
        );
    };
    if request.credential_configuration_id != prepared.kind() {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid_credential_request",
            "the credential configuration is not the one this token was issued for",
        );
    }
    if request.proofs.jwt.is_empty() || request.proofs.jwt.len() > MAXIMUM_HOLDER_KEYS {
        return problem(
            StatusCode::BAD_REQUEST,
            "invalid_proof",
            "a credential request must carry between one and sixteen proofs",
        );
    }

    let mut holder_keys = Vec::with_capacity(request.proofs.jwt.len());
    for proof in &request.proofs.jwt {
        match holder_key_from_proof(&service, proof) {
            Ok(key) => holder_keys.push(key),
            Err(refusal) => {
                return problem(StatusCode::BAD_REQUEST, refusal.error, refusal.description)
            }
        }
    }

    let Ok(offered) = serde_json::from_str::<OfferedRequest>(prepared.body()) else {
        return problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "the recorded offer could not be read",
        );
    };
    // One request, carrying every key that was proved together: one
    // authorization decision and one source acquisition behind however many
    // credentials the wallet asked for.
    let credentials = match service.issuer.issue(offered.into_spec(holder_keys)).await {
        Ok(credentials) => credentials,
        Err(error) => return issuance_response(&error),
    };

    // Always plural, and always what Evidence signed: this service reads no
    // credential it passes on and rewrites none of them.
    value_response(
        StatusCode::OK,
        &json!({
            "credentials": credentials
                .into_iter()
                .map(|credential| json!({"credential": credential}))
                .collect::<Vec<_>>(),
        }),
    )
}

/// Why a proof was not accepted.
///
/// Every refusal below is a bad request, so a refusal is the OAuth error code
/// and the fixed description a wallet is told. Neither is built from anything
/// the proof carried.
struct ProofRefusal {
    error: &'static str,
    description: &'static str,
}

impl ProofRefusal {
    const fn new(error: &'static str, description: &'static str) -> Self {
        Self { error, description }
    }
}

/// Validate one proof and read the public key it presented.
///
/// The nonce is read from the proof before the signature is checked, and then
/// established by recomputing its keyed tag, which is independent of the
/// signature. The proof validator is then given that nonce and verifies the
/// signature before it parses the same payload bytes again, so no decision here
/// rests on an unverified claim.
fn holder_key_from_proof(
    service: &DeliveryService,
    proof: &str,
) -> Result<HolderPublicKey, ProofRefusal> {
    if proof.len() > MAXIMUM_PROOF_BYTES {
        return Err(ProofRefusal::new(
            "invalid_proof",
            "the proof is larger than this service reads",
        ));
    }
    let Some(nonce) = peek_proof_nonce(proof) else {
        return Err(ProofRefusal::new(
            "invalid_proof",
            "the proof does not carry a nonce",
        ));
    };
    match service.nonces.verify(&nonce, now()) {
        Ok(()) => {}
        Err(NonceError::Expired) => {
            return Err(ProofRefusal::new("invalid_nonce", "the nonce has expired"))
        }
        Err(NonceError::Refused) => {
            return Err(ProofRefusal::new(
                "invalid_nonce",
                "the nonce is not one this service issued",
            ))
        }
    }
    let policy = Oid4vciProofPolicy {
        audience: service.config.credential_issuer.clone(),
        nonce,
        max_age: PROOF_MAX_AGE,
        max_future_skew: PROOF_MAX_FUTURE_SKEW,
    };
    let claims = validate_oid4vci_proof_jwt(proof, &policy, now())
        .map_err(|_| ProofRefusal::new("invalid_proof", "the proof was not accepted"))?;
    holder_public_key(&claims.holder_jwk).ok_or(ProofRefusal::new(
        "invalid_proof",
        "the proof presented a key this service cannot forward",
    ))
}

/// Read the nonce a proof states, without deciding anything from it.
///
/// Bounded on both the token and its payload, and it reads exactly one member.
fn peek_proof_nonce(proof: &str) -> Option<String> {
    let mut parts = proof.split('.');
    let (_header, payload, _signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || payload.len() > MAXIMUM_PROOF_PAYLOAD_BYTES {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let payload: Value = serde_json::from_slice(&decoded).ok()?;
    payload.get("nonce")?.as_str().map(str::to_owned)
}

/// Carry a validated proof's public key into the request to Evidence.
///
/// Only public members are copied, because only public members exist: the
/// target type declares none a private key could be written into, and the
/// deployment refuses a key it does not accept even if one arrived.
fn holder_public_key(jwk: &PublicJwk) -> Option<HolderPublicKey> {
    let key = HolderPublicKey {
        kty: jwk.kty.clone(),
        crv: jwk.crv.clone()?,
        x: jwk.x.clone()?,
        y: jwk.y.clone()?,
        alg: jwk.alg.clone(),
        kid: jwk.kid.clone(),
    };
    key.is_acceptable().then_some(key)
}

/// Authorize one offer request, or answer why not.
async fn authorize_offer(
    service: &DeliveryService,
    headers: &HeaderMap,
) -> Result<crate::authorizer::AuthorizedOffer, Response> {
    let credential = bearer_credential(headers).unwrap_or_default();
    service
        .authorizer
        .authorize(credential)
        .await
        .map_err(|error| match error {
            AuthorizationError::Missing => unauthorized("a bearer access token is required"),
            AuthorizationError::Refused => unauthorized("the presented credential was refused"),
            AuthorizationError::KeySource => problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "offers cannot be authorized at the moment",
            ),
        })
}

/// The bearer credential a request presented, if it presented one.
fn bearer_credential(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(AUTHORIZATION)?.to_str().ok()?;
    let (scheme, credential) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Bearer") {
        return None;
    }
    let credential = credential.trim();
    (!credential.is_empty()).then_some(credential)
}

fn now() -> i64 {
    Utc::now().timestamp()
}

/// Every store fault, mapped without saying which entry was involved.
///
/// A wallet is told the same thing whether its code was never issued, was
/// already redeemed, or was locked out, because the difference between those is
/// exactly what a caller working through codes would want to learn.
fn store_response(error: &StoreError) -> Response {
    match error {
        StoreError::Unknown
        | StoreError::AlreadyRedeemed
        | StoreError::TransactionCodeRefused
        | StoreError::LockedOut => problem(
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "the pre-authorized code cannot be redeemed",
        ),
        StoreError::Saturated | StoreError::Poisoned => {
            tracing::warn!(
                target: "registry_evidence_oid4vci::service",
                "the offer store cannot take this request"
            );
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "this service cannot take the request at the moment",
            )
        }
    }
}

/// Every Evidence failure, as much as a caller is told.
fn issuance_response(error: &IssuanceError) -> Response {
    match error {
        IssuanceError::Refused => problem(
            StatusCode::FORBIDDEN,
            "invalid_credential_request",
            "the credential source refused this request",
        ),
        IssuanceError::NotAvailable => problem(
            StatusCode::BAD_REQUEST,
            "invalid_credential_request",
            "the credential source has no evidence for this request",
        ),
        IssuanceError::Unavailable | IssuanceError::Malformed | IssuanceError::Configuration(_) => {
            tracing::warn!(
                target: "registry_evidence_oid4vci::service",
                "the credential source did not answer usably"
            );
            problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "temporarily_unavailable",
                "credentials cannot be issued at the moment",
            )
        }
    }
}

async fn unknown_route() -> Response {
    problem(StatusCode::NOT_FOUND, "invalid_request", "no such route")
}

fn unauthorized(description: &str) -> Response {
    let mut response = problem(StatusCode::UNAUTHORIZED, "invalid_token", description);
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

/// One error shape for every refusal: the OAuth members a wallet already reads,
/// carrying fixed text chosen here and never any part of the request.
fn problem(status: StatusCode, error: &str, description: &str) -> Response {
    value_response(
        status,
        &json!({"error": error, "error_description": description}),
    )
}

fn value_response(status: StatusCode, value: &Value) -> Response {
    json_response(status, value.to_string().into_bytes())
}

fn json_response(status: StatusCode, body: Vec<u8>) -> Response {
    (
        status,
        [(CONTENT_TYPE, HeaderValue::from_static(JSON_MEDIA_TYPE))],
        body,
    )
        .into_response()
}

/// Bound how long one request may occupy this service.
///
/// The whole request is inside the bound: reading the body, whatever the
/// handler does with it, and the outbound call behind it. A request that
/// outlives the bound is refused and its work is dropped, so a caller that
/// stalls holds a connection and a task for a configured length of time rather
/// than for as long as it likes.
async fn refuse_a_stalled_request(
    State(bound): State<Duration>,
    request: Request<Body>,
    next: Next,
) -> Response {
    match tokio::time::timeout(bound, next.run(request)).await {
        Ok(response) => response,
        Err(_) => {
            tracing::warn!(
                target: "registry_evidence_oid4vci::service",
                "a request outlived the configured timeout and was refused"
            );
            problem(
                StatusCode::REQUEST_TIMEOUT,
                "invalid_request",
                "the request took longer than this service waits",
            )
        }
    }
}

/// Nothing this service returns belongs in a shared cache, and the token and
/// credential responses require these headers by RFC 6749 section 5.1. Applying
/// them to every route keeps a route from having to remember.
async fn add_no_store(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        fs,
        io::Write,
        net::TcpListener as StdTcpListener,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        sync::Mutex,
    };

    use async_trait::async_trait;
    use axum_test::TestServer;
    use registry_evidence_client::HolderBoundRequestSpec;

    use crate::{
        authorizer::AuthorizedOffer,
        metadata::CredentialCatalog,
        testing::{
            private_jwk, proof_jwt, proof_jwt_over_payload_text, proof_jwt_with,
            proof_jwt_with_header, public_jwk, unsigned_proof_jwt,
        },
    };

    const OFFER_TOKEN: &str = "offer-token";
    const CONFIGURATION_ID: &str = "urn:example:requirement:holder-bound";

    /// Authorizes exactly one credential, and nothing else.
    ///
    /// It reads no key and no configuration, which is the point: the offer
    /// boundary is reachable without anything belonging to the client half.
    struct StubAuthorizer {
        accepted: String,
    }

    #[async_trait]
    impl OfferAuthorizer for StubAuthorizer {
        async fn authorize(&self, credential: &str) -> Result<AuthorizedOffer, AuthorizationError> {
            if credential.is_empty() {
                return Err(AuthorizationError::Missing);
            }
            if credential != self.accepted {
                return Err(AuthorizationError::Refused);
            }
            Ok(AuthorizedOffer {
                client: Some("adopter-front-end".to_owned()),
                subject: None,
            })
        }
    }

    /// Records every request it is asked to issue, and answers with one
    /// credential per holder key.
    struct RecordingIssuer {
        catalog: Arc<CredentialCatalog>,
        requests: Mutex<Vec<HolderBoundRequestSpec>>,
    }

    impl RecordingIssuer {
        fn new() -> Self {
            Self {
                catalog: Arc::new(CredentialCatalog::derive(
                    &crate::metadata::tests::document(),
                )),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn requests(&self) -> Vec<HolderBoundRequestSpec> {
            self.requests
                .lock()
                .expect("the recorder is usable")
                .clone()
        }
    }

    /// The exact text a stub credential is made of, so a test can prove the
    /// service passed it on without touching it.
    fn signed_credential(index: usize) -> String {
        format!("signed.credential.{index}")
    }

    #[async_trait]
    impl CredentialIssuer for RecordingIssuer {
        async fn catalog(&self) -> Result<Arc<CredentialCatalog>, IssuanceError> {
            Ok(Arc::clone(&self.catalog))
        }

        async fn issue(&self, spec: HolderBoundRequestSpec) -> Result<Vec<String>, IssuanceError> {
            let credentials = (0..spec.holder_keys.len()).map(signed_credential).collect();
            self.requests
                .lock()
                .expect("the recorder is usable")
                .push(spec);
            Ok(credentials)
        }
    }

    fn write_deployment(directory: &Path, port: u16, key_mode: u32) -> PathBuf {
        let key_path = directory.join("delivery-client.jwk.json");
        let mut key = fs::File::create(&key_path).expect("create the client key file");
        key.write_all(private_jwk("delivery-client").as_bytes())
            .expect("write the client key file");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(key_mode))
            .expect("set the client key mode");

        let path = directory.join("oid4vci.yaml");
        let text = format!(
            "version: 1\n\
             credentialIssuer: https://wallet.example.org\n\
             listener:\n  address: 127.0.0.1\n  port: {port}\n\
             evidence:\n  baseUrl: https://evidence.example.org\n\
             mint:\n  tokenEndpoint: https://mint.example.org/token\n  clientId: evidence-oid4vci\n  privateKeyFile: delivery-client.jwk.json\n\
             offers:\n  issuer: https://mint.example.org\n  jwksUri: https://mint.example.org/.well-known/jwks.json\n  audiences: [\"https://wallet.example.org\"]\n"
        );
        fs::write(&path, text).expect("write the configuration document");
        path
    }

    fn load_deployment(directory: &Path) -> DeliveryConfig {
        DeliveryConfig::load(&write_deployment(directory, 8090, 0o600))
            .expect("the deployment configuration loads")
    }

    /// A service over the two stubs, so a test drives the protocol rather than
    /// the network.
    fn wired_service(directory: &Path) -> (Arc<DeliveryService>, Arc<RecordingIssuer>) {
        wired_service_over(load_deployment(directory))
    }

    /// The same two stubs, over a configuration a test wrote itself.
    fn wired_service_over(config: DeliveryConfig) -> (Arc<DeliveryService>, Arc<RecordingIssuer>) {
        let issuer = Arc::new(RecordingIssuer::new());
        let service = Arc::new(DeliveryService::with_halves(
            config,
            Arc::new(StubAuthorizer {
                accepted: OFFER_TOKEN.to_owned(),
            }),
            Arc::clone(&issuer) as Arc<dyn CredentialIssuer>,
        ));
        (service, issuer)
    }

    /// The selector value an offer asks about.
    ///
    /// Distinctive on purpose: a test that proves a refusal quoted no selector
    /// value has to scan for something that could only have come from the
    /// request.
    const SELECTOR_VALUE: &str = "subject-identifier-value";

    fn offer_body(transaction_code: bool) -> Value {
        json!({
            "credentialConfigurationId": CONFIGURATION_ID,
            "subjects": [{"role": "primary", "selectorValues": {"identifier": SELECTOR_VALUE}}],
            "transactionCode": transaction_code,
        })
    }

    /// A token request, as the form-encoded pairs a wallet sends.
    fn token_form(code: &str, transaction_code: Option<&str>) -> Vec<(String, String)> {
        let mut form = vec![
            (
                "grant_type".to_owned(),
                crate::PRE_AUTHORIZED_CODE_GRANT_TYPE.to_owned(),
            ),
            ("pre-authorized_code".to_owned(), code.to_owned()),
        ];
        if let Some(transaction_code) = transaction_code {
            form.push(("tx_code".to_owned(), transaction_code.to_owned()));
        }
        form
    }

    /// The pre-authorized code an offer response carries.
    fn offered_code(offer: &Value) -> String {
        offer["credentialOffer"]["grants"][crate::PRE_AUTHORIZED_CODE_GRANT_TYPE]
            ["pre-authorized_code"]
            .as_str()
            .expect("the offer carries a pre-authorized code")
            .to_owned()
    }

    /// Walk the whole flow up to the access token, as a wallet would.
    async fn access_token(server: &TestServer) -> String {
        let created = server
            .post(OFFERS_PATH)
            .add_header("authorization", format!("Bearer {OFFER_TOKEN}"))
            .json(&offer_body(false))
            .await;
        assert_eq!(created.status_code(), StatusCode::CREATED);
        let code = offered_code(&created.json());

        let granted = server.post(TOKEN_PATH).form(&token_form(&code, None)).await;
        assert_eq!(granted.status_code(), StatusCode::OK);
        granted.json::<Value>()["access_token"]
            .as_str()
            .expect("the token response carries an access token")
            .to_owned()
    }

    /// Ask for a nonce the way the specification says a wallet does, with no
    /// authorization at all. Every flow below therefore walks the path a
    /// conforming wallet walks.
    async fn minted_nonce(server: &TestServer) -> String {
        let response = server.post(NONCE_PATH).await;
        assert_eq!(response.status_code(), StatusCode::OK);
        response.json::<Value>()["c_nonce"]
            .as_str()
            .expect("the nonce response carries a nonce")
            .to_owned()
    }

    #[test]
    fn check_validates_a_deployment_without_binding_its_port() {
        let directory = tempfile::tempdir().expect("temp dir");
        // Hold the configured port for the whole check. A `check` that bound
        // anything would fail here, which is exactly the property an operator
        // relies on when validating an edit against the deployment it is about
        // to replace.
        let occupied = StdTcpListener::bind(("127.0.0.1", 0)).expect("hold a port");
        let port = occupied.local_addr().expect("read the held port").port();
        let path = write_deployment(directory.path(), port, 0o600);
        let config = DeliveryConfig::load(&path).expect("the configuration loads");

        DeliveryService::check(&config).expect("check succeeds against an occupied port");
    }

    #[test]
    fn check_refuses_a_client_key_that_is_readable_by_anyone_else() {
        for mode in [0o640, 0o604, 0o644, 0o660] {
            let directory = tempfile::tempdir().expect("temp dir");
            let path = write_deployment(directory.path(), 8090, mode);
            let config = DeliveryConfig::load(&path).expect("the configuration loads");

            let error = DeliveryService::check(&config)
                .expect_err("a group or world readable client key must be refused");
            assert!(
                matches!(error, ServiceError::ClientKey(_)),
                "mode {mode:o} must be refused as a key fault, got {error:?}"
            );
        }
    }

    #[test]
    fn check_refuses_a_client_key_that_is_not_there() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_deployment(directory.path(), 8090, 0o600);
        let config = DeliveryConfig::load(&path).expect("the configuration loads");
        fs::remove_file(directory.path().join("delivery-client.jwk.json"))
            .expect("remove the client key file");

        assert!(matches!(
            DeliveryService::check(&config),
            Err(ServiceError::ClientKey(_))
        ));
    }

    #[test]
    fn the_loaded_client_key_never_reaches_debug_output() {
        let directory = tempfile::tempdir().expect("temp dir");
        let config = load_deployment(directory.path());
        let service = DeliveryService::load(config).expect("the service loads");

        let rendered = format!("{service:?}");
        for member in ["kty", "\"d\"", "delivery-client"] {
            assert!(!rendered.contains(member), "rendered: {rendered}");
        }
        assert!(rendered.contains("https://wallet.example.org"));
    }

    #[tokio::test]
    async fn the_liveness_and_readiness_probes_answer() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, _) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        for path in [HEALTH_PATH, READY_PATH] {
            let response = server.get(path).await;
            assert_eq!(response.status_code(), StatusCode::OK, "path {path}");
            assert_eq!(
                response
                    .headers()
                    .get("cache-control")
                    .map(|v| v.as_bytes()),
                Some(&b"no-store"[..]),
                "path {path}"
            );
        }
    }

    #[tokio::test]
    async fn an_unknown_route_is_refused_rather_than_answered_emptily() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, _) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        for path in ["/", "/credentials", "/.well-known/openid-configuration"] {
            let response = server.get(path).await;
            assert_eq!(response.status_code(), StatusCode::NOT_FOUND, "path {path}");
        }
    }

    #[tokio::test]
    async fn the_published_metadata_is_derived_from_the_evidence_bundle() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, _) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let response = server.get(ISSUER_METADATA_PATH).await;
        assert_eq!(response.status_code(), StatusCode::OK);
        let metadata: Value = response.json();
        let supported = &metadata["credential_configurations_supported"];
        assert!(supported[CONFIGURATION_ID].is_object());
        assert_eq!(supported[CONFIGURATION_ID]["format"], json!("dc+sd-jwt"));
        assert!(supported[CONFIGURATION_ID]["proof_types_supported"].is_object());
        // The audience-scoped requirement in the same bundle is not published.
        assert!(supported["urn:example:requirement:audience-scoped"].is_null());
    }

    #[tokio::test]
    async fn an_offer_without_authorization_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, issuer) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let unauthenticated = server.post(OFFERS_PATH).json(&offer_body(false)).await;
        assert_eq!(unauthenticated.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            unauthenticated
                .headers()
                .get("www-authenticate")
                .map(|value| value.as_bytes()),
            Some(&b"Bearer"[..])
        );

        let wrong = server
            .post(OFFERS_PATH)
            .add_header("authorization", "Bearer not-the-offer-token")
            .json(&offer_body(false))
            .await;
        assert_eq!(wrong.status_code(), StatusCode::UNAUTHORIZED);

        // Nothing reached Evidence, and no offer was created.
        assert!(issuer.requests().is_empty());
    }

    /// Everything the deployment knows that an unauthorized caller must not
    /// learn from a refusal.
    ///
    /// Each entry is a value the offer request carried or the Evidence bundle
    /// publishes: the credential configuration identifier, which is also the
    /// requirement identifier, the purpose, the type, the selector this
    /// deployment matches on, and the value the caller asked about. A refusal
    /// that quoted any of them would answer a question the caller was not
    /// authorized to ask.
    const OFFER_REFUSAL_MUST_NOT_REVEAL: [&str; 6] = [
        CONFIGURATION_ID,
        "urn:example:requirement:audience-scoped",
        "urn:example:purpose:demonstration",
        "urn:example:evidence-type:holder-bound",
        "identifier",
        SELECTOR_VALUE,
    ];

    /// An unauthorized offer request is refused without describing anything
    /// this deployment offers.
    ///
    /// The 401 itself is proven above. What is proven here is the other half of
    /// the property: the bytes a refused caller reads carry the two OAuth
    /// members and nothing else, so probing the offer endpoint reveals neither
    /// which requirements exist nor whether the one named does. The whole
    /// response body is scanned, and the member set is closed, so a later
    /// "unknown requirement" hint would fail this whichever way it were added,
    /// including through the `WWW-Authenticate` challenge, which is where RFC
    /// 6750 invites a resource server to elaborate.
    #[tokio::test]
    async fn an_unauthorized_offer_refusal_describes_nothing_this_deployment_offers() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, _) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let missing = server.post(OFFERS_PATH).json(&offer_body(false)).await;
        let wrong = server
            .post(OFFERS_PATH)
            .add_header("authorization", "Bearer not-the-offer-token")
            .json(&offer_body(false))
            .await;

        for (case, response) in [("missing token", &missing), ("wrong token", &wrong)] {
            assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED, "{case}");

            // The response bytes, not a struct read out of them: a leak in a
            // member this service does not model would be invisible otherwise.
            // The challenge is scanned with them, because a hint added to it
            // would be just as readable to an unauthorized caller.
            let bytes = response.as_bytes();
            let rendered = String::from_utf8_lossy(bytes);
            let challenge = response
                .headers()
                .get(WWW_AUTHENTICATE)
                .map(|value| value.as_bytes().to_vec())
                .unwrap_or_default();
            for revealing in OFFER_REFUSAL_MUST_NOT_REVEAL {
                for (part, read) in [("body", bytes.as_ref()), ("challenge", &challenge[..])] {
                    assert!(
                        !read
                            .windows(revealing.len())
                            .any(|window| window == revealing.as_bytes()),
                        "{case}: the refusal {part} revealed {revealing}: {rendered}"
                    );
                }
            }

            let body: Value = response.json();
            let members = body
                .as_object()
                .expect("a refusal is a JSON object")
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>();
            assert_eq!(
                members,
                ["error", "error_description"],
                "{case}: a refusal carries the two OAuth members and nothing else: {rendered}"
            );
            assert_eq!(body["error"], json!("invalid_token"), "{case}");
        }
    }

    #[tokio::test]
    async fn the_offer_boundary_shares_no_code_path_with_the_mint_client_identity() {
        // The client key on disk is not a usable identity, so the client half
        // cannot be built from it. The offer boundary is built from its own
        // document and authorizes anyway, which is only possible because
        // neither half is derived from the other.
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_deployment(directory.path(), 8090, 0o600);
        fs::write(directory.path().join("delivery-client.jwk.json"), "{}")
            .expect("replace the client key with an unusable one");
        fs::set_permissions(
            directory.path().join("delivery-client.jwk.json"),
            fs::Permissions::from_mode(0o600),
        )
        .expect("set the client key mode");
        let config = DeliveryConfig::load(&path).expect("the configuration loads");
        assert!(
            matches!(DeliveryService::load(config), Err(ServiceError::Issuer(_))),
            "an unusable client key must fail the client half"
        );

        let (service, _) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));
        let created = server
            .post(OFFERS_PATH)
            .add_header("authorization", format!("Bearer {OFFER_TOKEN}"))
            .json(&offer_body(false))
            .await;
        assert_eq!(created.status_code(), StatusCode::CREATED);
    }

    #[tokio::test]
    async fn an_audience_scoped_requirement_cannot_be_offered_to_a_wallet() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, _) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let mut body = offer_body(false);
        body["credentialConfigurationId"] = json!("urn:example:requirement:audience-scoped");
        let response = server
            .post(OFFERS_PATH)
            .add_header("authorization", format!("Bearer {OFFER_TOKEN}"))
            .json(&body)
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.json::<Value>()["error_description"],
            json!("the credential configuration is not offered by this deployment")
        );
    }

    #[tokio::test]
    async fn the_offer_states_the_grant_and_the_transaction_code_shape() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, _) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let created = server
            .post(OFFERS_PATH)
            .add_header("authorization", format!("Bearer {OFFER_TOKEN}"))
            .json(&offer_body(true))
            .await;
        assert_eq!(created.status_code(), StatusCode::CREATED);
        let body: Value = created.json();
        let grant = &body["credentialOffer"]["grants"][crate::PRE_AUTHORIZED_CODE_GRANT_TYPE];
        assert!(grant["pre-authorized_code"].is_string());
        assert_eq!(grant["tx_code"]["length"], json!(6));
        assert_eq!(
            body["transactionCode"]
                .as_str()
                .expect("a requested transaction code is returned once")
                .len(),
            6
        );
        assert!(body["credentialOfferUri"]
            .as_str()
            .expect("the offer carries a URI")
            .starts_with("openid-credential-offer://"));
    }

    #[tokio::test]
    async fn the_token_response_carries_no_nonce() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, _) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let created = server
            .post(OFFERS_PATH)
            .add_header("authorization", format!("Bearer {OFFER_TOKEN}"))
            .json(&offer_body(false))
            .await;
        let code = offered_code(&created.json());

        let granted = server.post(TOKEN_PATH).form(&token_form(&code, None)).await;
        let body: Value = granted.json();
        assert_eq!(body["token_type"], json!("Bearer"));
        assert!(body.get("c_nonce").is_none(), "body: {body}");
        assert!(body.get("c_nonce_expires_in").is_none(), "body: {body}");
    }

    #[tokio::test]
    async fn a_pre_authorized_code_is_redeemable_once() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, _) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let created = server
            .post(OFFERS_PATH)
            .add_header("authorization", format!("Bearer {OFFER_TOKEN}"))
            .json(&offer_body(false))
            .await;
        let code = offered_code(&created.json());
        let request = token_form(&code, None);

        assert_eq!(
            server.post(TOKEN_PATH).form(&request).await.status_code(),
            StatusCode::OK
        );
        let replayed = server.post(TOKEN_PATH).form(&request).await;
        assert_eq!(replayed.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(replayed.json::<Value>()["error"], json!("invalid_grant"));
    }

    #[tokio::test]
    async fn a_wrong_transaction_code_is_refused_and_bounded() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, _) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let created = server
            .post(OFFERS_PATH)
            .add_header("authorization", format!("Bearer {OFFER_TOKEN}"))
            .json(&offer_body(true))
            .await;
        let body: Value = created.json();
        let code = offered_code(&body);
        let transaction_code = body["transactionCode"]
            .as_str()
            .expect("the offer carries a transaction code")
            .to_owned();

        // The configured ceiling is three attempts, and exhausting it locks the
        // offer out for the rest of its life, so the correct code is refused
        // afterwards too.
        for _ in 0..3 {
            let refused = server
                .post(TOKEN_PATH)
                .form(&token_form(&code, Some("000000")))
                .await;
            assert_eq!(refused.status_code(), StatusCode::BAD_REQUEST);
        }
        let locked_out = server
            .post(TOKEN_PATH)
            .form(&token_form(&code, Some(&transaction_code)))
            .await;
        assert_eq!(locked_out.status_code(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn an_unsupported_grant_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, _) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let response = server
            .post(TOKEN_PATH)
            .form(&[
                ("grant_type", "authorization_code"),
                ("pre-authorized_code", "x"),
            ])
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response.json::<Value>()["error"],
            json!("unsupported_grant_type")
        );
    }

    #[tokio::test]
    async fn the_nonce_endpoint_answers_without_authorization() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, _) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let response = server.post(NONCE_PATH).await;
        assert_eq!(response.status_code(), StatusCode::OK);
        assert!(response.json::<Value>()["c_nonce"].is_string());
    }

    /// A wallet that follows the specification can collect its credential.
    ///
    /// OpenID4VCI 1.0 Final section 7 gives the nonce endpoint no
    /// authorization, so a conforming wallet holds a nonce that was minted for
    /// a request carrying no access token. Issuance reachable only with a nonce
    /// minted under the token would be issuance no conforming wallet could
    /// reach, so the whole flow is walked here with the one header the
    /// specification says is not sent.
    #[tokio::test]
    async fn a_wallet_that_never_authorizes_its_nonce_request_can_collect_its_credential() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, issuer) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let access_token = access_token(&server).await;
        let minted = server.post(NONCE_PATH).await;
        assert_eq!(minted.status_code(), StatusCode::OK);
        let nonce = minted.json::<Value>()["c_nonce"]
            .as_str()
            .expect("the nonce response carries a nonce")
            .to_owned();

        let key = private_jwk("holder");
        let response = server
            .post(CREDENTIAL_PATH)
            .add_header("authorization", format!("Bearer {access_token}"))
            .json(&json!({
                "credential_configuration_id": CONFIGURATION_ID,
                "proofs": {"jwt": [proof_jwt(&key, "https://wallet.example.org", &nonce, now())]},
            }))
            .await;
        let status = response.status_code();
        let body: Value = response.json();
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(issuer.requests().len(), 1);
    }

    #[tokio::test]
    async fn one_credential_request_with_several_proofs_becomes_one_evidence_request() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, issuer) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let access_token = access_token(&server).await;
        let nonce = minted_nonce(&server).await;
        let keys: Vec<String> = (0..3)
            .map(|index| private_jwk(&format!("k{index}")))
            .collect();
        let proofs: Vec<String> = keys
            .iter()
            .map(|key| proof_jwt(key, "https://wallet.example.org", &nonce, now()))
            .collect();

        let response = server
            .post(CREDENTIAL_PATH)
            .add_header("authorization", format!("Bearer {access_token}"))
            .json(&json!({
                "credential_configuration_id": CONFIGURATION_ID,
                "proofs": {"jwt": proofs},
            }))
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let requests = issuer.requests();
        assert_eq!(requests.len(), 1, "one request, whatever the proof count");
        assert_eq!(requests[0].holder_keys.len(), 3);
        assert_eq!(requests[0].requirement, CONFIGURATION_ID);
    }

    #[tokio::test]
    async fn the_credential_response_is_plural_and_is_what_evidence_signed() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, _) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let access_token = access_token(&server).await;
        let nonce = minted_nonce(&server).await;
        let key = private_jwk("only");
        let response = server
            .post(CREDENTIAL_PATH)
            .add_header("authorization", format!("Bearer {access_token}"))
            .json(&json!({
                "credential_configuration_id": CONFIGURATION_ID,
                "proofs": {"jwt": [proof_jwt(&key, "https://wallet.example.org", &nonce, now())]},
            }))
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let body: Value = response.json();
        // Plural even for one, and each entry is an object with one member.
        let credentials = body["credentials"]
            .as_array()
            .expect("the response carries a credentials array");
        assert_eq!(credentials.len(), 1);
        // Byte for byte what the source returned: this service signs nothing
        // and rewrites nothing.
        assert_eq!(credentials[0]["credential"], json!(signed_credential(0)));
        assert!(body.get("credential").is_none(), "body: {body}");
    }

    #[tokio::test]
    async fn the_service_holds_no_credential_signing_key_and_signs_nothing() {
        // Nothing in the configuration can give this process a credential
        // signing key: there is no member for one, and an unknown member is a
        // load failure rather than a key that is quietly ignored.
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_deployment(directory.path(), 8090, 0o600);
        let document = fs::read_to_string(&path).expect("read the configuration document");
        for member in [
            "signingKey: keys/signing.jwk.json",
            "credentialSigningKey: keys/signing.jwk.json",
            "issuerKey: keys/signing.jwk.json",
        ] {
            let text = document.replace("version: 1", &format!("version: 1\n{member}"));
            fs::write(&path, &text).expect("write the configuration document");
            assert!(
                DeliveryConfig::load(&path).is_err(),
                "the configuration accepted {member}"
            );
        }
        fs::write(&path, &document).expect("restore the configuration document");

        // And what a wallet receives is the source's bytes, unchanged. A
        // credential this service had signed, or re-signed, could not be.
        let (service, _) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));
        let access_token = access_token(&server).await;
        let nonce = minted_nonce(&server).await;
        let key = private_jwk("holder");
        let response = server
            .post(CREDENTIAL_PATH)
            .add_header("authorization", format!("Bearer {access_token}"))
            .json(&json!({
                "credential_configuration_id": CONFIGURATION_ID,
                "proofs": {"jwt": [proof_jwt(&key, "https://wallet.example.org", &nonce, now())]},
            }))
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);
        assert_eq!(
            response.json::<Value>()["credentials"][0]["credential"],
            json!(signed_credential(0))
        );
    }

    /// The header a proof this service accepts carries, so a case can vary one
    /// member of it and leave every other member correct.
    fn proof_header(private_key: &str) -> Value {
        json!({
            "alg": "ES256",
            "typ": "openid4vci-proof+jwt",
            "jwk": public_jwk(private_key),
        })
    }

    /// The self-contained key-reference form used by wallets that identify a
    /// proof key with `did:jwk` instead of placing the JWK directly in the
    /// header. The encoded JWK includes the ordinary public `use: sig`
    /// metadata and no Registry-specific member.
    fn did_jwk_proof_header(private_key: &str) -> Value {
        let mut jwk = public_jwk(private_key);
        let members = jwk.as_object_mut().expect("public JWK object");
        members.remove("alg");
        members.remove("kid");
        members.insert("use".to_owned(), json!("sig"));
        let encoded = URL_SAFE_NO_PAD.encode(jwk.to_string());
        json!({
            "alg": "ES256",
            "typ": "openid4vci-proof+jwt",
            "kid": format!("did:jwk:{encoded}#0"),
        })
    }

    /// The payload a proof this service accepts carries.
    fn proof_payload(nonce: &str) -> Value {
        json!({"aud": "https://wallet.example.org", "iat": now(), "nonce": nonce})
    }

    /// Present one proof at the credential endpoint, over the whole flow a
    /// wallet walks: an authorized offer, a redeemed pre-authorized code, and a
    /// fresh nonce collected without authorization.
    ///
    /// Everything except the proof is therefore correct, which is what makes a
    /// refusal attributable to the proof. The proof is built from a freshly
    /// generated holder key and the nonce this service just minted.
    ///
    /// Answered as the three things a refusal case asserts on: the status, the
    /// response document, and how many requests reached Evidence.
    async fn credential_request_with_proof(
        build_proof: impl FnOnce(&str, &str) -> String,
    ) -> (StatusCode, Value, usize) {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, issuer) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let access_token = access_token(&server).await;
        let nonce = minted_nonce(&server).await;
        let key = private_jwk("holder");
        let response = server
            .post(CREDENTIAL_PATH)
            .add_header("authorization", format!("Bearer {access_token}"))
            .json(&json!({
                "credential_configuration_id": CONFIGURATION_ID,
                "proofs": {"jwt": [build_proof(&key, &nonce)]},
            }))
            .await;
        (
            response.status_code(),
            response.json(),
            issuer.requests().len(),
        )
    }

    /// Assert the two halves of what a closed proof shape means.
    ///
    /// The endpoint refused, and Evidence was never asked. The second half is
    /// what makes "rejected before any Evidence call" a proven claim rather
    /// than a stated one: a service that validated the proof after asking
    /// Evidence would answer the same status and fail here.
    ///
    /// The description is pinned as well, because the endpoint refuses an
    /// unreadable proof with its own wording before the validator sees one. A
    /// case that named a proof shape and was in fact refused for being
    /// unparseable would report that wording and fail here rather than pass for
    /// a reason it does not claim.
    fn assert_proof_refused_before_any_evidence_call(
        case: &str,
        (status, body, evidence_requests): (StatusCode, Value, usize),
    ) {
        assert_eq!(status, StatusCode::BAD_REQUEST, "{case}: body {body}");
        assert_eq!(body["error"], json!("invalid_proof"), "{case}: body {body}");
        assert_eq!(
            body["error_description"],
            json!("the proof was not accepted"),
            "{case}: the refusal must come from proof validation: body {body}"
        );
        assert_eq!(
            evidence_requests, 0,
            "{case}: nothing may reach Evidence behind a refused proof"
        );
    }

    /// The proof every refusal case starts from is one this service accepts.
    ///
    /// Each case below varies exactly one thing about a proof built by these
    /// helpers. Without this, a fault in a shared helper would refuse every
    /// proof and leave each case passing for a reason it does not name. Both
    /// builders the cases use are exercised: the one that serializes a payload
    /// and the one that signs payload text.
    #[tokio::test]
    async fn the_proof_the_refusal_cases_vary_is_otherwise_accepted() {
        let serialized = credential_request_with_proof(|key, nonce| {
            proof_jwt_with_header(key, proof_header(key), proof_payload(nonce))
        })
        .await;
        assert_eq!(serialized.0, StatusCode::OK, "body: {}", serialized.1);
        assert_eq!(serialized.2, 1, "one request reaches Evidence");

        let from_text = credential_request_with_proof(|key, nonce| {
            let payload = format!(
                r#"{{"aud":"https://wallet.example.org","iat":{},"nonce":"{nonce}"}}"#,
                now()
            );
            proof_jwt_over_payload_text(key, proof_header(key), &payload)
        })
        .await;
        assert_eq!(from_text.0, StatusCode::OK, "body: {}", from_text.1);
        assert_eq!(from_text.2, 1, "one request reaches Evidence");
    }

    /// A self-contained `did:jwk` proof is the same key-possession statement
    /// as an inline JWK proof. Its optional `exp` is enforced in addition to,
    /// and never instead of, the short `iat` freshness window.
    #[tokio::test]
    async fn a_local_did_jwk_proof_with_an_expiry_is_accepted() {
        let accepted = credential_request_with_proof(|key, nonce| {
            let mut payload = proof_payload(nonce);
            payload["exp"] = json!(now() + 18_000);
            proof_jwt_with_header(key, did_jwk_proof_header(key), payload)
        })
        .await;

        assert_eq!(accepted.0, StatusCode::OK, "body: {}", accepted.1);
        assert_eq!(accepted.2, 1, "one request reaches Evidence");
    }

    /// The registered media type carries an `application/` prefix and the
    /// header value does not, so the prefixed spelling is a different `typ` and
    /// not a lenient one.
    #[tokio::test]
    async fn a_proof_typed_with_the_registered_media_type_prefix_is_refused() {
        let refusal = credential_request_with_proof(|key, nonce| {
            let mut header = proof_header(key);
            header["typ"] = json!("application/openid4vci-proof+jwt");
            proof_jwt_with_header(key, header, proof_payload(nonce))
        })
        .await;

        assert_proof_refused_before_any_evidence_call("a prefixed typ", refusal);
    }

    /// A `kid` outside the self-contained `did:jwk` method nominates a key this
    /// service would have to resolve from somewhere else. There is nowhere
    /// else, so a remote nomination is refused rather than resolved.
    #[tokio::test]
    async fn a_proof_nominating_a_remote_key_by_kid_is_refused() {
        let refusal = credential_request_with_proof(|key, nonce| {
            let header = json!({
                "alg": "ES256",
                "typ": "openid4vci-proof+jwt",
                "kid": "did:web:wallet.example#holder",
            });
            proof_jwt_with_header(key, header, proof_payload(nonce))
        })
        .await;

        assert_proof_refused_before_any_evidence_call("a remote kid nomination", refusal);
    }

    /// An `x5c` nominates a key behind a certificate chain, which is the same
    /// refusal for the same reason: this service resolves no key it was not
    /// handed inside the proof.
    #[tokio::test]
    async fn a_proof_nominating_its_key_by_x5c_is_refused() {
        let refusal = credential_request_with_proof(|key, nonce| {
            let header = json!({
                "alg": "ES256",
                "typ": "openid4vci-proof+jwt",
                "x5c": ["Zm9v"],
            });
            proof_jwt_with_header(key, header, proof_payload(nonce))
        })
        .await;

        assert_proof_refused_before_any_evidence_call("an x5c nomination", refusal);
    }

    /// A proof is what makes a credential holder-bound, so a proof that
    /// declares itself unsigned is refused. The key it presents is the one it
    /// would have been bound to, which is what would make accepting it a
    /// binding to a key nobody proved possession of.
    #[tokio::test]
    async fn a_proof_carrying_no_signature_under_alg_none_is_refused() {
        let refusal = credential_request_with_proof(|key, nonce| {
            let header = json!({
                "alg": "none",
                "typ": "openid4vci-proof+jwt",
                "jwk": public_jwk(key),
            });
            unsigned_proof_jwt(header, proof_payload(nonce))
        })
        .await;

        assert_proof_refused_before_any_evidence_call("an unsigned proof", refusal);
    }

    /// The nonce bounds the exchange and `iat` bounds the proof itself, on both
    /// sides: a proof older than the accepted window is refused, and so is one
    /// dated further ahead of this clock than the window allows.
    #[tokio::test]
    async fn a_proof_issued_outside_the_accepted_window_is_refused() {
        let stale =
            i64::try_from(PROOF_MAX_AGE.as_secs()).expect("the window is representable") + 1;
        let ahead = i64::try_from(PROOF_MAX_FUTURE_SKEW.as_secs())
            .expect("the window is representable")
            + 1;

        for (case, offset) in [("a stale iat", -stale), ("a future iat", ahead)] {
            let refusal = credential_request_with_proof(|key, nonce| {
                let mut payload = proof_payload(nonce);
                payload["iat"] = json!(now() + offset);
                proof_jwt_with_header(key, proof_header(key), payload)
            })
            .await;

            assert_proof_refused_before_any_evidence_call(case, refusal);
        }
    }

    #[tokio::test]
    async fn a_proof_past_its_optional_expiry_is_refused() {
        let refusal = credential_request_with_proof(|key, nonce| {
            let mut payload = proof_payload(nonce);
            payload["exp"] = json!(now());
            proof_jwt_with_header(key, did_jwk_proof_header(key), payload)
        })
        .await;

        assert_proof_refused_before_any_evidence_call("an expired proof", refusal);
    }

    /// A payload naming one claim twice is refused rather than resolved.
    ///
    /// The nonce is the member duplicated, and the second copy is the one this
    /// service minted, so the reader that takes the last of two duplicates
    /// accepts the nonce and only a decoder that refuses duplicates outright
    /// can refuse this proof. A service that resolved duplicates last-wins
    /// would issue here, against a proof whose earlier reader saw a different
    /// challenge.
    #[tokio::test]
    async fn a_proof_payload_naming_a_claim_twice_is_refused_rather_than_resolved() {
        let refusal = credential_request_with_proof(|key, nonce| {
            // Written as text because `serde_json` will not emit an object
            // carrying the same member twice.
            let payload = format!(
                r#"{{"aud":"https://wallet.example.org","iat":{},"nonce":"invented","nonce":"{nonce}"}}"#,
                now()
            );
            proof_jwt_over_payload_text(key, proof_header(key), &payload)
        })
        .await;

        assert_proof_refused_before_any_evidence_call("a duplicate payload member", refusal);
    }

    #[tokio::test]
    async fn a_proof_presenting_a_private_key_member_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, issuer) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let access_token = access_token(&server).await;
        let nonce = minted_nonce(&server).await;
        let key = private_jwk("holder");
        // A correctly signed proof whose header presents the private key
        // itself, so the refusal is attributable to the key and not to a broken
        // signature. There is no path from here to a stored or forwarded
        // private member: the proof is refused, and the type a forwarded key is
        // read into declares no member one could be written to.
        let forged = proof_jwt_with_header(
            &key,
            json!({
                "alg": "ES256",
                "typ": "openid4vci-proof+jwt",
                "jwk": serde_json::from_str::<Value>(&key).expect("the key parses"),
            }),
            json!({"aud": "https://wallet.example.org", "iat": now(), "nonce": nonce}),
        );

        let response = server
            .post(CREDENTIAL_PATH)
            .add_header("authorization", format!("Bearer {access_token}"))
            .json(&json!({
                "credential_configuration_id": CONFIGURATION_ID,
                "proofs": {"jwt": [forged]},
            }))
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(response.json::<Value>()["error"], json!("invalid_proof"));
        assert!(issuer.requests().is_empty(), "nothing may be requested");
    }

    #[tokio::test]
    async fn a_nonce_this_service_did_not_mint_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, issuer) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let access_token = access_token(&server).await;
        let key = private_jwk("holder");
        let response = server
            .post(CREDENTIAL_PATH)
            .add_header("authorization", format!("Bearer {access_token}"))
            .json(&json!({
                "credential_configuration_id": CONFIGURATION_ID,
                "proofs": {
                    "jwt": [proof_jwt(&key, "https://wallet.example.org", "invented", now())],
                },
            }))
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(response.json::<Value>()["error"], json!("invalid_nonce"));
        assert!(issuer.requests().is_empty());
    }

    /// A nonce whose expiry has been rewritten is refused.
    ///
    /// The nonce states its own expiry, so a wallet that wants a longer window
    /// has an obvious thing to edit. The tag covers the expiry, so the edit is
    /// a nonce this process did not mint rather than a longer-lived one.
    #[tokio::test]
    async fn a_nonce_whose_expiry_was_rewritten_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, issuer) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let access_token = access_token(&server).await;
        let nonce = minted_nonce(&server).await;
        let (expiry, tag) = nonce
            .split_once('.')
            .expect("the nonce carries its own expiry");
        let extended = format!(
            "{}.{tag}",
            expiry.parse::<i64>().expect("the expiry is a number") + 86_400
        );
        let key = private_jwk("holder");

        let response = server
            .post(CREDENTIAL_PATH)
            .add_header("authorization", format!("Bearer {access_token}"))
            .json(&json!({
                "credential_configuration_id": CONFIGURATION_ID,
                "proofs": {
                    "jwt": [proof_jwt(&key, "https://wallet.example.org", &extended, now())],
                },
            }))
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(response.json::<Value>()["error"], json!("invalid_nonce"));
        assert!(issuer.requests().is_empty());
    }

    /// A wallet addresses its proof to the identifier this service publishes,
    /// which is the only identifier it has been given. The published document
    /// and the audience the proof is compared against are therefore the same
    /// string, whichever spelling of it the operator wrote.
    #[tokio::test]
    async fn a_proof_addressed_to_the_published_identifier_is_accepted() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = write_deployment(directory.path(), 8090, 0o600);
        let document = fs::read_to_string(&path).expect("read the configuration document");
        fs::write(
            &path,
            document.replace(
                "credentialIssuer: https://wallet.example.org",
                "credentialIssuer: https://wallet.example.org/",
            ),
        )
        .expect("write the configuration document");
        let config = DeliveryConfig::load(&path).expect("the configuration loads");
        let (service, issuer) = wired_service_over(config);
        let server = TestServer::new(build_app(service));

        let published = server.get(ISSUER_METADATA_PATH).await.json::<Value>()["credential_issuer"]
            .as_str()
            .expect("the metadata publishes an identifier")
            .to_owned();

        let access_token = access_token(&server).await;
        let nonce = minted_nonce(&server).await;
        let key = private_jwk("holder");
        let response = server
            .post(CREDENTIAL_PATH)
            .add_header("authorization", format!("Bearer {access_token}"))
            .json(&json!({
                "credential_configuration_id": CONFIGURATION_ID,
                "proofs": {"jwt": [proof_jwt(&key, &published, &nonce, now())]},
            }))
            .await;
        let status = response.status_code();
        let body: Value = response.json();
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(issuer.requests().len(), 1);
    }

    /// A proof addressed to another credential issuer is one a wallet could
    /// have been given anywhere. Accepting it here would let a proof minted for
    /// one deployment bind a credential at this one.
    #[tokio::test]
    async fn a_proof_for_another_audience_is_refused() {
        let refusal = credential_request_with_proof(|key, nonce| {
            proof_jwt(key, "https://elsewhere.example.org", nonce, now())
        })
        .await;

        assert_proof_refused_before_any_evidence_call("another audience", refusal);
    }

    /// OpenID4VCI 1.0 sends `iss` only from a wallet that authenticated as an
    /// OAuth client. The pre-authorized code grant has no such client, so `iss`
    /// asserts an identity nothing here can check, and it is refused rather
    /// than ignored.
    #[tokio::test]
    async fn a_proof_claiming_an_issuer_is_refused() {
        let refusal = credential_request_with_proof(|key, nonce| {
            proof_jwt_with(
                key,
                json!({
                    "aud": "https://wallet.example.org",
                    "iat": now(),
                    "nonce": nonce,
                    "iss": "https://wallet.example.com",
                }),
            )
        })
        .await;

        assert_proof_refused_before_any_evidence_call("a claimed issuer", refusal);
    }

    #[tokio::test]
    async fn an_access_token_is_claimed_once() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, _) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let access_token = access_token(&server).await;
        let nonce = minted_nonce(&server).await;
        let key = private_jwk("holder");
        let request = json!({
            "credential_configuration_id": CONFIGURATION_ID,
            "proofs": {"jwt": [proof_jwt(&key, "https://wallet.example.org", &nonce, now())]},
        });

        assert_eq!(
            server
                .post(CREDENTIAL_PATH)
                .add_header("authorization", format!("Bearer {access_token}"))
                .json(&request)
                .await
                .status_code(),
            StatusCode::OK
        );
        let replayed = server
            .post(CREDENTIAL_PATH)
            .add_header("authorization", format!("Bearer {access_token}"))
            .json(&request)
            .await;
        assert_eq!(replayed.status_code(), StatusCode::UNAUTHORIZED);
    }

    /// A request refused after the token was claimed does not give the token
    /// back.
    ///
    /// The token is claimed before the body is parsed and before any proof is
    /// looked at, which is what makes one authorization mean one attempt rather
    /// than one success. Without that, the credential endpoint would be a place
    /// to try proofs against a live token until one was accepted. The refusal
    /// here comes from the deepest validation step, so every step between the
    /// claim and it is covered: a service that restored the token on any of
    /// them would let the retry below succeed.
    #[tokio::test]
    async fn a_credential_request_refused_after_the_token_is_claimed_leaves_it_spent() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, issuer) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let access_token = access_token(&server).await;
        let key = private_jwk("holder");
        let refused = server
            .post(CREDENTIAL_PATH)
            .add_header("authorization", format!("Bearer {access_token}"))
            .json(&json!({
                "credential_configuration_id": CONFIGURATION_ID,
                "proofs": {
                    "jwt": [proof_jwt(&key, "https://wallet.example.org", "invented", now())],
                },
            }))
            .await;
        assert_eq!(refused.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(refused.json::<Value>()["error"], json!("invalid_nonce"));

        // Everything wrong with the first request is corrected, and the same
        // token is presented again. It is gone.
        let nonce = minted_nonce(&server).await;
        let retried = server
            .post(CREDENTIAL_PATH)
            .add_header("authorization", format!("Bearer {access_token}"))
            .json(&json!({
                "credential_configuration_id": CONFIGURATION_ID,
                "proofs": {"jwt": [proof_jwt(&key, "https://wallet.example.org", &nonce, now())]},
            }))
            .await;
        assert_eq!(retried.status_code(), StatusCode::UNAUTHORIZED);
        assert!(
            issuer.requests().is_empty(),
            "a spent token may reach no credential"
        );
    }

    /// The batch ceiling a wallet reads is the batch ceiling it may use.
    ///
    /// The published number is taken from the served metadata and used as the
    /// proof count, so a metadata entry that overstated what the endpoint
    /// accepts would fail on the accepted case and one that understated it
    /// would fail on the refused case.
    #[tokio::test]
    async fn the_published_batch_size_is_what_the_credential_endpoint_accepts() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, issuer) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let published = server.get(ISSUER_METADATA_PATH).await.json::<Value>()
            ["batch_credential_issuance"]["batch_size"]
            .as_u64()
            .expect("the metadata publishes a batch size") as usize;

        let keys: Vec<String> = (0..published + 1)
            .map(|index| private_jwk(&format!("k{index}")))
            .collect();

        let nonce = minted_nonce(&server).await;
        let at_the_ceiling: Vec<String> = keys[..published]
            .iter()
            .map(|key| proof_jwt(key, "https://wallet.example.org", &nonce, now()))
            .collect();
        let accepted = server
            .post(CREDENTIAL_PATH)
            .add_header(
                "authorization",
                format!("Bearer {}", access_token(&server).await),
            )
            .json(&json!({
                "credential_configuration_id": CONFIGURATION_ID,
                "proofs": {"jwt": at_the_ceiling},
            }))
            .await;
        let status = accepted.status_code();
        let body: Value = accepted.json();
        assert_eq!(status, StatusCode::OK, "body: {body}");
        assert_eq!(issuer.requests()[0].holder_keys.len(), published);

        let nonce = minted_nonce(&server).await;
        let over_the_ceiling: Vec<String> = keys
            .iter()
            .map(|key| proof_jwt(key, "https://wallet.example.org", &nonce, now()))
            .collect();
        let refused = server
            .post(CREDENTIAL_PATH)
            .add_header(
                "authorization",
                format!("Bearer {}", access_token(&server).await),
            )
            .json(&json!({
                "credential_configuration_id": CONFIGURATION_ID,
                "proofs": {"jwt": over_the_ceiling},
            }))
            .await;
        assert_eq!(refused.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(issuer.requests().len(), 1, "one request reached Evidence");
    }

    #[tokio::test]
    async fn a_credential_request_for_another_configuration_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, issuer) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let access_token = access_token(&server).await;
        let nonce = minted_nonce(&server).await;
        let key = private_jwk("holder");
        let response = server
            .post(CREDENTIAL_PATH)
            .add_header("authorization", format!("Bearer {access_token}"))
            .json(&json!({
                "credential_configuration_id": "urn:example:requirement:audience-scoped",
                "proofs": {"jwt": [proof_jwt(&key, "https://wallet.example.org", &nonce, now())]},
            }))
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
        assert!(issuer.requests().is_empty());
    }

    #[tokio::test]
    async fn a_credential_request_without_a_token_is_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, _) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let response = server
            .post(CREDENTIAL_PATH)
            .json(&json!({
                "credential_configuration_id": CONFIGURATION_ID,
                "proofs": {"jwt": ["a.b.c"]},
            }))
            .await;
        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn more_proofs_than_a_request_may_carry_are_refused() {
        let directory = tempfile::tempdir().expect("temp dir");
        let (service, issuer) = wired_service(directory.path());
        let server = TestServer::new(build_app(service));

        let access_token = access_token(&server).await;
        let nonce = minted_nonce(&server).await;
        let key = private_jwk("holder");
        let proof = proof_jwt(&key, "https://wallet.example.org", &nonce, now());
        let proofs = vec![proof.as_str(); MAXIMUM_HOLDER_KEYS + 1];

        let response = server
            .post(CREDENTIAL_PATH)
            .add_header("authorization", format!("Bearer {access_token}"))
            .json(&json!({
                "credential_configuration_id": CONFIGURATION_ID,
                "proofs": {"jwt": proofs},
            }))
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
        assert!(issuer.requests().is_empty());
    }

    /// Open a connection to a listener that is still coming up.
    async fn connect(port: u16) -> tokio::net::TcpStream {
        let mut attempts = 0;
        loop {
            match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                Ok(stream) => break stream,
                Err(error) if attempts < 50 => {
                    attempts += 1;
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    let _ = error;
                }
                Err(error) => panic!("the listener never accepted a connection: {error}"),
            }
        }
    }

    /// A caller that opens a request and then stalls is refused.
    ///
    /// The request head promises a body that never arrives, which is the shape
    /// a body limit cannot bound: nothing is oversized, and without the
    /// configured timeout the connection and the task behind it would be held
    /// for as long as the caller cared to hold them. The answer is read under a
    /// window far wider than the configured one, so a service that never
    /// answered would fail here rather than hang the suite.
    #[tokio::test]
    async fn a_request_that_stalls_past_the_configured_timeout_is_refused() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let directory = tempfile::tempdir().expect("temp dir");
        let port = {
            let probe = StdTcpListener::bind(("127.0.0.1", 0)).expect("probe a free port");
            probe.local_addr().expect("read the probed port").port()
        };
        let path = write_deployment(directory.path(), port, 0o600);
        let document = fs::read_to_string(&path).expect("read the configuration document");
        fs::write(
            &path,
            document.replace(
                &format!("  port: {port}\n"),
                &format!("  port: {port}\n  requestTimeoutMilliseconds: 200\n"),
            ),
        )
        .expect("write the configuration document");
        let config = DeliveryConfig::load(&path).expect("the configuration loads");
        assert_eq!(config.listener.request_timeout_milliseconds, 200);
        let service = Arc::new(DeliveryService::load(config).expect("the service loads"));

        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(serve(service, async move {
            let _ = stopped.await;
        }));

        let mut stream = connect(port).await;
        stream
            .write_all(
                format!(
                    "POST {TOKEN_PATH} HTTP/1.1\r\n\
                     Host: 127.0.0.1\r\n\
                     Content-Type: application/x-www-form-urlencoded\r\n\
                     Content-Length: 64\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("write the request head");

        let mut answer = Vec::new();
        let read = tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer))
            .await
            .expect("the stalled request must be answered rather than held open");
        read.expect("the answer is readable");
        let rendered = String::from_utf8_lossy(&answer);
        assert!(
            rendered.starts_with("HTTP/1.1 408"),
            "the stalled request was not refused: {rendered}"
        );
        drop(stream);

        stop.send(()).expect("request shutdown");
        serving
            .await
            .expect("the serving task joins")
            .expect("serving ends cleanly");
    }

    #[tokio::test]
    async fn serve_binds_the_configured_listener_and_stops_on_shutdown() {
        let directory = tempfile::tempdir().expect("temp dir");
        let port = {
            let probe = StdTcpListener::bind(("127.0.0.1", 0)).expect("probe a free port");
            probe.local_addr().expect("read the probed port").port()
        };
        let path = write_deployment(directory.path(), port, 0o600);
        let config = DeliveryConfig::load(&path).expect("the configuration loads");
        let service = Arc::new(DeliveryService::load(config).expect("the service loads"));

        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let serving = tokio::spawn(serve(service, async move {
            let _ = stopped.await;
        }));

        // Reaching the bound port is the proof that `serve` binds what `check`
        // deliberately does not.
        let mut attempts = 0;
        let connected = loop {
            match tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                Ok(stream) => break stream,
                Err(error) if attempts < 50 => {
                    attempts += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                    let _ = error;
                }
                Err(error) => panic!("the listener never accepted a connection: {error}"),
            }
        };
        drop(connected);

        stop.send(()).expect("request shutdown");
        serving
            .await
            .expect("the serving task joins")
            .expect("serving ends cleanly");
    }
}
