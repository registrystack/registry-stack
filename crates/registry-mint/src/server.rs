//! The Mint HTTP boundary.
//!
//! The boundary serves the token endpoint, published key set, equivalent OAuth
//! authorization-server and OpenID Provider metadata resources, and two
//! liveness probes. Everything a caller sends is treated as an unauthenticated
//! claim about identity until the selected credential has been verified only
//! against that client's registered authentication material.
//!
//! The service holds two kinds of state with deliberately different lifetimes.
//! Issuer identity, signing and audit keys, listener, and token policy are startup-only:
//! changing them means restarting. The client registry is reloadable, so
//! onboarding or removing a caller never restarts a resource server.

use std::{
    future::{Future, IntoFuture},
    io,
    net::SocketAddr,
    sync::{Arc, RwLock},
    time::Duration,
};

use axum::{
    body::{to_bytes, Body},
    extract::State,
    http::{
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, PRAGMA},
        HeaderMap, HeaderValue, Request, StatusCode,
    },
    middleware::{from_fn, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use registry_platform_httputil::MAXIMUM_TOKEN_RESPONSE_BYTES;
use serde_json::{json, Value};
use thiserror::Error;
use tokio::net::TcpListener;
use zeroize::Zeroizing;

use crate::{
    assertion::ClientAuthenticator,
    audit::{MintAuditError, MintAuditLog},
    clients::{ClientRegistry, ClientRegistryError},
    config::{
        MintConfig, MINT_HEALTH_PATH, MINT_METADATA_PATH, MINT_OIDC_METADATA_PATH, MINT_READY_PATH,
        MINT_TOKEN_PATH,
    },
    error::TokenError,
    replay::ReplayCache,
    token::{projected_standard_token_response_bytes, MinterError, TokenMinter},
    CLIENT_ASSERTION_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS,
};

/// Relay's verifier accepts access tokens for at most fifteen minutes. Keeping
/// this bound on the standard profile makes every accepted registration usable
/// by the resource server that profile was introduced to support, while the
/// existing Evidence profile retains Mint's wider configured range.
const MAXIMUM_STANDARD_TOKEN_LIFETIME_SECONDS: u64 = 15 * 60;

const FORM_MEDIA_TYPE: &str = "application/x-www-form-urlencoded";
const JSON_MEDIA_TYPE: &str = "application/json";
const JWKS_MEDIA_TYPE: &str = "application/jwk-set+json";
const MAXIMUM_BASIC_AUTHORIZATION_BYTES: usize = 2 * 1024;
const MAXIMUM_CLIENT_ID_BYTES: usize = 256;
const MAXIMUM_CLIENT_SECRET_BYTES: usize = 512;

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("the token signing boundary could not be initialized: {0}")]
    Minter(#[from] MinterError),
    #[error("the client registry could not be loaded: {0}")]
    Registry(#[from] ClientRegistryError),
    #[error("the audit boundary could not be initialized: {0}")]
    Audit(#[from] MintAuditError),
    #[error("client {0} cannot be served: {1}")]
    Registration(String, &'static str),
}

/// The whole serving state: an immutable minter over a reloadable registry.
pub struct MintService {
    config: MintConfig,
    minter: TokenMinter,
    /// Swapped wholesale on reload. Readers clone the `Arc` and release the
    /// lock before any await, so a reload never blocks in-flight requests.
    authenticator: RwLock<Arc<ClientAuthenticator>>,
    /// Owned by the service rather than the authenticator so that reloading the
    /// registry never forgets which assertion identifiers were already spent.
    replay: Arc<ReplayCache>,
    audit: MintAuditLog,
    metadata: Value,
}

impl std::fmt::Debug for MintService {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MintService")
            .field("issuer", &self.config.issuer)
            .field("clients", &self.client_count())
            .finish_non_exhaustive()
    }
}

impl MintService {
    /// Load the keys, audit chain, and client registry described by `config`.
    pub async fn load(config: MintConfig) -> Result<Self, ServiceError> {
        let minter = TokenMinter::new(&config).await?;
        let registry = Arc::new(ClientRegistry::load(&config.clients.directory)?);
        check_client_profiles(&registry, &config)?;
        let replay = Arc::new(ReplayCache::new(
            config.client_assertion.replay_cache_entries,
        ));
        let authenticator =
            ClientAuthenticator::new(registry, &config.client_assertion, Arc::clone(&replay));
        let audit =
            MintAuditLog::initialize(&config.audit, &config.secret_providers, &config.issuer)
                .await?;
        let metadata = build_metadata(&config);
        Ok(Self {
            config,
            minter,
            authenticator: RwLock::new(Arc::new(authenticator)),
            replay,
            audit,
            metadata,
        })
    }

    /// Validate a configuration without taking what a serving instance holds.
    ///
    /// Everything [`MintService::load`] does except claiming the audit writer,
    /// so an operator can check an edited configuration against the deployment
    /// it is about to replace. Returns the number of registered clients.
    pub async fn check(config: &MintConfig) -> Result<usize, ServiceError> {
        let _minter = TokenMinter::new(config).await?;
        let registry = ClientRegistry::load(&config.clients.directory)?;
        check_client_profiles(&registry, config)?;
        MintAuditLog::check(&config.audit, &config.secret_providers)?;
        Ok(registry.len())
    }

    /// Re-read the client registry directory and swap it in atomically.
    ///
    /// A failed reload leaves the previous registry in place: a malformed file
    /// dropped into the directory must not silently revoke every caller.
    pub fn reload_clients(&self) -> Result<usize, ServiceError> {
        let registry = Arc::new(ClientRegistry::load(&self.config.clients.directory)?);
        // Checked on every reload, not only at startup: a registration dropped
        // into the directory later must clear the same bar.
        check_client_profiles(&registry, &self.config)?;
        let count = registry.len();
        let authenticator = Arc::new(ClientAuthenticator::new(
            registry,
            &self.config.client_assertion,
            Arc::clone(&self.replay),
        ));
        *self
            .authenticator
            .write()
            .expect("the client registry lock is never poisoned") = authenticator;
        Ok(count)
    }

    #[must_use]
    pub fn client_count(&self) -> usize {
        self.authenticator().registry().len()
    }

    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.config.issuer
    }

    #[must_use]
    pub fn jwks(&self) -> &Value {
        self.minter.jwks()
    }

    fn authenticator(&self) -> Arc<ClientAuthenticator> {
        Arc::clone(
            &self
                .authenticator
                .read()
                .expect("the client registry lock is never poisoned"),
        )
    }

    /// Authenticate a token request and mint the authority its registry entry
    /// carries. Nothing is read from the assertion payload.
    async fn issue(
        &self,
        operation: &str,
        request: &TokenRequest,
        now: i64,
    ) -> Result<Response, TokenError> {
        if request.grant_type != GRANT_TYPE_CLIENT_CREDENTIALS {
            return Err(TokenError::unsupported_grant_type(
                "grant type is not supported",
            ));
        }
        // Cloned out of the lock so a concurrent reload cannot block here.
        let authenticator = self.authenticator();
        let authenticated = match &request.authentication {
            TokenAuthentication::PrivateKeyJwt {
                client_id,
                client_assertion_type,
                client_assertion,
            } => {
                if client_assertion_type != CLIENT_ASSERTION_TYPE {
                    return Err(TokenError::invalid_request(
                        "client assertion type is not supported",
                    ));
                }
                let authenticated = authenticator.authenticate(client_assertion, now).await?;
                if client_id
                    .as_deref()
                    .is_some_and(|client_id| client_id != authenticated.client.client_id())
                {
                    return Err(TokenError::invalid_client(
                        "client identifier does not match the assertion",
                    ));
                }
                authenticated
            }
            TokenAuthentication::ClientSecret {
                client_id,
                client_secret,
            } => authenticator.authenticate_client_secret(client_id, client_secret)?,
        };
        let token = self.minter.mint(&authenticated, now).await?;
        let body = serde_json::to_vec(&token)
            .map_err(|_| TokenError::server_error("the token response could not be serialized"))?;
        self.audit
            .append_issued(operation, &authenticated, &token)
            .await
            .map_err(|_| TokenError::server_error("the token release could not be audited"))?;
        Ok(json_response(StatusCode::OK, JSON_MEDIA_TYPE, body))
    }

    async fn reject(&self, operation: &str, error: TokenError) -> Response {
        if self
            .audit
            .append_rejected(operation, error.code().as_str())
            .await
            .is_err()
        {
            tracing::error!(
                target: "registry_mint::audit",
                operation,
                "the token denial could not be audited"
            );
            return TokenError::server_error("the token decision could not be audited")
                .into_operation_response(operation);
        }
        error.into_operation_response(operation)
    }

    #[must_use]
    /// Report whether this loaded service can satisfy the same readiness
    /// contract used by the serving endpoint.
    pub async fn ready(&self) -> bool {
        self.client_count() > 0 && self.minter.ready().await && self.audit.ready().await
    }
}

/// Refuse a registry whose authority profiles this configuration cannot express.
///
/// The registry and the claim-name configuration are loaded independently, so
/// this is the only place their agreement can be established. A disagreement
/// caught here is an operator error at startup or reload. Deferring it until a
/// token request would turn the same mistake into a caller-specific outage or
/// an unusable token.
fn check_client_profiles(
    registry: &ClientRegistry,
    config: &MintConfig,
) -> Result<(), ServiceError> {
    let claims = config.access_tokens.claims.as_ref();
    let evidence_claim_names = claims.map(|claims| {
        let mut names = vec![
            claims.principal.as_str(),
            claims.requester_tags.as_str(),
            claims.evidence_audience.as_str(),
            claims.grant_id.as_str(),
            claims.grant_authority.as_str(),
        ];
        names.extend(claims.actor.as_deref());
        names
    });
    for client_id in registry.client_ids() {
        let client = registry
            .get(client_id)
            .expect("client id came from this registry");
        if client.authorization().is_some() {
            if config.access_tokens.audiences.len() != 1 {
                return Err(ServiceError::Registration(
                    client_id.to_owned(),
                    "standard authorization requires exactly one access-token audience",
                ));
            }
            if config.access_tokens.lifetime_seconds > MAXIMUM_STANDARD_TOKEN_LIFETIME_SECONDS {
                return Err(ServiceError::Registration(
                    client_id.to_owned(),
                    "standard authorization requires an access-token lifetime of at most 900 seconds",
                ));
            }
            let projected =
                projected_standard_token_response_bytes(config, client).map_err(|_| {
                    ServiceError::Registration(
                        client_id.to_owned(),
                        "the standard token response could not be projected",
                    )
                })?;
            if projected > MAXIMUM_TOKEN_RESPONSE_BYTES {
                return Err(ServiceError::Registration(
                    client_id.to_owned(),
                    "standard authorization would exceed the shared client token-response bound",
                ));
            }
        }
        if let (Some(authorization), Some(evidence_claim_names)) =
            (client.authorization(), evidence_claim_names.as_ref())
        {
            if authorization
                .claims
                .keys()
                .any(|name| evidence_claim_names.contains(&name.as_str()))
            {
                return Err(ServiceError::Registration(
                    client_id.to_owned(),
                    "a standard authorization claim would overlap configured Evidence authority",
                ));
            }
        }
        if client.authorization().is_none() && claims.is_none() {
            return Err(ServiceError::Registration(
                client_id.to_owned(),
                "it uses Evidence authority but no Evidence claim names are configured",
            ));
        }
        let Some(delegation) = client.delegation() else {
            continue;
        };
        let claims = claims.expect("an Evidence registration was checked above");
        // The claims Mint writes itself. A subject minted over one of these
        // would replace authority the registry, not the caller, is supposed to
        // decide.
        let mut reserved = vec![
            "iss",
            "aud",
            "exp",
            "iat",
            "nbf",
            "jti",
            "client_id",
            "sub",
            "scope",
        ];
        reserved.push(claims.principal.as_str());
        reserved.push(claims.requester_tags.as_str());
        reserved.push(claims.evidence_audience.as_str());
        reserved.push(claims.grant_id.as_str());
        reserved.push(claims.grant_authority.as_str());
        reserved.extend(claims.actor.as_deref());
        if claims.actor.is_none() {
            return Err(ServiceError::Registration(
                client_id.to_owned(),
                "it declares a delegation but no actor claim name is configured",
            ));
        }
        for path in delegation.subject_claims.values() {
            let root = path.split('.').next().unwrap_or(path);
            if reserved.contains(&root) {
                return Err(ServiceError::Registration(
                    client_id.to_owned(),
                    "a subject claim path would overwrite an authority claim",
                ));
            }
        }
    }
    Ok(())
}

fn build_metadata(config: &MintConfig) -> Value {
    let issuer = config.issuer.trim_end_matches('/');
    let algorithms = {
        let mut algorithms = config
            .client_assertion
            .algorithms
            .iter()
            .map(|algorithm| algorithm.as_header_value())
            .collect::<Vec<_>>();
        algorithms.sort_unstable();
        algorithms.dedup();
        algorithms
    };
    json!({
        "issuer": config.issuer,
        "token_endpoint": format!("{issuer}{MINT_TOKEN_PATH}"),
        "jwks_uri": format!("{issuer}{}", config.signing.jwks_path),
        "grant_types_supported": [GRANT_TYPE_CLIENT_CREDENTIALS],
        "token_endpoint_auth_methods_supported": [
            "private_key_jwt",
            "client_secret_basic",
            "client_secret_post"
        ],
        "token_endpoint_auth_signing_alg_values_supported": algorithms,
        // Mint has no authorization endpoint: there is no user to redirect.
        "response_types_supported": [],
    })
}

/// One and only one authentication method selected from the token request.
enum TokenAuthentication {
    PrivateKeyJwt {
        client_id: Option<String>,
        client_assertion_type: String,
        client_assertion: String,
    },
    ClientSecret {
        client_id: String,
        client_secret: Zeroizing<String>,
    },
}

impl std::fmt::Debug for TokenAuthentication {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PrivateKeyJwt { .. } => formatter.write_str("PrivateKeyJwt([redacted])"),
            Self::ClientSecret { .. } => formatter.write_str("ClientSecret([redacted])"),
        }
    }
}

/// The parameters Mint reads from a token request.
///
/// RFC 6749 section 3.1 requires unrecognized parameters to be ignored and
/// forbids any parameter appearing more than once, so this is parsed by hand
/// rather than through a permissive form deserializer.
#[derive(Debug)]
struct TokenRequest {
    grant_type: String,
    authentication: TokenAuthentication,
}

struct BasicClientCredentials {
    client_id: String,
    client_secret: Zeroizing<String>,
}

impl std::fmt::Debug for BasicClientCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BasicClientCredentials([redacted])")
    }
}

fn parse_token_request(
    body: &[u8],
    basic: Option<BasicClientCredentials>,
) -> Result<TokenRequest, TokenError> {
    let mut grant_type = None;
    let mut client_assertion_type = None;
    let mut client_assertion = None;
    let mut client_id = None;
    let mut client_secret = None;

    for (name, value) in url::form_urlencoded::parse(body) {
        let slot = match name.as_ref() {
            "grant_type" => &mut grant_type,
            "client_assertion_type" => &mut client_assertion_type,
            "client_assertion" => &mut client_assertion,
            "client_id" => &mut client_id,
            "client_secret" => &mut client_secret,
            // Ignored by RFC 6749 section 3.1.
            _ => continue,
        };
        // A repeated parameter leaves which value was authenticated ambiguous.
        if slot.is_some() {
            return Err(TokenError::invalid_request(
                "a request parameter was repeated",
            ));
        }
        *slot = Some(value.into_owned());
    }

    let grant_type =
        grant_type.ok_or_else(|| TokenError::invalid_request("grant_type is missing"))?;
    let body_secret_present = client_secret.is_some();
    let assertion_present = client_assertion_type.is_some() || client_assertion.is_some();

    let authentication = if let Some(basic) = basic {
        if body_secret_present || assertion_present {
            return Err(TokenError::invalid_request(
                "multiple client authentication methods were presented",
            ));
        }
        if let Some(client_id) = client_id {
            let client_id = bounded_client_id(client_id)?;
            if client_id != basic.client_id {
                return Err(TokenError::invalid_client(
                    "client identifier does not match the Basic credential",
                ));
            }
        }
        TokenAuthentication::ClientSecret {
            client_id: basic.client_id,
            client_secret: basic.client_secret,
        }
    } else if body_secret_present {
        if assertion_present {
            return Err(TokenError::invalid_request(
                "multiple client authentication methods were presented",
            ));
        }
        TokenAuthentication::ClientSecret {
            client_id: bounded_client_id(
                client_id.ok_or_else(|| TokenError::invalid_client("client id is missing"))?,
            )?,
            client_secret: bounded_client_secret(
                client_secret
                    .ok_or_else(|| TokenError::invalid_client("client secret is missing"))?,
            )?,
        }
    } else {
        TokenAuthentication::PrivateKeyJwt {
            client_id: client_id.map(bounded_client_id).transpose()?,
            client_assertion_type: client_assertion_type
                .ok_or_else(|| TokenError::invalid_request("client_assertion_type is missing"))?,
            client_assertion: client_assertion
                .ok_or_else(|| TokenError::invalid_request("client_assertion is missing"))?,
        }
    };

    Ok(TokenRequest {
        grant_type,
        authentication,
    })
}

fn parse_basic_client_credentials(
    headers: &HeaderMap,
) -> Result<Option<BasicClientCredentials>, TokenError> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(TokenError::invalid_request(
            "multiple authorization headers were presented",
        ));
    }
    let value = value
        .to_str()
        .map_err(|_| TokenError::invalid_client("basic client credentials are malformed"))?;
    if value.len() > MAXIMUM_BASIC_AUTHORIZATION_BYTES {
        return Err(TokenError::invalid_client(
            "basic client credentials are malformed",
        ));
    }
    let Some((scheme, encoded)) = value.split_once(' ') else {
        return Err(TokenError::invalid_client(
            "basic client credentials are malformed",
        ));
    };
    let encoded = encoded.trim_start_matches(' ');
    if !scheme.eq_ignore_ascii_case("Basic")
        || encoded.is_empty()
        || encoded.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(TokenError::invalid_client(
            "basic client credentials are malformed",
        ));
    }
    let decoded = Zeroizing::new(
        STANDARD
            .decode(encoded)
            .map_err(|_| TokenError::invalid_client("basic client credentials are malformed"))?,
    );
    let decoded = std::str::from_utf8(&decoded)
        .map_err(|_| TokenError::invalid_client("basic client credentials are malformed"))?;
    let (client_id, client_secret) = decoded
        .split_once(':')
        .ok_or_else(|| TokenError::invalid_client("basic client credentials are malformed"))?;
    let client_id = decode_form_component(client_id)?;
    let client_secret = decode_form_component(client_secret)?;
    Ok(Some(BasicClientCredentials {
        client_id: bounded_client_id(client_id)?,
        client_secret: bounded_client_secret(client_secret)?,
    }))
}

/// Decode RFC 6749 section 2.3.1's form-encoded Basic components strictly.
fn decode_form_component(value: &str) -> Result<String, TokenError> {
    let mut decoded = Vec::with_capacity(value.len());
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => decoded.push(b' '),
            b'%' if index + 2 < bytes.len() => {
                let high = hex_nibble(bytes[index + 1])?;
                let low = hex_nibble(bytes[index + 2])?;
                decoded.push((high << 4) | low);
                index += 2;
            }
            b'%' => {
                return Err(TokenError::invalid_client(
                    "basic client credentials are malformed",
                ))
            }
            byte => decoded.push(byte),
        }
        index += 1;
    }
    String::from_utf8(decoded)
        .map_err(|_| TokenError::invalid_client("basic client credentials are malformed"))
}

fn hex_nibble(byte: u8) -> Result<u8, TokenError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(TokenError::invalid_client(
            "basic client credentials are malformed",
        )),
    }
}

fn bounded_client_id(value: String) -> Result<String, TokenError> {
    if value.trim().is_empty() || value.len() > MAXIMUM_CLIENT_ID_BYTES {
        return Err(TokenError::invalid_client("client id is not bounded"));
    }
    Ok(value)
}

fn bounded_client_secret(value: String) -> Result<Zeroizing<String>, TokenError> {
    if value.is_empty() || value.len() > MAXIMUM_CLIENT_SECRET_BYTES {
        return Err(TokenError::invalid_client("client secret is not bounded"));
    }
    Ok(Zeroizing::new(value))
}

/// Build the router over an already loaded service.
pub fn build_app(service: Arc<MintService>) -> Router {
    let jwks_path = service.config.signing.jwks_path.clone();
    let routes = Router::new()
        .route(MINT_TOKEN_PATH, post(token))
        .route(&jwks_path, get(jwks))
        .route(MINT_METADATA_PATH, get(metadata))
        .route(MINT_OIDC_METADATA_PATH, get(metadata))
        .route(MINT_HEALTH_PATH, get(health))
        .route(MINT_READY_PATH, get(ready))
        .fallback(unknown_route)
        .method_not_allowed_fallback(unknown_route)
        .with_state(service);
    routes.layer(from_fn(add_no_store))
}

/// Bind the configured listener and serve until `shutdown` resolves.
pub async fn serve<F>(service: Arc<MintService>, shutdown: F) -> io::Result<()>
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
        target: "registry_mint::server",
        issuer = %service.config.issuer,
        clients = service.client_count(),
        "mint listening"
    );
    let app = build_app(service);
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .into_future()
        .await
}

async fn token(State(service): State<Arc<MintService>>, request: Request<Body>) -> Response {
    let operation = format!("urn:ulid:{}", ulid::Ulid::new());
    let used_http_authorization = request.headers().contains_key(AUTHORIZATION);
    if !has_exact_content_type(request.headers(), FORM_MEDIA_TYPE) {
        return reject_token_request(
            &service,
            &operation,
            used_http_authorization,
            TokenError::invalid_request("content type must be form encoded"),
        )
        .await;
    }
    let basic = match parse_basic_client_credentials(request.headers()) {
        Ok(basic) => basic,
        Err(error) => {
            return reject_token_request(&service, &operation, used_http_authorization, error).await
        }
    };

    let maximum_bytes = service.config.listener.maximum_request_bytes as usize;
    let timeout = Duration::from_millis(service.config.listener.request_timeout_milliseconds);
    let body =
        match tokio::time::timeout(timeout, to_bytes(request.into_body(), maximum_bytes)).await {
            Ok(Ok(body)) => body,
            Ok(Err(_)) => {
                return reject_token_request(
                    &service,
                    &operation,
                    used_http_authorization,
                    TokenError::invalid_request("the request body could not be read"),
                )
                .await
            }
            Err(_) => {
                return reject_token_request(
                    &service,
                    &operation,
                    used_http_authorization,
                    TokenError::invalid_request("the request body timed out"),
                )
                .await;
            }
        };

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let parsed = match parse_token_request(&body, basic) {
        Ok(parsed) => parsed,
        Err(error) => {
            return reject_token_request(&service, &operation, used_http_authorization, error).await
        }
    };
    match service.issue(&operation, &parsed, now).await {
        Ok(response) => response,
        Err(error) => {
            reject_token_request(&service, &operation, used_http_authorization, error).await
        }
    }
}

async fn reject_token_request(
    service: &MintService,
    operation: &str,
    used_http_authorization: bool,
    error: TokenError,
) -> Response {
    let invalid_client = error.code() == crate::error::TokenErrorCode::InvalidClient;
    let mut response = service.reject(operation, error).await;
    if used_http_authorization && invalid_client && response.status() == StatusCode::UNAUTHORIZED {
        response.headers_mut().insert(
            axum::http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"registry-mint\""),
        );
    }
    response
}

async fn jwks(State(service): State<Arc<MintService>>) -> Response {
    match serde_json::to_vec(service.jwks()) {
        Ok(body) => json_response(StatusCode::OK, JWKS_MEDIA_TYPE, body),
        Err(_) => TokenError::server_error("the key set could not be serialized").into_response(),
    }
}

async fn metadata(State(service): State<Arc<MintService>>) -> Response {
    match serde_json::to_vec(&service.metadata) {
        Ok(body) => json_response(StatusCode::OK, JSON_MEDIA_TYPE, body),
        Err(_) => TokenError::server_error("the metadata could not be serialized").into_response(),
    }
}

async fn health() -> Response {
    json_response(
        StatusCode::OK,
        JSON_MEDIA_TYPE,
        br#"{"status":"ok"}"#.to_vec(),
    )
}

async fn ready(State(service): State<Arc<MintService>>) -> Response {
    // A Mint with no clients or a poisoned audit writer is live but cannot
    // safely issue a token, so admission fails until the process is repaired.
    if !service.ready().await {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            JSON_MEDIA_TYPE,
            br#"{"status":"not ready"}"#.to_vec(),
        );
    }
    json_response(
        StatusCode::OK,
        JSON_MEDIA_TYPE,
        br#"{"status":"ready"}"#.to_vec(),
    )
}

async fn unknown_route() -> Response {
    TokenError::invalid_request("no such route").into_response()
}

/// RFC 6749 section 5.1 requires both headers on token responses. Applying them
/// to every route keeps the key set and metadata out of shared caches too.
async fn add_no_store(request: Request<Body>, next: Next) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        http::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn json_response(status: StatusCode, media_type: &'static str, body: Vec<u8>) -> Response {
    (
        status,
        [(CONTENT_TYPE, HeaderValue::from_static(media_type))],
        body,
    )
        .into_response()
}

fn has_exact_content_type(headers: &HeaderMap, expected: &str) -> bool {
    let Some(value) = headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };
    // Only a bare type or one carrying the redundant charset is accepted; a
    // multipart or otherwise decorated type is not this endpoint's input.
    let (media_type, parameters) = match value.split_once(';') {
        Some((media_type, parameters)) => (media_type, Some(parameters)),
        None => (value, None),
    };
    if !media_type.trim().eq_ignore_ascii_case(expected) {
        return false;
    }
    match parameters {
        None => true,
        Some(parameters) => parameters.trim().eq_ignore_ascii_case("charset=utf-8"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_repeated_parameter_is_rejected() {
        let error = parse_token_request(b"grant_type=a&grant_type=b", None)
            .expect_err("a repeated parameter must be rejected");
        assert_eq!(
            error,
            TokenError::invalid_request("a request parameter was repeated")
        );
    }

    #[test]
    fn unrecognized_parameters_are_ignored() {
        let request = parse_token_request(
            b"grant_type=client_credentials&scope=anything&client_assertion_type=t&client_assertion=a",
            None,
        )
        .expect("unrecognized parameters must be ignored");
        assert_eq!(request.grant_type, "client_credentials");
        assert!(matches!(
            request.authentication,
            TokenAuthentication::PrivateKeyJwt {
                client_assertion_type,
                client_assertion,
                ..
            } if client_assertion_type == "t" && client_assertion == "a"
        ));
    }

    #[test]
    fn private_key_jwt_accepts_the_rfc7523_client_identifier() {
        let request = parse_token_request(
            b"grant_type=client_credentials&client_id=evidence-source&client_assertion_type=t&client_assertion=a",
            None,
        )
        .expect("client_id can travel beside a private-key assertion");
        assert!(matches!(
            request.authentication,
            TokenAuthentication::PrivateKeyJwt {
                client_id: Some(client_id),
                client_assertion_type,
                client_assertion,
            } if client_id == "evidence-source"
                && client_assertion_type == "t"
                && client_assertion == "a"
        ));
    }

    #[test]
    fn each_required_parameter_is_required() {
        for body in [
            &b"client_assertion_type=t&client_assertion=a"[..],
            &b"grant_type=g&client_assertion=a"[..],
            &b"grant_type=g&client_assertion_type=t"[..],
        ] {
            let error =
                parse_token_request(body, None).expect_err("a missing parameter must be rejected");
            assert_eq!(error.code(), crate::error::TokenErrorCode::InvalidRequest);
        }
    }

    #[test]
    fn client_secret_post_requires_one_bounded_pair() {
        let request = parse_token_request(
            b"grant_type=client_credentials&client_id=qgis-installation&client_secret=secret-value",
            None,
        )
        .expect("client_secret_post parses");
        assert!(matches!(
            request.authentication,
            TokenAuthentication::ClientSecret { client_id, client_secret }
                if client_id == "qgis-installation" && client_secret.as_str() == "secret-value"
        ));

        for body in [
            &b"grant_type=client_credentials&client_secret=secret-value"[..],
            &b"grant_type=client_credentials&client_id=&client_secret=secret-value"[..],
            &b"grant_type=client_credentials&client_id=qgis-installation&client_secret="[..],
        ] {
            assert_eq!(
                parse_token_request(body, None)
                    .expect_err("an incomplete credential pair is rejected")
                    .code(),
                crate::error::TokenErrorCode::InvalidClient
            );
        }
    }

    #[test]
    fn client_secret_request_debug_output_is_redacted() {
        let request = parse_token_request(
            b"grant_type=client_credentials&client_id=qgis-installation&client_secret=secret-value",
            None,
        )
        .expect("client_secret_post parses");

        let rendered = format!("{request:?}");
        assert!(rendered.contains("ClientSecret([redacted])"));
        assert!(!rendered.contains("qgis-installation"));
        assert!(!rendered.contains("secret-value"));
    }

    #[test]
    fn client_secret_basic_decodes_rfc6749_form_components() {
        let credentials = STANDARD.encode("qgis%3Ainstallation:secret%3Avalue");
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("bAsIc   {credentials}")).expect("header"),
        );
        let basic = parse_basic_client_credentials(&headers)
            .expect("basic header parses")
            .expect("basic credentials are present");
        assert_eq!(basic.client_id, "qgis:installation");
        assert_eq!(basic.client_secret.as_str(), "secret:value");

        let request = parse_token_request(b"grant_type=client_credentials", Some(basic))
            .expect("client_secret_basic selects the credential");
        assert!(matches!(
            request.authentication,
            TokenAuthentication::ClientSecret { client_id, client_secret }
                if client_id == "qgis:installation" && client_secret.as_str() == "secret:value"
        ));
    }

    #[test]
    fn basic_authentication_accepts_only_a_matching_body_client_identifier() {
        let basic = BasicClientCredentials {
            client_id: "qgis-installation".to_owned(),
            client_secret: Zeroizing::new("secret-value".to_owned()),
        };
        parse_token_request(
            b"grant_type=client_credentials&client_id=qgis-installation",
            Some(basic),
        )
        .expect("a matching informational client_id is accepted");

        let basic = BasicClientCredentials {
            client_id: "qgis-installation".to_owned(),
            client_secret: Zeroizing::new("secret-value".to_owned()),
        };
        assert_eq!(
            parse_token_request(
                b"grant_type=client_credentials&client_id=another-installation",
                Some(basic),
            )
            .expect_err("a mismatched client_id is rejected")
            .code(),
            crate::error::TokenErrorCode::InvalidClient
        );
    }

    #[test]
    fn malformed_or_multiple_basic_credentials_are_rejected() {
        for value in ["Bearer value", "Basic", "Basic !!!", "Basic bm9jb2xvbg=="] {
            let mut headers = HeaderMap::new();
            headers.insert(AUTHORIZATION, HeaderValue::from_str(value).expect("header"));
            assert_eq!(
                parse_basic_client_credentials(&headers)
                    .expect_err("malformed Basic credentials are rejected")
                    .code(),
                crate::error::TokenErrorCode::InvalidClient,
                "{value}"
            );
        }

        let mut headers = HeaderMap::new();
        headers.append(AUTHORIZATION, HeaderValue::from_static("Basic YTpi"));
        headers.append(AUTHORIZATION, HeaderValue::from_static("Basic Yzpk"));
        assert_eq!(
            parse_basic_client_credentials(&headers)
                .expect_err("multiple authorization headers are rejected")
                .code(),
            crate::error::TokenErrorCode::InvalidRequest
        );
    }

    #[test]
    fn multiple_client_authentication_methods_are_rejected() {
        let basic = BasicClientCredentials {
            client_id: "qgis-installation".to_owned(),
            client_secret: Zeroizing::new("secret-value".to_owned()),
        };
        assert_eq!(
            parse_token_request(
                b"grant_type=client_credentials&client_id=qgis-installation&client_secret=secret-value",
                Some(basic),
            )
            .expect_err("Basic and body authentication cannot be combined"),
            TokenError::invalid_request("multiple client authentication methods were presented")
        );

        assert_eq!(
            parse_token_request(
                b"grant_type=client_credentials&client_id=qgis-installation&client_secret=secret-value&client_assertion_type=t&client_assertion=a",
                None,
            )
            .expect_err("secret and assertion authentication cannot be combined"),
            TokenError::invalid_request("multiple client authentication methods were presented")
        );
    }

    #[test]
    fn content_type_must_be_the_form_media_type() {
        let mut headers = HeaderMap::new();
        for (value, expected) in [
            ("application/x-www-form-urlencoded", true),
            ("application/x-www-form-urlencoded; charset=utf-8", true),
            ("application/x-www-form-urlencoded; charset=UTF-8", true),
            ("application/json", false),
            ("multipart/form-data; boundary=x", false),
            ("application/x-www-form-urlencoded; boundary=x", false),
        ] {
            headers.insert(CONTENT_TYPE, HeaderValue::from_str(value).expect("header"));
            assert_eq!(
                has_exact_content_type(&headers, FORM_MEDIA_TYPE),
                expected,
                "{value}"
            );
        }
    }

    fn registry_with(extra: &str) -> ClientRegistry {
        let directory = tempfile::tempdir().expect("temp dir");
        let public = crate::assertion::tests::test_key(1).1;
        std::fs::write(
            directory.path().join("client-a.yaml"),
            format!("clientId: client-a\nprincipal: urn:example:client-a\nevidenceAudience: https://client-a.example.org\nrequesterTags: [tag-a]\nkeys: [{public}]\n{extra}"),
        )
        .expect("write client registration");
        ClientRegistry::load(directory.path()).expect("registry loads")
    }

    fn claim_names() -> crate::config::ClaimNames {
        crate::config::tests::sample_config()
            .access_tokens
            .claims
            .expect("the Evidence sample names its claims")
    }

    fn check_profiles(
        registry: &ClientRegistry,
        claims: Option<&crate::config::ClaimNames>,
        audience_count: usize,
    ) -> Result<(), ServiceError> {
        check_profiles_with_lifetime(registry, claims, audience_count, 300)
    }

    fn check_profiles_with_lifetime(
        registry: &ClientRegistry,
        claims: Option<&crate::config::ClaimNames>,
        audience_count: usize,
        lifetime_seconds: u64,
    ) -> Result<(), ServiceError> {
        let mut config = crate::config::tests::sample_config();
        config.access_tokens.claims = claims.cloned();
        config.access_tokens.audiences = (0..audience_count)
            .map(|index| format!("audience-{index}"))
            .collect();
        config.access_tokens.lifetime_seconds = lifetime_seconds;
        check_client_profiles(registry, &config)
    }

    const DELEGATION: &str = "delegation:\n  subjectClaims:\n    given_name: identity.given_name\n";

    /// The registry and the claim-name configuration are loaded independently,
    /// so a delegation with nowhere to mint its actor has to be caught here or
    /// not at all.
    #[test]
    fn a_delegation_without_a_configured_actor_claim_refuses_to_load() {
        let mut claims = claim_names();
        claims.actor = None;
        let error = check_profiles(&registry_with(DELEGATION), Some(&claims), 1)
            .expect_err("an unconfigured actor claim must refuse the registry");
        assert!(matches!(error, ServiceError::Registration(client, _) if client == "client-a"));

        claims.actor = Some("evidence_actor".to_owned());
        assert!(check_profiles(&registry_with(DELEGATION), Some(&claims), 1).is_ok());
    }

    /// A subject path rooted at a claim Mint writes itself would let the caller
    /// choose authority the registry is supposed to decide.
    #[test]
    fn a_subject_path_rooted_at_an_authority_claim_refuses_to_load() {
        let mut claims = claim_names();
        claims.actor = Some("evidence_actor".to_owned());

        let mut paths = vec!["scope".to_owned(), "scope.value".to_owned()];
        paths.extend(
            [
                "iss",
                "sub",
                "jti",
                "client_id",
                claims.requester_tags.as_str(),
                claims.evidence_audience.as_str(),
                claims.grant_id.as_str(),
                claims.grant_authority.as_str(),
                "evidence_actor",
            ]
            .into_iter()
            .map(|root| format!("{root}.given_name")),
        );
        for path in paths {
            let registry = registry_with(&format!(
                "delegation:\n  subjectClaims:\n    given_name: {path}\n"
            ));
            assert!(
                matches!(
                    check_profiles(&registry, Some(&claims), 1),
                    Err(ServiceError::Registration(client, reason))
                        if client == "client-a"
                            && reason == "a subject claim path would overwrite an authority claim"
                ),
                "a subject path at {path} must be refused as an authority collision"
            );
        }
    }

    /// A registry with no delegations is unaffected by the actor claim either
    /// way, so an existing deployment does not have to configure one.
    #[test]
    fn an_undelegated_registry_loads_without_an_actor_claim() {
        let mut claims = claim_names();
        claims.actor = None;
        assert!(check_profiles(&registry_with(""), Some(&claims), 1).is_ok());
    }

    #[test]
    fn evidence_registrations_require_claim_names_but_scoped_registrations_do_not() {
        assert!(matches!(
            check_profiles(&registry_with(""), None, 1),
            Err(ServiceError::Registration(client, _)) if client == "client-a"
        ));

        let directory = tempfile::tempdir().expect("temp dir");
        let public = crate::assertion::tests::test_key(1).1;
        std::fs::write(
            directory.path().join("client-a.yaml"),
            format!(
                "clientId: client-a\nprincipal: urn:example:client-a\nauthorization: {{scopes: [registry:read]}}\nkeys: [{public}]\n"
            ),
        )
        .expect("write scoped registration");
        let registry = ClientRegistry::load(directory.path()).expect("registry loads");
        assert!(check_profiles(&registry, None, 1).is_ok());
    }

    #[test]
    fn standard_authorization_cannot_overlap_configured_evidence_authority() {
        let mut claims = claim_names();
        claims.principal = "evidence_principal".to_owned();
        claims.actor = Some("evidence_actor".to_owned());
        for name in [
            claims.principal.as_str(),
            claims.requester_tags.as_str(),
            claims.evidence_audience.as_str(),
            claims.grant_id.as_str(),
            claims.grant_authority.as_str(),
            claims
                .actor
                .as_deref()
                .expect("the actor claim is configured"),
        ] {
            let directory = tempfile::tempdir().expect("temp dir");
            let public = crate::assertion::tests::test_key(1).1;
            std::fs::write(
                directory.path().join("client-a.yaml"),
                format!(
                    "clientId: client-a\nprincipal: urn:example:client-a\nauthorization:\n  scopes: [registry:read]\n  claims: {{{name}: authority}}\nkeys: [{public}]\n"
                ),
            )
            .expect("write scoped registration");
            let registry = ClientRegistry::load(directory.path()).expect("registry loads");
            assert!(matches!(
                check_profiles(&registry, Some(&claims), 1),
                Err(ServiceError::Registration(client, _)) if client == "client-a"
            ));
        }
    }

    #[test]
    fn standard_authorization_requires_one_exact_audience() {
        let directory = tempfile::tempdir().expect("temp dir");
        let public = crate::assertion::tests::test_key(1).1;
        std::fs::write(
            directory.path().join("client-a.yaml"),
            format!(
                "clientId: client-a\nprincipal: urn:example:client-a\nauthorization: {{scopes: [registry:read]}}\nkeys: [{public}]\n"
            ),
        )
        .expect("write scoped registration");
        let registry = ClientRegistry::load(directory.path()).expect("registry loads");

        assert!(check_profiles(&registry, None, 1).is_ok());
        for audience_count in [0, 2] {
            assert!(matches!(
                check_profiles(&registry, None, audience_count),
                Err(ServiceError::Registration(client, _)) if client == "client-a"
            ));
        }
    }

    #[test]
    fn standard_authorization_requires_a_relay_compatible_lifetime() {
        let directory = tempfile::tempdir().expect("temp dir");
        let public = crate::assertion::tests::test_key(1).1;
        std::fs::write(
            directory.path().join("client-a.yaml"),
            format!(
                "clientId: client-a\nprincipal: urn:example:client-a\nauthorization: {{scopes: [registry:read]}}\nkeys: [{public}]\n"
            ),
        )
        .expect("write scoped registration");
        let registry = ClientRegistry::load(directory.path()).expect("registry loads");

        assert!(check_profiles_with_lifetime(&registry, None, 1, 900).is_ok());
        assert!(matches!(
            check_profiles_with_lifetime(&registry, None, 1, 901),
            Err(ServiceError::Registration(client, _)) if client == "client-a"
        ));
    }

    #[test]
    fn standard_authorization_must_fit_the_shared_token_response_bound() {
        let directory = tempfile::tempdir().expect("temp dir");
        let public = crate::assertion::tests::test_key(1).1;
        let claims = (0..32)
            .map(|index| format!("    claim{index}: '{}'", "x".repeat(512)))
            .collect::<Vec<_>>()
            .join("\n");
        std::fs::write(
            directory.path().join("client-a.yaml"),
            format!(
                "clientId: client-a\nprincipal: urn:example:client-a\nauthorization:\n  scopes: [registry:read]\n  claims:\n{claims}\nkeys: [{public}]\n"
            ),
        )
        .expect("write oversized scoped registration");
        let registry = ClientRegistry::load(directory.path())
            .expect("per-field-valid standard authority loads");

        assert!(matches!(
            check_profiles(&registry, None, 1),
            Err(ServiceError::Registration(client, reason))
                if client == "client-a" && reason.contains("token-response bound")
        ));
    }

    #[test]
    fn metadata_describes_the_endpoints_a_client_needs() {
        let config = crate::config::tests::sample_config();
        let metadata = build_metadata(&config);
        assert_eq!(metadata["issuer"], json!("https://mint.example.org"));
        assert_eq!(
            metadata["token_endpoint"],
            json!("https://mint.example.org/token")
        );
        assert_eq!(
            metadata["jwks_uri"],
            json!("https://mint.example.org/.well-known/jwks.json")
        );
        assert_eq!(
            metadata["token_endpoint_auth_methods_supported"],
            json!([
                "private_key_jwt",
                "client_secret_basic",
                "client_secret_post"
            ])
        );
        assert_eq!(
            metadata["grant_types_supported"],
            json!(["client_credentials"])
        );
    }
}
