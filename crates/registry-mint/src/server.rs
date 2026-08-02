//! The Mint HTTP boundary.
//!
//! Four routes: the token endpoint, the published key set, authorization server
//! metadata, and the two liveness probes. Everything a caller sends is treated
//! as an unauthenticated claim about identity until the client assertion has
//! been verified against that client's own registered keys.
//!
//! The service holds two kinds of state with deliberately different lifetimes.
//! Issuer identity, signing keys, listener, and token policy are startup-only:
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
        header::{CACHE_CONTROL, CONTENT_TYPE, PRAGMA},
        HeaderMap, HeaderValue, Request, StatusCode,
    },
    middleware::{from_fn, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use serde_json::{json, Value};
use thiserror::Error;
use tokio::net::TcpListener;

use crate::{
    assertion::ClientAuthenticator,
    clients::{ClientRegistry, ClientRegistryError},
    config::MintConfig,
    error::TokenError,
    replay::ReplayCache,
    token::{MinterError, TokenMinter},
    CLIENT_ASSERTION_TYPE, GRANT_TYPE_CLIENT_CREDENTIALS,
};

const FORM_MEDIA_TYPE: &str = "application/x-www-form-urlencoded";
const JSON_MEDIA_TYPE: &str = "application/json";
const JWKS_MEDIA_TYPE: &str = "application/jwk-set+json";
const METADATA_PATH: &str = "/.well-known/oauth-authorization-server";
const TOKEN_PATH: &str = "/token";

#[derive(Debug, Error)]
pub enum ServiceError {
    #[error("the signing key could not be loaded: {0}")]
    Minter(#[from] MinterError),
    #[error("the client registry could not be loaded: {0}")]
    Registry(#[from] ClientRegistryError),
    #[error("client {0} cannot be served: {1}")]
    Delegation(String, &'static str),
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
    /// Load the signing key and the client registry described by `config`.
    pub fn load(config: MintConfig) -> Result<Self, ServiceError> {
        let minter = TokenMinter::new(&config)?;
        let registry = Arc::new(ClientRegistry::load(&config.clients.directory)?);
        check_delegations(&registry, minter.claims())?;
        let replay = Arc::new(ReplayCache::new(
            config.client_assertion.replay_cache_entries,
        ));
        let authenticator =
            ClientAuthenticator::new(registry, &config.client_assertion, Arc::clone(&replay));
        let metadata = build_metadata(&config);
        Ok(Self {
            config,
            minter,
            authenticator: RwLock::new(Arc::new(authenticator)),
            replay,
            metadata,
        })
    }

    /// Re-read the client registry directory and swap it in atomically.
    ///
    /// A failed reload leaves the previous registry in place: a malformed file
    /// dropped into the directory must not silently revoke every caller.
    pub fn reload_clients(&self) -> Result<usize, ServiceError> {
        let registry = Arc::new(ClientRegistry::load(&self.config.clients.directory)?);
        // Checked on every reload, not only at startup: a registration dropped
        // into the directory later must clear the same bar.
        check_delegations(&registry, self.minter.claims())?;
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
    async fn issue(&self, request: &TokenRequest, now: i64) -> Result<Response, TokenError> {
        if request.grant_type != GRANT_TYPE_CLIENT_CREDENTIALS {
            return Err(TokenError::unsupported_grant_type(
                "grant type is not supported",
            ));
        }
        if request.client_assertion_type != CLIENT_ASSERTION_TYPE {
            return Err(TokenError::invalid_request(
                "client assertion type is not supported",
            ));
        }

        // Cloned out of the lock so a concurrent reload cannot block here.
        let authenticator = self.authenticator();
        let authenticated = authenticator
            .authenticate(&request.client_assertion, now)
            .await?;
        let token = self.minter.mint(&authenticated, now).await?;

        serde_json::to_vec(&token)
            .map(|body| json_response(StatusCode::OK, JSON_MEDIA_TYPE, body))
            .map_err(|_| TokenError::server_error("the token response could not be serialized"))
    }
}

/// Refuse a registry whose delegations this configuration cannot express.
///
/// The registry and the claim-name configuration are loaded independently, so
/// this is the only place their agreement can be established. A disagreement
/// caught here is an operator error at startup or reload; caught at the first
/// token request instead, it would be an outage for one caller and a token
/// missing its actor for another.
fn check_delegations(
    registry: &ClientRegistry,
    claims: &crate::config::ClaimNames,
) -> Result<(), ServiceError> {
    // The claims Mint writes itself. A subject minted over one of these would
    // replace authority the registry, not the caller, is supposed to decide.
    let mut reserved = vec!["iss", "aud", "exp", "iat", "nbf", "jti", "client_id", "sub"];
    reserved.push(claims.principal.as_str());
    reserved.push(claims.requester_tags.as_str());
    reserved.push(claims.evidence_audience.as_str());
    reserved.push(claims.grant_id.as_str());
    reserved.push(claims.grant_authority.as_str());
    reserved.extend(claims.actor.as_deref());

    for client_id in registry.client_ids() {
        let client = registry
            .get(client_id)
            .expect("client id came from this registry");
        let Some(delegation) = client.delegation() else {
            continue;
        };
        if claims.actor.is_none() {
            return Err(ServiceError::Delegation(
                client_id.to_owned(),
                "it declares a delegation but no actor claim name is configured",
            ));
        }
        for path in delegation.subject_claims.values() {
            let root = path.split('.').next().unwrap_or(path);
            if reserved.contains(&root) {
                return Err(ServiceError::Delegation(
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
        "token_endpoint": format!("{issuer}{TOKEN_PATH}"),
        "jwks_uri": format!("{issuer}{}", config.signing.jwks_path),
        "grant_types_supported": [GRANT_TYPE_CLIENT_CREDENTIALS],
        "token_endpoint_auth_methods_supported": ["private_key_jwt"],
        "token_endpoint_auth_signing_alg_values_supported": algorithms,
        // Mint has no authorization endpoint: there is no user to redirect.
        "response_types_supported": [],
    })
}

/// The three parameters Mint reads from a token request.
///
/// RFC 6749 section 3.1 requires unrecognized parameters to be ignored and
/// forbids any parameter appearing more than once, so this is parsed by hand
/// rather than through a permissive form deserializer.
#[derive(Debug)]
struct TokenRequest {
    grant_type: String,
    client_assertion_type: String,
    client_assertion: String,
}

fn parse_token_request(body: &[u8]) -> Result<TokenRequest, TokenError> {
    let mut grant_type = None;
    let mut client_assertion_type = None;
    let mut client_assertion = None;

    for (name, value) in url::form_urlencoded::parse(body) {
        let slot = match name.as_ref() {
            "grant_type" => &mut grant_type,
            "client_assertion_type" => &mut client_assertion_type,
            "client_assertion" => &mut client_assertion,
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

    Ok(TokenRequest {
        grant_type: grant_type
            .ok_or_else(|| TokenError::invalid_request("grant_type is missing"))?,
        client_assertion_type: client_assertion_type
            .ok_or_else(|| TokenError::invalid_request("client_assertion_type is missing"))?,
        client_assertion: client_assertion
            .ok_or_else(|| TokenError::invalid_request("client_assertion is missing"))?,
    })
}

/// Build the router over an already loaded service.
pub fn build_app(service: Arc<MintService>) -> Router {
    let jwks_path = service.config.signing.jwks_path.clone();
    let routes = Router::new()
        .route(TOKEN_PATH, post(token))
        .route(&jwks_path, get(jwks))
        .route(METADATA_PATH, get(metadata))
        .route("/health", get(health))
        .route("/ready", get(ready))
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
    if !has_exact_content_type(request.headers(), FORM_MEDIA_TYPE) {
        return TokenError::invalid_request("content type must be form encoded").into_response();
    }

    let maximum_bytes = service.config.listener.maximum_request_bytes as usize;
    let timeout = Duration::from_millis(service.config.listener.request_timeout_milliseconds);
    let body =
        match tokio::time::timeout(timeout, to_bytes(request.into_body(), maximum_bytes)).await {
            Ok(Ok(body)) => body,
            Ok(Err(_)) => {
                return TokenError::invalid_request("the request body could not be read")
                    .into_response()
            }
            Err(_) => {
                return TokenError::invalid_request("the request body timed out").into_response();
            }
        };

    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let parsed = match parse_token_request(&body) {
        Ok(parsed) => parsed,
        Err(error) => return error.into_response(),
    };
    match service.issue(&parsed, now).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
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
    // A Mint with no registered clients is running but cannot serve anybody,
    // so it reports live but not ready rather than failing every request.
    if service.client_count() == 0 {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            JSON_MEDIA_TYPE,
            br#"{"status":"no clients registered"}"#.to_vec(),
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
        let error = parse_token_request(b"grant_type=a&grant_type=b")
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
        )
        .expect("unrecognized parameters must be ignored");
        assert_eq!(request.grant_type, "client_credentials");
        assert_eq!(request.client_assertion_type, "t");
        assert_eq!(request.client_assertion, "a");
    }

    #[test]
    fn each_required_parameter_is_required() {
        for body in [
            &b"client_assertion_type=t&client_assertion=a"[..],
            &b"grant_type=g&client_assertion=a"[..],
            &b"grant_type=g&client_assertion_type=t"[..],
        ] {
            let error =
                parse_token_request(body).expect_err("a missing parameter must be rejected");
            assert_eq!(error.code(), crate::error::TokenErrorCode::InvalidRequest);
        }
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
        crate::config::tests::sample_config().access_tokens.claims
    }

    const DELEGATION: &str = "delegation:\n  subjectClaims:\n    given_name: identity.given_name\n";

    /// The registry and the claim-name configuration are loaded independently,
    /// so a delegation with nowhere to mint its actor has to be caught here or
    /// not at all.
    #[test]
    fn a_delegation_without_a_configured_actor_claim_refuses_to_load() {
        let mut claims = claim_names();
        claims.actor = None;
        let error = check_delegations(&registry_with(DELEGATION), &claims)
            .expect_err("an unconfigured actor claim must refuse the registry");
        assert!(matches!(error, ServiceError::Delegation(client, _) if client == "client-a"));

        claims.actor = Some("evidence_actor".to_owned());
        assert!(check_delegations(&registry_with(DELEGATION), &claims).is_ok());
    }

    /// A subject path rooted at a claim Mint writes itself would let the caller
    /// choose authority the registry is supposed to decide.
    #[test]
    fn a_subject_path_rooted_at_an_authority_claim_refuses_to_load() {
        let mut claims = claim_names();
        claims.actor = Some("evidence_actor".to_owned());

        for root in [
            "iss",
            "sub",
            "jti",
            "client_id",
            claims.requester_tags.as_str(),
            claims.evidence_audience.as_str(),
            claims.grant_id.as_str(),
            claims.grant_authority.as_str(),
            "evidence_actor",
        ] {
            let registry = registry_with(&format!(
                "delegation:\n  subjectClaims:\n    given_name: {root}.given_name\n"
            ));
            assert!(
                check_delegations(&registry, &claims).is_err(),
                "a subject path rooted at {root} must be refused"
            );
        }
    }

    /// A registry with no delegations is unaffected by the actor claim either
    /// way, so an existing deployment does not have to configure one.
    #[test]
    fn an_undelegated_registry_loads_without_an_actor_claim() {
        let mut claims = claim_names();
        claims.actor = None;
        assert!(check_delegations(&registry_with(""), &claims).is_ok());
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
            json!(["private_key_jwt"])
        );
        assert_eq!(
            metadata["grant_types_supported"],
            json!(["client_credentials"])
        );
    }
}
