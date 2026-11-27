//! Token requests of a confidential web client that authenticates with a
//! client secret.
//!
//! This is the OAuth 2.0 authorization code flow of a relying party that keeps
//! its tokens on the server: it redeems a code with its PKCE verifier, renews
//! with the refresh grant, and revokes a refresh token at sign-out. The client
//! authenticates with the `client_secret_post` method of RFC 6749 section
//! 2.3.1: `client_id` and `client_secret` are form fields of the request body,
//! never part of a URL, a header, or a log line.
//!
//! It is plain OAuth and knows nothing about which authorization server it
//! talks to. It shares the destination checks, bounded reads, refusal decoding,
//! and credential types of the signed-assertion client in this module's
//! sibling, so a refusal reports the registered error code and nothing else,
//! and no credential reaches a `Debug` rendering or an error message.
//!
//! The client holds no tokens. Each call is one request, and what it returns
//! is moved to the caller, who owns storage and renewal.

use std::{
    fmt,
    time::{Duration, Instant},
};

use serde::{Deserialize, Deserializer};
use url::Url;
use zeroize::Zeroizing;

use crate::FetchUrlPolicy;

use super::{
    outbound::{
        self, base_url_without_userinfo, transport_protects_the_credential, OutboundOptions,
    },
    private_key_jwt::{present_value, valid_resource_uri, AUTHORIZATION_CODE_GRANT_TYPE},
    token::{BearerToken, TokenError, MAXIMUM_TOKEN_BYTES},
    token_endpoint::{self, Transport},
    DEFAULT_CONNECT_TIMEOUT, DEFAULT_REQUEST_TIMEOUT,
};

const REFRESH_TOKEN_GRANT_TYPE: &str = "refresh_token";
const REFRESH_TOKEN_TYPE_HINT: &str = "refresh_token";

/// A refresh token the authorization server issued.
///
/// It is bounded and header-safe like [`BearerToken`], wiped on drop, and
/// renders without its value. It has no `Display` and no `Serialize`: a caller
/// that stores it asks for the text explicitly with [`RefreshToken::expose`].
pub struct RefreshToken(Zeroizing<String>);

impl RefreshToken {
    /// Accept a refresh token of visible ASCII within the accepted length.
    /// The rejection carries no part of the value.
    ///
    /// # Errors
    /// [`TokenError::Invalid`] for an empty, overlong, or non-visible-ASCII
    /// value.
    pub fn new(value: impl Into<String>) -> Result<Self, TokenError> {
        let value = Zeroizing::new(value.into());
        if value.is_empty() || value.len() > MAXIMUM_TOKEN_BYTES {
            return Err(TokenError::Invalid {
                reason: "a refresh token must be non-empty and within the accepted length",
            });
        }
        if !value.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(TokenError::Invalid {
                reason: "a refresh token must contain only visible ASCII characters",
            });
        }
        Ok(Self(value))
    }

    /// The token text, for the one place that stores or presents it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Clone for RefreshToken {
    fn clone(&self) -> Self {
        Self(Zeroizing::new(self.0.as_str().to_owned()))
    }
}

impl fmt::Debug for RefreshToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RefreshToken")
            .finish_non_exhaustive()
    }
}

/// What a token request issued: the access token, when it stops being worth
/// presenting, and the refresh token and OpenID Connect ID token when the
/// issuer returned them.
///
/// The ID token is returned unverified. A caller that relies on it verifies it
/// (issuer, audience, nonce, expiry) before reading any claim.
///
/// A refresh answer carries the rotated refresh token, which the caller must
/// store. Hand everything over at once with [`IssuedTokens::into_parts`], so
/// the refresh token is named or explicitly discarded.
#[must_use = "a refresh answer carries the rotated refresh token"]
pub struct IssuedTokens {
    access_token: BearerToken,
    expires_at: Option<Instant>,
    lifetime_stated: bool,
    refresh_token: Option<RefreshToken>,
    id_token: Option<Zeroizing<String>>,
}

/// Every token of an [`IssuedTokens`], moved out together.
#[must_use = "a refresh answer carries the rotated refresh token"]
pub struct IssuedTokenParts {
    pub access_token: BearerToken,
    /// See [`IssuedTokens::expires_at`].
    pub expires_at: Option<Instant>,
    /// See [`IssuedTokens::lifetime_stated`].
    pub lifetime_stated: bool,
    pub refresh_token: Option<RefreshToken>,
    /// The unverified ID token.
    pub id_token: Option<Zeroizing<String>>,
}

impl fmt::Debug for IssuedTokenParts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedTokenParts")
            .field("expires_at", &self.expires_at)
            .field("lifetime_stated", &self.lifetime_stated)
            .field("has_refresh_token", &self.refresh_token.is_some())
            .field("has_id_token", &self.id_token.is_some())
            .finish_non_exhaustive()
    }
}

impl IssuedTokens {
    #[must_use]
    pub fn access_token(&self) -> &BearerToken {
        &self.access_token
    }

    /// Move every token out. Nothing is copied.
    pub fn into_parts(self) -> IssuedTokenParts {
        IssuedTokenParts {
            access_token: self.access_token,
            expires_at: self.expires_at,
            lifetime_stated: self.lifetime_stated,
            refresh_token: self.refresh_token,
            id_token: self.id_token,
        }
    }

    /// A monotonic deadline from the issuer's stated `expires_in`, clamped to
    /// [`MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS`](super::MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS).
    /// `None` when the issuer stated no usable lifetime: see
    /// [`IssuedTokens::lifetime_stated`] for the two reasons.
    #[must_use]
    pub fn expires_at(&self) -> Option<Instant> {
        self.expires_at
    }

    /// Whether the issuer stated a lifetime at all, whatever it was. An absent
    /// deadline beside `true` is an issuer calling the token already spent (a
    /// zero, negative, or null `expires_in`), and beside `false` it is an issuer
    /// saying nothing.
    #[must_use]
    pub fn lifetime_stated(&self) -> bool {
        self.lifetime_stated
    }

    #[must_use]
    pub fn refresh_token(&self) -> Option<&RefreshToken> {
        self.refresh_token.as_ref()
    }

    /// Move the refresh token out, leaving none behind.
    #[must_use]
    pub fn take_refresh_token(&mut self) -> Option<RefreshToken> {
        self.refresh_token.take()
    }

    /// The unverified ID token, if the issuer returned one.
    #[must_use]
    pub fn id_token(&self) -> Option<&str> {
        self.id_token.as_ref().map(|token| token.as_str())
    }

    /// Move the unverified ID token out, leaving none behind.
    #[must_use]
    pub fn take_id_token(&mut self) -> Option<Zeroizing<String>> {
        self.id_token.take()
    }
}

impl fmt::Debug for IssuedTokens {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IssuedTokens")
            .field("expires_at", &self.expires_at)
            .field("lifetime_stated", &self.lifetime_stated)
            .field("has_refresh_token", &self.refresh_token.is_some())
            .field("has_id_token", &self.id_token.is_some())
            .finish_non_exhaustive()
    }
}

/// What an integrator decides before the client can authenticate.
pub struct ClientSecretConfig {
    token_endpoint: Url,
    revocation_endpoint: Option<Url>,
    client_id: String,
    client_secret: Zeroizing<String>,
    request_timeout: Duration,
    connect_timeout: Duration,
    user_agent: Option<String>,
    trusted_root_certificates: Option<Zeroizing<Vec<u8>>>,
    fetch_url_policy: Option<FetchUrlPolicy>,
}

/// The refusal both endpoints share: a secret travels to each, so each must be
/// reached over https or over HTTP on a loopback host, with no credentials or
/// fragment in its URL.
fn check_endpoint(endpoint: &Url) -> Result<(), TokenError> {
    let refuse = |reason: &'static str| TokenError::Configuration { reason };
    if !endpoint.username().is_empty()
        || endpoint.password().is_some()
        || endpoint.fragment().is_some()
    {
        return Err(refuse("an endpoint must carry no credentials or fragment"));
    }
    if !transport_protects_the_credential(endpoint) {
        return Err(refuse(
            "an endpoint must use HTTPS, or HTTP with a loopback host",
        ));
    }
    Ok(())
}

impl ClientSecretConfig {
    /// Authenticate as `client_id` at `token_endpoint` with `client_secret`.
    ///
    /// # Errors
    /// [`TokenError::Configuration`] for an empty client identifier or secret,
    /// or an endpoint that is not https (or http on a loopback host) or that
    /// carries credentials or a fragment.
    pub fn new(
        token_endpoint: Url,
        client_id: impl Into<String>,
        client_secret: Zeroizing<String>,
    ) -> Result<Self, TokenError> {
        let client_id = client_id.into();
        if client_id.trim().is_empty() {
            return Err(TokenError::Configuration {
                reason: "the client identifier must not be empty",
            });
        }
        if client_secret.is_empty() {
            return Err(TokenError::Configuration {
                reason: "the client secret must not be empty",
            });
        }
        check_endpoint(&token_endpoint)?;
        Ok(Self {
            token_endpoint,
            revocation_endpoint: None,
            client_id,
            client_secret,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            user_agent: None,
            trusted_root_certificates: None,
            fetch_url_policy: None,
        })
    }

    /// State the RFC 7009 revocation endpoint. Without one,
    /// [`ClientSecretClient::revoke_refresh_token`] is a configuration error.
    ///
    /// # Errors
    /// [`TokenError::Configuration`] under the same endpoint rules as the
    /// token endpoint.
    pub fn with_revocation_endpoint(mut self, endpoint: Url) -> Result<Self, TokenError> {
        check_endpoint(&endpoint)?;
        self.revocation_endpoint = Some(endpoint);
        Ok(self)
    }

    #[must_use]
    pub fn with_request_timeout(mut self, timeout: Duration) -> Self {
        self.request_timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_user_agent(mut self, user_agent: impl Into<String>) -> Self {
        self.user_agent = Some(user_agent.into());
        self
    }

    /// Trust exactly these PEM roots. They replace the platform's roots rather
    /// than adding to them, so an endpoint with a publicly issued certificate
    /// is no longer reachable through this client.
    #[must_use]
    pub fn with_trusted_root_certificates(mut self, pem_bundle: impl Into<Vec<u8>>) -> Self {
        self.trusted_root_certificates = Some(Zeroizing::new(pem_bundle.into()));
        self
    }

    /// Resolve and pin each endpoint through this policy before every request.
    #[must_use]
    pub fn with_fetch_url_policy(mut self, policy: FetchUrlPolicy) -> Self {
        self.fetch_url_policy = Some(policy);
        self
    }
}

impl fmt::Debug for ClientSecretConfig {
    /// The secret and the trusted roots are withheld.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientSecretConfig")
            .field(
                "token_endpoint",
                &base_url_without_userinfo(&self.token_endpoint),
            )
            .field(
                "revocation_endpoint",
                &self
                    .revocation_endpoint
                    .as_ref()
                    .map(|endpoint| base_url_without_userinfo(endpoint).into_owned()),
            )
            .field("client_id", &self.client_id)
            .field("uses_dns_pinned_fetch", &self.fetch_url_policy.is_some())
            .finish_non_exhaustive()
    }
}

/// A confidential client that redeems, renews, and revokes with a client
/// secret.
pub struct ClientSecretClient {
    http: reqwest::Client,
    config: ClientSecretConfig,
}

impl ClientSecretClient {
    /// # Errors
    /// [`TokenError::Configuration`] for a zero timeout or an outbound client
    /// that cannot be built from the stated options.
    pub fn new(config: ClientSecretConfig) -> Result<Self, TokenError> {
        let refuse = |reason: &'static str| TokenError::Configuration { reason };
        if config.request_timeout.is_zero() || config.connect_timeout.is_zero() {
            return Err(refuse("the timeouts must be greater than zero"));
        }
        let http = outbound::build_client(OutboundOptions {
            request_timeout: config.request_timeout,
            connect_timeout: config.connect_timeout,
            user_agent: config.user_agent.as_deref(),
            trusted_root_certificates: config
                .trusted_root_certificates
                .as_ref()
                .map(|pem| pem.as_slice()),
        })
        .map_err(refuse)?;
        Ok(Self { http, config })
    }

    /// Redeem an authorization code with its PKCE `code_verifier` and the
    /// `redirect_uri` the authorization request named. `resource` is the
    /// RFC 8707 resource indicator, when the request names one.
    ///
    /// Malformed inputs are refused before any request is made.
    ///
    /// # Errors
    /// [`TokenError::Invalid`] for malformed inputs, [`TokenError::Refused`]
    /// with the registered code when the server declines (`invalid_grant` for
    /// a spent or unknown code), [`TokenError::Transport`] when the exchange
    /// does not complete, and [`TokenError::Protocol`] for an answer that is
    /// not a token response.
    pub async fn redeem_authorization_code(
        &self,
        code: &str,
        redirect_uri: &Url,
        code_verifier: &str,
        resource: Option<&str>,
    ) -> Result<IssuedTokens, TokenError> {
        token_endpoint::check_redemption_inputs(code, redirect_uri, code_verifier)?;
        check_resource(resource)?;
        let body = self.form(|form| {
            form.append_pair("grant_type", AUTHORIZATION_CODE_GRANT_TYPE);
            form.append_pair("code", code);
            form.append_pair("redirect_uri", redirect_uri.as_str());
            form.append_pair("code_verifier", code_verifier);
            if let Some(resource) = resource {
                form.append_pair("resource", resource);
            }
        });
        self.issue(body).await
    }

    /// Renew with the refresh grant. `resource` is the RFC 8707 resource
    /// indicator, when the original request named one.
    ///
    /// # Errors
    /// As [`Self::redeem_authorization_code`]; a refresh token the server no
    /// longer accepts is `Refused` with `InvalidGrant`.
    ///
    /// The issuer may rotate the refresh token: the caller must store the one
    /// in the answer, because the presented one is spent. An answer with no
    /// refresh token means the issuer did not rotate, so keep presenting the
    /// one you sent (RFC 6749 section 6). Dropping the answer without taking
    /// its refresh token loses the session at the next renewal, and an issuer
    /// that treats reuse as theft records one.
    pub async fn refresh(
        &self,
        refresh_token: &RefreshToken,
        resource: Option<&str>,
    ) -> Result<IssuedTokens, TokenError> {
        check_resource(resource)?;
        let body = self.form(|form| {
            form.append_pair("grant_type", REFRESH_TOKEN_GRANT_TYPE);
            form.append_pair("refresh_token", refresh_token.expose());
            if let Some(resource) = resource {
                form.append_pair("resource", resource);
            }
        });
        self.issue(body).await
    }

    /// Revoke a refresh token (RFC 7009, `token_type_hint=refresh_token`). A
    /// 200 answer is success whatever its body.
    ///
    /// # Errors
    /// [`TokenError::Configuration`] when no revocation endpoint is
    /// configured, otherwise as [`Self::redeem_authorization_code`].
    pub async fn revoke_refresh_token(
        &self,
        refresh_token: &RefreshToken,
    ) -> Result<(), TokenError> {
        let endpoint =
            self.config
                .revocation_endpoint
                .as_ref()
                .ok_or(TokenError::Configuration {
                    reason: "no revocation endpoint is configured",
                })?;
        // The token fields lead and the client credentials follow, which is the
        // order RFC 7009 section 2.1 lists its own parameters in.
        let body = self.form(|form| {
            form.append_pair("token", refresh_token.expose());
            form.append_pair("token_type_hint", REFRESH_TOKEN_TYPE_HINT);
        });
        let answer = self.post(endpoint, body).await?;
        // RFC 7009 section 2.2: the server answers 200 whether or not the
        // token was known, so the body carries nothing to act on and is never
        // read.
        if answer.status == 200 {
            return Ok(());
        }
        Err(answer.into_refusal())
    }

    /// The form of one token request: the grant's own fields, then the client
    /// credentials the `client_secret_post` method places in the body.
    ///
    /// The serializer's buffer grows by reallocation and leaves partial copies
    /// in freed memory, so it starts large enough for any request this client
    /// builds from bounded inputs short of a pathological one.
    fn form(
        &self,
        grant_fields: impl FnOnce(&mut url::form_urlencoded::Serializer<'_, String>),
    ) -> Zeroizing<String> {
        let mut form = url::form_urlencoded::Serializer::new(String::with_capacity(4096));
        grant_fields(&mut form);
        form.append_pair("client_id", &self.config.client_id);
        form.append_pair("client_secret", &self.config.client_secret);
        Zeroizing::new(form.finish())
    }

    /// Post a token request body and read the answer as a token response.
    async fn issue(&self, body: Zeroizing<String>) -> Result<IssuedTokens, TokenError> {
        let answer = self.post(&self.config.token_endpoint, body).await?;
        let status = answer.status;
        let issued: IssuedToken = answer.into_token_response()?;
        token_endpoint::require_bearer(&issued.token_type, status)?;
        let (lifetime_stated, expires_at) =
            token_endpoint::lifetime_deadline(issued.expires_in, Instant::now());
        // A token the server sent that this client cannot use is the server's
        // fault, not the caller's input, so it is a protocol failure.
        let unusable = |_: TokenError| TokenError::Protocol { status };
        Ok(IssuedTokens {
            // Moved rather than copied, so each credential ends up in the
            // buffer its type wipes on drop.
            access_token: BearerToken::new(issued.access_token.into_inner()).map_err(unusable)?,
            expires_at,
            lifetime_stated,
            refresh_token: issued
                .refresh_token
                .map(|token| RefreshToken::new(token.into_inner()))
                .transpose()
                .map_err(unusable)?,
            id_token: issued.id_token.map(WipedString::into_zeroizing),
        })
    }

    async fn post(
        &self,
        endpoint: &Url,
        body: Zeroizing<String>,
    ) -> Result<token_endpoint::Answer, TokenError> {
        token_endpoint::post_form(
            Transport {
                http: &self.http,
                fetch_url_policy: self.config.fetch_url_policy.as_ref(),
                request_timeout: self.config.request_timeout,
                connect_timeout: self.config.connect_timeout,
                user_agent: self.config.user_agent.as_deref(),
                trusted_root_certificates: self
                    .config
                    .trusted_root_certificates
                    .as_deref()
                    .map(|value| value.as_slice()),
            },
            endpoint,
            body,
        )
        .await
    }
}

/// A string member of a response that is wiped when dropped, so a token this
/// client rejects on any path is not left behind in freed memory. The JSON
/// reader's own scratch buffer for escaped strings is out of reach.
struct WipedString(Zeroizing<String>);

impl WipedString {
    fn into_inner(mut self) -> String {
        std::mem::take(&mut *self.0)
    }

    fn into_zeroizing(self) -> Zeroizing<String> {
        self.0
    }
}

impl<'de> Deserialize<'de> for WipedString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|value| Self(Zeroizing::new(value)))
    }
}

/// The success response of RFC 6749 section 5.1, in the members this client
/// uses.
#[derive(Deserialize)]
struct IssuedToken {
    access_token: WipedString,
    token_type: String,
    /// Member presence outside, stated value inside, so a stated `null` is
    /// kept apart from silence.
    #[serde(default, deserialize_with = "present_value")]
    expires_in: Option<Option<i64>>,
    refresh_token: Option<WipedString>,
    id_token: Option<WipedString>,
}

fn check_resource(resource: Option<&str>) -> Result<(), TokenError> {
    if resource.is_some_and(|value| !valid_resource_uri(value)) {
        return Err(TokenError::Invalid {
            reason: "the resource must be one absolute URI without a fragment or userinfo",
        });
    }
    Ok(())
}

impl fmt::Debug for ClientSecretClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClientSecretClient")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::*;
    use crate::client::{
        private_key_jwt::{
            MAXIMUM_AUTHORIZATION_CODE_BYTES, MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS,
            MAXIMUM_TOKEN_RESPONSE_BYTES,
        },
        OAuthErrorCode,
    };

    const CLIENT_ID: &str = "web-client";
    const SECRET_SENTINEL: &str = "secret-sentinel-0f3a";
    const ACCESS_SENTINEL: &str = "access-sentinel-91bc";
    const REFRESH_SENTINEL: &str = "refresh-sentinel-77de";
    const ID_SENTINEL: &str = "id-sentinel-5a10";
    const NEW_REFRESH_SENTINEL: &str = "rotated-refresh-sentinel-23c4";
    const REDIRECT_URI: &str = "https://app.example.org/callback";
    const VERIFIER: &str = "verifier-0123456789-0123456789-0123456789-0123456789";
    const RESOURCE: &str = "https://api.example.org/";

    fn secret() -> Zeroizing<String> {
        Zeroizing::new(SECRET_SENTINEL.to_owned())
    }

    fn redirect_uri() -> Url {
        Url::parse(REDIRECT_URI).expect("the redirect URI parses")
    }

    fn client_for(server: &MockServer) -> ClientSecretClient {
        let base = Url::parse(&server.uri()).expect("the mock server URI parses");
        let config = ClientSecretConfig::new(base.join("token").unwrap(), CLIENT_ID, secret())
            .expect("the token endpoint is loopback http")
            .with_revocation_endpoint(base.join("revoke").unwrap())
            .expect("the revocation endpoint is loopback http");
        ClientSecretClient::new(config).expect("the client is usable as configured")
    }

    async fn serving(route: &str, response: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(route))
            .respond_with(response)
            .mount(&server)
            .await;
        server
    }

    fn issued(body: serde_json::Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(body)
    }

    /// The query and the form fields of the one request the server saw.
    async fn only_request(server: &MockServer) -> (Option<String>, Vec<(String, String)>) {
        let requests = server
            .received_requests()
            .await
            .expect("the mock server records its requests");
        assert_eq!(requests.len(), 1);
        let body = String::from_utf8(requests[0].body.clone()).expect("form-encoded ASCII");
        let form = url::form_urlencoded::parse(body.as_bytes())
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        (requests[0].url.query().map(str::to_owned), form)
    }

    /// The secret travels in the form body alone: no `Authorization` header
    /// (the `client_secret_basic` method) and no header value carrying it.
    async fn assert_secret_only_in_the_body(server: &MockServer) {
        let requests = server
            .received_requests()
            .await
            .expect("the mock server records its requests");
        for request in &requests {
            assert!(request.headers.get("authorization").is_none());
            for (_, value) in request.headers.iter() {
                assert!(!value
                    .as_bytes()
                    .windows(SECRET_SENTINEL.len())
                    .any(|w| w == SECRET_SENTINEL.as_bytes()));
            }
        }
    }

    fn field<'a>(form: &'a [(String, String)], name: &str) -> Option<&'a str> {
        form.iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    }

    /// The field names in sorted order: a form is a set of fields, and the
    /// order they are written in carries no meaning.
    fn names(form: &[(String, String)]) -> Vec<&str> {
        let mut names: Vec<&str> = form.iter().map(|(name, _)| name.as_str()).collect();
        names.sort_unstable();
        names
    }

    #[tokio::test]
    async fn a_code_is_redeemed_with_the_secret_in_the_body_only() {
        let server = serving(
            "/token",
            issued(json!({
                "access_token": ACCESS_SENTINEL,
                "token_type": "Bearer",
                "expires_in": 300,
                "refresh_token": REFRESH_SENTINEL,
                "id_token": ID_SENTINEL,
            })),
        )
        .await;

        let mut tokens = client_for(&server)
            .redeem_authorization_code("synthetic-code", &redirect_uri(), VERIFIER, Some(RESOURCE))
            .await
            .expect("the code is redeemed");

        assert!(tokens.expires_at().is_some());
        assert_eq!(tokens.id_token(), Some(ID_SENTINEL));
        assert_eq!(
            tokens
                .take_refresh_token()
                .expect("a refresh token")
                .expose(),
            REFRESH_SENTINEL
        );
        assert!(tokens.refresh_token().is_none());
        assert_eq!(
            tokens.take_id_token().expect("an ID token").as_str(),
            ID_SENTINEL
        );
        assert!(tokens.id_token().is_none());
        assert_eq!(
            tokens
                .into_parts()
                .access_token
                .authorization_header_value()
                .to_str()
                .unwrap(),
            format!("Bearer {ACCESS_SENTINEL}")
        );
        let (query, form) = only_request(&server).await;
        assert_eq!(query, None);
        assert_secret_only_in_the_body(&server).await;
        assert_eq!(
            names(&form),
            [
                "client_id",
                "client_secret",
                "code",
                "code_verifier",
                "grant_type",
                "redirect_uri",
                "resource"
            ]
        );
        assert_eq!(field(&form, "grant_type"), Some("authorization_code"));
        assert_eq!(field(&form, "client_id"), Some(CLIENT_ID));
        assert_eq!(field(&form, "client_secret"), Some(SECRET_SENTINEL));
        assert_eq!(field(&form, "code"), Some("synthetic-code"));
        assert_eq!(field(&form, "redirect_uri"), Some(REDIRECT_URI));
        assert_eq!(field(&form, "code_verifier"), Some(VERIFIER));
        assert_eq!(field(&form, "resource"), Some(RESOURCE));
    }

    #[tokio::test]
    async fn a_redemption_without_a_resource_sends_none() {
        let server = serving(
            "/token",
            issued(json!({"access_token": ACCESS_SENTINEL, "token_type": "bearer"})),
        )
        .await;

        let _tokens = client_for(&server)
            .redeem_authorization_code("synthetic-code", &redirect_uri(), VERIFIER, None)
            .await
            .expect("the code is redeemed");

        let (_, form) = only_request(&server).await;
        assert_eq!(field(&form, "resource"), None);
    }

    #[tokio::test]
    async fn a_response_without_refresh_or_id_token_or_lifetime_states_none() {
        let server = serving(
            "/token",
            issued(json!({"access_token": ACCESS_SENTINEL, "token_type": "Bearer"})),
        )
        .await;

        let tokens = client_for(&server)
            .redeem_authorization_code("synthetic-code", &redirect_uri(), VERIFIER, None)
            .await
            .expect("the code is redeemed");

        assert!(tokens.refresh_token().is_none());
        assert!(tokens.id_token().is_none());
        assert!(tokens.expires_at().is_none());
    }

    #[tokio::test]
    async fn an_issuer_lifetime_beyond_the_trusted_maximum_is_clamped() {
        let server = serving(
            "/token",
            issued(json!({
                "access_token": ACCESS_SENTINEL,
                "token_type": "Bearer",
                "expires_in": 10_000_000_000_i64,
            })),
        )
        .await;
        let before = Instant::now();

        let tokens = client_for(&server)
            .redeem_authorization_code("synthetic-code", &redirect_uri(), VERIFIER, None)
            .await
            .expect("the code is redeemed");

        let deadline = tokens.expires_at().expect("a stated lifetime");
        let ceiling = Duration::from_secs(MAXIMUM_CACHED_TOKEN_LIFETIME_SECONDS.unsigned_abs());
        assert!(deadline.duration_since(before) <= ceiling + Duration::from_secs(5));
    }

    #[tokio::test]
    async fn the_refresh_grant_sends_the_token_and_the_secret_in_the_body() {
        let server = serving(
            "/token",
            issued(json!({
                "access_token": ACCESS_SENTINEL,
                "token_type": "Bearer",
                "expires_in": 300,
                "refresh_token": NEW_REFRESH_SENTINEL,
            })),
        )
        .await;
        let presented = RefreshToken::new(REFRESH_SENTINEL).unwrap();

        let mut tokens = client_for(&server)
            .refresh(&presented, Some(RESOURCE))
            .await
            .expect("the refresh succeeds");

        assert_eq!(
            tokens.take_refresh_token().unwrap().expose(),
            NEW_REFRESH_SENTINEL
        );
        let (query, form) = only_request(&server).await;
        assert_eq!(query, None);
        assert_secret_only_in_the_body(&server).await;
        assert_eq!(
            names(&form),
            [
                "client_id",
                "client_secret",
                "grant_type",
                "refresh_token",
                "resource"
            ]
        );
        assert_eq!(field(&form, "grant_type"), Some("refresh_token"));
        assert_eq!(field(&form, "client_id"), Some(CLIENT_ID));
        assert_eq!(field(&form, "client_secret"), Some(SECRET_SENTINEL));
        assert_eq!(field(&form, "refresh_token"), Some(REFRESH_SENTINEL));
        assert_eq!(field(&form, "resource"), Some(RESOURCE));
    }

    #[tokio::test]
    async fn a_refused_refresh_reports_invalid_grant_and_nothing_else() {
        let server = serving(
            "/token",
            ResponseTemplate::new(400).set_body_json(json!({
                "error": "invalid_grant",
                "error_description": "canary-description",
            })),
        )
        .await;

        let error = client_for(&server)
            .refresh(&RefreshToken::new(REFRESH_SENTINEL).unwrap(), None)
            .await
            .expect_err("the refresh is refused");

        assert_eq!(
            error,
            TokenError::Refused {
                code: OAuthErrorCode::InvalidGrant
            }
        );
        assert!(!error.to_string().contains("canary"));
    }

    #[tokio::test]
    async fn an_oversized_response_is_refused() {
        let padding = "a".repeat(usize::try_from(MAXIMUM_TOKEN_RESPONSE_BYTES).unwrap() + 1);
        let server = serving(
            "/token",
            issued(json!({
                "access_token": ACCESS_SENTINEL,
                "token_type": "Bearer",
                "padding": padding,
            })),
        )
        .await;

        let error = client_for(&server)
            .redeem_authorization_code("synthetic-code", &redirect_uri(), VERIFIER, None)
            .await
            .expect_err("the oversized body is refused");

        assert!(
            matches!(
                error,
                TokenError::Transport {
                    kind: crate::client::TransportKind::ResponseTooLarge
                }
            ),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn a_body_that_is_not_json_is_a_protocol_failure() {
        let server = serving(
            "/token",
            ResponseTemplate::new(200)
                .insert_header("content-type", "application/json")
                .set_body_string("<html>not json</html>"),
        )
        .await;

        let error = client_for(&server)
            .refresh(&RefreshToken::new(REFRESH_SENTINEL).unwrap(), None)
            .await
            .expect_err("the body is not a token response");

        assert_eq!(error, TokenError::Protocol { status: 200 });
    }

    #[tokio::test]
    async fn a_token_type_other_than_bearer_is_a_protocol_failure() {
        let server = serving(
            "/token",
            issued(json!({"access_token": ACCESS_SENTINEL, "token_type": "mac"})),
        )
        .await;

        let error = client_for(&server)
            .refresh(&RefreshToken::new(REFRESH_SENTINEL).unwrap(), None)
            .await
            .expect_err("only bearer tokens are usable");

        assert_eq!(error, TokenError::Protocol { status: 200 });
    }

    #[tokio::test]
    async fn an_unreachable_server_is_a_transport_failure() {
        // A port that was bound a moment ago and is now closed.
        let closed = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        let address = closed.local_addr().expect("the bound address");
        drop(closed);
        let config = ClientSecretConfig::new(
            Url::parse(&format!("http://{address}/token")).unwrap(),
            CLIENT_ID,
            secret(),
        )
        .unwrap();
        let client = ClientSecretClient::new(config).unwrap();

        let error = client
            .refresh(&RefreshToken::new(REFRESH_SENTINEL).unwrap(), None)
            .await
            .expect_err("nothing is listening");

        assert!(matches!(error, TokenError::Transport { .. }), "{error:?}");
    }

    #[tokio::test]
    async fn malformed_redemption_inputs_are_refused_before_any_request() {
        let server = serving(
            "/token",
            issued(json!({"access_token": ACCESS_SENTINEL, "token_type": "Bearer"})),
        )
        .await;
        let client = client_for(&server);
        let long_code = "c".repeat(MAXIMUM_AUTHORIZATION_CODE_BYTES + 1);
        for (code, verifier, resource) in [
            ("", VERIFIER, None),
            ("code\r\ncanary", VERIFIER, None),
            (long_code.as_str(), VERIFIER, None),
            ("synthetic-code", "too-short-canary", None),
            ("synthetic-code", VERIFIER, Some("not a uri canary")),
        ] {
            let error = client
                .redeem_authorization_code(code, &redirect_uri(), verifier, resource)
                .await
                .expect_err("the malformed input is refused");
            assert!(matches!(error, TokenError::Invalid { .. }), "{error:?}");
            assert!(!error.to_string().contains("canary"));
        }
        let with_fragment = Url::parse("https://app.example.org/callback#canary").unwrap();
        let error = client
            .redeem_authorization_code("synthetic-code", &with_fragment, VERIFIER, None)
            .await
            .expect_err("a redirect URI with a fragment is refused");
        assert!(matches!(error, TokenError::Invalid { .. }));
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn revocation_sends_the_token_and_its_type_hint_with_the_secret_in_the_body() {
        let server = serving("/revoke", ResponseTemplate::new(200)).await;

        client_for(&server)
            .revoke_refresh_token(&RefreshToken::new(REFRESH_SENTINEL).unwrap())
            .await
            .expect("the revocation succeeds");

        let (query, form) = only_request(&server).await;
        assert_eq!(query, None);
        assert_secret_only_in_the_body(&server).await;
        assert_eq!(
            names(&form),
            ["client_id", "client_secret", "token", "token_type_hint"]
        );
        assert_eq!(field(&form, "token"), Some(REFRESH_SENTINEL));
        assert_eq!(field(&form, "token_type_hint"), Some("refresh_token"));
        assert_eq!(field(&form, "client_id"), Some(CLIENT_ID));
        assert_eq!(field(&form, "client_secret"), Some(SECRET_SENTINEL));
    }

    #[tokio::test]
    async fn a_200_revocation_succeeds_whatever_the_body() {
        let server = serving(
            "/revoke",
            ResponseTemplate::new(200).set_body_string("anything at all"),
        )
        .await;

        client_for(&server)
            .revoke_refresh_token(&RefreshToken::new(REFRESH_SENTINEL).unwrap())
            .await
            .expect("a 200 is success");
    }

    #[tokio::test]
    async fn a_refused_revocation_reports_the_registered_code() {
        let server = serving(
            "/revoke",
            ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_client"})),
        )
        .await;

        let error = client_for(&server)
            .revoke_refresh_token(&RefreshToken::new(REFRESH_SENTINEL).unwrap())
            .await
            .expect_err("the revocation is refused");

        assert_eq!(
            error,
            TokenError::Refused {
                code: OAuthErrorCode::InvalidClient
            }
        );
    }

    #[tokio::test]
    async fn revocation_without_an_endpoint_is_a_configuration_error() {
        let config = ClientSecretConfig::new(
            Url::parse("https://issuer.example.org/token").unwrap(),
            CLIENT_ID,
            secret(),
        )
        .unwrap();
        let client = ClientSecretClient::new(config).unwrap();

        let error = client
            .revoke_refresh_token(&RefreshToken::new(REFRESH_SENTINEL).unwrap())
            .await
            .expect_err("no revocation endpoint is configured");

        assert!(
            matches!(error, TokenError::Configuration { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn plain_http_to_a_non_loopback_host_is_refused_at_construction() {
        let refused = ClientSecretConfig::new(
            Url::parse("http://issuer.example.org/token").unwrap(),
            CLIENT_ID,
            secret(),
        )
        .expect_err("cleartext off the host is refused");
        assert!(matches!(refused, TokenError::Configuration { .. }));

        let config = ClientSecretConfig::new(
            Url::parse("https://issuer.example.org/token").unwrap(),
            CLIENT_ID,
            secret(),
        )
        .unwrap();
        let refused = config
            .with_revocation_endpoint(Url::parse("http://issuer.example.org/revoke").unwrap())
            .expect_err("the revocation endpoint is held to the same rule");
        assert!(matches!(refused, TokenError::Configuration { .. }));

        ClientSecretConfig::new(
            Url::parse("http://127.0.0.1:9/token").unwrap(),
            CLIENT_ID,
            secret(),
        )
        .expect("loopback http is accepted");
    }

    #[test]
    fn endpoints_with_credentials_or_a_fragment_and_empty_identities_are_refused() {
        for endpoint in [
            "https://user:pass@issuer.example.org/token",
            "https://issuer.example.org/token#fragment",
        ] {
            let result =
                ClientSecretConfig::new(Url::parse(endpoint).unwrap(), CLIENT_ID, secret());
            assert!(
                matches!(result, Err(TokenError::Configuration { .. })),
                "{endpoint}"
            );
        }
        let token = Url::parse("https://issuer.example.org/token").unwrap();
        assert!(ClientSecretConfig::new(token.clone(), " ", secret()).is_err());
        assert!(ClientSecretConfig::new(token, CLIENT_ID, Zeroizing::new(String::new())).is_err());
    }

    #[test]
    fn a_zero_timeout_is_refused_when_the_client_is_built() {
        let config = ClientSecretConfig::new(
            Url::parse("https://issuer.example.org/token").unwrap(),
            CLIENT_ID,
            secret(),
        )
        .unwrap()
        .with_request_timeout(Duration::ZERO);
        assert!(matches!(
            ClientSecretClient::new(config),
            Err(TokenError::Configuration { .. })
        ));
    }

    #[test]
    fn a_refresh_token_must_be_bounded_visible_ascii() {
        assert!(RefreshToken::new("").is_err());
        assert!(RefreshToken::new("has space").is_err());
        assert!(RefreshToken::new("a".repeat(MAXIMUM_TOKEN_BYTES + 1)).is_err());
        assert!(RefreshToken::new("a".repeat(MAXIMUM_TOKEN_BYTES)).is_ok());
    }

    #[tokio::test]
    async fn debug_renderings_never_contain_a_secret_or_a_token() {
        let server = serving(
            "/token",
            issued(json!({
                "access_token": ACCESS_SENTINEL,
                "token_type": "Bearer",
                "expires_in": 300,
                "refresh_token": REFRESH_SENTINEL,
                "id_token": ID_SENTINEL,
            })),
        )
        .await;
        let base = Url::parse(&server.uri()).unwrap();
        let config =
            ClientSecretConfig::new(base.join("token").unwrap(), CLIENT_ID, secret()).unwrap();
        let rendered_config = format!("{config:?}");
        let client = ClientSecretClient::new(config).unwrap();
        let tokens = client
            .redeem_authorization_code("synthetic-code", &redirect_uri(), VERIFIER, None)
            .await
            .unwrap();
        let refresh = RefreshToken::new(REFRESH_SENTINEL).unwrap();

        for rendered in [
            rendered_config,
            format!("{client:?}"),
            format!("{tokens:?}"),
            format!("{:?}", tokens.access_token()),
            format!("{refresh:?}"),
            format!("{:#?}", tokens),
        ] {
            for sentinel in [
                SECRET_SENTINEL,
                ACCESS_SENTINEL,
                REFRESH_SENTINEL,
                ID_SENTINEL,
            ] {
                assert!(!rendered.contains(sentinel), "{rendered}");
            }
        }
    }

    fn assert_send<T: Send>(_: &T) {}

    #[test]
    fn every_public_future_is_send() {
        let config = ClientSecretConfig::new(
            Url::parse("https://issuer.example.org/token").unwrap(),
            CLIENT_ID,
            secret(),
        )
        .unwrap()
        .with_revocation_endpoint(Url::parse("https://issuer.example.org/revoke").unwrap())
        .unwrap();
        let client = ClientSecretClient::new(config).unwrap();
        let refresh = RefreshToken::new(REFRESH_SENTINEL).unwrap();
        let redirect = redirect_uri();

        assert_send(&client.redeem_authorization_code("code", &redirect, VERIFIER, None));
        assert_send(&client.refresh(&refresh, None));
        assert_send(&client.revoke_refresh_token(&refresh));
    }

    #[tokio::test]
    async fn a_refresh_answer_without_a_new_refresh_token_names_none() {
        let server = serving(
            "/token",
            issued(
                json!({"access_token": ACCESS_SENTINEL, "token_type": "Bearer", "expires_in": 60}),
            ),
        )
        .await;

        let parts = client_for(&server)
            .refresh(&RefreshToken::new(REFRESH_SENTINEL).unwrap(), None)
            .await
            .expect("the refresh succeeds")
            .into_parts();

        assert!(parts.refresh_token.is_none());
        assert!(parts.expires_at.is_some());
        assert!(parts.lifetime_stated);
    }

    #[tokio::test]
    async fn into_parts_hands_back_every_token_at_once() {
        let server = serving(
            "/token",
            issued(json!({
                "access_token": ACCESS_SENTINEL,
                "token_type": "Bearer",
                "expires_in": 60,
                "refresh_token": NEW_REFRESH_SENTINEL,
                "id_token": ID_SENTINEL,
            })),
        )
        .await;

        let parts = client_for(&server)
            .refresh(&RefreshToken::new(REFRESH_SENTINEL).unwrap(), None)
            .await
            .expect("the refresh succeeds")
            .into_parts();

        assert_eq!(parts.refresh_token.unwrap().expose(), NEW_REFRESH_SENTINEL);
        assert_eq!(parts.id_token.unwrap().as_str(), ID_SENTINEL);
        let rendered = format!("{:?}", parts.access_token);
        assert!(!rendered.contains(ACCESS_SENTINEL));
    }

    #[tokio::test]
    async fn a_lifetime_that_is_not_positive_leaves_no_deadline_but_is_stated() {
        for expires_in in [
            json!(0),
            json!(-3600),
            json!(i64::MIN),
            serde_json::Value::Null,
        ] {
            let server = serving(
                "/token",
                issued(json!({
                    "access_token": ACCESS_SENTINEL,
                    "token_type": "Bearer",
                    "expires_in": expires_in,
                })),
            )
            .await;

            let tokens = client_for(&server)
                .refresh(&RefreshToken::new(REFRESH_SENTINEL).unwrap(), None)
                .await
                .expect("the answer is a token response");

            assert!(tokens.expires_at().is_none(), "{expires_in}");
            assert!(tokens.lifetime_stated(), "{expires_in}");
        }
    }

    #[tokio::test]
    async fn a_missing_lifetime_is_not_stated() {
        let server = serving(
            "/token",
            issued(json!({"access_token": ACCESS_SENTINEL, "token_type": "Bearer"})),
        )
        .await;

        let tokens = client_for(&server)
            .refresh(&RefreshToken::new(REFRESH_SENTINEL).unwrap(), None)
            .await
            .expect("the answer is a token response");

        assert!(tokens.expires_at().is_none());
        assert!(!tokens.lifetime_stated());
    }

    #[tokio::test]
    async fn a_201_token_answer_is_a_protocol_failure() {
        let server = serving(
            "/token",
            ResponseTemplate::new(201).set_body_json(json!({
                "access_token": ACCESS_SENTINEL,
                "token_type": "Bearer",
            })),
        )
        .await;

        let error = client_for(&server)
            .refresh(&RefreshToken::new(REFRESH_SENTINEL).unwrap(), None)
            .await
            .expect_err("only a 200 is a token answer");

        assert_eq!(error, TokenError::Protocol { status: 201 });
    }

    #[tokio::test]
    async fn a_verifier_with_a_reserved_character_is_refused_before_any_request() {
        let server = serving(
            "/token",
            issued(json!({"access_token": ACCESS_SENTINEL, "token_type": "Bearer"})),
        )
        .await;
        let client = client_for(&server);
        for bad in ["+", "=", " ", "/"] {
            let verifier = format!("{}{bad}", &VERIFIER[..42]);
            assert_eq!(verifier.len(), 43);
            let error = client
                .redeem_authorization_code("synthetic-code", &redirect_uri(), &verifier, None)
                .await
                .expect_err("the verifier is outside the unreserved set");
            assert!(matches!(error, TokenError::Invalid { .. }), "{error:?}");
        }
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn an_unusable_token_in_the_answer_is_a_protocol_failure() {
        for body in [
            json!({"access_token": ACCESS_SENTINEL, "token_type": "Bearer", "refresh_token": "has space"}),
            json!({"access_token": "has space", "token_type": "Bearer"}),
            json!({"access_token": ACCESS_SENTINEL, "token_type": "Bearer", "refresh_token": ""}),
            json!({"access_token": "", "token_type": "Bearer"}),
        ] {
            let server = serving("/token", issued(body)).await;

            let error = client_for(&server)
                .refresh(&RefreshToken::new(REFRESH_SENTINEL).unwrap(), None)
                .await
                .expect_err("the answer carries an unusable token");

            assert_eq!(error, TokenError::Protocol { status: 200 });
        }
    }

    #[tokio::test]
    async fn a_dns_pinned_client_posts_each_request_to_its_own_endpoint() {
        let server = MockServer::start().await;
        for route in ["/token", "/revoke"] {
            Mock::given(method("POST"))
                .and(path(route))
                .respond_with(if route == "/token" {
                    issued(json!({"access_token": ACCESS_SENTINEL, "token_type": "Bearer"}))
                } else {
                    ResponseTemplate::new(200)
                })
                .mount(&server)
                .await;
        }
        let base = Url::parse(&server.uri()).unwrap();
        let config = ClientSecretConfig::new(base.join("token").unwrap(), CLIENT_ID, secret())
            .unwrap()
            .with_revocation_endpoint(base.join("revoke").unwrap())
            .unwrap()
            .with_fetch_url_policy(FetchUrlPolicy::https_or_loopback());
        let client = ClientSecretClient::new(config).unwrap();

        let _tokens = client
            .redeem_authorization_code("synthetic-code", &redirect_uri(), VERIFIER, None)
            .await
            .expect("the approved loopback endpoint issues a token");
        client
            .revoke_refresh_token(&RefreshToken::new(REFRESH_SENTINEL).unwrap())
            .await
            .expect("the approved loopback endpoint revokes");

        let requests = server.received_requests().await.unwrap();
        let paths: Vec<&str> = requests.iter().map(|request| request.url.path()).collect();
        assert_eq!(paths, ["/token", "/revoke"]);
        assert_secret_only_in_the_body(&server).await;
    }

    #[tokio::test]
    async fn a_strict_fetch_policy_refuses_a_loopback_endpoint_without_a_request() {
        let server = serving("/token", ResponseTemplate::new(200)).await;
        let base = Url::parse(&server.uri()).unwrap();
        let config = ClientSecretConfig::new(base.join("token").unwrap(), CLIENT_ID, secret())
            .unwrap()
            .with_revocation_endpoint(base.join("revoke").unwrap())
            .unwrap()
            .with_fetch_url_policy(FetchUrlPolicy::strict());
        let client = ClientSecretClient::new(config).unwrap();

        let refused = client
            .refresh(&RefreshToken::new(REFRESH_SENTINEL).unwrap(), None)
            .await
            .expect_err("strict policy refuses loopback");
        assert!(
            matches!(refused, TokenError::Configuration { .. }),
            "{refused:?}"
        );
        let refused = client
            .revoke_refresh_token(&RefreshToken::new(REFRESH_SENTINEL).unwrap())
            .await
            .expect_err("strict policy refuses loopback");
        assert!(
            matches!(refused, TokenError::Configuration { .. }),
            "{refused:?}"
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn a_200_revocation_with_an_oversized_body_is_still_success() {
        let padding = "a".repeat(usize::try_from(MAXIMUM_TOKEN_RESPONSE_BYTES).unwrap() + 1);
        let server = serving(
            "/revoke",
            ResponseTemplate::new(200).set_body_string(padding),
        )
        .await;

        client_for(&server)
            .revoke_refresh_token(&RefreshToken::new(REFRESH_SENTINEL).unwrap())
            .await
            .expect("a 200 is success whatever its body");
    }

    #[tokio::test]
    async fn a_200_revocation_whose_body_stalls_is_still_success() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let serve = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // The request is read, then the answer starts and stalls.
            let mut request = [0_u8; 4096];
            let _read = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nabc")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let base = Url::parse(&format!("http://{address}/")).unwrap();
        let config = ClientSecretConfig::new(base.join("token").unwrap(), CLIENT_ID, secret())
            .unwrap()
            .with_revocation_endpoint(base.join("revoke").unwrap())
            .unwrap()
            .with_request_timeout(Duration::from_millis(500));
        let client = ClientSecretClient::new(config).unwrap();

        client
            .revoke_refresh_token(&RefreshToken::new(REFRESH_SENTINEL).unwrap())
            .await
            .expect("a 200 is success whatever happens to its body");
        serve.abort();
    }

    #[tokio::test]
    async fn a_stalled_200_token_answer_is_a_timeout() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let serve = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 4096];
            let _read = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 100\r\n\r\n{")
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_secs(30)).await;
        });
        let base = Url::parse(&format!("http://{address}/")).unwrap();
        let config = ClientSecretConfig::new(base.join("token").unwrap(), CLIENT_ID, secret())
            .unwrap()
            .with_request_timeout(Duration::from_millis(500));
        let client = ClientSecretClient::new(config).unwrap();

        let error = client
            .refresh(&RefreshToken::new(REFRESH_SENTINEL).unwrap(), None)
            .await
            .expect_err("a token answer that stalls is not a token");

        assert_eq!(
            error,
            TokenError::Transport {
                kind: crate::client::TransportKind::Timeout
            }
        );
        serve.abort();
    }
}
