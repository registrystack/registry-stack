// SPDX-License-Identifier: Apache-2.0

//! The compiled authentication plan of one endpoint
//! (`products/adapter/CONCEPT.md` section 10.2).
//!
//! Compilation pairs the pack endpoint's declared
//! [`EndpointAuthentication`] with the runtime's [`EndpointBinding`] and
//! refuses everything the concept refuses, before any secret is
//! resolved: a credential kind that does not match the declared kind, a
//! `none` endpoint reaching past numeric loopback without an mTLS
//! identity, a scheme or header name out of Evidence's bounds, a
//! reserved API-key header name, and an unusable fixed token endpoint.
//! These re-run the `adapterctl check` refusals defensively on the
//! runtime path, the way Evidence re-checks its bundle validation when
//! it compiles a source.

use crate::auth::{
    material::{basic_value, is_credential_value_bytes, scheme_value, AuthHeader},
    token::{
        acquire_token, resolve_protected, CacheBounds, ClientAssertionSigner, TokenBudget,
        TokenEndpointPlan, TokenRequestParameters, TokenSend, UpstreamStatusAction,
    },
    AuthError, AuthEvent,
};
use registry_adapter_core::{
    is_reserved_header_name, EndpointAuthentication, EndpointBinding, RuntimeCredential,
};
use registry_platform_config::SecretResolver;
use registry_platform_httputil::valid_resource_uri;
use registry_platform_yaml::SecretReference;
use std::fmt;
use std::time::Duration;

/// The six closed kinds, spelled as Evidence's `SourceAuthentication`
/// tags are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthKind {
    /// Nothing is sent.
    None,
    /// `Authorization: Basic` from the runtime's pair.
    Basic,
    /// `Authorization: <scheme> <token>` from the runtime's token.
    StaticAuthorization,
    /// One declared header from the runtime's key.
    StaticApiKey,
    /// RFC 6749 client credentials with a shared secret.
    Oauth2ClientCredentials,
    /// RFC 7523 client credentials with a signed assertion.
    Oauth2PrivateKeyJwt,
}

impl AuthKind {
    /// The tag this kind serializes with, matching Evidence's.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Basic => "basic",
            Self::StaticAuthorization => "static-authorization",
            Self::StaticApiKey => "static-api-key",
            Self::Oauth2ClientCredentials => "oauth2-client-credentials",
            Self::Oauth2PrivateKeyJwt => "oauth2-private-key-jwt",
        }
    }

    /// Whether an upstream 401 triggers the single refresh of
    /// section 10.2; only the OAuth2 kinds hold a refreshable
    /// credential.
    #[must_use]
    pub const fn is_oauth2(self) -> bool {
        matches!(
            self,
            Self::Oauth2ClientCredentials | Self::Oauth2PrivateKeyJwt
        )
    }
}

/// Why an endpoint and its binding do not form a usable plan. Every
/// rendering is fixed text; none carries configuration values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPlanFault {
    /// The runtime credential's kind does not match the endpoint's
    /// declared kind, or a kind that sends a credential has none bound.
    KindMismatch,
    /// A `none` endpoint reaches an origin that is neither numeric
    /// loopback nor `https` with an mTLS client identity.
    NoneNotAdmitted,
    /// `scheme` is not 1 to 32 HTTP token bytes.
    SchemeOutOfBounds,
    /// `headerName` is a header the engine owns.
    HeaderNameReserved,
    /// `headerName` is not 1 to 64 bytes of header-name token bytes.
    HeaderNameOutOfBounds,
    /// The fixed token endpoint is not an absolute `http`/`https` URL
    /// without userinfo, query, or fragment, with plain HTTP confined to
    /// numeric loopback.
    TokenEndpointNotUsable,
    /// `resource` is not a valid RFC 8707 resource indicator.
    ResourceInvalid,
    /// `scope` is not a 1 to 512 byte string, Evidence's source
    /// authentication bound.
    ScopeInvalid,
    /// `audience` is not a non-blank 1 to 512 byte string, Evidence's
    /// source authentication bound.
    AudienceInvalid,
    /// `clientAssertionAudience` is not 1 to 512 non-blank bytes.
    AssertionAudienceInvalid,
}

impl fmt::Display for AuthPlanFault {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KindMismatch => formatter.write_str(
                "the runtime credential's kind does not match the endpoint's declared kind",
            ),
            Self::NoneNotAdmitted => formatter.write_str(
                "a none endpoint reaches an origin that is neither numeric loopback nor https \
                 with an mTLS client identity",
            ),
            Self::SchemeOutOfBounds => {
                formatter.write_str("the authorization scheme must be 1 to 32 HTTP token bytes")
            }
            Self::HeaderNameReserved => formatter
                .write_str("the API-key header name is reserved by the engine"),
            Self::HeaderNameOutOfBounds => formatter
                .write_str("the API-key header name must be 1 to 64 header-name token bytes"),
            Self::TokenEndpointNotUsable => formatter.write_str(
                "the token endpoint must be an absolute http or https URL without userinfo, query, or fragment",
            ),
            Self::ResourceInvalid => {
                formatter.write_str("the resource parameter is not a valid resource indicator")
            }
            Self::ScopeInvalid => {
                formatter.write_str("the scope parameter is not within Evidence's bounds")
            }
            Self::AudienceInvalid => {
                formatter.write_str("the audience parameter is not within Evidence's bounds")
            }
            Self::AssertionAudienceInvalid => formatter.write_str(
                "the client assertion audience must be 1 to 512 non-blank bytes",
            ),
        }
    }
}

/// The static credential a plan resolves per send. The OAuth2 kinds keep
/// theirs inside [`TokenEndpointPlan`] instead.
#[derive(Debug, Clone, PartialEq)]
pub enum StaticCredential {
    /// The Basic pair.
    Basic {
        /// The username secret reference.
        username_ref: SecretReference,
        /// The password secret reference.
        password_ref: SecretReference,
    },
    /// The token, under the endpoint's declared scheme.
    Authorization {
        /// The RFC 9110 scheme the token is presented under.
        scheme: String,
        /// The token secret reference.
        token_ref: SecretReference,
    },
    /// The key, in the endpoint's declared header.
    ApiKey {
        /// The declared header name, already validated.
        header_name: String,
        /// The key secret reference.
        value_ref: SecretReference,
    },
}

/// One endpoint's frozen authentication plan. An OAuth2 plan owns its
/// endpoint's token cache, so a credential cached for one endpoint can
/// never be served to another.
#[derive(Debug, Clone)]
pub struct AuthPlan {
    kind: AuthKind,
    static_credential: Option<StaticCredential>,
    token: Option<TokenEndpointPlan>,
}

/// Everything one authorization needs from the engine: the secret
/// resolver, the exchange's token budget, the token send through the
/// endpoint's own outbound client, the assertion signer, and the
/// value-free event log the journal keeps. The endpoint's cache is the
/// plan's own, not the caller's to supply.
pub struct AuthorizeContext<'a> {
    /// Resolves `secret:` references under the deployment's providers.
    pub resolver: &'a SecretResolver,
    /// The exchange's token budget: at most two token sends per endpoint
    /// per exchange, keyed by endpoint.
    pub budget: &'a mut TokenBudget,
    /// Sends one token request through the endpoint's own outbound
    /// client: the same trust profile and the same mTLS identity.
    pub send: &'a dyn TokenSend,
    /// Signs RFC 7523 client assertions for the private-key-jwt kind.
    pub signer: &'a dyn ClientAssertionSigner,
    /// The value-free outcomes the journal records.
    pub events: &'a mut Vec<AuthEvent>,
}

/// One credential the engine may send: the header to append and, when
/// the credential came from an OAuth2 endpoint's cache, the generation
/// of that cached issuance. The engine hands the generation back to the
/// 401 rule with the status, which clears only the issuance its send
/// carried, never one a concurrent refresh already replaced.
#[derive(Debug)]
pub struct AuthorizedCredential {
    /// The header to append to the send.
    pub header: AuthHeader,
    /// The cached issuance the header carries; `None` when the kind
    /// holds no cache to invalidate (the static kinds), or when the
    /// issuance earned no cache lifetime and nothing was stored.
    pub generation: Option<u64>,
}

impl AuthPlan {
    /// Compile one endpoint's declared kind against its runtime binding.
    ///
    /// One rule for callers: compile once per deployment start and hold
    /// the plan in runtime state; never per exchange: each compile owns
    /// a fresh cache. Compilation runs at deployment load, and a
    /// failure refuses startup with a value-free diagnostic that
    /// names the endpoint id and the fault.
    ///
    /// This re-runs, defensively, the refusals `adapterctl check` owns;
    /// a deployment whose artifacts were never checked still cannot send
    /// a credential an endpoint did not declare.
    pub fn compile(
        endpoint: &EndpointAuthentication,
        binding: &EndpointBinding,
    ) -> Result<Self, AuthPlanFault> {
        match (endpoint, binding.credential.as_ref()) {
            (EndpointAuthentication::None {}, None | Some(RuntimeCredential::None {})) => {
                // A `none` endpoint leans on the transport alone: numeric
                // loopback keeps plain HTTP off the network, and an mTLS
                // identity is only a credential when the handshake itself
                // is encrypted, so plain HTTP refuses even with one bound.
                let loopback = is_numeric_loopback(&binding.base_url)
                    && (binding.base_url.is_https()
                        || has_canonical_loopback_authority(binding.base_url.as_str()));
                let identity_over_https = binding.mtls_identity.is_some()
                    && binding.base_url.to_url().scheme() == "https";
                if !loopback && !identity_over_https {
                    return Err(AuthPlanFault::NoneNotAdmitted);
                }
                Ok(Self {
                    kind: AuthKind::None,
                    static_credential: None,
                    token: None,
                })
            }
            (
                EndpointAuthentication::Basic {},
                Some(RuntimeCredential::Basic {
                    username_ref,
                    password_ref,
                }),
            ) => Ok(Self {
                kind: AuthKind::Basic,
                static_credential: Some(StaticCredential::Basic {
                    username_ref: username_ref.clone(),
                    password_ref: password_ref.clone(),
                }),
                token: None,
            }),
            (
                EndpointAuthentication::StaticAuthorization { scheme },
                Some(RuntimeCredential::StaticAuthorization { token_ref }),
            ) => {
                let scheme = scheme.as_deref().unwrap_or("Bearer");
                if !scheme_is_admissible(scheme) {
                    return Err(AuthPlanFault::SchemeOutOfBounds);
                }
                Ok(Self {
                    kind: AuthKind::StaticAuthorization,
                    static_credential: Some(StaticCredential::Authorization {
                        scheme: scheme.to_owned(),
                        token_ref: token_ref.clone(),
                    }),
                    token: None,
                })
            }
            (
                EndpointAuthentication::StaticApiKey { header_name },
                Some(RuntimeCredential::StaticApiKey { value_ref }),
            ) => {
                if is_reserved_header_name(header_name) {
                    return Err(AuthPlanFault::HeaderNameReserved);
                }
                if !header_name_is_admissible(header_name) {
                    return Err(AuthPlanFault::HeaderNameOutOfBounds);
                }
                Ok(Self {
                    kind: AuthKind::StaticApiKey,
                    static_credential: Some(StaticCredential::ApiKey {
                        header_name: header_name.clone(),
                        value_ref: value_ref.clone(),
                    }),
                    token: None,
                })
            }
            (
                EndpointAuthentication::Oauth2ClientCredentials {},
                Some(RuntimeCredential::Oauth2ClientCredentials {
                    token_endpoint,
                    client_id_ref,
                    client_secret_ref,
                    scope,
                    audience,
                    resource,
                    credential_placement,
                    maximum_cache_seconds,
                    assumed_lifetime_seconds,
                }),
            ) => {
                validate_token_endpoint(token_endpoint)?;
                let parameters = validate_request_parameters(scope, audience, resource)?;
                Ok(Self {
                    kind: AuthKind::Oauth2ClientCredentials,
                    static_credential: None,
                    token: Some(TokenEndpointPlan::client_secret(
                        binding.endpoint.clone(),
                        token_endpoint.as_str().to_owned(),
                        client_id_ref.clone(),
                        client_secret_ref.clone(),
                        *credential_placement,
                        parameters,
                        CacheBounds {
                            maximum: Duration::from_secs(maximum_cache_seconds.get()),
                            assumed: assumed_lifetime_seconds
                                .map(|seconds| Duration::from_secs(seconds.get())),
                        },
                    )),
                })
            }
            (
                EndpointAuthentication::Oauth2PrivateKeyJwt {},
                Some(RuntimeCredential::Oauth2PrivateKeyJwt {
                    token_endpoint,
                    client_id_ref,
                    client_assertion_key_ref,
                    client_assertion_audience,
                    scope,
                    audience,
                    resource,
                    maximum_cache_seconds,
                    assumed_lifetime_seconds,
                }),
            ) => {
                validate_token_endpoint(token_endpoint)?;
                let parameters = validate_request_parameters(scope, audience, resource)?;
                if let Some(audience) = client_assertion_audience {
                    if audience.len() > 512 || audience.contains('\0') || audience.trim().is_empty()
                    {
                        return Err(AuthPlanFault::AssertionAudienceInvalid);
                    }
                }
                // The default audience is the token endpoint exactly as
                // the operator wrote it, because RFC 7523 section 3
                // compares it by Simple String Comparison.
                let assertion_audience = client_assertion_audience
                    .clone()
                    .unwrap_or_else(|| token_endpoint.as_str().to_owned());
                Ok(Self {
                    kind: AuthKind::Oauth2PrivateKeyJwt,
                    static_credential: None,
                    token: Some(TokenEndpointPlan::private_key_jwt(
                        binding.endpoint.clone(),
                        token_endpoint.as_str().to_owned(),
                        client_id_ref.clone(),
                        client_assertion_key_ref.clone(),
                        assertion_audience,
                        parameters,
                        CacheBounds {
                            maximum: Duration::from_secs(maximum_cache_seconds.get()),
                            assumed: assumed_lifetime_seconds
                                .map(|seconds| Duration::from_secs(seconds.get())),
                        },
                    )),
                })
            }
            _ => Err(AuthPlanFault::KindMismatch),
        }
    }

    /// The endpoint's kind.
    #[must_use]
    pub fn kind(&self) -> AuthKind {
        self.kind
    }

    /// The static credential this plan resolves per send, if any.
    #[must_use]
    pub fn static_credential(&self) -> Option<&StaticCredential> {
        self.static_credential.as_ref()
    }

    /// The fixed token endpoint plan, for the OAuth2 kinds.
    #[must_use]
    pub fn token_plan(&self) -> Option<&TokenEndpointPlan> {
        self.token.as_ref()
    }

    /// The credential for one upstream send, or `None` under the
    /// `none` kind.
    ///
    /// Static kinds resolve their secret on every send. The OAuth2 kinds
    /// acquire a credential through the fixed token endpoint under the
    /// exchange's budget; the acquisition holds the endpoint's cache
    /// lock until it completes, which is the single-flight refresh of
    /// section 10.2. The returned generation names the cached issuance
    /// the header carries; the engine passes it back to
    /// [`AuthPlan::on_upstream_status`] when the send draws a 401. The
    /// future is `Send`, so the engine may poll it on any worker.
    pub async fn authorize(
        &self,
        context: &mut AuthorizeContext<'_>,
    ) -> Result<Option<AuthorizedCredential>, AuthError> {
        if self.kind == AuthKind::None {
            return Ok(None);
        }
        if let Some(credential) = &self.static_credential {
            return authorize_static(credential, context.resolver).map(|header| {
                Some(AuthorizedCredential {
                    header,
                    generation: None,
                })
            });
        }
        // Compile refuses an OAuth2 kind whose token endpoint is
        // missing, so a compiled plan always carries one; refuse rather
        // than panic if a future compile path forgets that.
        let plan = self
            .token
            .as_ref()
            .ok_or(AuthError::Plan(AuthPlanFault::KindMismatch))?;
        let (token, generation) = acquire_token(
            plan,
            context.budget,
            context.resolver,
            context.send,
            context.signer,
            context.events,
        )
        .await?;
        let value = scheme_value("Bearer", token.as_bytes()).map_err(|_| AuthError::Credential)?;
        Ok(Some(AuthorizedCredential {
            header: AuthHeader::new("authorization", value),
            generation,
        }))
    }

    /// Apply the 401 rule of section 10.2 to one upstream status.
    ///
    /// The rule holds whatever `okStatusCodeRange` and
    /// `throwExceptionOnFailure` say: an upstream 401 under an OAuth2
    /// kind invalidates the cached credential the send carried, named by
    /// `sent_generation` from the [`AuthorizedCredential`], and the send
    /// repeats once with a fresh one. The comparison is what keeps the
    /// rule from racing a concurrent refresh: a 401 that arrives late,
    /// about an issuance another exchange has already replaced, leaves
    /// the newer issuance cached instead of forcing another token
    /// request. `None` invalidates unconditionally, the fallback for an
    /// engine that lost track of what it sent. A 401 after the one
    /// refresh, or any 401 under a static kind, raises the uncatchable
    /// `credential.rejected`. A 403 stays the caller's `upstream.http`:
    /// it answers about the request, not the credential.
    pub async fn on_upstream_status(
        &self,
        status: u16,
        sent_generation: Option<u64>,
        refresh_used: &mut bool,
        events: &mut Vec<AuthEvent>,
    ) -> UpstreamStatusAction {
        if status != 401 {
            // A 403 answers about the request, not the credential, so it
            // stays the caller's `upstream.http`; so does every other
            // status.
            return UpstreamStatusAction::Continue;
        }
        if self.kind.is_oauth2() && !*refresh_used {
            *refresh_used = true;
            if let Some(plan) = &self.token {
                plan.cache().invalidate_if(sent_generation).await;
            }
            events.push(AuthEvent::TokenInvalidatedAfterUnauthorized);
            return UpstreamStatusAction::RetryWithFreshCredential;
        }
        events.push(AuthEvent::CredentialRejected);
        UpstreamStatusAction::CredentialRejected
    }
}

/// Resolve one static credential to its header, per kind.
fn authorize_static(
    credential: &StaticCredential,
    resolver: &SecretResolver,
) -> Result<AuthHeader, AuthError> {
    match credential {
        StaticCredential::Basic {
            username_ref,
            password_ref,
        } => {
            let username = resolve_protected(resolver, username_ref)?;
            let password = resolve_protected(resolver, password_ref)?;
            let value = basic_value(username.as_bytes(), password.as_bytes())
                .map_err(|_| AuthError::Credential)?;
            Ok(AuthHeader::new("authorization", value))
        }
        StaticCredential::Authorization { scheme, token_ref } => {
            let token = resolve_protected(resolver, token_ref)?;
            let value =
                scheme_value(scheme, token.as_bytes()).map_err(|_| AuthError::Credential)?;
            Ok(AuthHeader::new("authorization", value))
        }
        StaticCredential::ApiKey {
            header_name,
            value_ref,
        } => {
            let key = resolve_protected(resolver, value_ref)?;
            if !is_credential_value_bytes(key.as_bytes()) {
                return Err(AuthError::Credential);
            }
            Ok(AuthHeader::new(header_name, key))
        }
    }
}

/// Whether the fixed token endpoint is usable, Evidence's rules: an
/// absolute `http`/`https` URL without query, fragment, or userinfo, with
/// plain HTTP confined to a canonically spelled numeric loopback. The
/// `Url` type already refuses userinfo and non-HTTP schemes; these
/// re-checks are the runtime side of the authoring checks.
fn validate_token_endpoint(endpoint: &registry_platform_yaml::Url) -> Result<(), AuthPlanFault> {
    let parsed = endpoint.to_url();
    let usable = parsed.query().is_none()
        && parsed.fragment().is_none()
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && (parsed.scheme() == "https"
            || (is_numeric_loopback(endpoint)
                && has_canonical_loopback_authority(endpoint.as_str())));
    if usable {
        Ok(())
    } else {
        Err(AuthPlanFault::TokenEndpointNotUsable)
    }
}

/// The token-request parameters Evidence validates on its source
/// authentication: `scope` a 1 to 512 byte string, `audience` a non-blank
/// 1 to 512 byte string, `resource` one bounded RFC 8707 resource
/// indicator.
fn validate_request_parameters(
    scope: &Option<String>,
    audience: &Option<String>,
    resource: &Option<String>,
) -> Result<TokenRequestParameters, AuthPlanFault> {
    if let Some(scope) = scope {
        if scope.is_empty() || scope.len() > 512 || scope.contains('\0') {
            return Err(AuthPlanFault::ScopeInvalid);
        }
    }
    if let Some(audience) = audience {
        if audience.is_empty()
            || audience.len() > 512
            || audience.contains('\0')
            || audience.trim().is_empty()
        {
            return Err(AuthPlanFault::AudienceInvalid);
        }
    }
    if let Some(resource) = resource {
        if resource.len() > 512 || !valid_resource_uri(resource) {
            return Err(AuthPlanFault::ResourceInvalid);
        }
    }
    Ok(TokenRequestParameters {
        scope: scope.clone(),
        audience: audience.clone(),
        resource: resource.clone(),
    })
}

/// Whether an origin denotes numeric loopback, the way the concept
/// admits a `none` endpoint and a plain-HTTP token endpoint: either IP
/// loopback family, by address, never by name.
fn is_numeric_loopback(url: &registry_platform_yaml::Url) -> bool {
    let parsed = url.to_url();
    let host = parsed.host_str().unwrap_or_default();
    let host = host
        .strip_prefix('[')
        .and_then(|unbracketed| unbracketed.strip_suffix(']'))
        .unwrap_or(host);
    host.parse::<std::net::IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

/// Whether the plain-HTTP loopback authority is spelled the way the
/// address prints, Evidence's rule: a full `127` dotted quad with no
/// leading-zero octet, or exactly `[::1]`, with any explicit port. The
/// URL schema refuses a host the parser rewrites, but IPv6 has several
/// ordinary spellings of one address, and a plain-HTTP credential
/// travels over an origin everyone reads the same way or not at all.
fn has_canonical_loopback_authority(written: &str) -> bool {
    let Some(rest) = written.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split('/').next().unwrap_or(rest);
    if let Some(suffix) = authority.strip_prefix("[::1]") {
        return suffix.is_empty() || valid_port_suffix(suffix);
    }
    let (host, port) = authority
        .rsplit_once(':')
        .filter(|(_, port)| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
        .map_or((authority, None), |(host, port)| (host, Some(port)));
    if port.is_some_and(|port| !valid_port(port)) {
        return false;
    }
    let octets = host.split('.').collect::<Vec<_>>();
    octets.len() == 4
        && octets[0] == "127"
        && octets.iter().all(|octet| {
            !octet.is_empty()
                && (octet == &"0" || !octet.starts_with('0'))
                && octet.bytes().all(|byte| byte.is_ascii_digit())
                && octet.parse::<u8>().is_ok()
        })
}

/// One `:` followed by a usable plain-HTTP port.
fn valid_port_suffix(value: &str) -> bool {
    value.strip_prefix(':').is_some_and(valid_port)
}

/// A non-zero port without a leading zero, Evidence's bound.
fn valid_port(value: &str) -> bool {
    !value.starts_with('0') && value.parse::<u16>().is_ok_and(|port| port != 0)
}

/// Whether `scheme` is 1 to 32 HTTP token bytes.
fn scheme_is_admissible(scheme: &str) -> bool {
    !scheme.is_empty() && scheme.len() <= 32 && scheme.bytes().all(is_token_byte)
}

/// Whether `name` is 1 to 64 bytes of header-name token bytes.
fn header_name_is_admissible(name: &str) -> bool {
    !name.is_empty() && name.len() <= 64 && name.bytes().all(is_token_byte)
}

/// Whether one byte is an RFC 9110 token byte: the alphabet and digits,
/// plus the twenty-three separators the grammar allows.
fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::TransportFailure;
    use registry_adapter_core::{CredentialPlacement, MtlsIdentity};
    use registry_platform_yaml::{BoundedU64, ExternalId, SecretProvider, Url};

    fn secret(name: &str) -> SecretReference {
        SecretReference::new(format!("secret:env/{name}")).expect("secret reference")
    }

    fn binding(base_url: &str, credential: Option<RuntimeCredential>) -> EndpointBinding {
        EndpointBinding {
            endpoint: ExternalId::new("case-api").expect("id"),
            base_url: Url::new(base_url).expect("url"),
            credential,
            tls_trust_profile: None,
            mtls_identity: None,
        }
    }

    fn oauth_credential(token_endpoint: &str) -> RuntimeCredential {
        RuntimeCredential::Oauth2ClientCredentials {
            token_endpoint: Url::new(token_endpoint).expect("url"),
            client_id_ref: secret("CLIENT_ID"),
            client_secret_ref: secret("CLIENT_SECRET"),
            scope: None,
            audience: None,
            resource: None,
            credential_placement: CredentialPlacement::BasicHeader,
            maximum_cache_seconds: BoundedU64::new(3600).expect("cache"),
            assumed_lifetime_seconds: None,
        }
    }

    fn pkjwt_credential(audience: Option<String>) -> RuntimeCredential {
        RuntimeCredential::Oauth2PrivateKeyJwt {
            token_endpoint: Url::new("https://token.example.invalid/token").expect("url"),
            client_id_ref: secret("CLIENT_ID"),
            // Private key material is a file reference, the only provider
            // that carries it.
            client_assertion_key_ref: SecretReference::new("secret:file/assertion-key.pem")
                .expect("secret reference"),
            client_assertion_audience: audience,
            scope: None,
            audience: None,
            resource: None,
            maximum_cache_seconds: BoundedU64::new(3600).expect("cache"),
            assumed_lifetime_seconds: None,
        }
    }

    /// Each declared kind pairs with its matching credential.
    #[test]
    fn kinds_pair_with_their_credentials() {
        let cases: Vec<(EndpointAuthentication, RuntimeCredential, AuthKind)> = vec![
            (
                EndpointAuthentication::None {},
                RuntimeCredential::None {},
                AuthKind::None,
            ),
            (
                EndpointAuthentication::Basic {},
                RuntimeCredential::Basic {
                    username_ref: secret("USER"),
                    password_ref: secret("PASS"),
                },
                AuthKind::Basic,
            ),
            (
                EndpointAuthentication::StaticAuthorization { scheme: None },
                RuntimeCredential::StaticAuthorization {
                    token_ref: secret("TOKEN"),
                },
                AuthKind::StaticAuthorization,
            ),
            (
                EndpointAuthentication::StaticApiKey {
                    header_name: "X-Api-Key".to_owned(),
                },
                RuntimeCredential::StaticApiKey {
                    value_ref: secret("KEY"),
                },
                AuthKind::StaticApiKey,
            ),
            (
                EndpointAuthentication::Oauth2ClientCredentials {},
                oauth_credential("https://token.example.invalid/token"),
                AuthKind::Oauth2ClientCredentials,
            ),
            (
                EndpointAuthentication::Oauth2PrivateKeyJwt {},
                pkjwt_credential(None),
                AuthKind::Oauth2PrivateKeyJwt,
            ),
        ];
        for (endpoint, credential, kind) in cases {
            // The `none` pairing reaches numeric loopback, the only origin
            // its rule admits without an mTLS identity.
            let base_url = if kind == AuthKind::None {
                "http://127.0.0.1:9/"
            } else {
                "https://cases.example.invalid"
            };
            let binding = binding(base_url, Some(credential));
            let plan = AuthPlan::compile(&endpoint, &binding)
                .unwrap_or_else(|fault| panic!("{} must admit: {fault}", kind.tag()));
            assert_eq!(plan.kind(), kind, "{}", kind.tag());
        }
    }

    /// A credential whose kind does not match, and a kind with no
    /// credential bound, both refuse.
    #[test]
    fn kind_mismatches_refuse() {
        let mismatch = binding(
            "https://cases.example.invalid",
            Some(RuntimeCredential::None {}),
        );
        assert_eq!(
            AuthPlan::compile(&EndpointAuthentication::Basic {}, &mismatch).unwrap_err(),
            AuthPlanFault::KindMismatch
        );
        let missing = binding("https://cases.example.invalid", None);
        assert_eq!(
            AuthPlan::compile(&EndpointAuthentication::Basic {}, &missing).unwrap_err(),
            AuthPlanFault::KindMismatch
        );
    }

    /// `none` reaches canonically spelled numeric loopback, either
    /// family, with or without mTLS, and any origin over `https` with an
    /// mTLS client identity; a loopback name, a non-canonical IPv6
    /// spelling over plain HTTP, a non-loopback origin without mTLS,
    /// and plain HTTP with mTLS, whose handshake no identity can
    /// protect, refuse.
    #[test]
    fn none_is_admitted_only_on_numeric_loopback_or_mtls() {
        for base_url in ["http://127.0.0.1:9/", "http://[::1]:9/"] {
            let binding = binding(base_url, Some(RuntimeCredential::None {}));
            AuthPlan::compile(&EndpointAuthentication::None {}, &binding)
                .unwrap_or_else(|fault| panic!("{base_url} must admit none: {fault}"));
        }
        let named = binding("http://localhost:9/", Some(RuntimeCredential::None {}));
        assert_eq!(
            AuthPlan::compile(&EndpointAuthentication::None {}, &named).unwrap_err(),
            AuthPlanFault::NoneNotAdmitted,
            "a loopback name is resolved off-host and is not numeric loopback"
        );
        let alternate = binding(
            "http://[0:0:0:0:0:0:0:1]:9/",
            Some(RuntimeCredential::None {}),
        );
        assert_eq!(
            AuthPlan::compile(&EndpointAuthentication::None {}, &alternate).unwrap_err(),
            AuthPlanFault::NoneNotAdmitted,
            "a plain-http credential travels over an origin everyone reads the same way"
        );
        let public = binding(
            "https://cases.example.invalid",
            Some(RuntimeCredential::None {}),
        );
        assert_eq!(
            AuthPlan::compile(&EndpointAuthentication::None {}, &public).unwrap_err(),
            AuthPlanFault::NoneNotAdmitted
        );
        let mut with_mtls = binding(
            "https://cases.example.invalid",
            Some(RuntimeCredential::None {}),
        );
        with_mtls.mtls_identity = Some(MtlsIdentity {
            certificate_ref: secret("CLIENT_CERT"),
            key_ref: secret("CLIENT_KEY"),
        });
        assert!(AuthPlan::compile(&EndpointAuthentication::None {}, &with_mtls).is_ok());
        let mut plain_with_mtls = binding(
            "http://cases.example.invalid:9/",
            Some(RuntimeCredential::None {}),
        );
        plain_with_mtls.mtls_identity = with_mtls.mtls_identity;
        assert_eq!(
            AuthPlan::compile(&EndpointAuthentication::None {}, &plain_with_mtls).unwrap_err(),
            AuthPlanFault::NoneNotAdmitted,
            "an mTLS identity over plain http is not a credential"
        );
    }

    /// A plain-HTTP loopback authority is spelled the way the address
    /// prints: the full dotted quad or exactly `[::1]`, never a
    /// shorthand or an alternate IPv6 spelling a reader could parse
    /// differently.
    #[test]
    fn plain_http_loopback_is_admitted_only_canonically_spelled() {
        for written in [
            "http://127.0.0.1:9/",
            "http://127.0.0.1/",
            "http://127.0.0.1",
            "http://[::1]",
            "http://[::1]:8080/",
            "http://127.0.0.1/path?q=1",
        ] {
            assert!(
                has_canonical_loopback_authority(written),
                "{written} is canonical"
            );
        }
        for written in [
            "http://127.1/",
            "http://127.0.0.01/",
            "http://0127.0.0.1/",
            "http://[0:0:0:0:0:0:0:1]/",
            "http://[::1]:0/",
            "http://[::1]:99999/",
            "http://localhost:9/",
            "https://127.0.0.1:9/",
        ] {
            assert!(
                !has_canonical_loopback_authority(written),
                "{written} is not canonical"
            );
        }
    }

    /// A scheme is 1 to 32 HTTP token bytes; anything else refuses.
    #[test]
    fn scheme_bounds_hold() {
        let credential = RuntimeCredential::StaticAuthorization {
            token_ref: secret("TOKEN"),
        };
        for scheme in ["", "Bearer token", "s\u{e9}cheme", &"x".repeat(33)] {
            let binding = binding("https://cases.example.invalid", Some(credential.clone()));
            let endpoint = EndpointAuthentication::StaticAuthorization {
                scheme: Some(scheme.to_owned()),
            };
            assert_eq!(
                AuthPlan::compile(&endpoint, &binding).unwrap_err(),
                AuthPlanFault::SchemeOutOfBounds,
                "scheme {scheme:?} must refuse"
            );
        }
        for scheme in ["Bearer", "ApiToken", &"x".repeat(32)] {
            let binding = binding("https://cases.example.invalid", Some(credential.clone()));
            let endpoint = EndpointAuthentication::StaticAuthorization {
                scheme: Some(scheme.to_owned()),
            };
            assert!(
                AuthPlan::compile(&endpoint, &binding).is_ok(),
                "scheme {scheme:?} must admit"
            );
        }
    }

    /// A reserved header name, whatever its case, refuses; so do names
    /// over 64 bytes and names that are not header-name token bytes.
    #[test]
    fn api_key_header_names_are_bounded_and_unreserved() {
        let credential = RuntimeCredential::StaticApiKey {
            value_ref: secret("KEY"),
        };
        for name in [
            "Authorization",
            "HOST",
            "Proxy-Session",
            "content-length",
            &"X".repeat(65),
            "X Api-Key",
            "X\u{e9}",
        ] {
            let binding = binding("https://cases.example.invalid", Some(credential.clone()));
            let endpoint = EndpointAuthentication::StaticApiKey {
                header_name: name.to_owned(),
            };
            let fault = AuthPlan::compile(&endpoint, &binding).unwrap_err();
            assert!(
                matches!(
                    fault,
                    AuthPlanFault::HeaderNameReserved | AuthPlanFault::HeaderNameOutOfBounds
                ),
                "name {name:?} must refuse, got {fault:?}"
            );
        }
        let binding = binding("https://cases.example.invalid", Some(credential));
        let endpoint = EndpointAuthentication::StaticApiKey {
            header_name: "X-Api-Key".to_owned(),
        };
        assert!(AuthPlan::compile(&endpoint, &binding).is_ok());
    }

    /// The token endpoint must be absolute `http`/`https` without
    /// userinfo, query, or fragment; plain HTTP is confined to numeric
    /// loopback spelled the way the address prints. Userinfo cannot be
    /// constructed through the `Url` type (it refuses one at parse), so
    /// the compile-time re-check of userinfo stays a defense no test
    /// can reach.
    #[test]
    fn token_endpoints_are_usable_or_refused() {
        for endpoint in [
            "https://token.example.invalid/token",
            "http://127.0.0.1:9/token",
        ] {
            let binding = binding(
                "https://cases.example.invalid",
                Some(oauth_credential(endpoint)),
            );
            AuthPlan::compile(
                &EndpointAuthentication::Oauth2ClientCredentials {},
                &binding,
            )
            .unwrap_or_else(|fault| panic!("{endpoint} must admit: {fault}"));
        }
        for endpoint in [
            "https://token.example.invalid/token?extra=1",
            "https://token.example.invalid/token#fragment",
            "http://localhost:9/token",
            "http://10.0.0.5:9/token",
            "http://[0:0:0:0:0:0:0:1]:9/token",
        ] {
            let binding = binding(
                "https://cases.example.invalid",
                Some(oauth_credential(endpoint)),
            );
            assert_eq!(
                AuthPlan::compile(
                    &EndpointAuthentication::Oauth2ClientCredentials {},
                    &binding
                )
                .unwrap_err(),
                AuthPlanFault::TokenEndpointNotUsable,
                "{endpoint} must refuse"
            );
        }
    }

    /// Resource follows Evidence's validator: a parseable absolute URI
    /// without fragment or userinfo.
    #[test]
    fn resources_follow_evidence() {
        let mut credential = oauth_credential("https://token.example.invalid/token");
        if let RuntimeCredential::Oauth2ClientCredentials { resource, .. } = &mut credential {
            *resource = Some("not a uri".to_owned());
        }
        let binding = binding("https://cases.example.invalid", Some(credential));
        assert_eq!(
            AuthPlan::compile(
                &EndpointAuthentication::Oauth2ClientCredentials {},
                &binding
            )
            .unwrap_err(),
            AuthPlanFault::ResourceInvalid
        );
    }

    /// Scope follows Evidence's source authentication bound: a 1 to 512
    /// byte string. Evidence's own validator checks no scope grammar here;
    /// the grammar is the authorization server's to answer at the token
    /// endpoint, where a narrowed answer refuses.
    #[test]
    fn scopes_follow_evidence() {
        for scope in ["", &"s".repeat(513), "read\0write"] {
            let mut credential = oauth_credential("https://token.example.invalid/token");
            if let RuntimeCredential::Oauth2ClientCredentials {
                scope: configured, ..
            } = &mut credential
            {
                *configured = Some(scope.to_owned());
            }
            let binding = binding("https://cases.example.invalid", Some(credential));
            assert_eq!(
                AuthPlan::compile(
                    &EndpointAuthentication::Oauth2ClientCredentials {},
                    &binding
                )
                .unwrap_err(),
                AuthPlanFault::ScopeInvalid,
                "scope {scope:?} must refuse"
            );
        }
        let binding = binding(
            "https://cases.example.invalid",
            Some(oauth_credential("https://token.example.invalid/token")),
        );
        assert!(AuthPlan::compile(
            &EndpointAuthentication::Oauth2ClientCredentials {},
            &binding
        )
        .is_ok());
    }

    /// Audience follows Evidence: a non-blank 1 to 512 byte string, and a
    /// blank one is refused by name, not at the first token request.
    #[test]
    fn audiences_follow_evidence() {
        for audience in ["", "   ", &"a".repeat(513)] {
            let mut credential = oauth_credential("https://token.example.invalid/token");
            if let RuntimeCredential::Oauth2ClientCredentials {
                audience: configured,
                ..
            } = &mut credential
            {
                *configured = Some(audience.to_owned());
            }
            let binding = binding("https://cases.example.invalid", Some(credential));
            assert_eq!(
                AuthPlan::compile(
                    &EndpointAuthentication::Oauth2ClientCredentials {},
                    &binding
                )
                .unwrap_err(),
                AuthPlanFault::AudienceInvalid,
                "audience {audience:?} must refuse"
            );
        }
        let mut credential = oauth_credential("https://token.example.invalid/token");
        if let RuntimeCredential::Oauth2ClientCredentials {
            audience: configured,
            ..
        } = &mut credential
        {
            *configured = Some("registry-api".to_owned());
        }
        let binding = binding("https://cases.example.invalid", Some(credential));
        assert!(AuthPlan::compile(
            &EndpointAuthentication::Oauth2ClientCredentials {},
            &binding
        )
        .is_ok());
    }

    /// `clientAssertionAudience` is 1 to 512 non-blank bytes.
    #[test]
    fn assertion_audiences_are_bounded() {
        for audience in ["", "   ", &"a".repeat(513)] {
            let binding = binding(
                "https://cases.example.invalid",
                Some(pkjwt_credential(Some(audience.to_owned()))),
            );
            assert_eq!(
                AuthPlan::compile(&EndpointAuthentication::Oauth2PrivateKeyJwt {}, &binding)
                    .unwrap_err(),
                AuthPlanFault::AssertionAudienceInvalid,
                "audience {audience:?} must refuse"
            );
        }
        let binding = binding(
            "https://cases.example.invalid",
            Some(pkjwt_credential(Some("token.example.invalid".to_owned()))),
        );
        assert!(
            AuthPlan::compile(&EndpointAuthentication::Oauth2PrivateKeyJwt {}, &binding).is_ok()
        );
    }

    /// Static kinds resolve to the header the concept states: Basic from
    /// the pair, the declared scheme with the token (defaulting to
    /// `Bearer`), the declared header with the key; `none` resolves
    /// nothing.
    #[tokio::test]
    async fn authorize_shapes_each_static_kind() {
        use crate::auth::{ProtectedText, TokenRequest, TokenWire};
        use std::future::Future;
        use std::pin::Pin;

        std::env::set_var("ADAPTER_TEST_AUTH_USER", "user");
        std::env::set_var("ADAPTER_TEST_AUTH_PASS", "pass");
        std::env::set_var("ADAPTER_TEST_AUTH_TOKEN", "tok");
        std::env::set_var("ADAPTER_TEST_AUTH_KEY", "key123");

        /// No static kind ever sends a token request; a call is a bug.
        struct NeverSend;
        impl TokenSend for NeverSend {
            fn send<'a>(
                &'a self,
                _request: &'a TokenRequest,
            ) -> Pin<Box<dyn Future<Output = Result<TokenWire, TransportFailure>> + Send + 'a>>
            {
                Box::pin(async {
                    panic!("a static kind never sends a token request");
                })
            }
        }
        /// No static kind ever signs an assertion; a call is a bug.
        struct NeverSigns;
        impl ClientAssertionSigner for NeverSigns {
            fn sign_client_assertion(
                &self,
                _request: crate::auth::ClientAssertion<'_>,
            ) -> Result<ProtectedText, AuthError> {
                panic!("a static kind never signs an assertion");
            }
        }

        async fn authorize(
            endpoint: &EndpointAuthentication,
            credential: Option<RuntimeCredential>,
            resolver: &SecretResolver,
        ) -> Option<AuthHeader> {
            let mut budget = TokenBudget::new_exchange();
            let mut events = Vec::new();
            let binding = binding("https://cases.example.invalid", credential);
            let plan = AuthPlan::compile(endpoint, &binding).expect("a usable plan");
            let mut context = AuthorizeContext {
                resolver,
                budget: &mut budget,
                send: &NeverSend,
                signer: &NeverSigns,
                events: &mut events,
            };
            plan.authorize(&mut context)
                .await
                .expect("a resolved credential")
                .map(|credential| credential.header)
        }

        let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
        let header = authorize(
            &EndpointAuthentication::Basic {},
            Some(RuntimeCredential::Basic {
                username_ref: secret("ADAPTER_TEST_AUTH_USER"),
                password_ref: secret("ADAPTER_TEST_AUTH_PASS"),
            }),
            &resolver,
        )
        .await
        .expect("basic sends a header");
        assert_eq!(header.name(), "authorization");
        assert_eq!(header.value().as_bytes(), b"Basic dXNlcjpwYXNz");

        let header = authorize(
            &EndpointAuthentication::StaticAuthorization { scheme: None },
            Some(RuntimeCredential::StaticAuthorization {
                token_ref: secret("ADAPTER_TEST_AUTH_TOKEN"),
            }),
            &resolver,
        )
        .await
        .expect("static authorization sends a header");
        assert_eq!(header.name(), "authorization");
        assert_eq!(header.value().as_bytes(), b"Bearer tok");

        let header = authorize(
            &EndpointAuthentication::StaticAuthorization {
                scheme: Some("ApiToken".to_owned()),
            },
            Some(RuntimeCredential::StaticAuthorization {
                token_ref: secret("ADAPTER_TEST_AUTH_TOKEN"),
            }),
            &resolver,
        )
        .await
        .expect("a declared scheme is honored");
        assert_eq!(header.value().as_bytes(), b"ApiToken tok");

        let header = authorize(
            &EndpointAuthentication::StaticApiKey {
                header_name: "X-Api-Key".to_owned(),
            },
            Some(RuntimeCredential::StaticApiKey {
                value_ref: secret("ADAPTER_TEST_AUTH_KEY"),
            }),
            &resolver,
        )
        .await
        .expect("static api key sends a header");
        assert_eq!(header.name(), "X-Api-Key");
        assert_eq!(header.value().as_bytes(), b"key123");

        let loopback = binding("http://127.0.0.1:9/", Some(RuntimeCredential::None {}));
        let plan =
            AuthPlan::compile(&EndpointAuthentication::None {}, &loopback).expect("a usable plan");
        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();
        let mut context = AuthorizeContext {
            resolver: &resolver,
            budget: &mut budget,
            send: &NeverSend,
            signer: &NeverSigns,
            events: &mut events,
        };
        assert!(plan
            .authorize(&mut context)
            .await
            .expect("none resolves")
            .is_none());
    }

    /// An apiKey credential must arrive exactly as declared: leading or
    /// trailing space or tab, which intermediaries strip, refuses, while
    /// interior space stays.
    #[tokio::test]
    async fn an_api_key_with_edge_whitespace_refuses() {
        use crate::auth::{TokenRequest, TokenWire, TransportKind};
        use std::future::Future;
        use std::pin::Pin;

        /// A send a static kind must never make; a call is a bug.
        struct NeverSend;
        impl TokenSend for NeverSend {
            fn send<'a>(
                &'a self,
                _request: &'a TokenRequest,
            ) -> Pin<Box<dyn Future<Output = Result<TokenWire, TransportFailure>> + Send + 'a>>
            {
                Box::pin(async {
                    Err(TransportFailure {
                        kind: TransportKind::Connect,
                    })
                })
            }
        }

        /// A static kind never signs an assertion; a call is a bug.
        struct NeverSigns;
        impl ClientAssertionSigner for NeverSigns {
            fn sign_client_assertion(
                &self,
                _request: crate::auth::ClientAssertion<'_>,
            ) -> Result<crate::auth::ProtectedText, AuthError> {
                panic!("a static kind never signs an assertion");
            }
        }

        let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
        let credential = || {
            Some(RuntimeCredential::StaticApiKey {
                value_ref: secret("ADAPTER_TEST_PADDED_KEY"),
            })
        };
        for value in [" key123", "key123 ", "\tkey123", "key123\t", " key "] {
            std::env::set_var("ADAPTER_TEST_PADDED_KEY", value);
            let binding = binding("https://cases.example.invalid", credential());
            let plan = AuthPlan::compile(
                &EndpointAuthentication::StaticApiKey {
                    header_name: "X-Api-Key".to_owned(),
                },
                &binding,
            )
            .expect("a usable plan");
            let mut budget = TokenBudget::new_exchange();
            let mut events = Vec::new();
            let mut context = AuthorizeContext {
                resolver: &resolver,
                budget: &mut budget,
                send: &NeverSend,
                signer: &NeverSigns,
                events: &mut events,
            };
            let error = plan.authorize(&mut context).await.unwrap_err();
            assert_eq!(error, AuthError::Credential, "{value:?} must refuse");
        }
        std::env::set_var("ADAPTER_TEST_PADDED_KEY", "key 123");
        let binding = binding("https://cases.example.invalid", credential());
        let plan = AuthPlan::compile(
            &EndpointAuthentication::StaticApiKey {
                header_name: "X-Api-Key".to_owned(),
            },
            &binding,
        )
        .expect("a usable plan");
        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();
        let mut context = AuthorizeContext {
            resolver: &resolver,
            budget: &mut budget,
            send: &NeverSend,
            signer: &NeverSigns,
            events: &mut events,
        };
        let credential = plan
            .authorize(&mut context)
            .await
            .expect("interior space is the credential")
            .expect("a header is sent");
        assert_eq!(credential.header.value().as_bytes(), b"key 123");
    }

    /// The 401 rule: one refresh under an OAuth2 kind with the cache
    /// invalidated, `credential.rejected` after that or under a static
    /// kind, and 403 continuing as the caller's `upstream.http`.
    #[tokio::test]
    async fn the_401_rule_decides_by_kind_and_refresh() {
        use crate::auth::{TokenRequest, TokenWire};
        use std::future::Future;
        use std::pin::Pin;
        use zeroize::Zeroizing;

        std::env::set_var("CLIENT_ID", "cid");
        std::env::set_var("CLIENT_SECRET", "csecret");

        /// Issues one fixed readable token response, so the cache holds a
        /// credential the rule can be seen to invalidate.
        struct IssuesOne;
        impl TokenSend for IssuesOne {
            fn send<'a>(
                &'a self,
                _request: &'a TokenRequest,
            ) -> Pin<Box<dyn Future<Output = Result<TokenWire, TransportFailure>> + Send + 'a>>
            {
                Box::pin(async {
                    Ok(TokenWire {
                        status: 200,
                        media_type: Some("application/json".to_owned()),
                        body: Zeroizing::new(
                            br#"{"access_token":"at","token_type":"Bearer","expires_in":600}"#
                                .to_vec(),
                        ),
                    })
                })
            }
        }

        /// The client-credentials kind never signs an assertion; a call is
        /// a bug.
        struct NeverSigns;
        impl ClientAssertionSigner for NeverSigns {
            fn sign_client_assertion(
                &self,
                _request: crate::auth::ClientAssertion<'_>,
            ) -> Result<crate::auth::ProtectedText, AuthError> {
                panic!("client-credentials never signs an assertion");
            }
        }

        let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();
        let oauth_binding = binding(
            "https://cases.example.invalid",
            Some(oauth_credential("https://token.example.invalid/token")),
        );
        let plan = AuthPlan::compile(
            &EndpointAuthentication::Oauth2ClientCredentials {},
            &oauth_binding,
        )
        .expect("a usable plan");
        let cache = plan
            .token_plan()
            .expect("the OAuth2 plan carries its token endpoint")
            .cache();
        let mut context = AuthorizeContext {
            resolver: &resolver,
            budget: &mut budget,
            send: &IssuesOne,
            signer: &NeverSigns,
            events: &mut events,
        };
        let primed = plan
            .authorize(&mut context)
            .await
            .expect("the cache is primed with one credential")
            .expect("a header is sent");
        assert!(cache.remaining_lifetime().await.is_some());
        // The priming's token events are not this rule's record.
        events.clear();

        let mut refresh_used = false;
        assert_eq!(
            plan.on_upstream_status(401, primed.generation, &mut refresh_used, &mut events)
                .await,
            UpstreamStatusAction::RetryWithFreshCredential
        );
        assert!(refresh_used, "the single refresh is now spent");
        assert!(
            cache.remaining_lifetime().await.is_none(),
            "the cached credential was discarded"
        );
        assert_eq!(events, vec![AuthEvent::TokenInvalidatedAfterUnauthorized]);

        assert_eq!(
            // The spent refresh short-circuits before the generation is
            // read, so `None` stands for the send this test never made.
            plan.on_upstream_status(401, None, &mut refresh_used, &mut events)
                .await,
            UpstreamStatusAction::CredentialRejected
        );
        assert_eq!(events.last(), Some(&AuthEvent::CredentialRejected));

        assert_eq!(
            plan.on_upstream_status(403, None, &mut refresh_used, &mut events)
                .await,
            UpstreamStatusAction::Continue,
            "a 403 stays the caller's upstream.http"
        );

        let basic_binding = binding(
            "https://cases.example.invalid",
            Some(RuntimeCredential::Basic {
                username_ref: secret("USER"),
                password_ref: secret("PASS"),
            }),
        );
        let basic =
            AuthPlan::compile(&EndpointAuthentication::Basic {}, &basic_binding).expect("plan");
        let mut refresh_used = false;
        assert_eq!(
            basic
                .on_upstream_status(401, None, &mut refresh_used, &mut events)
                .await,
            UpstreamStatusAction::CredentialRejected,
            "a static kind holds nothing to refresh"
        );
        assert_eq!(
            basic
                .on_upstream_status(403, None, &mut refresh_used, &mut events)
                .await,
            UpstreamStatusAction::Continue
        );
    }

    /// A 401 about an issuance the engine has already replaced leaves
    /// the newer issuance cached: the rule clears only the generation
    /// the refused send carried, so a late refusal neither drops a
    /// healthy credential nor buys a refresh with an allowance the
    /// exchange may not have.
    #[tokio::test]
    async fn a_stale_401_leaves_the_fresher_issuance() {
        use crate::auth::{TokenRequest, TokenWire};
        use std::future::Future;
        use std::pin::Pin;
        use zeroize::Zeroizing;

        std::env::set_var("CLIENT_ID", "cid");
        std::env::set_var("CLIENT_SECRET", "csecret");

        /// Answers the first ask with one token and every later ask with
        /// another, so the test can tell which issuance serves.
        struct IssuesInSequence {
            asks: std::sync::Mutex<u32>,
        }
        impl TokenSend for IssuesInSequence {
            fn send<'a>(
                &'a self,
                _request: &'a TokenRequest,
            ) -> Pin<Box<dyn Future<Output = Result<TokenWire, TransportFailure>> + Send + 'a>>
            {
                Box::pin(async {
                    let mut asks = self.asks.lock().expect("asks");
                    *asks += 1;
                    let issuance = if *asks == 1 { "issued-1" } else { "issued-2" };
                    Ok(TokenWire {
                        status: 200,
                        media_type: Some("application/json".to_owned()),
                        body: Zeroizing::new(
                            format!(
                                r#"{{"access_token":"{issuance}","token_type":"Bearer","expires_in":600}}"#
                            )
                            .into_bytes(),
                        ),
                    })
                })
            }
        }

        /// The client-credentials kind never signs an assertion; a call
        /// is a bug.
        struct NeverSigns;
        impl ClientAssertionSigner for NeverSigns {
            fn sign_client_assertion(
                &self,
                _request: crate::auth::ClientAssertion<'_>,
            ) -> Result<crate::auth::ProtectedText, AuthError> {
                panic!("client-credentials never signs an assertion");
            }
        }

        let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
        let send = IssuesInSequence {
            asks: std::sync::Mutex::new(0),
        };
        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();
        let plan = AuthPlan::compile(
            &EndpointAuthentication::Oauth2ClientCredentials {},
            &binding(
                "https://cases.example.invalid",
                Some(oauth_credential("https://token.example.invalid/token")),
            ),
        )
        .expect("a usable plan");
        let cache = plan
            .token_plan()
            .expect("the OAuth2 plan carries its token endpoint")
            .cache();

        let first = {
            let mut context = AuthorizeContext {
                resolver: &resolver,
                budget: &mut budget,
                send: &send,
                signer: &NeverSigns,
                events: &mut events,
            };
            plan.authorize(&mut context)
                .await
                .expect("the first issuance")
                .expect("a header is sent")
        };
        assert_eq!(first.header.value().as_bytes(), b"Bearer issued-1");

        // The first send's 401 invalidates the only issuance there is.
        let mut refresh_used = false;
        assert_eq!(
            plan.on_upstream_status(401, first.generation, &mut refresh_used, &mut events)
                .await,
            UpstreamStatusAction::RetryWithFreshCredential
        );
        assert!(cache.remaining_lifetime().await.is_none());

        // The refresh issues a second credential; the send carrying it
        // has not drawn an answer yet.
        let second = {
            let mut context = AuthorizeContext {
                resolver: &resolver,
                budget: &mut budget,
                send: &send,
                signer: &NeverSigns,
                events: &mut events,
            };
            plan.authorize(&mut context)
                .await
                .expect("the second issuance")
                .expect("a header is sent")
        };
        assert_eq!(second.header.value().as_bytes(), b"Bearer issued-2");

        // A late 401 about the first send arrives: the newer issuance
        // stays cached because its generation is not the one named.
        let mut refresh_used = false;
        assert_eq!(
            plan.on_upstream_status(401, first.generation, &mut refresh_used, &mut events)
                .await,
            UpstreamStatusAction::RetryWithFreshCredential
        );
        assert!(
            cache.remaining_lifetime().await.is_some(),
            "the fresher issuance survived the stale 401"
        );

        // The engine's retry reuses the surviving cache; no third ask.
        let third = {
            let mut context = AuthorizeContext {
                resolver: &resolver,
                budget: &mut budget,
                send: &send,
                signer: &NeverSigns,
                events: &mut events,
            };
            plan.authorize(&mut context)
                .await
                .expect("the cache answers")
                .expect("a header is sent")
        };
        assert_eq!(third.header.value().as_bytes(), b"Bearer issued-2");
        let asks = *send.asks.lock().expect("asks");
        assert_eq!(asks, 2, "the stale 401 sent nothing");
    }

    /// Two OAuth2 endpoints over one exchange keep separate caches and
    /// separate budget allowances: a credential issued to one endpoint
    /// never serves the other, and one endpoint's spent sends never
    /// starve the other's refresh.
    #[tokio::test]
    async fn two_endpoints_keep_separate_caches_and_budgets() {
        use crate::auth::{TokenRequest, TokenWire};
        use std::future::Future;
        use std::pin::Pin;
        use zeroize::Zeroizing;

        std::env::set_var("ADAPTER_TEST_TWO_A_ID", "cid-a");
        std::env::set_var("ADAPTER_TEST_TWO_A_SECRET", "secret-a");
        std::env::set_var("ADAPTER_TEST_TWO_B_ID", "cid-b");
        std::env::set_var("ADAPTER_TEST_TWO_B_SECRET", "secret-b");

        /// Answers each token endpoint with a credential naming the
        /// host that issued it, recording every destination asked.
        struct IssuesByName {
            requests: std::sync::Mutex<Vec<String>>,
        }
        impl TokenSend for IssuesByName {
            fn send<'a>(
                &'a self,
                request: &'a TokenRequest,
            ) -> Pin<Box<dyn Future<Output = Result<TokenWire, TransportFailure>> + Send + 'a>>
            {
                Box::pin(async move {
                    self.requests
                        .lock()
                        .expect("requests")
                        .push(request.url.clone());
                    let host = request.url.split('/').nth(2).unwrap_or_default();
                    Ok(TokenWire {
                        status: 200,
                        media_type: Some("application/json".to_owned()),
                        body: Zeroizing::new(
                            format!(
                                r#"{{"access_token":"issued-{host}","token_type":"Bearer","expires_in":600}}"#
                            )
                            .into_bytes(),
                        ),
                    })
                })
            }
        }

        /// The client-credentials kind never signs an assertion; a call
        /// is a bug.
        struct NeverSigns;
        impl ClientAssertionSigner for NeverSigns {
            fn sign_client_assertion(
                &self,
                _request: crate::auth::ClientAssertion<'_>,
            ) -> Result<crate::auth::ProtectedText, AuthError> {
                panic!("client-credentials never signs an assertion");
            }
        }

        fn endpoint_binding(
            endpoint: &str,
            token_endpoint: &str,
            id_env: &str,
            secret_env: &str,
        ) -> EndpointBinding {
            EndpointBinding {
                endpoint: ExternalId::new(endpoint).expect("id"),
                base_url: Url::new("https://cases.example.invalid").expect("url"),
                credential: Some(RuntimeCredential::Oauth2ClientCredentials {
                    token_endpoint: Url::new(token_endpoint).expect("url"),
                    client_id_ref: secret(id_env),
                    client_secret_ref: secret(secret_env),
                    scope: None,
                    audience: None,
                    resource: None,
                    credential_placement: CredentialPlacement::BasicHeader,
                    maximum_cache_seconds: BoundedU64::new(3600).expect("cache"),
                    assumed_lifetime_seconds: None,
                }),
                tls_trust_profile: None,
                mtls_identity: None,
            }
        }

        let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
        let send = IssuesByName {
            requests: std::sync::Mutex::new(Vec::new()),
        };
        let plan_a = AuthPlan::compile(
            &EndpointAuthentication::Oauth2ClientCredentials {},
            &endpoint_binding(
                "case-api",
                "https://a.example.invalid/token",
                "ADAPTER_TEST_TWO_A_ID",
                "ADAPTER_TEST_TWO_A_SECRET",
            ),
        )
        .expect("a usable plan");
        let plan_b = AuthPlan::compile(
            &EndpointAuthentication::Oauth2ClientCredentials {},
            &endpoint_binding(
                "audit-api",
                "https://b.example.invalid/token",
                "ADAPTER_TEST_TWO_B_ID",
                "ADAPTER_TEST_TWO_B_SECRET",
            ),
        )
        .expect("a usable plan");
        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();

        // Each endpoint issues its own credential and then serves its
        // own cache; a shared cache would have handed endpoint B the
        // credential endpoint A issued.
        let mut sent_generations = Vec::new();
        for (plan, expected) in [
            (&plan_a, &b"Bearer issued-a.example.invalid"[..]),
            (&plan_b, b"Bearer issued-b.example.invalid"),
        ] {
            for _ in 0..2 {
                let mut context = AuthorizeContext {
                    resolver: &resolver,
                    budget: &mut budget,
                    send: &send,
                    signer: &NeverSigns,
                    events: &mut events,
                };
                let credential = plan
                    .authorize(&mut context)
                    .await
                    .expect("a credential issues")
                    .expect("a header is sent");
                assert_eq!(credential.header.value().as_bytes(), expected);
                sent_generations.push(credential.generation);
            }
        }
        // Count the asks inside a block, so the recorder's lock is
        // released before the awaits that follow.
        let (asked_a, asked_b) = {
            let requests = send.requests.lock().expect("requests");
            (
                requests
                    .iter()
                    .filter(|url| url.contains("a.example.invalid"))
                    .count(),
                requests
                    .iter()
                    .filter(|url| url.contains("b.example.invalid"))
                    .count(),
            )
        };
        assert_eq!(asked_a, 1, "endpoint A was asked once");
        assert_eq!(asked_b, 1, "endpoint B was asked once");
        let endpoint_a = ExternalId::new("case-api").expect("id");
        let endpoint_b = ExternalId::new("audit-api").expect("id");
        assert_eq!(budget.remaining(&endpoint_a), 1);
        assert_eq!(budget.remaining(&endpoint_b), 1);

        // Spend endpoint A's remaining allowance through the 401 rule's
        // invalidation; endpoint B's cache keeps answering, and B's
        // allowance is still whole.
        let mut refresh_used = false;
        assert_eq!(
            plan_a
                .on_upstream_status(401, sent_generations[0], &mut refresh_used, &mut events)
                .await,
            UpstreamStatusAction::RetryWithFreshCredential
        );
        let mut context = AuthorizeContext {
            resolver: &resolver,
            budget: &mut budget,
            send: &send,
            signer: &NeverSigns,
            events: &mut events,
        };
        let refreshed = plan_a
            .authorize(&mut context)
            .await
            .expect("the refreshed credential issues")
            .expect("a header is sent");
        assert_eq!(budget.remaining(&endpoint_a), 0, "A's allowance is spent");

        let mut refresh_used = false;
        assert_eq!(
            plan_a
                .on_upstream_status(401, refreshed.generation, &mut refresh_used, &mut events)
                .await,
            UpstreamStatusAction::RetryWithFreshCredential
        );
        let mut context = AuthorizeContext {
            resolver: &resolver,
            budget: &mut budget,
            send: &send,
            signer: &NeverSigns,
            events: &mut events,
        };
        assert_eq!(
            plan_a.authorize(&mut context).await.unwrap_err(),
            AuthError::BudgetExhausted,
            "A cannot spend B's allowance"
        );

        let mut context = AuthorizeContext {
            resolver: &resolver,
            budget: &mut budget,
            send: &send,
            signer: &NeverSigns,
            events: &mut events,
        };
        let credential = plan_b
            .authorize(&mut context)
            .await
            .expect("B's cache still answers")
            .expect("a header is sent");
        assert_eq!(
            credential.header.value().as_bytes(),
            b"Bearer issued-b.example.invalid"
        );
    }

    /// An OAuth2 kind whose token endpoint went missing refuses rather
    /// than panics: compile always binds one, and the uncatchable plan
    /// fault keeps a future compile path honest.
    #[tokio::test]
    async fn a_missing_token_endpoint_refuses_instead_of_panicking() {
        use crate::auth::{TokenRequest, TokenWire, TransportKind};
        use std::future::Future;
        use std::pin::Pin;

        /// A send the refused plan must never reach; a call is a bug.
        struct SendsNothing;
        impl TokenSend for SendsNothing {
            fn send<'a>(
                &'a self,
                _request: &'a TokenRequest,
            ) -> Pin<Box<dyn Future<Output = Result<TokenWire, TransportFailure>> + Send + 'a>>
            {
                Box::pin(async {
                    Err(TransportFailure {
                        kind: TransportKind::Connect,
                    })
                })
            }
        }

        /// The client-credentials kind never signs an assertion; a call
        /// is a bug.
        struct NeverSigns;
        impl ClientAssertionSigner for NeverSigns {
            fn sign_client_assertion(
                &self,
                _request: crate::auth::ClientAssertion<'_>,
            ) -> Result<crate::auth::ProtectedText, AuthError> {
                panic!("the missing endpoint is refused before any send");
            }
        }

        let plan = AuthPlan {
            kind: AuthKind::Oauth2ClientCredentials,
            static_credential: None,
            token: None,
        };
        let resolver = SecretResolver::new([SecretProvider::Environment], "").expect("resolver");
        let mut budget = TokenBudget::new_exchange();
        let mut events = Vec::new();
        let mut context = AuthorizeContext {
            resolver: &resolver,
            budget: &mut budget,
            send: &SendsNothing,
            signer: &NeverSigns,
            events: &mut events,
        };
        assert_eq!(
            plan.authorize(&mut context).await.unwrap_err(),
            AuthError::Plan(AuthPlanFault::KindMismatch)
        );
        assert!(events.is_empty(), "the refusal precedes any token event");
    }
}
