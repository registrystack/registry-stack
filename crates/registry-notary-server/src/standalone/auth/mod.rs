use super::*;

mod audit;
mod credentials;
mod middleware;
mod notary_tokens;
mod oidc;

pub(super) use audit::config_boot_audit_event;
pub(crate) use audit::AuditPipeline;
pub(super) use credentials::*;
pub use credentials::{find_credential, ResolvedCredential};
pub(super) use middleware::*;
pub(crate) use notary_tokens::NotaryTokenAnchor;
pub(super) use notary_tokens::*;
pub(super) use oidc::*;

#[derive(Debug)]
pub(crate) struct AuthAuditState {
    pub(super) authenticator: RwLock<Arc<Authenticator>>,
    pub(super) audit: AuditPipeline,
    pub(super) replay: ReplayStores,
    pub(super) metrics: Arc<AppMetrics>,
    pub(super) openapi_requires_auth: AtomicBool,
    pub(super) self_attestation_invalid_token_limiter: Option<Arc<SelfAttestationRateLimiter>>,
    pub(super) self_attestation_rate_keys: Option<Arc<SelfAttestationRateLimitKeys>>,
}

#[derive(Debug, Clone)]
pub(super) enum Authenticator {
    Static {
        api_keys: Vec<ResolvedCredential>,
        bearer_tokens: Vec<ResolvedCredential>,
    },
    Oidc {
        verifier: Arc<TokenVerifier>,
        fetch_url_policy: FetchUrlPolicy,
        principal_claim: String,
        subject_binding_claim: Option<String>,
        subject_binding_claim_source: SelfAttestationClaimSource,
        assurance_claim_source: SelfAttestationAssuranceClaimSource,
        userinfo_endpoint: Option<String>,
        userinfo_issuers: Vec<String>,
        /// Second, separately-keyed trust anchor for the Notary's own issuer
        /// (the pre-authorized-code access tokens). `None` unless self-issuance
        /// is enabled. Dispatched by the UNVERIFIED `iss` (route-only) and fully
        /// verified against its own key + issuer + typ. Boxed to keep the enum
        /// variants similarly sized.
        notary_anchor: Option<Arc<RwLock<NotaryTokenAnchor>>>,
    },
}

impl AuthAuditState {
    pub(super) fn from_config(
        config: &StandaloneRegistryNotaryConfig,
        metrics: Arc<AppMetrics>,
        replay: ReplayStores,
    ) -> Result<Self, StandaloneServerError> {
        let audit = AuditPipeline::from_config(&config.audit)?;
        let self_attestation_invalid_token_limiter = config.self_attestation.enabled.then(|| {
            Arc::new(SelfAttestationRateLimiter::new(
                config.self_attestation.rate_limits.clone(),
            ))
        });
        let self_attestation_rate_keys = config.self_attestation.enabled.then(|| {
            Arc::new(SelfAttestationRateLimitKeys::new(
                audit.profile.key_hasher(),
            ))
        });
        Ok(Self {
            authenticator: RwLock::new(Arc::new(Authenticator::from_config(config)?)),
            audit,
            replay,
            metrics,
            openapi_requires_auth: AtomicBool::new(config.server.openapi_requires_auth),
            self_attestation_invalid_token_limiter,
            self_attestation_rate_keys,
        })
    }

    #[must_use]
    pub(super) fn with_postgres_state_plane(
        mut self,
        state_plane: Arc<crate::state_plane::NotaryStatePlaneHandle>,
        rate_limits: registry_notary_core::SelfAttestationRateLimitsConfig,
    ) -> Self {
        if self.self_attestation_invalid_token_limiter.is_some() {
            self.self_attestation_invalid_token_limiter = Some(Arc::new(
                SelfAttestationRateLimiter::with_state_plane(rate_limits, state_plane),
            ));
        }
        self
    }

    pub(super) async fn authenticate(
        &self,
        credentials: RequestCredentials,
    ) -> Result<EvidencePrincipal, EvidenceError> {
        let authenticator = self
            .authenticator
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone();
        authenticator.authenticate(credentials, &self.replay).await
    }

    pub(crate) fn openapi_requires_auth(&self) -> bool {
        self.openapi_requires_auth.load(Ordering::Relaxed)
    }
}

impl Authenticator {
    fn from_config(config: &StandaloneRegistryNotaryConfig) -> Result<Self, StandaloneServerError> {
        match config.auth.mode {
            EvidenceAuthMode::ApiKey => Ok(Self::Static {
                api_keys: resolve_credentials(&config.auth.api_keys)?,
                bearer_tokens: resolve_credentials(&config.auth.bearer_tokens)?,
            }),
            EvidenceAuthMode::Oidc => {
                let oidc = config.auth.oidc.as_ref().ok_or_else(|| {
                    StandaloneServerError::InvalidOidcConfig(
                        "auth.oidc is required when auth.mode = oidc".to_string(),
                    )
                })?;
                let allowed_algorithms = oidc
                    .allowed_algorithms
                    .iter()
                    .map(|algorithm| parse_oidc_algorithm(algorithm))
                    .collect::<Result<Vec<_>, _>>()?;
                let scope_separator = oidc.scope_separator.chars().next().ok_or_else(|| {
                    StandaloneServerError::InvalidOidcConfig(
                        "scope_separator must be exactly one character".to_string(),
                    )
                })?;
                let fetch_url_policy = if oidc.allow_insecure_localhost {
                    FetchUrlPolicy::dev()
                } else {
                    FetchUrlPolicy::strict()
                };
                let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
                    oidc.jwks_url.clone(),
                    JwksFetcherConfig::defaults(),
                    fetch_url_policy.clone(),
                ));
                let userinfo_requires_exp = !(config.self_attestation.enabled
                    && config.self_attestation.subject_binding.claim_source
                        == SelfAttestationClaimSource::Userinfo);
                let verifier = TokenVerifier::new(
                    TokenVerifierConfig::registry_notary_access_profile(
                        oidc.issuer.clone(),
                        oidc.audiences.clone(),
                        allowed_algorithms,
                        oidc.allowed_token_types.clone(),
                    )
                    .with_scope_claim(oidc.scope_claim.clone())
                    .with_scope_separator(scope_separator)
                    .with_scope_map(
                        Some(
                            oidc.scope_map
                                .iter()
                                .map(|(from, to)| (from.clone(), to.clone()))
                                .collect::<HashMap<_, _>>(),
                        )
                        .filter(|scope_map| !scope_map.is_empty()),
                    )
                    .with_allowed_clients(oidc.allowed_clients.clone())
                    .with_leeway(oidc.leeway)
                    .with_userinfo_requires_exp(userinfo_requires_exp),
                    fetcher,
                );
                let userinfo_issuers = if oidc.userinfo_issuers.is_empty() {
                    vec![oidc.issuer.clone()]
                } else {
                    oidc.userinfo_issuers.clone()
                };
                let subject_binding_claim = config
                    .self_attestation
                    .enabled
                    .then(|| config.self_attestation.subject_binding.token_claim.clone())
                    .filter(|claim| !claim.is_empty());
                let notary_anchor = Self::build_notary_anchor(
                    config,
                    oidc.principal_claim.clone(),
                    subject_binding_claim.clone(),
                )?;
                Ok(Self::Oidc {
                    verifier: Arc::new(verifier),
                    fetch_url_policy,
                    principal_claim: oidc.principal_claim.clone(),
                    subject_binding_claim,
                    subject_binding_claim_source: config
                        .self_attestation
                        .subject_binding
                        .claim_source,
                    assurance_claim_source: config
                        .self_attestation
                        .token_policy
                        .assurance_claim_source,
                    userinfo_endpoint: oidc.userinfo_endpoint.clone(),
                    userinfo_issuers,
                    notary_anchor,
                })
            }
        }
    }

    pub(super) async fn authenticate(
        &self,
        credentials: RequestCredentials,
        replay: &ReplayStores,
    ) -> Result<EvidencePrincipal, EvidenceError> {
        if credentials.credential_type_count() > 1 {
            return Err(EvidenceError::MultipleCredentials);
        }
        match self {
            Self::Static {
                api_keys,
                bearer_tokens,
            } => authenticate_static(&credentials, api_keys, bearer_tokens),
            Self::Oidc {
                verifier,
                fetch_url_policy,
                principal_claim,
                subject_binding_claim,
                subject_binding_claim_source,
                assurance_claim_source,
                userinfo_endpoint,
                userinfo_issuers,
                notary_anchor,
            } => {
                // Route by the UNVERIFIED `iss` (never trusted before signature
                // verification): a token claiming the Notary's own issuer is
                // verified against the separate, separately-keyed Notary anchor;
                // everything else takes the existing eSignet path unchanged.
                if let Some(anchor) = notary_anchor {
                    if let Some(token) = credentials.bearer_token.as_deref() {
                        let anchor = anchor
                            .read()
                            .map_err(|_| EvidenceError::MissingCredential)?
                            .clone();
                        if unverified_issuer(token).as_deref() == Some(anchor.issuer.as_str()) {
                            return authenticate_notary_token(token, &anchor, replay).await;
                        }
                    }
                }
                authenticate_oidc(
                    &credentials,
                    verifier,
                    fetch_url_policy,
                    principal_claim,
                    subject_binding_claim.as_deref(),
                    *subject_binding_claim_source,
                    *assurance_claim_source,
                    userinfo_endpoint.as_deref(),
                    userinfo_issuers,
                )
                .await
            }
        }
    }

    /// Build the Notary self-issuance anchor from the access-token signing
    /// config and the dedicated signing key's public JWK.
    fn build_notary_anchor(
        config: &StandaloneRegistryNotaryConfig,
        principal_claim: String,
        subject_binding_claim: Option<String>,
    ) -> Result<Option<Arc<RwLock<NotaryTokenAnchor>>>, StandaloneServerError> {
        Ok(
            Self::build_notary_anchor_value(config, principal_claim, subject_binding_claim)?
                .map(|anchor| Arc::new(RwLock::new(anchor))),
        )
    }

    fn build_notary_anchor_value(
        config: &StandaloneRegistryNotaryConfig,
        principal_claim: String,
        subject_binding_claim: Option<String>,
    ) -> Result<Option<NotaryTokenAnchor>, StandaloneServerError> {
        let signing = &config.auth.access_token_signing;
        if !signing.enabled {
            return Ok(None);
        }
        Ok(Some(NotaryTokenAnchor {
            verification_keys: access_token_verification_keys(config)?,
            issuer: signing.issuer.clone(),
            token_typ: signing.token_typ.clone(),
            audiences: signing.audiences.clone(),
            principal_claim,
            subject_binding_claim,
        }))
    }
}
