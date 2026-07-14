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
    pub(super) subject_access_invalid_token_limiter: Option<Arc<SubjectAccessRateLimiter>>,
    pub(super) subject_access_rate_keys: Option<Arc<SubjectAccessRateLimitKeys>>,
}

#[derive(Debug, Clone)]
pub(super) struct Authenticator {
    pub(super) api_keys: Vec<ResolvedCredential>,
    pub(super) bearer_tokens: Vec<ResolvedCredential>,
    pub(super) oidc: Option<OidcAuthenticator>,
}

#[derive(Debug, Clone)]
pub(super) struct OidcAuthenticator {
    verifier: Arc<TokenVerifier>,
    fetch_url_policy: FetchUrlPolicy,
    principal_claim: String,
    subject_binding_claim: Option<String>,
    subject_binding_claim_source: SubjectAccessClaimSource,
    assurance_claim_source: SubjectAccessAssuranceClaimSource,
    userinfo_endpoint: Option<String>,
    userinfo_issuers: Vec<String>,
    /// Second, separately-keyed trust anchor for the Notary's own issuer
    /// (the pre-authorized-code access tokens). `None` unless self-issuance
    /// is enabled. The unverified issuer is used only to select this verifier;
    /// the selected anchor performs complete signature and claim validation.
    notary_anchor: Option<Arc<RwLock<NotaryTokenAnchor>>>,
}

impl AuthAuditState {
    pub(super) fn from_config(
        config: &StandaloneRegistryNotaryConfig,
        metrics: Arc<AppMetrics>,
        replay: ReplayStores,
    ) -> Result<Self, StandaloneServerError> {
        let audit = AuditPipeline::from_config(&config.audit)?;
        let subject_access_invalid_token_limiter = config.subject_access.enabled.then(|| {
            Arc::new(SubjectAccessRateLimiter::new(
                config.subject_access.rate_limits.clone(),
            ))
        });
        let subject_access_rate_keys = config
            .subject_access
            .enabled
            .then(|| Arc::new(SubjectAccessRateLimitKeys::new(audit.profile.key_hasher())));
        Ok(Self {
            authenticator: RwLock::new(Arc::new(Authenticator::from_config(config)?)),
            audit,
            replay,
            metrics,
            openapi_requires_auth: AtomicBool::new(config.server.openapi_requires_auth),
            subject_access_invalid_token_limiter,
            subject_access_rate_keys,
        })
    }

    #[must_use]
    pub(super) fn with_postgres_state_plane(
        mut self,
        state_plane: Arc<crate::state_plane::NotaryStatePlaneHandle>,
        rate_limits: registry_notary_core::SubjectAccessRateLimitsConfig,
    ) -> Self {
        if self.subject_access_invalid_token_limiter.is_some() {
            self.subject_access_invalid_token_limiter = Some(Arc::new(
                SubjectAccessRateLimiter::with_state_plane(rate_limits, state_plane),
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
        Ok(Self {
            api_keys: resolve_credentials(&config.auth.api_keys)?,
            bearer_tokens: resolve_credentials(&config.auth.bearer_tokens)?,
            oidc: config
                .auth
                .oidc
                .as_ref()
                .map(|_| OidcAuthenticator::from_config(config))
                .transpose()?,
        })
    }

    pub(super) async fn authenticate(
        &self,
        credentials: RequestCredentials,
        replay: &ReplayStores,
    ) -> Result<EvidencePrincipal, EvidenceError> {
        if credentials.credential_type_count() > 1 {
            return Err(EvidenceError::MultipleCredentials);
        }
        if credentials.api_key.is_some() {
            return authenticate_api_key(&credentials, &self.api_keys);
        }
        if let Some(oidc) = &self.oidc {
            return oidc.authenticate(&credentials, replay).await;
        }
        authenticate_static_bearer(&credentials, &self.bearer_tokens)
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

impl OidcAuthenticator {
    fn from_config(config: &StandaloneRegistryNotaryConfig) -> Result<Self, StandaloneServerError> {
        let oidc = config.auth.oidc.as_ref().ok_or_else(|| {
            StandaloneServerError::InvalidOidcConfig("auth.oidc is required".to_string())
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
        let userinfo_requires_exp = !(config.subject_access.enabled
            && config.subject_access.subject_binding.claim_source
                == SubjectAccessClaimSource::Userinfo);
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
            .subject_access
            .enabled
            .then(|| config.subject_access.subject_binding.token_claim.clone())
            .filter(|claim| !claim.is_empty());
        let notary_anchor = Authenticator::build_notary_anchor(
            config,
            oidc.principal_claim.clone(),
            subject_binding_claim.clone(),
        )?;
        Ok(Self {
            verifier: Arc::new(verifier),
            fetch_url_policy,
            principal_claim: oidc.principal_claim.clone(),
            subject_binding_claim,
            subject_binding_claim_source: config.subject_access.subject_binding.claim_source,
            assurance_claim_source: config.subject_access.token_policy.assurance_claim_source,
            userinfo_endpoint: oidc.userinfo_endpoint.clone(),
            userinfo_issuers,
            notary_anchor,
        })
    }

    async fn authenticate(
        &self,
        credentials: &RequestCredentials,
        replay: &ReplayStores,
    ) -> Result<EvidencePrincipal, EvidenceError> {
        // Route by the unverified issuer only to select a verifier. The chosen
        // verifier still validates signature, algorithm, type, issuer,
        // audience, and lifetime, and failure never falls back to another
        // bearer-token verifier.
        if let Some(anchor) = &self.notary_anchor {
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
            credentials,
            &self.verifier,
            &self.fetch_url_policy,
            &self.principal_claim,
            self.subject_binding_claim.as_deref(),
            self.subject_binding_claim_source,
            self.assurance_claim_source,
            self.userinfo_endpoint.as_deref(),
            &self.userinfo_issuers,
        )
        .await
    }
}
