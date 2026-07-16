use super::*;

/// The eSignet-verified subject extracted at the offer callback.
///
/// `subject_binding_value` (the civil ID) is load-bearing; `Debug` redacts the
/// civil ID and the eSignet subject so they never reach logs.
pub(crate) struct EsignetSubject {
    pub(crate) subject: String,
    pub(crate) subject_binding_value: String,
    pub(crate) client_id: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) acr: Option<String>,
    pub(crate) auth_time: Option<i64>,
}

impl std::fmt::Debug for EsignetSubject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EsignetSubject")
            .field("subject", &"[redacted]")
            .field("subject_binding_value", &"[redacted]")
            .field("client_id", &self.client_id)
            .field("scopes", &self.scopes)
            .field("acr", &self.acr)
            .field("auth_time", &self.auth_time)
            .finish()
    }
}

/// Runtime for the pre-authorized-code flow: the dedicated access-token signer
/// (never the credential key), the eSignet RP credentials and verifier for the
/// citizen login leg, and the short-lived login-state store.
///
/// Built only when both `oid4vci.pre_authorized_code.enabled` and
/// `auth.access_token_signing.enabled` are set; otherwise the flow's endpoints
/// stay `404`.
pub(crate) struct PreAuthRuntime {
    /// Dedicated access-token signing key (mints the pre-authorized code and
    /// the access token). Distinct from the SD-JWT VC credential key (enforced
    /// by config validation).
    access_token_signer: Arc<dyn SigningProvider>,
    /// Public keys accepted by the in-process second verifier, with rotation
    /// expiry metadata preserved for runtime checks.
    access_token_verification_keys: Vec<AccessTokenVerificationKey>,
    /// Notary issuer stamped into and pinned for Notary-minted tokens.
    notary_issuer: String,
    /// Audiences stamped into Notary access tokens.
    notary_audiences: Vec<String>,
    /// Header `typ` for the Notary access token.
    access_token_typ: String,
    /// Pre-authorized code lifetime, seconds.
    pre_authorized_code_ttl_seconds: u64,
    /// Access-token lifetime, seconds.
    access_token_ttl_seconds: u64,
    /// Whether the offer includes a wallet-entered `tx_code` PIN.
    tx_code_required: bool,
    /// `tx_code` length (numeric PIN).
    tx_code_length: u64,
    /// eSignet confidential client id presented by the Notary RP.
    esignet_client_id: String,
    /// eSignet RP signer for the `private_key_jwt` client assertion.
    esignet_client_signer: Arc<dyn SigningProvider>,
    esignet_authorize_url: String,
    esignet_token_url: String,
    esignet_redirect_uri: String,
    esignet_scopes: Vec<String>,
    /// eSignet issuer, accepted as the userinfo JWS `iss` when the subject
    /// binding is userinfo-sourced.
    esignet_issuer: String,
    /// eSignet userinfo endpoint. `Some` only when the subject-binding claim is
    /// userinfo-sourced; the callback fetches the userinfo JWS from here.
    esignet_userinfo_url: Option<String>,
    /// How the subject-binding claim is sourced. `Userinfo` makes the callback
    /// fetch the eSignet userinfo JWS; otherwise the binding value is read from
    /// the `id_token`.
    subject_binding_claim_source: SubjectAccessClaimSource,
    /// Claim name that must bind the credential subject during the citizen
    /// login leg.
    subject_binding_claim: String,
    /// eSignet `id_token` verifier (pins eSignet `iss`, `aud`=RP client_id,
    /// signature via the eSignet JWKS, `exp`/`nbf`). Also verifies the userinfo
    /// JWS (same eSignet signing keys) when the binding is userinfo-sourced.
    esignet_id_token_verifier: Arc<TokenVerifier>,
    fetch_url_policy: FetchUrlPolicy,
    login_state_ttl_seconds: u64,
    /// Typed state contract for login-state and code-redemption transactions.
    preauthorization_state: Arc<crate::preauth_state::PreauthorizationState>,
    /// Audit pipeline so the callback and token endpoints (public, so not
    /// covered by the auth-audit middleware) can emit hashed audit events.
    audit: AuditPipeline,
}

impl std::fmt::Debug for PreAuthRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreAuthRuntime")
            .field("notary_issuer", &self.notary_issuer)
            .field("notary_audiences", &self.notary_audiences)
            .field("access_token_typ", &self.access_token_typ)
            .field("esignet_client_id", &self.esignet_client_id)
            .field("esignet_authorize_url", &self.esignet_authorize_url)
            .field("esignet_token_url", &self.esignet_token_url)
            .finish_non_exhaustive()
    }
}

pub(super) const ESIGNET_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
pub(super) const ESIGNET_MAX_RESPONSE_BYTES: u64 = 64 * 1024;
pub(super) const PRIVATE_KEY_JWT_CLIENT_ASSERTION_TYPE: &str =
    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// The eSignet token-endpoint response material the callback needs: the
/// `id_token` (always) and the `access_token` (used to fetch userinfo when the
/// subject binding is userinfo-sourced).
pub(super) struct EsignetTokenResponse {
    id_token: String,
    access_token: Option<String>,
}

/// Read the subject-binding claim value from verified OIDC claims (the
/// `id_token` or the userinfo JWS).
pub(super) fn subject_binding_value_from_claims(
    claims: &registry_platform_oidc::Claims,
    subject_binding_claim: &str,
) -> Result<String, EvidenceError> {
    let value = if subject_binding_claim == "sub" {
        claims.sub.clone().ok_or(EvidenceError::MissingCredential)?
    } else {
        claims
            .extra
            .get(subject_binding_claim)
            .and_then(Value::as_str)
            .ok_or(EvidenceError::MissingCredential)?
            .to_string()
    };
    if value.trim().is_empty() {
        return Err(EvidenceError::MissingCredential);
    }
    Ok(value)
}

/// Read the subject-binding claim from a verified `id_token`.
pub(super) fn subject_binding_value_from_id_token(
    verified: &VerifiedToken,
    subject_binding_claim: &str,
) -> Result<String, EvidenceError> {
    subject_binding_value_from_claims(&verified.claims, subject_binding_claim)
}

/// Build the verifier config for eSignet `id_token`s and userinfo JWS.
///
/// The `id_token`'s `aud` is the RP client_id, so eSignet's issuer is pinned and
/// the RP client_id is the only accepted audience. MOSIP eSignet signs its
/// userinfo JWS without an `exp` claim (OpenID Connect Core makes `exp` optional
/// for UserInfo responses), so this verifier must not require one; requiring it
/// would reject every eSignet userinfo response and fail userinfo-sourced
/// subject binding.
pub(super) fn esignet_token_verifier_config(issuer: &str, client_id: &str) -> TokenVerifierConfig {
    TokenVerifierConfig::access_token_profile(
        issuer.to_string(),
        vec![client_id.to_string()],
        vec![
            Algorithm::EdDSA,
            Algorithm::RS256,
            Algorithm::PS256,
            Algorithm::ES256,
        ],
        vec!["JWT".to_string()],
    )
    .with_userinfo_requires_exp(false)
}

impl PreAuthRuntime {
    pub(super) fn from_config(
        config: &StandaloneRegistryNotaryConfig,
        signing_keys: &SigningKeyRegistry,
        audit: AuditPipeline,
        state_plane: Arc<NotaryStatePlaneHandle>,
    ) -> Result<Option<Self>, StandaloneServerError> {
        let pre_auth = &config.oid4vci.pre_authorized_code;
        let signing = &config.auth.access_token_signing;
        if !pre_auth.enabled {
            return Ok(None);
        }
        if !signing.enabled {
            return Err(StandaloneServerError::InvalidOidcConfig(
                "oid4vci.pre_authorized_code.enabled requires auth.access_token_signing.enabled"
                    .to_string(),
            ));
        }
        let access_token_signer = signing_keys
            .signing_provider(signing.signing_key_id.as_str())
            .ok_or_else(|| {
                invalid_signing_key(
                    signing.signing_key_id.as_str(),
                    "active access-token signing key was not built",
                )
            })?;
        let access_token_verification_keys = access_token_verification_keys(config)?;
        let esignet = &pre_auth.esignet;
        let esignet_client_signer = signing_keys
            .signing_provider(esignet.client_signing_key_id.as_str())
            .ok_or_else(|| {
                invalid_signing_key(
                    esignet.client_signing_key_id.as_str(),
                    "active eSignet RP client signing key was not built",
                )
            })?;
        let fetch_url_policy = if esignet.allow_insecure_localhost {
            FetchUrlPolicy::dev()
        } else {
            FetchUrlPolicy::strict()
        };
        let id_token_fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
            esignet.jwks_uri.clone(),
            JwksFetcherConfig::defaults(),
            fetch_url_policy.clone(),
        ));
        let esignet_id_token_verifier = Arc::new(TokenVerifier::new(
            esignet_token_verifier_config(&esignet.issuer, &esignet.client_id),
            id_token_fetcher,
        ));
        Ok(Some(Self {
            access_token_signer,
            access_token_verification_keys,
            notary_issuer: signing.issuer.clone(),
            notary_audiences: signing.audiences.clone(),
            access_token_typ: signing.token_typ.clone(),
            pre_authorized_code_ttl_seconds: pre_auth.pre_authorized_code_ttl_seconds,
            access_token_ttl_seconds: signing.access_token_ttl_seconds,
            tx_code_required: pre_auth.tx_code.required,
            tx_code_length: pre_auth.tx_code.length,
            esignet_client_id: esignet.client_id.clone(),
            esignet_client_signer,
            esignet_authorize_url: esignet.authorize_url.clone(),
            esignet_token_url: esignet.token_url.clone(),
            esignet_redirect_uri: esignet.redirect_uri.clone(),
            esignet_scopes: esignet.scopes.clone(),
            esignet_issuer: esignet.issuer.clone(),
            esignet_userinfo_url: {
                let url = esignet.userinfo_url.trim();
                (!url.is_empty()).then(|| url.to_string())
            },
            subject_binding_claim_source: config.subject_access.subject_binding.claim_source,
            subject_binding_claim: config.subject_access.subject_binding.token_claim.clone(),
            esignet_id_token_verifier,
            fetch_url_policy,
            login_state_ttl_seconds: esignet.login_state_ttl_seconds,
            preauthorization_state: Arc::new(
                crate::preauth_state::PreauthorizationState::from_state_plane(state_plane)
                    .map_err(|_| {
                        StandaloneServerError::InvalidOidcConfig(
                            "preauthorization state could not initialize its process-local key"
                                .to_string(),
                        )
                    })?,
            ),
            audit,
        }))
    }

    /// Emit a hashed pre-auth audit event. Returns an error if emission fails so
    /// callers fail closed rather than silently dropping the audit trail.
    pub(crate) async fn emit_audit(&self, event: &EvidenceAuditEvent) -> Result<(), AuditError> {
        self.audit.emit(event).await
    }

    pub(crate) fn access_token_signer(&self) -> &dyn SigningProvider {
        self.access_token_signer.as_ref()
    }

    pub(crate) fn access_token_verification_keys(&self) -> &[AccessTokenVerificationKey] {
        &self.access_token_verification_keys
    }

    pub(crate) fn notary_issuer(&self) -> &str {
        &self.notary_issuer
    }

    pub(crate) fn notary_audiences(&self) -> &[String] {
        &self.notary_audiences
    }

    pub(crate) fn access_token_typ(&self) -> &str {
        &self.access_token_typ
    }

    pub(crate) fn pre_authorized_code_ttl_seconds(&self) -> u64 {
        self.pre_authorized_code_ttl_seconds
    }

    pub(crate) fn access_token_ttl_seconds(&self) -> u64 {
        self.access_token_ttl_seconds
    }

    pub(crate) fn tx_code_required(&self) -> bool {
        self.tx_code_required
    }

    pub(crate) fn tx_code_length(&self) -> u64 {
        self.tx_code_length
    }

    pub(crate) fn login_state_ttl_seconds(&self) -> u64 {
        self.login_state_ttl_seconds
    }

    pub(crate) fn preauthorization_state(&self) -> &crate::preauth_state::PreauthorizationState {
        self.preauthorization_state.as_ref()
    }

    /// Build the eSignet authorization redirect URL for the citizen browser.
    ///
    /// PKCE S256, the confidential RP `client_id`, the configured redirect URI
    /// and scopes, plus the caller-provided `state` and `nonce`.
    pub(crate) fn authorize_redirect_url(
        &self,
        state: &str,
        nonce: &str,
        pkce_challenge: &str,
    ) -> Result<String, EvidenceError> {
        let scope = if self.esignet_scopes.is_empty() {
            "openid".to_string()
        } else {
            self.esignet_scopes.join(" ")
        };
        let mut url = reqwest::Url::parse(&self.esignet_authorize_url)
            .map_err(|_| EvidenceError::CredentialIssuanceFailed)?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.esignet_client_id)
            .append_pair("redirect_uri", &self.esignet_redirect_uri)
            .append_pair("scope", &scope)
            .append_pair("state", state)
            .append_pair("nonce", nonce)
            .append_pair("code_challenge", pkce_challenge)
            .append_pair("code_challenge_method", "S256");
        if let Some(claims) = self.authorization_claims_param() {
            url.query_pairs_mut().append_pair("claims", &claims);
        }
        Ok(url.to_string())
    }

    fn authorization_claims_param(&self) -> Option<String> {
        if !matches!(
            self.subject_binding_claim_source,
            SubjectAccessClaimSource::Userinfo
        ) {
            return None;
        }
        let claim = self.subject_binding_claim.trim();
        if claim.is_empty() {
            return None;
        }
        let mut userinfo = Map::new();
        userinfo.insert(claim.to_string(), json!({ "essential": true }));
        Some(json!({ "userinfo": Value::Object(userinfo) }).to_string())
    }

    /// Exchange the eSignet authorization `code` for an `id_token` (and
    /// `access_token`) using `private_key_jwt` client authentication, validate
    /// the `id_token` (signature against the eSignet JWKS, `iss`, `aud`==RP
    /// client_id, `exp`, `nonce`==`expected_nonce`), then extract the subject
    /// claims. The subject-binding value is read from the `id_token` or, when
    /// the binding is userinfo-sourced, fetched from the eSignet userinfo JWS.
    ///
    /// Every failure maps to `EvidenceError::MissingCredential` so the callback
    /// leaks no detail about why the login failed.
    pub(crate) async fn exchange_code_for_subject(
        &self,
        code: &str,
        pkce_verifier: &str,
        expected_nonce: &str,
        subject_binding_claim: &str,
    ) -> Result<EsignetSubject, EvidenceError> {
        let tokens = self
            .esignet_token_exchange(code, pkce_verifier)
            .await
            .map_err(|_| EvidenceError::MissingCredential)?;
        let verified = self
            .esignet_id_token_verifier
            .verify_related_token(&tokens.id_token)
            .await
            .map_err(|err| {
                tracing::warn!(error = %err, "eSignet id_token verification failed");
                EvidenceError::MissingCredential
            })?;
        // Bind the id_token to this login: the nonce must equal the one this
        // Notary generated at offer/start. This is the CSRF/replay guard.
        let nonce = verified
            .claims
            .extra
            .get("nonce")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                tracing::warn!("eSignet id_token missing nonce claim");
                EvidenceError::MissingCredential
            })?;
        if !constant_time_eq(nonce.as_bytes(), expected_nonce.as_bytes()) {
            tracing::warn!("eSignet id_token nonce did not match the offer nonce");
            return Err(EvidenceError::MissingCredential);
        }
        let subject_binding_value = match self.subject_binding_claim_source {
            SubjectAccessClaimSource::Userinfo => {
                self.subject_binding_value_from_userinfo(
                    &verified,
                    subject_binding_claim,
                    tokens.access_token.as_deref(),
                )
                .await?
            }
            SubjectAccessClaimSource::AccessToken => {
                subject_binding_value_from_id_token(&verified, subject_binding_claim)?
            }
        };
        self.esignet_subject(&verified, subject_binding_value)
    }

    /// Resolve the subject-binding claim from the eSignet userinfo JWS. The
    /// callback fetches userinfo with the eSignet access token, verifies the JWS
    /// against the eSignet signing keys, binds it to the `id_token` subject, and
    /// reads the configured binding claim from it.
    async fn subject_binding_value_from_userinfo(
        &self,
        verified_id_token: &VerifiedToken,
        subject_binding_claim: &str,
        access_token: Option<&str>,
    ) -> Result<String, EvidenceError> {
        let userinfo_url = self
            .esignet_userinfo_url
            .as_deref()
            .ok_or(EvidenceError::MissingCredential)?;
        let access_token = access_token.ok_or(EvidenceError::MissingCredential)?;
        let userinfo_jwt = fetch_userinfo_jwt_with_policy(
            userinfo_url,
            access_token,
            &self.fetch_url_policy,
            ESIGNET_REQUEST_TIMEOUT,
            ESIGNET_MAX_RESPONSE_BYTES,
        )
        .await
        .map_err(|err| {
            tracing::warn!(error = %err, "eSignet userinfo fetch failed");
            EvidenceError::MissingCredential
        })?;
        let userinfo = self
            .esignet_id_token_verifier
            .verify_userinfo_jwt_with_claims_policy(
                &userinfo_jwt,
                verified_id_token,
                &[self.esignet_issuer.as_str()],
                std::slice::from_ref(&self.esignet_client_id),
            )
            .await
            .map_err(|err| {
                tracing::warn!(error = %err, "eSignet userinfo verification failed");
                EvidenceError::MissingCredential
            })?;
        subject_binding_value_from_claims(&userinfo, subject_binding_claim)
    }

    /// Build the `EsignetSubject` from the verified `id_token`, carrying the
    /// already-resolved subject-binding value (from the `id_token` or userinfo).
    fn esignet_subject(
        &self,
        verified: &VerifiedToken,
        subject_binding_value: String,
    ) -> Result<EsignetSubject, EvidenceError> {
        let subject = verified
            .claims
            .sub
            .clone()
            .ok_or(EvidenceError::MissingCredential)?;
        let scopes = if verified.scopes.is_empty() {
            verified
                .claims
                .extra
                .get("scope")
                .and_then(Value::as_str)
                .map(|scope| {
                    scope
                        .split(' ')
                        .filter(|s| !s.is_empty())
                        .map(ToString::to_string)
                        .collect()
                })
                .unwrap_or_default()
        } else {
            verified.scopes.clone()
        };
        let acr = verified
            .claims
            .extra
            .get("acr")
            .and_then(Value::as_str)
            .map(ToString::to_string);
        let auth_time = verified
            .claims
            .extra
            .get("auth_time")
            .and_then(Value::as_i64);
        Ok(EsignetSubject {
            subject,
            subject_binding_value,
            // The credential's citizen client is the Notary RP client that
            // authenticated the citizen at eSignet.
            client_id: self.esignet_client_id.clone(),
            scopes,
            acr,
            auth_time,
        })
    }

    async fn esignet_token_exchange(
        &self,
        code: &str,
        pkce_verifier: &str,
    ) -> Result<EsignetTokenResponse, EvidenceError> {
        let token_url = reqwest::Url::parse(&self.esignet_token_url)
            .map_err(|_| EvidenceError::MissingCredential)?;
        let validated_url = self
            .fetch_url_policy
            .validate_for_immediate_fetch_with_timeout(&token_url, ESIGNET_REQUEST_TIMEOUT)
            .await
            .map_err(|_| EvidenceError::MissingCredential)?;
        if validated_url.url() != &token_url {
            return Err(EvidenceError::MissingCredential);
        }
        let request = pinned_request_builder(
            &validated_url,
            reqwest::Method::POST,
            ESIGNET_REQUEST_TIMEOUT,
        )
        .map_err(|_| EvidenceError::MissingCredential)?
        .timeout(ESIGNET_REQUEST_TIMEOUT)
        .header("accept", "application/json");
        let client_assertion = self.client_assertion_jwt().await?;
        let mut params: BTreeMap<&str, &str> = BTreeMap::new();
        params.insert("grant_type", "authorization_code");
        params.insert("code", code);
        params.insert("redirect_uri", self.esignet_redirect_uri.as_str());
        params.insert("client_id", self.esignet_client_id.as_str());
        params.insert("code_verifier", pkce_verifier);
        params.insert(
            "client_assertion_type",
            PRIVATE_KEY_JWT_CLIENT_ASSERTION_TYPE,
        );
        params.insert("client_assertion", client_assertion.as_str());
        let response = request
            .form(&params)
            .send()
            .await
            .map_err(|_| EvidenceError::MissingCredential)?;
        if !response.status().is_success() {
            return Err(EvidenceError::MissingCredential);
        }
        let body = read_bounded(response, ESIGNET_MAX_RESPONSE_BYTES)
            .await
            .map_err(|_| EvidenceError::MissingCredential)?;
        let body: Value =
            serde_json::from_slice(&body).map_err(|_| EvidenceError::MissingCredential)?;
        let id_token = body
            .get("id_token")
            .and_then(Value::as_str)
            .filter(|id_token| !id_token.is_empty())
            .map(ToString::to_string)
            .ok_or(EvidenceError::MissingCredential)?;
        let access_token = body
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|access_token| !access_token.is_empty())
            .map(ToString::to_string);
        Ok(EsignetTokenResponse {
            id_token,
            access_token,
        })
    }

    /// Build the `private_key_jwt` client assertion the eSignet token endpoint
    /// requires (`aud`==token endpoint, `iss`/`sub`==RP client_id, short-lived,
    /// unique `jti`), signed with the RP client signing key.
    async fn client_assertion_jwt(&self) -> Result<String, EvidenceError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let jti = generate_opaque_token().map_err(|_| EvidenceError::MissingCredential)?;
        let payload = json!({
            "iss": self.esignet_client_id,
            "sub": self.esignet_client_id,
            "aud": self.esignet_token_url,
            "iat": now,
            "exp": now + 120,
            "jti": jti,
        });
        let public_jwk = self.esignet_client_signer.public_jwk();
        let kid = public_jwk
            .kid
            .clone()
            .filter(|kid| kid == self.esignet_client_signer.key_id())
            .ok_or(EvidenceError::MissingCredential)?;
        let alg = public_jwk
            .alg
            .clone()
            .unwrap_or_else(|| "EdDSA".to_string());
        let header = json!({ "alg": alg, "typ": "JWT", "kid": kid });
        let header_b64 = base64_url_no_pad(
            &serde_json::to_vec(&header).map_err(|_| EvidenceError::MissingCredential)?,
        );
        let payload_b64 = base64_url_no_pad(
            &serde_json::to_vec(&payload).map_err(|_| EvidenceError::MissingCredential)?,
        );
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature = self
            .esignet_client_signer
            .sign(signing_input.as_bytes())
            .await
            .map_err(|_| EvidenceError::MissingCredential)?;
        Ok(format!("{signing_input}.{}", base64_url_no_pad(&signature)))
    }
}

#[derive(Clone)]
pub(crate) struct AccessTokenVerificationKey {
    pub(super) public_jwk: PublicJwk,
    pub(super) publish_until_unix_seconds: Option<u64>,
}

impl AccessTokenVerificationKey {
    pub(crate) fn public_jwk(&self) -> &PublicJwk {
        &self.public_jwk
    }

    pub(crate) fn may_verify_at(&self, now_unix_seconds: i64) -> bool {
        let Some(publish_until) = self.publish_until_unix_seconds else {
            return true;
        };
        let Ok(now) = u64::try_from(now_unix_seconds) else {
            return false;
        };
        now <= publish_until
    }
}

pub(super) fn access_token_verification_keys(
    config: &StandaloneRegistryNotaryConfig,
) -> Result<Vec<AccessTokenVerificationKey>, StandaloneServerError> {
    let signing = &config.auth.access_token_signing;
    let mut jwks = Vec::with_capacity(1 + signing.verification_key_ids.len());
    let public_jwk =
        signing_key_public_jwk_from_config(&config.evidence, signing.signing_key_id.as_str())?
            .ok_or_else(|| {
                invalid_signing_key(
                    signing.signing_key_id.as_str(),
                    "access-token signing key public JWK was not built",
                )
            })?;
    jwks.push(AccessTokenVerificationKey {
        public_jwk,
        publish_until_unix_seconds: None,
    });
    let now = current_unix_timestamp_seconds();
    for key_id in &signing.verification_key_ids {
        let Some(key) = config.evidence.signing_keys.get(key_id) else {
            continue;
        };
        if !key.may_publish_at(now) {
            continue;
        }
        if let Some(public_jwk) = signing_key_public_jwk_from_config(&config.evidence, key_id)? {
            jwks.push(AccessTokenVerificationKey {
                public_jwk,
                publish_until_unix_seconds: key.publish_until_unix_seconds,
            });
        }
    }
    Ok(jwks)
}

/// Constant-time byte comparison so secret comparisons (nonce, `tx_code`) do
/// not leak length-prefix timing.
pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    left.ct_eq(right).into()
}

pub(super) fn base64_url_no_pad(bytes: &[u8]) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

/// 32 bytes of randomness, base64url-encoded; used for opaque `state`, PKCE
/// verifier, and `jti` values.
pub(crate) fn generate_opaque_token() -> Result<String, EvidenceError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| EvidenceError::CredentialIssuanceFailed)?;
    Ok(base64_url_no_pad(&bytes))
}

/// Derive the PKCE S256 challenge from a verifier.
pub(crate) fn pkce_s256_challenge(verifier: &str) -> String {
    let digest = <sha2::Sha256 as sha2::Digest>::digest(verifier.as_bytes());
    base64_url_no_pad(&digest)
}

/// Generate a numeric `tx_code` (PIN) of the requested length.
///
/// Uses rejection sampling (discarding bytes >= 250) so each digit 0-9 is
/// uniformly likely; `byte % 10` alone would bias toward 0-5 since 256 is not a
/// multiple of 10.
pub(crate) fn generate_numeric_tx_code(length: u64) -> Result<String, EvidenceError> {
    let length = usize::try_from(length).map_err(|_| EvidenceError::CredentialIssuanceFailed)?;
    let mut pin = String::with_capacity(length);
    while pin.len() < length {
        let mut buf = [0_u8; 32];
        getrandom::fill(&mut buf).map_err(|_| EvidenceError::CredentialIssuanceFailed)?;
        for byte in buf {
            if byte < 250 {
                pin.push((b'0' + (byte % 10)) as char);
                if pin.len() == length {
                    break;
                }
            }
        }
    }
    Ok(pin)
}

/// Hashed/metadata-only fields for a pre-auth audit event. Carries no raw code,
/// PIN, or token; only hashes and config metadata.
#[derive(Debug, Default)]
pub(crate) struct PreAuthAuditFields {
    pub(crate) principal_id_hash: Option<Hashed<PrincipalIdentifier>>,
    pub(crate) correlation_id_hash: Option<Hashed<RequestIdentifier>>,
    pub(crate) credential_configuration_id: Option<registry_notary_core::ConfigMetadata>,
    pub(crate) denial_code: Option<SubjectAccessDenialCode>,
    pub(crate) rate_limit_bucket: Option<RateLimitBucket>,
}

/// Build a hashed pre-auth audit event for a public endpoint. The pre-auth
/// `offer/callback` and `/oid4vci/token` paths skip the auth-audit middleware
/// (they are public), so they emit their own audit events.
pub(crate) fn pre_auth_audit_event(
    method: &str,
    path: &str,
    status: u16,
    decision: &str,
    fields: PreAuthAuditFields,
) -> EvidenceAuditEvent {
    let occurred_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    EvidenceAuditEvent {
        event_id: Ulid::new().to_string(),
        occurred_at,
        principal_id_hash: fields.principal_id_hash,
        scopes_used: Vec::new(),
        decision: decision.to_string(),
        method: method.to_string(),
        path: path.to_string(),
        status,
        verification_id: None,
        claim_hash: None,
        purposes: None,
        row_count: None,
        relay_consultation_count: None,
        relay_consultation_ids: Vec::new(),
        forwarded: None,
        error_code: None,
        access_mode: Some(AccessMode::SubjectBound),
        federation_peer_id_hash: None,
        federation_issuer: None,
        federation_profile: None,
        federation_purpose: None,
        federation_request_jti_hash: None,
        federation_subject_ref_hash: None,
        denial_code: fields.denial_code,
        token_claim_name: None,
        correlation_id_hash: fields.correlation_id_hash,
        credential_profile: None,
        protocol: registry_notary_core::ConfigMetadata::new("openid4vci").ok(),
        credential_configuration_id: fields.credential_configuration_id,
        holder_binding_mode: None,
        rate_limit_bucket: fields.rate_limit_bucket,
        policy_version: None,
        policy_hash: None,
        target_type: None,
        target_ref_hash: None,
        requester_type: None,
        requester_ref_hash: None,
        redacted_fields: None,
        batch_items: None,
        config: None,
    }
}
