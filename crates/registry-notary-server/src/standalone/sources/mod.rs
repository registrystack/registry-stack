use super::*;

#[derive(Clone)]
pub(super) struct ResolvedEvidenceSourceConnection {
    pub(super) id: String,
    pub(super) base_url: String,
    pub(super) auth: SourceAuthRuntime,
    pub(super) fetch_url_policy: FetchUrlPolicy,
    pub(super) dci: DciSourceConnectionConfig,
    /// Process-global cap on concurrent outbound calls to this connection.
    /// Permits are acquired in `read_one` and held across retries so a flaky
    /// upstream cannot temporarily exceed the politeness cap by quick retry.
    pub(super) semaphore: Arc<Semaphore>,
    pub(super) max_in_flight: usize,
    pub(super) retry_on_5xx: bool,
    /// Bulk-read mode for this connection. See `BulkMode` for the available
    /// strategies. `None` disables bulk specialization and the runtime never
    /// invokes the specialized `read_many` path for this connection.
    pub(super) bulk_mode: BulkMode,
    /// Upper bound for the per-call timeout used by `read_many`.
    pub(super) bulk_timeout_max: Duration,
    pub(super) expected_sidecar: Option<ExpectedSidecarRuntime>,
}

#[derive(Clone)]
pub(super) enum SourceAuthRuntime {
    StaticBearer(Arc<str>),
    Oauth2ClientCredentials(Arc<Oauth2ClientCredentialsRuntime>),
}

impl std::fmt::Debug for SourceAuthRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SourceAuthRuntime::StaticBearer(_) => f.write_str("StaticBearer(<redacted>)"),
            SourceAuthRuntime::Oauth2ClientCredentials(_) => {
                f.write_str("Oauth2ClientCredentials(<redacted>)")
            }
        }
    }
}

pub(super) struct Oauth2ClientCredentialsRuntime {
    token_url: reqwest::Url,
    client_id: String,
    client_secret: String,
    request_format: String,
    scope: String,
    refresh_skew: Duration,
    cache: Mutex<Option<CachedSourceToken>>,
}

impl std::fmt::Debug for Oauth2ClientCredentialsRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Oauth2ClientCredentialsRuntime")
            .field("token_url", &self.token_url)
            .field("client_id", &"<redacted>")
            .field("client_secret", &"<redacted>")
            .field("request_format", &self.request_format)
            .field("scope", &self.scope)
            .field("refresh_skew", &self.refresh_skew)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(super) struct CachedSourceToken {
    pub(super) access_token: String,
    pub(super) refresh_after: Instant,
}

impl std::fmt::Debug for CachedSourceToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedSourceToken")
            .field("access_token", &"<redacted>")
            .field("refresh_after", &self.refresh_after)
            .finish()
    }
}

impl SourceAuthRuntime {
    pub(super) async fn bearer_token(
        &self,
        fetch_url_policy: &FetchUrlPolicy,
        force_refresh: bool,
    ) -> Result<String, EvidenceError> {
        match self {
            SourceAuthRuntime::StaticBearer(token) => Ok(token.to_string()),
            SourceAuthRuntime::Oauth2ClientCredentials(runtime) => {
                runtime.bearer_token(fetch_url_policy, force_refresh).await
            }
        }
    }

    pub(super) fn can_refresh(&self) -> bool {
        matches!(self, SourceAuthRuntime::Oauth2ClientCredentials(_))
    }
}

impl Oauth2ClientCredentialsRuntime {
    async fn bearer_token(
        &self,
        fetch_url_policy: &FetchUrlPolicy,
        force_refresh: bool,
    ) -> Result<String, EvidenceError> {
        let mut cache = self.cache.lock().await;
        let now = Instant::now();
        if !force_refresh {
            if let Some(token) = cache.as_ref() {
                if token.refresh_after > now {
                    return Ok(token.access_token.clone());
                }
            }
        }
        let token = self.fetch_token(fetch_url_policy).await?;
        let access_token = token.access_token.clone();
        *cache = Some(token);
        Ok(access_token)
    }

    async fn fetch_token(
        &self,
        fetch_url_policy: &FetchUrlPolicy,
    ) -> Result<CachedSourceToken, EvidenceError> {
        let validated_url = match fetch_url_policy
            .validate_for_immediate_fetch_with_timeout(&self.token_url, SOURCE_REQUEST_TIMEOUT)
            .await
        {
            Ok(validated_url) => validated_url,
            Err(error) => {
                tracing::warn!(
                    target: "registry_notary_server::outbound",
                    scheme = self.token_url.scheme(),
                    host = self.token_url.host_str().unwrap_or("<missing>"),
                    error = %error,
                    "source OAuth token URL rejected by fetch policy",
                );
                return Err(EvidenceError::SourceUnavailable);
            }
        };
        let mut request = match pinned_request_builder(
            &validated_url,
            reqwest::Method::POST,
            SOURCE_REQUEST_TIMEOUT,
        ) {
            Ok(request) => request
                .timeout(SOURCE_REQUEST_TIMEOUT)
                .header("accept", "application/json"),
            Err(error) => {
                tracing::error!(
                    target: "registry_notary_server::outbound",
                    scheme = self.token_url.scheme(),
                    host = self.token_url.host_str().unwrap_or("<missing>"),
                    error = %error,
                    "source OAuth token request could not use pinned fetch target",
                );
                return Err(EvidenceError::SourceUnavailable);
            }
        };
        tracing::debug!(
            target: "registry_notary_server::outbound",
            scheme = self.token_url.scheme(),
            host = self.token_url.host_str().unwrap_or("<missing>"),
            resolved_ips = ?validated_url.resolved_ips(),
            "source OAuth token URL validated for pinned immediate fetch",
        );
        if validated_url.url() != &self.token_url {
            tracing::warn!(
                target: "registry_notary_server::outbound",
                scheme = self.token_url.scheme(),
                host = self.token_url.host_str().unwrap_or("<missing>"),
                "source OAuth token URL changed during validation",
            );
            return Err(EvidenceError::SourceUnavailable);
        }
        let mut params = BTreeMap::new();
        params.insert("grant_type", "client_credentials");
        params.insert("client_id", self.client_id.as_str());
        params.insert("client_secret", self.client_secret.as_str());
        if !self.scope.trim().is_empty() {
            params.insert("scope", self.scope.as_str());
        }
        request = match self.request_format.as_str() {
            "json" => request.json(&params),
            "form" => request.form(&params),
            _ => return Err(EvidenceError::SourceUnavailable),
        };
        let response = request.send().await.map_err(|error| {
            tracing::error!(
                target: "registry_notary_server::outbound",
                scheme = self.token_url.scheme(),
                host = self.token_url.host_str().unwrap_or("<missing>"),
                path = self.token_url.path(),
                error = %error,
                "source OAuth token request failed",
            );
            EvidenceError::SourceUnavailable
        })?;
        if !response.status().is_success() {
            let status = response.status();
            tracing::error!(
                target: "registry_notary_server::outbound",
                scheme = self.token_url.scheme(),
                host = self.token_url.host_str().unwrap_or("<missing>"),
                path = self.token_url.path(),
                status = %status,
                "source OAuth token endpoint returned error status",
            );
            return Err(EvidenceError::SourceUnavailable);
        }
        let body = match read_source_json(response).await {
            Ok(body) => body,
            Err(error) => {
                tracing::error!(
                    target: "registry_notary_server::outbound",
                    scheme = self.token_url.scheme(),
                    host = self.token_url.host_str().unwrap_or("<missing>"),
                    path = self.token_url.path(),
                    "source OAuth token response could not be parsed",
                );
                return Err(error);
            }
        };
        let access_token = body
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| {
                tracing::error!(
                    target: "registry_notary_server::outbound",
                    scheme = self.token_url.scheme(),
                    host = self.token_url.host_str().unwrap_or("<missing>"),
                    path = self.token_url.path(),
                    "source OAuth token response was missing access_token",
                );
                EvidenceError::SourceUnavailable
            })?
            .to_string();
        let expires_in = body
            .get("expires_in")
            .and_then(Value::as_u64)
            .unwrap_or(300);
        let ttl = Duration::from_secs(expires_in);
        let refresh_after = Instant::now()
            + ttl
                .checked_sub(self.refresh_skew)
                .unwrap_or_else(|| Duration::from_secs(0));
        Ok(CachedSourceToken {
            access_token,
            refresh_after,
        })
    }
}

impl std::fmt::Debug for ResolvedEvidenceSourceConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResolvedEvidenceSourceConnection")
            .field("id", &self.id)
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .field("fetch_url_policy", &self.fetch_url_policy)
            .field("dci", &self.dci)
            .field("max_in_flight", &self.max_in_flight)
            .field("retry_on_5xx", &self.retry_on_5xx)
            .field("bulk_mode", &self.bulk_mode)
            .field("bulk_timeout_max", &self.bulk_timeout_max)
            .field(
                "expected_sidecar",
                &self.expected_sidecar.as_ref().map(|_| "<configured>"),
            )
            .finish()
    }
}

#[derive(Debug, Clone)]
pub struct HttpEvidenceSources {
    pub(super) request_timeout: Duration,
    pub(super) source_connections: BTreeMap<String, ResolvedEvidenceSourceConnection>,
    pub(super) metrics: Arc<AppMetrics>,
}

impl HttpEvidenceSources {
    pub(crate) fn from_config(
        config: &EvidenceConfig,
        metrics: Arc<AppMetrics>,
    ) -> Result<Self, StandaloneServerError> {
        let mut source_connections = BTreeMap::new();
        for (id, connection) in &config.source_connections {
            let auth = resolve_source_auth(connection)?;
            source_connections.insert(
                id.clone(),
                ResolvedEvidenceSourceConnection {
                    id: id.clone(),
                    base_url: connection.base_url.clone(),
                    auth,
                    fetch_url_policy: source_fetch_url_policy(connection),
                    dci: connection.effective_dci()?,
                    semaphore: Arc::new(Semaphore::new(connection.max_in_flight)),
                    max_in_flight: connection.max_in_flight,
                    retry_on_5xx: connection.retry_on_5xx,
                    bulk_mode: connection.bulk_mode,
                    bulk_timeout_max: Duration::from_millis(connection.bulk_timeout_max_ms),
                    expected_sidecar: connection.expected_sidecar.clone().map(|expected| {
                        ExpectedSidecarRuntime {
                            ttl: Duration::from_millis(expected.assurance_ttl_ms),
                            expected,
                            cache: Arc::new(StdMutex::new(None)),
                        }
                    }),
                },
            );
        }
        Ok(Self {
            request_timeout: SOURCE_REQUEST_TIMEOUT,
            source_connections,
            metrics,
        })
    }

    pub(super) fn source_connection(
        &self,
        binding: &SourceBindingConfig,
    ) -> Option<&ResolvedEvidenceSourceConnection> {
        binding
            .connection
            .as_deref()
            .and_then(|connection| self.source_connections.get(connection))
    }
}

pub(super) fn resolve_source_auth(
    connection: &SourceConnectionConfig,
) -> Result<SourceAuthRuntime, StandaloneServerError> {
    if let Some(source_auth) = &connection.source_auth {
        return match source_auth {
            SourceAuthConfig::Oauth2ClientCredentials(config) => {
                Ok(SourceAuthRuntime::Oauth2ClientCredentials(Arc::new(
                    resolve_oauth_source_auth(config)?,
                )))
            }
        };
    }
    let bearer_token = env::var(&connection.token_env)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            StandaloneServerError::MissingSourceTokenEnv(connection.token_env.clone())
        })?;
    Ok(SourceAuthRuntime::StaticBearer(Arc::from(
        bearer_token.into_boxed_str(),
    )))
}

pub(super) fn resolve_oauth_source_auth(
    config: &Oauth2ClientCredentialsSourceAuthConfig,
) -> Result<Oauth2ClientCredentialsRuntime, StandaloneServerError> {
    let client_id = env::var(&config.client_id_env)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            StandaloneServerError::MissingSourceTokenEnv(config.client_id_env.clone())
        })?;
    let client_secret = env::var(&config.client_secret_env)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            StandaloneServerError::MissingSourceTokenEnv(config.client_secret_env.clone())
        })?;
    let token_url = reqwest::Url::parse(&config.token_url)
        .map_err(|_| StandaloneServerError::InvalidSourceAuth("invalid token_url".to_string()))?;
    Ok(Oauth2ClientCredentialsRuntime {
        token_url,
        client_id,
        client_secret,
        request_format: config.request_format.clone(),
        scope: config.scope.clone(),
        refresh_skew: Duration::from_secs(config.refresh_skew_seconds),
        cache: Mutex::new(None),
    })
}

pub(super) fn source_fetch_url_policy(connection: &SourceConnectionConfig) -> FetchUrlPolicy {
    if connection.allow_insecure_private_network {
        FetchUrlPolicy {
            allowed_schemes: vec!["http".to_string(), "https".to_string()],
            allow_localhost: true,
            allow_http_private_network: true,
            deny_private_ranges: false,
            deny_cloud_metadata: true,
        }
    } else if connection.allow_insecure_localhost {
        FetchUrlPolicy::dev()
    } else {
        FetchUrlPolicy::strict()
    }
}

impl SourceReader for HttpEvidenceSources {
    fn has_readiness_check(&self) -> bool {
        self.source_connections
            .values()
            .any(|connection| connection.expected_sidecar.is_some())
    }

    fn check_ready<'a>(&'a self) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async move {
            for connection in self.source_connections.values() {
                if connection.expected_sidecar.is_some()
                    && ensure_source_adapter_sidecar_assurance(self, connection)
                        .await
                        .is_err()
                {
                    return false;
                }
            }
            true
        })
    }

    fn observed_sidecar_config_hashes<'a>(
        &'a self,
        evidence: &'a EvidenceConfig,
        claim_ids: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Vec<String>> + Send + 'a>> {
        Box::pin(async move {
            let mut hashes = BTreeSet::new();
            for claim_id in claim_ids {
                let Some(claim) = evidence.claims.iter().find(|claim| claim.id == *claim_id) else {
                    continue;
                };
                for binding in claim.source_bindings.values() {
                    if binding.connector != SourceConnectorKind::SourceAdapterSidecar {
                        continue;
                    }
                    let Some(connection) = self.source_connection(binding) else {
                        continue;
                    };
                    if let Some(config_hash) = cached_source_adapter_sidecar_config_hash(connection)
                    {
                        hashes.insert(config_hash);
                    }
                }
            }
            hashes.into_iter().collect()
        })
    }

    fn observed_source_runtimes<'a>(
        &'a self,
        evidence: &'a EvidenceConfig,
        claim_id: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<SourceRuntimeSummary>> + Send + 'a>> {
        Box::pin(async move {
            let Some(claim) = evidence.claims.iter().find(|claim| claim.id == claim_id) else {
                return Vec::new();
            };
            // Deduplicate on config_hash: two bindings can share one sidecar.
            let mut summaries: BTreeMap<String, SourceRuntimeSummary> = BTreeMap::new();
            for binding in claim.source_bindings.values() {
                if binding.connector != SourceConnectorKind::SourceAdapterSidecar {
                    continue;
                }
                let Some(connection) = self.source_connection(binding) else {
                    continue;
                };
                if let Some(summary) = cached_source_adapter_sidecar_runtime_summary(connection) {
                    summaries.insert(summary.config_hash.clone(), summary);
                }
            }
            summaries.into_values().collect()
        })
    }

    fn read_one<'a>(
        &'a self,
        binding: &'a SourceBindingConfig,
        subject: &'a SubjectRequest,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async move {
            let connection = self
                .source_connection(binding)
                .ok_or(EvidenceError::SourceUnavailable)?;
            match binding.connector {
                SourceConnectorKind::RegistryDataApi => {
                    read_remote_registry_data_api_one(self, connection, binding, subject, purpose)
                        .await
                }
                SourceConnectorKind::SourceAdapterSidecar => {
                    ensure_source_adapter_sidecar_assurance(self, connection).await?;
                    read_remote_registry_data_api_one(self, connection, binding, subject, purpose)
                        .await
                }
                SourceConnectorKind::Dci => {
                    read_external_dci_http_one(self, connection, binding, subject, purpose).await
                }
            }
        })
    }

    fn read_one_for_context<'a>(
        &'a self,
        binding: &'a SourceBindingConfig,
        context: &'a EvidenceRequestContext,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        Box::pin(async move {
            let connection = self
                .source_connection(binding)
                .ok_or(EvidenceError::SourceUnavailable)?;
            match binding.connector {
                SourceConnectorKind::RegistryDataApi => {
                    read_remote_registry_data_api_one_for_context(
                        self, connection, binding, context, purpose,
                    )
                    .await
                }
                SourceConnectorKind::SourceAdapterSidecar => {
                    ensure_source_adapter_sidecar_assurance(self, connection).await?;
                    read_remote_registry_data_api_one_for_context(
                        self, connection, binding, context, purpose,
                    )
                    .await
                }
                SourceConnectorKind::Dci => {
                    read_external_dci_http_one_for_context(
                        self, connection, binding, context, purpose,
                    )
                    .await
                }
            }
        })
    }

    fn source_observed_at_for_context<'a>(
        &'a self,
        binding: &'a SourceBindingConfig,
        context: &'a EvidenceRequestContext,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Option<OffsetDateTime>, EvidenceError>> + Send + 'a>>
    {
        Box::pin(async move {
            let connection = self
                .source_connection(binding)
                .ok_or(EvidenceError::SourceUnavailable)?;
            match binding.connector {
                SourceConnectorKind::RegistryDataApi => {
                    read_remote_registry_data_api_source_observed_at_for_context(
                        self, connection, binding, context, purpose,
                    )
                    .await
                }
                SourceConnectorKind::SourceAdapterSidecar => {
                    ensure_source_adapter_sidecar_assurance(self, connection).await?;
                    read_remote_registry_data_api_source_observed_at_for_context(
                        self, connection, binding, context, purpose,
                    )
                    .await
                }
                SourceConnectorKind::Dci => {
                    read_external_dci_source_observed_at_for_context(
                        self, connection, binding, context, purpose,
                    )
                    .await
                }
            }
        })
    }

    fn read_many<'a>(
        &'a self,
        bindings: Vec<(SourceBindingConfig, SubjectRequest)>,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<Result<Value, EvidenceError>>> + Send + 'a>> {
        Box::pin(async move {
            if bindings.is_empty() {
                return Vec::new();
            }
            // Determine the bulk mode from the first binding's connection.
            // The runtime guarantees every binding in this batch shares the
            // same (connection_id, dataset, entity, lookup_field, fields)
            // tuple, so they share `bulk_mode` too.
            let connection = match self.source_connection(&bindings[0].0) {
                Some(c) => c,
                None => {
                    return bindings
                        .iter()
                        .map(|_| Err(EvidenceError::SourceUnavailable))
                        .collect();
                }
            };
            tracing::info!(
                target: "registry_notary_server::bulk",
                connection_id = %connection.id,
                bulk_mode = ?connection.bulk_mode,
                bulk_request_size = bindings.len(),
                "bulk_request_size",
            );
            let outcome: Vec<Result<Value, EvidenceError>> = match connection.bulk_mode {
                BulkMode::None => {
                    tracing::info!(
                        target: "registry_notary_server::bulk",
                        connection_id = %connection.id,
                        path = "fallback",
                        "bulk_vs_fallback",
                    );
                    fallback_concurrent_read_one(self, &bindings, purpose).await
                }
                BulkMode::RdaInFilter => {
                    tracing::info!(
                        target: "registry_notary_server::bulk",
                        connection_id = %connection.id,
                        path = "bulk",
                        "bulk_vs_fallback",
                    );
                    read_remote_registry_data_api_many(self, connection, &bindings, purpose).await
                }
                BulkMode::DciBatchedSearch => {
                    tracing::info!(
                        target: "registry_notary_server::bulk",
                        connection_id = %connection.id,
                        path = "bulk",
                        "bulk_vs_fallback",
                    );
                    read_external_dci_http_many(self, connection, &bindings, purpose).await
                }
                BulkMode::SourceAdapterSidecarBatch => {
                    tracing::info!(
                        target: "registry_notary_server::bulk",
                        connection_id = %connection.id,
                        path = "bulk",
                        "bulk_vs_fallback",
                    );
                    if bindings.iter().all(|(binding, _)| {
                        binding.connector == SourceConnectorKind::SourceAdapterSidecar
                    }) {
                        if ensure_source_adapter_sidecar_assurance(self, connection)
                            .await
                            .is_err()
                        {
                            return bindings
                                .iter()
                                .map(|_| Err(EvidenceError::SourceUnavailable))
                                .collect();
                        }
                        let context_bindings: Vec<(SourceBindingConfig, EvidenceRequestContext)> =
                            bindings
                                .iter()
                                .map(|(binding, subject)| {
                                    (
                                        binding.clone(),
                                        EvidenceRequestContext {
                                            requester: None,
                                            target: EvidenceEntity::from_subject_request(
                                                binding.lookup.input.as_str(),
                                                subject.clone(),
                                            ),
                                            relationship: None,
                                            on_behalf_of: None,
                                        },
                                    )
                                })
                                .collect();
                        read_remote_source_adapter_sidecar_many_context(
                            self,
                            connection,
                            &context_bindings,
                            purpose,
                        )
                        .await
                    } else {
                        fallback_concurrent_read_one(self, &bindings, purpose).await
                    }
                }
            };
            outcome
        })
    }

    fn read_many_context<'a>(
        &'a self,
        bindings: Vec<(SourceBindingConfig, EvidenceRequestContext)>,
        purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Vec<Result<Value, EvidenceError>>> + Send + 'a>> {
        Box::pin(async move {
            if !bindings.is_empty() {
                if let Some(connection) = self.source_connection(&bindings[0].0) {
                    if connection.bulk_mode == BulkMode::SourceAdapterSidecarBatch
                        && bindings.iter().all(|(binding, _)| {
                            binding.connector == SourceConnectorKind::SourceAdapterSidecar
                        })
                    {
                        tracing::info!(
                            target: "registry_notary_server::bulk",
                            connection_id = %connection.id,
                            path = "bulk",
                            "bulk_vs_fallback",
                        );
                        if ensure_source_adapter_sidecar_assurance(self, connection)
                            .await
                            .is_err()
                        {
                            return bindings
                                .iter()
                                .map(|_| Err(EvidenceError::SourceUnavailable))
                                .collect();
                        }
                        return read_remote_source_adapter_sidecar_many_context(
                            self, connection, &bindings, purpose,
                        )
                        .await;
                    }
                }
            }
            if let Some(subject_bindings) = canonical_subject_bindings(&bindings) {
                return self.read_many(subject_bindings, purpose).await;
            }
            fallback_concurrent_read_one_for_context(self, &bindings, purpose).await
        })
    }

    fn required_scopes(
        &self,
        evidence: &EvidenceConfig,
        claim_id: &str,
    ) -> Result<Vec<String>, EvidenceError> {
        let claim = crate::find_claim(evidence, claim_id)?;
        self.required_scopes_for_claim(evidence, claim)
    }

    fn required_scopes_for_claim(
        &self,
        evidence: &EvidenceConfig,
        claim: &registry_notary_core::ClaimDefinition,
    ) -> Result<Vec<String>, EvidenceError> {
        let mut scopes = Vec::new();
        collect_claim_required_scopes_for_claim(evidence, claim, &mut scopes)?;
        scopes.sort();
        scopes.dedup();
        Ok(scopes)
    }
}

/// Run `read_one` concurrently for each binding (collision-fallback path for
/// bulk specializations and the BulkMode::None branch).
pub(super) async fn fallback_concurrent_read_one(
    sources: &HttpEvidenceSources,
    bindings: &[(SourceBindingConfig, SubjectRequest)],
    purpose: &str,
) -> Vec<Result<Value, EvidenceError>> {
    use std::task::{Context, Poll};

    if bindings.is_empty() {
        return Vec::new();
    }
    #[allow(clippy::type_complexity)]
    let mut futures: Vec<
        Option<Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + '_>>>,
    > = bindings
        .iter()
        .map(|(binding, subject)| Some(sources.read_one(binding, subject, purpose)))
        .collect();
    let mut results: Vec<Option<Result<Value, EvidenceError>>> =
        (0..futures.len()).map(|_| None).collect();
    std::future::poll_fn(move |cx: &mut Context<'_>| {
        let mut all_done = true;
        for (idx, slot) in futures.iter_mut().enumerate() {
            if let Some(fut) = slot.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(value) => {
                        results[idx] = Some(value);
                        *slot = None;
                    }
                    Poll::Pending => {
                        all_done = false;
                    }
                }
            }
        }
        if all_done {
            Poll::Ready(std::mem::take(&mut results))
        } else {
            Poll::Pending
        }
    })
    .await
    .into_iter()
    .map(|slot| slot.expect("every slot populated"))
    .collect()
}

pub(super) async fn fallback_concurrent_read_one_for_context(
    sources: &HttpEvidenceSources,
    bindings: &[(SourceBindingConfig, EvidenceRequestContext)],
    purpose: &str,
) -> Vec<Result<Value, EvidenceError>> {
    use std::task::{Context, Poll};

    if bindings.is_empty() {
        return Vec::new();
    }
    #[allow(clippy::type_complexity)]
    let mut futures: Vec<
        Option<Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + '_>>>,
    > = bindings
        .iter()
        .map(|(binding, context)| Some(sources.read_one_for_context(binding, context, purpose)))
        .collect();
    let mut results: Vec<Option<Result<Value, EvidenceError>>> =
        (0..futures.len()).map(|_| None).collect();
    std::future::poll_fn(move |cx: &mut Context<'_>| {
        let mut all_done = true;
        for (idx, slot) in futures.iter_mut().enumerate() {
            if let Some(fut) = slot.as_mut() {
                match fut.as_mut().poll(cx) {
                    Poll::Ready(value) => {
                        results[idx] = Some(value);
                        *slot = None;
                    }
                    Poll::Pending => {
                        all_done = false;
                    }
                }
            }
        }
        if all_done {
            Poll::Ready(std::mem::take(&mut results))
        } else {
            Poll::Pending
        }
    })
    .await
    .into_iter()
    .map(|slot| slot.expect("every slot populated"))
    .collect()
}

/// Batch-aware timeout budget: scale the per-call timeout with N up to a
/// configured cap. Default RDA/DCI single-call timeout is
/// `SOURCE_REQUEST_TIMEOUT` (10s); a 100-subject bulk call gets 10 * ceil(100/10)
/// = 100s, capped at `bulk_timeout_max` (30s by default).
pub(super) fn bulk_timeout(
    connection: &ResolvedEvidenceSourceConnection,
    batch_size: usize,
) -> Duration {
    let base = SOURCE_REQUEST_TIMEOUT.as_millis() as u64;
    let factor = batch_size.div_ceil(10).max(1) as u64;
    let scaled = Duration::from_millis(base.saturating_mul(factor));
    scaled.min(connection.bulk_timeout_max)
}
