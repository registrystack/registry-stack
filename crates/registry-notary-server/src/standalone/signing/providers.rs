use super::super::*;

#[derive(Debug, Clone)]
pub(in super::super) struct PublishedJwk {
    public_jwk: Value,
    publish_until_unix_seconds: Option<u64>,
}

impl PublishedJwk {
    fn is_published_at(&self, now_unix_seconds: u64) -> bool {
        self.publish_until_unix_seconds
            .is_none_or(|publish_until| now_unix_seconds <= publish_until)
    }
}

#[derive(Debug, Clone, Default)]
pub struct EvidenceIssuerRegistry {
    issuers: BTreeMap<String, EvidenceIssuer>,
    public_jwks: Vec<PublishedJwk>,
}

impl EvidenceIssuerRegistry {
    pub fn from_config(config: &EvidenceConfig) -> Result<Self, StandaloneServerError> {
        // Without the surrounding `StandaloneRegistryNotaryConfig` this builder
        // only sees credential-profile signing roles, so the resolved-material
        // reuse check (#173) is confined to those here. The access-token and
        // federation roles are checked on the real startup/apply paths
        // (`compile_notary_runtime`, signing-key rotation), which thread the
        // full role set through `SigningKeyRegistry::from_config`.
        let reuse_scoped_key_ids: HashSet<&str> = config
            .credential_profiles
            .values()
            .map(|profile| profile.signing_key.as_str())
            .collect();
        let signing_keys = SigningKeyRegistry::from_config(config, &reuse_scoped_key_ids)?;
        Self::from_signing_keys(config, &signing_keys)
    }

    pub(in super::super) fn from_signing_keys(
        config: &EvidenceConfig,
        signing_keys: &SigningKeyRegistry,
    ) -> Result<Self, StandaloneServerError> {
        let mut issuers = BTreeMap::new();
        for (profile_id, profile) in &config.credential_profiles {
            let issuer = signing_keys
                .issuer(profile.signing_key.as_str())
                .ok_or_else(|| {
                    invalid_signing_key(
                        profile.signing_key.as_str(),
                        "active signing key was not built",
                    )
                })?;
            issuers.insert(profile_id.clone(), issuer.clone());
        }
        Ok(Self {
            issuers,
            public_jwks: signing_keys.public_jwks(),
        })
    }
}

impl EvidenceIssuerResolver for EvidenceIssuerRegistry {
    fn issuer(&self, profile_id: &str) -> Result<EvidenceIssuer, EvidenceError> {
        self.issuers
            .get(profile_id)
            .cloned()
            .ok_or(EvidenceError::CredentialIssuerNotConfigured)
    }

    fn public_jwks(&self, _evidence: &EvidenceConfig) -> Result<Vec<Value>, EvidenceError> {
        Ok(published_jwks_at(
            &self.public_jwks,
            current_unix_timestamp_seconds(),
        ))
    }
}

#[derive(Debug, Clone, Default)]
pub(crate) struct SignerReadiness {
    entries: Arc<Vec<SignerReadinessEntry>>,
}

#[derive(Debug, Clone)]
pub(crate) struct SignerReadinessSnapshot {
    pub(crate) kid: String,
    pub(crate) readiness: KeyReadiness,
}

#[derive(Debug, Clone)]
pub(in super::super) struct SignerReadinessEntry {
    kid: String,
    provider: SigningKeyProviderConfig,
    required_for_signing: bool,
    state: SignerReadinessState,
}

#[derive(Clone)]
pub(in super::super) enum SignerReadinessState {
    Static(KeyReadiness),
    #[cfg_attr(not(feature = "pkcs11"), allow(dead_code))]
    Flag(Arc<AtomicBool>),
    Provider(Arc<dyn SigningProvider>),
}

impl std::fmt::Debug for SignerReadinessState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Static(readiness) => f.debug_tuple("Static").field(readiness).finish(),
            Self::Flag(_) => f.write_str("Flag(..)"),
            Self::Provider(provider) => f
                .debug_struct("Provider")
                .field("kid", &provider.key_id())
                .field("readiness", &provider.readiness())
                .finish(),
        }
    }
}

impl SignerReadinessEntry {
    fn readiness(&self) -> KeyReadiness {
        match &self.state {
            SignerReadinessState::Static(readiness) => *readiness,
            SignerReadinessState::Flag(flag) if flag.load(Ordering::SeqCst) => KeyReadiness::Ready,
            SignerReadinessState::Flag(_) => KeyReadiness::NotReady,
            SignerReadinessState::Provider(provider) => provider.readiness(),
        }
    }
}

pub(in super::super) const KEY_READINESS_READY: u8 = 0;
pub(in super::super) const KEY_READINESS_DEGRADED: u8 = 1;
pub(in super::super) const KEY_READINESS_NOT_READY: u8 = 2;
pub(in super::super) const KEY_READINESS_UNKNOWN: u8 = 3;

pub(in super::super) fn key_readiness_to_u8(readiness: KeyReadiness) -> u8 {
    match readiness {
        KeyReadiness::Ready => KEY_READINESS_READY,
        KeyReadiness::Degraded => KEY_READINESS_DEGRADED,
        KeyReadiness::NotReady => KEY_READINESS_NOT_READY,
        KeyReadiness::Unknown => KEY_READINESS_UNKNOWN,
        _ => KEY_READINESS_UNKNOWN,
    }
}

pub(in super::super) fn key_readiness_from_u8(value: u8) -> KeyReadiness {
    match value {
        KEY_READINESS_READY => KeyReadiness::Ready,
        KEY_READINESS_DEGRADED => KeyReadiness::Degraded,
        KEY_READINESS_NOT_READY => KeyReadiness::NotReady,
        _ => KeyReadiness::Unknown,
    }
}

impl SignerReadiness {
    #[allow(dead_code)]
    pub(crate) fn from_provider_flags(providers: Vec<Arc<AtomicBool>>) -> Self {
        Self {
            entries: Arc::new(
                providers
                    .into_iter()
                    .enumerate()
                    .map(|(index, flag)| SignerReadinessEntry {
                        kid: format!("provider-{}", index + 1),
                        provider: SigningKeyProviderConfig::LocalJwkEnv,
                        required_for_signing: true,
                        state: SignerReadinessState::Flag(flag),
                    })
                    .collect(),
            ),
        }
    }

    pub(in super::super) fn from_entries(entries: Vec<SignerReadinessEntry>) -> Self {
        Self {
            entries: Arc::new(entries),
        }
    }

    pub(crate) fn total(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.required_for_signing)
            .count()
    }

    pub(crate) fn ready_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.required_for_signing && entry.readiness().is_ready())
            .count()
    }

    pub(crate) fn failed_count(&self) -> usize {
        self.total().saturating_sub(self.ready_count())
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.failed_count() == 0
    }

    pub(crate) fn by_kid(&self) -> Vec<SignerReadinessSnapshot> {
        self.entries
            .iter()
            .map(|entry| SignerReadinessSnapshot {
                kid: entry.kid.clone(),
                readiness: entry.readiness(),
            })
            .collect()
    }

    pub(crate) fn provider_counts(&self) -> BTreeMap<String, usize> {
        let mut counts = BTreeMap::new();
        for entry in self
            .entries
            .iter()
            .filter(|entry| entry.required_for_signing)
        {
            *counts
                .entry(entry.provider.as_str().to_string())
                .or_insert(0) += 1;
        }
        counts
    }
}

#[derive(Clone, Default)]
pub(in super::super) struct SigningKeyRegistry {
    issuers: BTreeMap<String, EvidenceIssuer>,
    providers: BTreeMap<String, Arc<dyn SigningProvider>>,
    public_jwks: Vec<PublishedJwk>,
    readiness_entries: Vec<SignerReadinessEntry>,
}

impl SigningKeyRegistry {
    pub(in super::super) fn from_config(
        config: &EvidenceConfig,
        reuse_scoped_key_ids: &HashSet<&str>,
    ) -> Result<Self, StandaloneServerError> {
        let mut issuers = BTreeMap::new();
        let mut providers = BTreeMap::new();
        let mut public_jwks_by_kid = BTreeMap::new();
        let mut resolved_public_jwks = Vec::new();
        #[cfg_attr(not(feature = "pkcs11"), allow(unused_mut))]
        let mut readiness_entries = Vec::new();
        for (key_id, key) in &config.signing_keys {
            if !key.status.may_publish() {
                continue;
            }
            let (public_jwk, public_jwk_for_validation) = match key.provider {
                SigningKeyProviderConfig::LocalJwkEnv => {
                    if key.status.may_sign() {
                        let provider: Arc<dyn SigningProvider> =
                            Arc::new(build_local_jwk_signer(key_id, key)?);
                        readiness_entries.push(provider_key_readiness(
                            key.kid.clone(),
                            key.provider,
                            true,
                            Arc::clone(&provider),
                        ));
                        let issuer = EvidenceIssuer::from_signing_provider(Arc::clone(&provider))
                            .map_err(|_| {
                            invalid_signing_key(key_id, "local signer failed self-test")
                        })?;
                        let public_jwk = issuer.public_jwk();
                        let public_jwk_for_validation = provider.public_jwk();
                        issuers.insert(key_id.clone(), issuer);
                        providers.insert(key_id.clone(), provider);
                        (public_jwk, public_jwk_for_validation)
                    } else {
                        readiness_entries.push(static_key_readiness(
                            key.kid.clone(),
                            key.provider,
                            false,
                            KeyReadiness::Ready,
                        ));
                        let public_jwk_for_validation = build_public_jwk(key_id, key)?;
                        let public_jwk = serde_json::to_value(public_jwk_for_validation.clone())
                            .map_err(|_| {
                                invalid_signing_key(key_id, "public JWK could not be serialized")
                            })?;
                        (public_jwk, public_jwk_for_validation)
                    }
                }
                SigningKeyProviderConfig::Pkcs11 => {
                    if key.status.may_sign() {
                        #[cfg(feature = "pkcs11")]
                        {
                            let provider = super::Pkcs11SigningProvider::from_config(key_id, key)?;
                            let provider: Arc<dyn SigningProvider> = Arc::new(provider);
                            readiness_entries.push(provider_key_readiness(
                                key.kid.clone(),
                                key.provider,
                                true,
                                Arc::clone(&provider),
                            ));
                            let issuer =
                                EvidenceIssuer::from_signing_provider(Arc::clone(&provider))
                                    .map_err(|_| {
                                        invalid_signing_key(
                                            key_id,
                                            "PKCS#11 signer failed self-test",
                                        )
                                    })?;
                            let public_jwk = issuer.public_jwk();
                            let public_jwk_for_validation = provider.public_jwk();
                            issuers.insert(key_id.clone(), issuer);
                            providers.insert(key_id.clone(), provider);
                            (public_jwk, public_jwk_for_validation)
                        }
                        #[cfg(not(feature = "pkcs11"))]
                        {
                            return Err(StandaloneServerError::SigningKeyProviderUnavailable {
                                provider: "pkcs11".to_string(),
                            });
                        }
                    } else {
                        readiness_entries.push(static_key_readiness(
                            key.kid.clone(),
                            key.provider,
                            false,
                            KeyReadiness::Ready,
                        ));
                        let public_jwk_for_validation = build_public_jwk(key_id, key)?;
                        let public_jwk = serde_json::to_value(public_jwk_for_validation.clone())
                            .map_err(|_| {
                                invalid_signing_key(key_id, "public JWK could not be serialized")
                            })?;
                        (public_jwk, public_jwk_for_validation)
                    }
                }
                SigningKeyProviderConfig::FileWatch => {
                    if key.status.may_sign() {
                        let provider = FileWatchSigningProvider::from_config(key_id, key)?;
                        let provider: Arc<dyn SigningProvider> = Arc::new(provider);
                        readiness_entries.push(provider_key_readiness(
                            key.kid.clone(),
                            key.provider,
                            true,
                            Arc::clone(&provider),
                        ));
                        let issuer = EvidenceIssuer::from_signing_provider(Arc::clone(&provider))
                            .map_err(|_| {
                            invalid_signing_key(key_id, "file-watch signer failed self-test")
                        })?;
                        let public_jwk = issuer.public_jwk();
                        let public_jwk_for_validation = provider.public_jwk();
                        issuers.insert(key_id.clone(), issuer);
                        providers.insert(key_id.clone(), provider);
                        (public_jwk, public_jwk_for_validation)
                    } else {
                        continue;
                    }
                }
                SigningKeyProviderConfig::LocalPkcs12File => {
                    return Err(StandaloneServerError::SigningKeyProviderUnavailable {
                        provider: "local_pkcs12_file".to_string(),
                    });
                }
                _ => {
                    return Err(StandaloneServerError::SigningKeyProviderUnavailable {
                        provider: "unsupported".to_string(),
                    });
                }
            };
            resolved_public_jwks.push((key_id.clone(), public_jwk_for_validation));
            public_jwks_by_kid.insert(
                key.kid.clone(),
                PublishedJwk {
                    public_jwk,
                    publish_until_unix_seconds: key.publish_until_unix_seconds,
                },
            );
        }
        config.validate_resolved_signing_key_material(
            resolved_public_jwks
                .iter()
                .map(|(key_id, public_jwk)| (key_id.as_str(), public_jwk)),
            reuse_scoped_key_ids,
        )?;
        Ok(Self {
            issuers,
            providers,
            public_jwks: public_jwks_by_kid.into_values().collect(),
            readiness_entries,
        })
    }

    pub(in super::super) fn issuer(&self, key_id: &str) -> Option<&EvidenceIssuer> {
        self.issuers.get(key_id)
    }

    pub(in super::super) fn public_jwks(&self) -> Vec<PublishedJwk> {
        self.public_jwks.clone()
    }

    pub(in super::super) fn signing_provider(
        &self,
        key_id: &str,
    ) -> Option<Arc<dyn SigningProvider>> {
        self.providers.get(key_id).cloned()
    }

    /// The public JWK for an active signing key, resolved by its config
    /// `key_id`. Used to seed the in-process Notary token verifier without an
    /// HTTP JWKS round-trip.
    pub(in super::super) fn signer_readiness(&self) -> SignerReadiness {
        SignerReadiness::from_entries(self.readiness_entries.clone())
    }
}

pub(crate) fn signing_key_public_jwk_from_config(
    config: &EvidenceConfig,
    key_id: &str,
) -> Result<Option<PublicJwk>, StandaloneServerError> {
    let Some(key) = config.signing_keys.get(key_id) else {
        return Ok(None);
    };
    if !key.status.may_publish() {
        return Ok(None);
    }
    if key.status.may_sign() {
        return match key.provider {
            SigningKeyProviderConfig::LocalJwkEnv => {
                Ok(Some(build_local_jwk_signer(key_id, key)?.public_jwk()))
            }
            SigningKeyProviderConfig::FileWatch => Ok(Some(
                load_file_watch_jwk_signer(key_id, key, std::path::Path::new(&key.path))?
                    .public_jwk(),
            )),
            SigningKeyProviderConfig::Pkcs11 => {
                #[cfg(feature = "pkcs11")]
                {
                    Ok(Some(
                        super::Pkcs11SigningProvider::from_config(key_id, key)?.public_jwk(),
                    ))
                }
                #[cfg(not(feature = "pkcs11"))]
                {
                    Err(StandaloneServerError::SigningKeyProviderUnavailable {
                        provider: "pkcs11".to_string(),
                    })
                }
            }
            SigningKeyProviderConfig::LocalPkcs12File => {
                Err(StandaloneServerError::SigningKeyProviderUnavailable {
                    provider: "local_pkcs12_file".to_string(),
                })
            }
            _ => Err(StandaloneServerError::SigningKeyProviderUnavailable {
                provider: "unsupported".to_string(),
            }),
        };
    }
    let value = build_public_jwk_value(key_id, key)?;
    serde_json::from_value(value)
        .map(Some)
        .map_err(|_| invalid_signing_key(key_id, "public JWK could not be deserialized"))
}

pub(in super::super) fn published_jwks_at(
    public_jwks: &[PublishedJwk],
    now_unix_seconds: u64,
) -> Vec<Value> {
    public_jwks
        .iter()
        .filter(|entry| entry.is_published_at(now_unix_seconds))
        .map(|entry| entry.public_jwk.clone())
        .collect()
}

pub(in super::super) fn current_unix_timestamp_seconds() -> u64 {
    u64::try_from(OffsetDateTime::now_utc().unix_timestamp()).unwrap_or(0)
}

pub(in super::super) fn static_key_readiness(
    kid: String,
    provider: SigningKeyProviderConfig,
    required_for_signing: bool,
    readiness: KeyReadiness,
) -> SignerReadinessEntry {
    SignerReadinessEntry {
        kid,
        provider,
        required_for_signing,
        state: SignerReadinessState::Static(readiness),
    }
}

pub(in super::super) fn provider_key_readiness(
    kid: String,
    provider_kind: SigningKeyProviderConfig,
    required_for_signing: bool,
    provider: Arc<dyn SigningProvider>,
) -> SignerReadinessEntry {
    SignerReadinessEntry {
        kid,
        provider: provider_kind,
        required_for_signing,
        state: SignerReadinessState::Provider(provider),
    }
}

pub(in super::super) fn build_local_jwk_signer(
    key_id: &str,
    key: &SigningKeyConfig,
) -> Result<LocalJwkSigner, StandaloneServerError> {
    let raw = Zeroizing::new(
        env::var(&key.private_jwk_env)
            .ok()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| invalid_signing_key(key_id, "private_jwk_env is missing or empty"))?,
    );
    build_private_jwk_signer_from_raw(key_id, key, raw.as_str(), "private_jwk_env")
}

pub(in super::super) fn build_private_jwk_signer_from_raw(
    key_id: &str,
    key: &SigningKeyConfig,
    raw: &str,
    source: &str,
) -> Result<LocalJwkSigner, StandaloneServerError> {
    let mut jwk = PrivateJwk::parse(raw).map_err(|_| {
        invalid_signing_key(
            key_id,
            &format!("{source} does not contain a valid private JWK"),
        )
    })?;
    if jwk.kid.as_deref().is_some_and(|kid| kid != key.kid) {
        return Err(invalid_signing_key(
            key_id,
            "private JWK kid does not match configured kid",
        ));
    }
    if jwk.alg.as_deref().is_some_and(|alg| alg != key.alg) {
        return Err(invalid_signing_key(
            key_id,
            "private JWK alg does not match configured alg",
        ));
    }
    jwk.kid = Some(key.kid.clone());
    jwk.alg = Some(key.alg.clone());
    let public = jwk.public();
    let signature = sign(b"registry-notary signing self-test", &jwk)
        .map_err(|_| invalid_signing_key(key_id, "local signer self-test failed"))?;
    verify(b"registry-notary signing self-test", &signature, &public)
        .map_err(|_| invalid_signing_key(key_id, "local signer self-test verification failed"))?;
    LocalJwkSigner::new(jwk)
        .map_err(|_| invalid_signing_key(key_id, "local signer could not be constructed"))
}

#[derive(Clone)]
pub(in super::super) struct FileWatchSigningProvider {
    config_key_id: String,
    key_config: SigningKeyConfig,
    path: std::path::PathBuf,
    expected_public_jwk: PublicJwk,
    signer: Arc<StdMutex<LocalJwkSigner>>,
    pub(in super::super) file_state: Arc<StdMutex<FileWatchFileState>>,
    readiness: Arc<AtomicU8>,
    algorithm: registry_platform_crypto::SigningAlgorithm,
}

#[derive(Clone, Debug)]
pub(in super::super) struct FileWatchFileState {
    last_modified: Option<SystemTime>,
    last_content_digest: Option<[u8; 32]>,
    pub(in super::super) last_checked: Instant,
    metadata_missing: bool,
}

impl FileWatchSigningProvider {
    pub(in super::super) fn from_config(
        key_id: &str,
        key: &SigningKeyConfig,
    ) -> Result<Self, StandaloneServerError> {
        let path = std::path::PathBuf::from(&key.path);
        let signer = load_file_watch_jwk_signer(key_id, key, &path)?;
        let last_modified = file_watch_key_file_modified(key_id, &path)?;
        let last_content_digest = file_watch_key_file_content_digest(key_id, &path).ok();
        Ok(Self {
            config_key_id: key_id.to_string(),
            key_config: key.clone(),
            path,
            expected_public_jwk: signer.public_jwk(),
            algorithm: signer.algorithm(),
            signer: Arc::new(StdMutex::new(signer)),
            file_state: Arc::new(StdMutex::new(FileWatchFileState {
                last_modified: Some(last_modified),
                last_content_digest,
                last_checked: Instant::now(),
                metadata_missing: false,
            })),
            readiness: Arc::new(AtomicU8::new(key_readiness_to_u8(KeyReadiness::Ready))),
        })
    }

    fn readiness(&self) -> KeyReadiness {
        self.refresh();
        key_readiness_from_u8(self.readiness.load(Ordering::SeqCst))
    }

    fn current_signer(&self) -> LocalJwkSigner {
        self.refresh();
        self.signer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn refresh(&self) {
        let now = Instant::now();
        {
            let mut state = self
                .file_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if now.duration_since(state.last_checked) < FILE_WATCH_METADATA_CHECK_INTERVAL {
                return;
            }
            state.last_checked = now;
        }

        let modified = match file_watch_key_file_modified(&self.config_key_id, &self.path) {
            Ok(modified) => modified,
            Err(err) => {
                let mut state = self
                    .file_state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                if !state.metadata_missing {
                    tracing::warn!(
                        key_id = %self.config_key_id,
                        kid = %self.key_config.kid,
                        error = %err,
                        "file_watch signing key metadata refresh failed; keeping last good signer"
                    );
                }
                state.last_modified = None;
                state.metadata_missing = true;
                self.readiness.store(
                    key_readiness_to_u8(KeyReadiness::Degraded),
                    Ordering::SeqCst,
                );
                return;
            }
        };

        // Compute a content digest to detect same-mtime replacements (e.g. cp -p,
        // snapshot restore, coarse filesystem timestamp resolution). This read
        // happens at most once per debounce window, so for tiny key files it is
        // effectively free.
        let content_digest =
            file_watch_key_file_content_digest(&self.config_key_id, &self.path).ok();

        {
            let mut state = self
                .file_state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mtime_unchanged = !state.metadata_missing && state.last_modified == Some(modified);
            let digest_unchanged =
                content_digest.is_some() && state.last_content_digest == content_digest;
            if mtime_unchanged && digest_unchanged {
                return;
            }
            state.last_modified = Some(modified);
            state.last_content_digest = content_digest;
            state.metadata_missing = false;
        }

        match load_file_watch_jwk_signer(&self.config_key_id, &self.key_config, &self.path) {
            Ok(signer) if signer.public_jwk() == self.expected_public_jwk => {
                *self
                    .signer
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = signer;
                self.readiness
                    .store(key_readiness_to_u8(KeyReadiness::Ready), Ordering::SeqCst);
            }
            Ok(_) => {
                tracing::warn!(
                    key_id = %self.config_key_id,
                    kid = %self.key_config.kid,
                    "file_watch signing key reload produced a different public key; keeping last good signer"
                );
                self.readiness.store(
                    key_readiness_to_u8(KeyReadiness::Degraded),
                    Ordering::SeqCst,
                );
            }
            Err(err) => {
                tracing::warn!(
                    key_id = %self.config_key_id,
                    kid = %self.key_config.kid,
                    error = %err,
                    "file_watch signing key reload failed; keeping last good signer"
                );
                self.readiness.store(
                    key_readiness_to_u8(KeyReadiness::Degraded),
                    Ordering::SeqCst,
                );
            }
        }
    }
}

impl std::fmt::Debug for FileWatchSigningProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileWatchSigningProvider")
            .field("kid", &self.key_config.kid)
            .field("alg", &self.algorithm)
            .field("readiness", &self.readiness())
            .finish_non_exhaustive()
    }
}

#[async_trait]
impl SigningProvider for FileWatchSigningProvider {
    fn algorithm(&self) -> registry_platform_crypto::SigningAlgorithm {
        self.algorithm
    }

    fn key_id(&self) -> &str {
        &self.key_config.kid
    }

    fn public_jwk(&self) -> PublicJwk {
        self.current_signer().public_jwk()
    }

    async fn sign(
        &self,
        payload: &[u8],
    ) -> Result<Vec<u8>, registry_platform_crypto::SigningError> {
        self.current_signer().sign(payload).await
    }

    fn readiness(&self) -> KeyReadiness {
        self.readiness()
    }
}

pub(in super::super) fn file_watch_key_file_modified(
    key_id: &str,
    path: &std::path::Path,
) -> Result<SystemTime, StandaloneServerError> {
    std::fs::metadata(path)
        .and_then(|metadata| metadata.modified())
        .map_err(|_| invalid_signing_key(key_id, "file_watch key file metadata could not be read"))
}

pub(in super::super) fn file_watch_key_file_content_digest(
    key_id: &str,
    path: &std::path::Path,
) -> Result<[u8; 32], StandaloneServerError> {
    let bytes = std::fs::read(path)
        .map_err(|_| invalid_signing_key(key_id, "file_watch key file could not be read"))?;
    Ok(<sha2::Sha256 as sha2::Digest>::digest(&bytes).into())
}

pub(in super::super) fn load_file_watch_jwk_signer(
    key_id: &str,
    key: &SigningKeyConfig,
    path: &std::path::Path,
) -> Result<LocalJwkSigner, StandaloneServerError> {
    let raw = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|_| invalid_signing_key(key_id, "file_watch key file could not be read"))?,
    );
    build_private_jwk_signer_from_raw(key_id, key, raw.as_str(), "file_watch key file")
}

pub(in super::super) fn build_public_jwk_value(
    key_id: &str,
    key: &SigningKeyConfig,
) -> Result<Value, StandaloneServerError> {
    let public = build_public_jwk(key_id, key)?;
    serde_json::to_value(public)
        .map_err(|_| invalid_signing_key(key_id, "public JWK could not be serialized"))
}

pub(in super::super) fn build_public_jwk(
    key_id: &str,
    key: &SigningKeyConfig,
) -> Result<PublicJwk, StandaloneServerError> {
    let raw = env::var(&key.public_jwk_env)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| invalid_signing_key(key_id, "public_jwk_env is missing or empty"))?;
    let public = PublicJwk::parse(&raw).map_err(|_| {
        invalid_signing_key(key_id, "public_jwk_env does not contain a valid public JWK")
    })?;
    if public.kid.as_deref() != Some(key.kid.as_str()) {
        return Err(invalid_signing_key(
            key_id,
            "public JWK kid does not match configured kid",
        ));
    }
    if public.alg.as_deref() != Some(key.alg.as_str()) {
        return Err(invalid_signing_key(
            key_id,
            "public JWK alg does not match configured alg",
        ));
    }
    Ok(public)
}

pub(in super::super) fn invalid_signing_key(key: &str, reason: &str) -> StandaloneServerError {
    StandaloneServerError::InvalidSigningKey {
        key: key.to_string(),
        reason: reason.to_string(),
    }
}
