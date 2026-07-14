use super::*;

pub(in super::super) fn config_boot_audit_event(
    event: &'static str,
    audit: ConfigAuditEvent,
) -> EvidenceAuditEvent {
    let occurred_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string());
    EvidenceAuditEvent {
        event_id: Ulid::new().to_string(),
        occurred_at,
        principal_id_hash: None,
        scopes_used: Vec::new(),
        decision: "accepted".to_string(),
        method: "BACKGROUND".to_string(),
        path: format!("/__events/{event}"),
        status: 200,
        verification_id: None,
        claim_hash: None,
        purposes: None,
        row_count: None,
        source_read_count: None,
        relay_consultation_ids: Vec::new(),
        forwarded: None,
        error_code: None,
        access_mode: None,
        federation_peer_id_hash: None,
        federation_issuer: None,
        federation_profile: None,
        federation_purpose: None,
        federation_request_jti_hash: None,
        federation_subject_ref_hash: None,
        denial_code: None,
        token_claim_name: None,
        correlation_id_hash: None,
        credential_profile: None,
        protocol: None,
        credential_configuration_id: None,
        holder_binding_mode: None,
        rate_limit_bucket: None,
        policy_version: None,
        policy_hash: None,
        target_type: None,
        target_ref_hash: None,
        requester_type: None,
        requester_ref_hash: None,
        redacted_fields: None,
        batch_items: None,
        config: Some(audit),
    }
}

#[derive(Clone)]
pub(crate) struct AuditPipeline {
    pub(in super::super) sink: Arc<dyn PlatformAuditSink>,
    pub(in super::super) chain: Arc<OnceCell<ChainState>>,
    pub(in super::super) profile: AuditProfile,
    pub(in super::super) tail_init_in_progress: Arc<AtomicBool>,
}

pub(in super::super) struct TailInitReset(Arc<AtomicBool>);

impl Drop for TailInitReset {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl std::fmt::Debug for AuditPipeline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuditPipeline")
            .field("sink", &"<redacted>")
            .field("profile", &self.profile)
            .finish()
    }
}

impl AuditPipeline {
    pub(in super::super) fn from_config(
        config: &registry_notary_core::EvidenceAuditConfig,
    ) -> Result<Self, StandaloneServerError> {
        let hash_secret_env = config
            .hash_secret_env
            .as_deref()
            .ok_or(StandaloneServerError::MissingAuditHashSecretEnv)?;
        let profile = AuditProfile::registry_notary_from_env(hash_secret_env)?;
        let sink: Arc<dyn PlatformAuditSink> = match config.sink.as_str() {
            "stdout" => {
                validate_no_file_audit_fields(config, "stdout")?;
                validate_no_syslog_audit_fields(config, "stdout")?;
                Arc::new(JsonlStdoutSink::new())
            }
            "file" | "jsonl" => {
                validate_no_syslog_audit_fields(config, config.sink.as_str())?;
                if config.max_files == Some(0) {
                    return Err(StandaloneServerError::InvalidAuditConfig(
                        "audit.max_files must be at least 1 when set".to_string(),
                    ));
                }
                let path = config
                    .path
                    .as_deref()
                    .ok_or(StandaloneServerError::MissingAuditPath)?;
                // Single-writer advisory lock (#211): a second notary process
                // sharing this audit volume (or an overlapping container during
                // a restart/recreate) fails loudly with AuditError::SinkLocked
                // instead of silently forking the audit chain.
                Arc::new(JsonlFileSink::with_rotation_single_writer(
                    path,
                    config.max_size_bytes(),
                    config.max_files(),
                )?)
            }
            "syslog" => {
                validate_no_file_audit_fields(config, "syslog")?;
                let sink = match config.syslog_socket_path.as_deref() {
                    Some(path) => SyslogSink::with_socket_path(path),
                    None => SyslogSink::new(),
                };
                Arc::new(sink)
            }
            sink => return Err(StandaloneServerError::InvalidAuditSink(sink.to_string())),
        };
        Ok(Self {
            sink,
            chain: Arc::new(OnceCell::new()),
            profile,
            tail_init_in_progress: Arc::new(AtomicBool::new(false)),
        })
    }

    #[cfg(test)]
    pub(crate) fn for_sink_dev_only(sink: Arc<dyn PlatformAuditSink>) -> Self {
        Self {
            sink,
            chain: Arc::new(OnceCell::new()),
            profile: AuditProfile::unkeyed_dev_only(),
            tail_init_in_progress: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn hash_principal(&self, value: &str) -> Hashed<PrincipalIdentifier> {
        Hashed::from_hash(self.profile.key_hasher().hash(value))
    }

    pub(crate) fn hash_request_identifier(&self, value: &str) -> Hashed<RequestIdentifier> {
        Hashed::from_hash(self.profile.key_hasher().hash(value))
    }

    pub(crate) async fn emit(&self, event: &EvidenceAuditEvent) -> Result<(), AuditError> {
        let chain = self
            .chain
            .get_or_try_init(|| async {
                self.profile
                    .bootstrap_or_start_empty(self.sink.as_ref())
                    .await
            })
            .await?;
        let record = serde_json::to_value(event).map_err(AuditError::Json)?;
        chain.append(self.sink.as_ref(), record).await?;
        Ok(())
    }

    pub(crate) async fn current_tail_hash_bounded(&self) -> Option<[u8; 32]> {
        const DEADLINE: Duration = Duration::from_millis(500);
        if let Some(chain) = self.chain.get() {
            return chain.try_last_hash().flatten();
        }
        if self
            .tail_init_in_progress
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return None;
        }
        let pipeline = self.clone();
        let worker = tokio::spawn(async move {
            let _reset = TailInitReset(Arc::clone(&pipeline.tail_init_in_progress));
            let result = pipeline
                .chain
                .get_or_try_init(|| async {
                    pipeline
                        .profile
                        .bootstrap_or_start_empty(pipeline.sink.as_ref())
                        .await
                })
                .await
                .map(|chain| chain.try_last_hash().flatten());
            result
        });
        match tokio::time::timeout(DEADLINE, worker).await {
            Ok(Ok(Ok(tail))) => tail,
            Ok(Ok(Err(error))) => {
                tracing::error!(error = %error, "failed to read current audit chain tail");
                None
            }
            Ok(Err(error)) => {
                tracing::error!(error = %error, "audit chain tail worker failed");
                None
            }
            Err(_) => None,
        }
    }
}

pub(in super::super) fn validate_no_file_audit_fields(
    config: &registry_notary_core::EvidenceAuditConfig,
    sink: &str,
) -> Result<(), StandaloneServerError> {
    if config.path.is_some() {
        return Err(StandaloneServerError::InvalidAuditConfig(format!(
            "audit.path is only valid when audit.sink is file or jsonl, not {sink}"
        )));
    }
    if config.max_size_mb.is_some() || config.max_files.is_some() {
        return Err(StandaloneServerError::InvalidAuditConfig(format!(
            "audit.max_size_mb and audit.max_files are only valid when audit.sink is file or jsonl, not {sink}"
        )));
    }
    Ok(())
}

pub(in super::super) fn validate_no_syslog_audit_fields(
    config: &registry_notary_core::EvidenceAuditConfig,
    sink: &str,
) -> Result<(), StandaloneServerError> {
    if config.syslog_socket_path.is_some() {
        return Err(StandaloneServerError::InvalidAuditConfig(format!(
            "audit.syslog_socket_path is only valid when audit.sink is syslog, not {sink}"
        )));
    }
    Ok(())
}
