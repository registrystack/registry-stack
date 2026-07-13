use crate::*;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum DoctorOutputFormat {
    Text,
    Json,
}

impl fmt::Display for DoctorOutputFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Text => f.write_str("text"),
            Self::Json => f.write_str("json"),
        }
    }
}

#[derive(Debug)]
pub(crate) struct Diagnostic {
    pub(crate) ok: bool,
    pub(crate) warning: bool,
    pub(crate) label: String,
    pub(crate) action: Option<String>,
    pub(crate) report_code: Option<String>,
    pub(crate) report_severity: Option<&'static str>,
}

impl Diagnostic {
    fn ok(label: impl Into<String>) -> Self {
        Self {
            ok: true,
            warning: false,
            label: label.into(),
            action: None,
            report_code: None,
            report_severity: None,
        }
    }

    fn warn(label: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            ok: true,
            warning: true,
            label: label.into(),
            action: Some(action.into()),
            report_code: None,
            report_severity: None,
        }
    }

    fn warn_with_code(
        label: impl Into<String>,
        action: impl Into<String>,
        code: impl Into<String>,
    ) -> Self {
        Self {
            ok: true,
            warning: true,
            label: label.into(),
            action: Some(action.into()),
            report_code: Some(code.into()),
            report_severity: Some("warning"),
        }
    }

    fn fail(label: impl Into<String>, action: impl Into<String>) -> Self {
        Self {
            ok: false,
            warning: false,
            label: label.into(),
            action: Some(action.into()),
            report_code: None,
            report_severity: None,
        }
    }

    fn fail_with_code(
        label: impl Into<String>,
        action: impl Into<String>,
        code: impl Into<String>,
    ) -> Self {
        Self {
            ok: false,
            warning: false,
            label: label.into(),
            action: Some(action.into()),
            report_code: Some(code.into()),
            report_severity: Some("error"),
        }
    }

    fn deployment_finding(finding: &EvaluatedFinding, profile: Option<DeploymentProfile>) -> Self {
        let severity = finding.severity.as_str();
        let label = deployment_finding_label(finding, profile);
        let action = deployment_finding_action(finding);
        Self {
            ok: !matches!(severity, "startup_fail" | "readiness_fail")
                || finding.status == DeploymentFindingStatus::Waived,
            warning: !matches!(severity, "startup_fail" | "readiness_fail")
                || finding.status == DeploymentFindingStatus::Waived,
            label,
            action: Some(action),
            report_code: Some(finding.id.clone()),
            report_severity: Some(severity),
        }
    }
}

#[derive(Debug)]
pub(crate) struct DoctorOptions {
    pub(crate) live: bool,
    pub(crate) issue_demo_vc: bool,
    pub(crate) show_expanded_config: bool,
    pub(crate) profile_override: Option<String>,
    pub(crate) format: DoctorOutputFormat,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeploymentProfileReport {
    value: Option<String>,
    source: &'static str,
}

pub(crate) async fn doctor(
    config_path: &Path,
    env_report: &EnvFileReport,
    bind_override: Option<SocketAddr>,
    options: DoctorOptions,
) -> Result<bool, Box<dyn std::error::Error>> {
    let mut diagnostics = Vec::new();
    let mut expanded_config = None;
    let mut deployment_profile = DeploymentProfileReport {
        value: options.profile_override.clone(),
        source: if options.profile_override.is_some() {
            "override"
        } else {
            "undeclared"
        },
    };
    let raw = match fs::read_to_string(config_path) {
        Ok(raw) => {
            diagnostics.push(Diagnostic::ok("config file read"));
            raw
        }
        Err(err) => {
            diagnostics.push(Diagnostic::fail(
                format!("config file read failed: {err}"),
                "check --config points to a readable YAML file",
            ));
            render_doctor_output(
                &diagnostics,
                options.format,
                None,
                config_path,
                None,
                None,
                env_report,
            )?;
            return Ok(false);
        }
    };
    let parsed = match parse_expanded_config(&raw) {
        Ok(config) => {
            diagnostics.push(Diagnostic::ok("config YAML parsed and validated"));
            let mut config = config;
            apply_bind_override(&mut config, bind_override);
            Some(config)
        }
        Err(err) => {
            diagnostics.push(Diagnostic::fail(
                format!("config YAML parse or validation failed: {err}"),
                "fix the YAML syntax and field names",
            ));
            None
        }
    };
    let config = match parsed {
        Some(config) => {
            diagnostics.push(Diagnostic::ok("config semantics validated"));
            Some(config)
        }
        None => None,
    };
    if let Some(config) = &config {
        if options.profile_override.is_none() {
            if let Some(profile) = config.deployment.profile {
                deployment_profile = DeploymentProfileReport {
                    value: Some(profile.as_str().to_string()),
                    source: "config",
                };
            }
        }
        let profile_value = deployment_profile
            .value
            .as_deref()
            .and_then(deployment_profile_from_str);
        diagnostics.extend(deployment_profile_diagnostics(config, profile_value));
        diagnostics.extend(local_env_diagnostics(config, env_report));
        diagnostics.extend(holder_binding_diagnostics(config));
        if let Some(diagnostic) = pkcs11_preflight_diagnostic(config) {
            diagnostics.push(diagnostic);
        }
        diagnostics.extend(vc_diagnostics(config, options.issue_demo_vc));
        if options.live {
            diagnostics.extend(live_diagnostics(config).await);
        }
        if options.show_expanded_config {
            expanded_config = Some(redacted_config(config));
        }
    }
    render_doctor_output(
        &diagnostics,
        options.format,
        expanded_config.as_ref(),
        config_path,
        Some(&raw),
        config.as_ref(),
        env_report,
    )?;
    Ok(diagnostics.iter().all(|diag| diag.ok))
}

pub(crate) fn deployment_profile_diagnostics(
    config: &StandaloneRegistryNotaryConfig,
    profile_value: Option<DeploymentProfile>,
) -> Vec<Diagnostic> {
    let input = config.gate_input();
    let evaluation = evaluate_gates(
        profile_value,
        &input,
        &config.deployment.waivers,
        &today_utc_date(),
    );
    evaluation
        .findings
        .iter()
        .map(|finding| Diagnostic::deployment_finding(finding, profile_value))
        .collect()
}

pub(crate) fn deployment_profile_from_str(value: &str) -> Option<DeploymentProfile> {
    match value {
        "local" => Some(DeploymentProfile::Local),
        "hosted_lab" => Some(DeploymentProfile::HostedLab),
        "production" => Some(DeploymentProfile::Production),
        "evidence_grade" => Some(DeploymentProfile::EvidenceGrade),
        _ => None,
    }
}

pub(crate) fn deployment_finding_label(
    finding: &EvaluatedFinding,
    profile: Option<DeploymentProfile>,
) -> String {
    if finding.id == "deployment.profile_undeclared" {
        return "deployment profile is undeclared".to_string();
    }
    if finding.id == "deployment.waiver_expired" {
        if let Some(waiver) = &finding.waiver {
            return format!(
                "deployment waiver for '{}' expired on {}",
                waiver.finding, waiver.expires
            );
        }
        return "deployment waiver expired".to_string();
    }
    let profile = profile
        .map(DeploymentProfile::as_str)
        .unwrap_or("undeclared");
    let status = match finding.status {
        DeploymentFindingStatus::Active => "active",
        DeploymentFindingStatus::Waived => "waived",
    };
    format!(
        "{profile} deployment gate '{}' is {status} at severity {}",
        finding.id,
        finding.severity.as_str()
    )
}

pub(crate) fn deployment_finding_action(finding: &EvaluatedFinding) -> String {
    if finding.id == "deployment.profile_undeclared" {
        return "set deployment.profile or pass --profile for review-only doctor output"
            .to_string();
    }
    if finding.id == "deployment.waiver_expired" {
        return "renew the waiver only after review, or remove it and fix the deployment condition"
            .to_string();
    }
    if finding.status == DeploymentFindingStatus::Waived {
        return "review the active deployment waiver and expiry".to_string();
    }
    "update deployment config or runtime settings to clear the gate".to_string()
}

pub(crate) fn holder_binding_diagnostics(
    config: &StandaloneRegistryNotaryConfig,
) -> Vec<Diagnostic> {
    let unbound_profiles = config
        .evidence
        .credential_profiles
        .iter()
        .filter(|(_, profile)| profile.holder_binding.mode == "none")
        .map(|(profile_id, _)| profile_id.as_str())
        .collect::<Vec<_>>();
    if unbound_profiles.is_empty() {
        return Vec::new();
    }
    vec![Diagnostic::warn_with_code(
        format!(
            "credential profile(s) issue unbound SD-JWT VC credentials: {}",
            unbound_profiles.join(", ")
        ),
        "set holder_binding.mode: did with allowed_did_methods: [did:jwk], or keep mode: none only for an explicit bearer-style credential profile",
        "notary.credential_profile.unbound_holder_binding",
    )]
}

/// Today's date in UTC as a `YYYY-MM-DD` string, for waiver-expiry comparison.
pub(crate) fn today_utc_date() -> String {
    let now = OffsetDateTime::now_utc().date();
    format!(
        "{:04}-{:02}-{:02}",
        now.year(),
        u8::from(now.month()),
        now.day()
    )
}

pub(crate) fn pkcs11_preflight_diagnostic(
    config: &StandaloneRegistryNotaryConfig,
) -> Option<Diagnostic> {
    let has_active_pkcs11 = config.evidence.signing_keys.values().any(|key| {
        matches!(key.provider, SigningKeyProviderConfig::Pkcs11) && key.status.may_sign()
    });
    if !has_active_pkcs11 {
        return None;
    }
    match EvidenceIssuerRegistry::from_config(&config.evidence) {
        Ok(_) => Some(Diagnostic::ok(
            "PKCS#11 signing providers loaded and self-tested",
        )),
        Err(err) => Some(Diagnostic::fail(
            format!("PKCS#11 signing preflight failed: {err}"),
            "check module_path, token_label, pin_env, key_label, key_id_hex, public_jwk_env, and whether this binary was built with pkcs11",
        )),
    }
}

pub(crate) fn print_diagnostics(diagnostics: &[Diagnostic]) {
    for diag in diagnostics {
        let status = if diag.warning {
            "WARN"
        } else if diag.ok {
            "OK  "
        } else {
            "FAIL"
        };
        println!("{status}  {}", diag.label);
        if let Some(action) = &diag.action {
            println!("     Next action: {action}");
        }
    }
}

pub(crate) fn render_doctor_output(
    diagnostics: &[Diagnostic],
    format: DoctorOutputFormat,
    expanded_config: Option<&Value>,
    config_path: &Path,
    raw_config: Option<&str>,
    config: Option<&StandaloneRegistryNotaryConfig>,
    env_report: &EnvFileReport,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        DoctorOutputFormat::Text => {
            if let Some(config) = expanded_config {
                println!("{}", serde_json::to_string_pretty(config)?);
            }
            print_diagnostics(diagnostics);
        }
        DoctorOutputFormat::Json => {
            println!(
                "{}",
                serde_json::to_string_pretty(&doctor_json_report(
                    diagnostics,
                    config_path,
                    raw_config,
                    config,
                    env_report,
                ))?
            );
        }
    }
    Ok(())
}

pub(crate) fn doctor_json_report(
    diagnostics: &[Diagnostic],
    config_path: &Path,
    raw_config: Option<&str>,
    config: Option<&StandaloneRegistryNotaryConfig>,
    env_report: &EnvFileReport,
) -> Value {
    let diagnostics_json = diagnostics
        .iter()
        .map(doctor_json_diagnostic)
        .collect::<Vec<_>>();
    let error_count = diagnostics_json
        .iter()
        .filter(|diag| diag["severity"] == "error")
        .count();
    let warning_count = diagnostics_json
        .iter()
        .filter(|diag| diag["severity"] == "warning")
        .count();
    let mut report = json!({
        "schema_version": "registry.config.diagnostic_report.v1",
        "product": "registry-notary",
        "config_schema_version": NOTARY_CONFIG_SCHEMA_VERSION,
        "source": {
            "kind": "local_file",
            "path": path_for_json(config_path),
        },
        "status": if error_count > 0 {
            ReportStatus::Error.as_str()
        } else if warning_count > 0 {
            ReportStatus::Warning.as_str()
        } else {
            ReportStatus::Ok.as_str()
        },
        "summary": {
            "error_count": error_count,
            "warning_count": warning_count,
        },
        "diagnostics": diagnostics_json,
        "required_env": required_env_report(
            config.map(required_env_vars).unwrap_or_default(),
            env_report,
        ),
        "context_constraints": [],
        "generated_at": now_rfc3339(),
    });
    if let Some(config) = config {
        report["audit_shipping"] = notary_audit_shipping(config);
    }
    if let Some(raw) = raw_config {
        report["hashes"] = json!({
            "internal_config_hash": sha256_hash(raw),
        });
    }
    report
}

/// Report the audit shipping posture for the doctor diagnostic report. This
/// mirrors the `posture.audit` shipping fields (`sink_type`,
/// `shipping_target_configured`, `shipping_target`, `shipping_health`,
/// `shipping_observed_at`). The target is declared state derived from config via
/// the shared classifier. Doctor is offline, so a fresh cursor remains
/// `unverified` until a live runtime can bind it to the keyed chain tail.
/// Unmapped sink strings fall back to
/// [`AuditSinkKind::Unknown`] rather than a silent wildcard.
pub(crate) fn notary_audit_shipping(config: &StandaloneRegistryNotaryConfig) -> Value {
    let (sink_kind, sink_type) = match config.audit.sink.as_str() {
        "stdout" => (AuditSinkKind::Stdout, "stdout"),
        "syslog" => (AuditSinkKind::Syslog, "syslog"),
        "file" | "jsonl" => (AuditSinkKind::LocalFile, "file"),
        _ => (AuditSinkKind::Unknown, "unknown"),
    };
    let (shipping_target_configured, shipping_target) =
        audit_shipping_target(sink_kind, config.deployment.evidence.audit_offhost_shipping);
    // Read the local cursor safely, but never promote freshness to ok without a
    // live AuditPipeline and its keyed chain tail.
    let observation = evaluate_ack_health(
        config.deployment.evidence.audit_ack_cursor_path(),
        SystemTime::now(),
        config.deployment.evidence.audit_ack_max_age(),
    );
    let shipping_health = if shipping_target_configured {
        Value::from(observation.health.as_str())
    } else {
        Value::Null
    };
    let shipping_observed_at = if shipping_target_configured {
        observation.acked_at.map_or(Value::Null, Value::from)
    } else {
        Value::Null
    };
    json!({
        "sink_type": sink_type,
        "shipping_target_configured": shipping_target_configured,
        "shipping_target": shipping_target,
        "shipping_health": shipping_health,
        "shipping_observed_at": shipping_observed_at,
    })
}

pub(crate) fn doctor_json_diagnostic(diagnostic: &Diagnostic) -> Value {
    let (severity, code) = if let (Some(severity), Some(code)) = (
        diagnostic.report_severity,
        diagnostic.report_code.as_deref(),
    ) {
        (shared_severity(severity), code)
    } else if diagnostic.warning {
        ("warning", "warning")
    } else if diagnostic.ok {
        ("info", "ok")
    } else {
        ("error", "failed")
    };
    let message = if let Some(action) = &diagnostic.action {
        format!("{} Next action: {action}", diagnostic.label)
    } else {
        diagnostic.label.clone()
    };
    let value = json!({
        "severity": severity,
        "code": code,
        "message": message,
    });
    value
}

pub(crate) fn shared_severity(severity: &str) -> &'static str {
    match severity {
        "startup_fail" | "readiness_fail" | "finding_error" | "error" => "error",
        "finding_warn" | "warning" => "warning",
        _ => "info",
    }
}

pub(crate) fn required_env_report(
    vars: BTreeSet<String>,
    env_report: &EnvFileReport,
) -> Vec<Value> {
    vars.into_iter()
        .map(|name| {
            let status = if std::env::var_os(&name).is_some() || env_report.contains(&name) {
                RequiredEnvStatus::Present
            } else {
                RequiredEnvStatus::Missing
            };
            json!({
                "name": name,
                "classification": env_classification(&name).as_str(),
                "status": status.as_str(),
            })
        })
        .collect()
}

pub(crate) fn env_classification(name: &str) -> ConfigValueClassification {
    if name.to_ascii_uppercase().contains("PUBLIC") {
        ConfigValueClassification::Public
    } else {
        ConfigValueClassification::Secret
    }
}

pub(crate) fn now_rfc3339() -> String {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("UTC timestamp formats as RFC3339")
}

pub(crate) fn local_env_diagnostics(
    config: &StandaloneRegistryNotaryConfig,
    env_report: &EnvFileReport,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    if config
        .evidence
        .claims
        .iter()
        .any(|claim| claim.evidence_mode.is_registry_backed())
    {
        diagnostics.push(relay_token_file_diagnostic(config));
    }
    for credential in config
        .auth
        .api_keys
        .iter()
        .chain(config.auth.bearer_tokens.iter())
    {
        if let Some(env) = credential.fingerprint.name.as_deref() {
            diagnostics.push(check_fingerprint_env(env, env_report));
        }
    }
    if let Some(secret_env) = &config.audit.hash_secret_env {
        diagnostics.push(check_present_env(
            secret_env,
            env_report,
            "audit hash secret",
        ));
    }
    if matches!(config.audit.sink.as_str(), "file" | "jsonl")
        && !config.deployment.evidence.audit_offhost_shipping
    {
        // Once the operator declares off-host shipping over the local file sink,
        // the deployment gate is cleared and the declared state is visible in
        // the report's audit_shipping section, so this warning is silenced.
        diagnostics.push(Diagnostic::warn(
            "audit file/jsonl sink is local-chain-only",
            "for beta tamper-evidence, ship audit envelopes off-host via stdout/syslog or declare deployment.evidence.audit_offhost_shipping after external shipping is in place",
        ));
    }
    if config.replay.storage == "redis" {
        diagnostics.push(check_present_env(
            &config.replay.redis.url_env,
            env_report,
            "replay Redis URL",
        ));
    }
    if config.credential_status.enabled && config.credential_status.storage == "redis" {
        diagnostics.push(check_present_env(
            &config.credential_status.redis.url_env,
            env_report,
            "credential status Redis URL",
        ));
    }
    if config.federation.enabled {
        diagnostics.push(check_present_env(
            &config.federation.pairwise_subject_hash.secret_env,
            env_report,
            "federation pairwise subject hash secret",
        ));
    }
    for (key_id, key) in &config.evidence.signing_keys {
        if matches!(key.provider, SigningKeyProviderConfig::LocalJwkEnv) && key.status.may_sign() {
            diagnostics.push(check_local_jwk_env(
                &key.private_jwk_env,
                key_id,
                &key.kid,
                &key.alg,
                env_report,
            ));
        }
        if matches!(key.provider, SigningKeyProviderConfig::LocalJwkEnv)
            && key.status.may_publish()
            && !key.status.may_sign()
        {
            diagnostics.push(check_public_jwk_env(
                &key.public_jwk_env,
                key_id,
                &key.kid,
                &key.alg,
                env_report,
            ));
        }
        if matches!(key.provider, SigningKeyProviderConfig::Pkcs11) && key.status.may_sign() {
            diagnostics.push(check_present_env(
                &key.pin_env,
                env_report,
                &format!("PKCS#11 PIN for signing key {key_id}"),
            ));
        }
        if matches!(key.provider, SigningKeyProviderConfig::Pkcs11) && key.status.may_publish() {
            diagnostics.push(check_public_jwk_env(
                &key.public_jwk_env,
                key_id,
                &key.kid,
                &key.alg,
                env_report,
            ));
        }
    }
    diagnostics
}

fn relay_token_file_diagnostic(config: &StandaloneRegistryNotaryConfig) -> Diagnostic {
    let Some(relay) = config.evidence.relay.as_ref() else {
        return Diagnostic::fail_with_code(
            "Relay connection is not configured for Registry-backed claims",
            "configure evidence.relay before serving Registry-backed claims",
            "notary.relay.configuration_invalid",
        );
    };
    match fs::metadata(&relay.token_file) {
        Ok(metadata) if metadata.is_file() && metadata.len() > 0 => {
            #[cfg(unix)]
            if metadata.permissions().mode() & 0o077 != 0 {
                return Diagnostic::warn_with_code(
                    "Relay workload token file permits group or other access",
                    "restrict the mounted workload token to the Notary service account, for example mode 0600",
                    "notary.relay.credential_permissions",
                );
            }
            Diagnostic::ok("Relay workload token file is present and non-empty")
        }
        Ok(_) => Diagnostic::fail_with_code(
            "Relay workload token file is not a non-empty regular file",
            "mount a non-empty workload JWT at the configured evidence.relay.token_file path",
            "notary.relay.credential_unavailable",
        ),
        Err(_) => Diagnostic::fail_with_code(
            "Relay workload token file is unavailable",
            "mount a readable workload JWT at the configured evidence.relay.token_file path",
            "notary.relay.credential_unavailable",
        ),
    }
}

pub(crate) fn check_fingerprint_env(env: &str, env_report: &EnvFileReport) -> Diagnostic {
    match std::env::var(env) {
        Ok(value) if valid_sha256_hash(&value) => {
            Diagnostic::ok(format!("{env} is present and valid"))
        }
        Ok(_) => Diagnostic::fail(
            format!("{env} is present but not a sha256:<64 hex> fingerprint"),
            format!("set {env} using `registry-notary hash-api-key --hash-only`"),
        ),
        Err(_) => missing_env_diag(env, env_report, "fingerprint env var"),
    }
}

pub(crate) fn check_present_env(env: &str, env_report: &EnvFileReport, label: &str) -> Diagnostic {
    match std::env::var(env) {
        Ok(value) if !value.trim().is_empty() => {
            Diagnostic::ok(format!("{env} is present for {label}"))
        }
        Ok(_) => Diagnostic::fail(
            format!("{env} is present but empty for {label}"),
            format!("set {env} to a non-empty value"),
        ),
        Err(_) => missing_env_diag(env, env_report, label),
    }
}

pub(crate) fn check_local_jwk_env(
    env: &str,
    key_id: &str,
    expected_kid: &str,
    expected_alg: &str,
    env_report: &EnvFileReport,
) -> Diagnostic {
    match std::env::var(env) {
        Ok(value) => {
            let result = PrivateJwk::parse(&value)
                .and_then(|mut jwk| {
                    if jwk.kid.as_deref().is_some_and(|kid| kid != expected_kid) {
                        return Err(registry_platform_crypto::JwkError::Invalid("kid mismatch"));
                    }
                    if jwk.alg.as_deref().is_some_and(|alg| alg != expected_alg) {
                        return Err(registry_platform_crypto::JwkError::Invalid("alg mismatch"));
                    }
                    jwk.kid = Some(expected_kid.to_string());
                    jwk.alg = Some(expected_alg.to_string());
                    Ok(jwk)
                })
                .map_err(|err| err.to_string())
                .and_then(|jwk| LocalJwkSigner::new(jwk).map_err(|err| err.to_string()));
            match result {
                Ok(_) => Diagnostic::ok(format!("{env} is a usable local JWK for {key_id}")),
                Err(err) => Diagnostic::fail(
                    format!("{env} is not a usable local JWK for {key_id}: {err}"),
                    "generate a local demo key with `registry-notary demo-issuer-key`",
                ),
            }
        }
        Err(_) => missing_env_diag(env, env_report, &format!("local JWK for {key_id}")),
    }
}

pub(crate) fn check_public_jwk_env(
    env: &str,
    key_id: &str,
    expected_kid: &str,
    expected_alg: &str,
    env_report: &EnvFileReport,
) -> Diagnostic {
    match std::env::var(env) {
        Ok(value) => {
            let result = PublicJwk::parse(&value).and_then(|jwk| {
                if jwk.kid.as_deref() != Some(expected_kid) {
                    return Err(registry_platform_crypto::JwkError::Invalid("kid mismatch"));
                }
                if jwk.alg.as_deref() != Some(expected_alg) {
                    return Err(registry_platform_crypto::JwkError::Invalid("alg mismatch"));
                }
                Ok(jwk)
            });
            match result {
                Ok(_) => Diagnostic::ok(format!("{env} is a usable public JWK for {key_id}")),
                Err(err) => Diagnostic::fail(
                    format!("{env} is not a usable public JWK for {key_id}: {err}"),
                    "set it to a public JWK with the configured kid",
                ),
            }
        }
        Err(_) => missing_env_diag(env, env_report, &format!("public JWK for {key_id}")),
    }
}

pub(crate) fn missing_env_diag(env: &str, env_report: &EnvFileReport, label: &str) -> Diagnostic {
    let source_hint = if env_report.contains(env) {
        "it was named in --env-file but not loaded because the process value was absent or empty"
    } else {
        "it was absent from the process and not present in --env-file"
    };
    Diagnostic::fail(
        format!("{env} is missing for {label}"),
        format!("set {env}; {source_hint}"),
    )
}

pub(crate) fn valid_sha256_hash(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit())
}

pub(crate) fn vc_diagnostics(
    config: &StandaloneRegistryNotaryConfig,
    issue_demo_vc: bool,
) -> Vec<Diagnostic> {
    let claim_ids: BTreeSet<&str> = config
        .evidence
        .claims
        .iter()
        .map(|claim| claim.id.as_str())
        .collect();
    let mut diagnostics = Vec::new();
    for (profile_id, profile) in &config.evidence.credential_profiles {
        for claim_id in &profile.allowed_claims {
            if !claim_ids.contains(claim_id.as_str()) {
                diagnostics.push(Diagnostic::fail(
                    format!("{profile_id} allows unknown claim {claim_id}"),
                    "remove the claim id or add the claim definition",
                ));
                continue;
            }
            let claim = config
                .evidence
                .claims
                .iter()
                .find(|claim| claim.id == *claim_id)
                .expect("claim was checked above");
            if !claim
                .credential_profiles
                .iter()
                .any(|configured| configured == profile_id)
            {
                diagnostics.push(Diagnostic::fail(
                    format!("{claim_id} does not opt into credential profile {profile_id}"),
                    "add the profile id to the claim credential_profiles list",
                ));
            } else {
                diagnostics.push(Diagnostic::ok(format!(
                    "{profile_id} can issue claim {claim_id}"
                )));
            }
        }
    }
    if issue_demo_vc {
        diagnostics.push(Diagnostic::ok(
            "local VC wiring checked; demo credential issuance requires an HTTP request with a holder proof when configured",
        ));
    }
    diagnostics
}

pub(crate) async fn live_diagnostics(config: &StandaloneRegistryNotaryConfig) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    if config
        .evidence
        .claims
        .iter()
        .any(|claim| claim.evidence_mode.is_registry_backed())
    {
        diagnostics.push(match verify_relay_from_config(config).await {
            Ok(true) => {
                Diagnostic::ok("Relay workload credential and pinned consultation profile verified")
            }
            Ok(false) => Diagnostic::fail_with_code(
                "Relay activation plan did not include Registry-backed claims",
                "check the Registry-backed claim and evidence.relay configuration",
                "notary.relay.configuration_invalid",
            ),
            Err(error) => relay_live_failure_diagnostic(&error),
        });
    }
    if diagnostics.is_empty() {
        diagnostics.push(Diagnostic::ok(
            "live Relay probe skipped because no Registry-backed claim is configured",
        ));
    }
    diagnostics
}

fn relay_live_failure_diagnostic(error: &StandaloneServerError) -> Diagnostic {
    match error {
        StandaloneServerError::RelayCredentialUnavailable => Diagnostic::fail_with_code(
            "Relay workload credential is unavailable",
            "mount a current readable workload JWT at evidence.relay.token_file",
            "notary.relay.credential_unavailable",
        ),
        StandaloneServerError::RelayCredentialsRejected => Diagnostic::fail_with_code(
            "Relay rejected the configured workload credential",
            "rotate the workload JWT and verify that Relay recognizes its workload binding, required scope, and validity window",
            "notary.relay.credentials_rejected",
        ),
        StandaloneServerError::RelayProfileNotFound => Diagnostic::fail_with_code(
            "Relay consultation profile was not found",
            "deploy the configured Relay profile id, then retry the live check",
            "notary.relay.profile_not_found",
        ),
        StandaloneServerError::RelayProfileMismatch => Diagnostic::fail_with_code(
            "Relay consultation profile does not match the configured contract pin",
            "reconcile the Notary profile id and contract hash with the reviewed Relay consultation contract",
            "notary.relay.profile_mismatch",
        ),
        StandaloneServerError::RelayUnavailable => Diagnostic::fail_with_code(
            "Relay consultation service is unavailable",
            "check Relay reachability, TLS, destination policy, and service health",
            "notary.relay.unavailable",
        ),
        StandaloneServerError::InvalidRelayDestination
        | StandaloneServerError::InvalidRelayActivationPlan
        | StandaloneServerError::RelayActivation
        | StandaloneServerError::RelayAlreadyActivated
        | StandaloneServerError::RelayNotActivated => Diagnostic::fail_with_code(
            "Relay consultation configuration is invalid",
            "check the evidence.relay connection and Registry-backed consultation configuration",
            "notary.relay.configuration_invalid",
        ),
        _ => Diagnostic::fail_with_code(
            "Relay consultation activation failed",
            "check the Notary configuration and startup environment",
            "notary.relay.activation_failed",
        ),
    }
}

#[cfg(test)]
#[path = "doctor/tests.rs"]
mod tests;
