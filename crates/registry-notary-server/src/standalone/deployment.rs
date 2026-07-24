use super::*;

/// Deployment gate evaluation result carried through runtime assembly.
///
/// `startup_fail` gates abort assembly. The startup config source is retained so
/// readiness and posture can safely re-evaluate time-varying facts without
/// weakening signed-config provenance.
#[derive(Debug, Clone)]
pub(crate) struct DeploymentGateState {
    config_source: ConfigSource,
    pub(crate) profile: Option<&'static str>,
    pub(crate) startup_failures: Vec<String>,
    pub(crate) readiness_failures: Vec<String>,
    pub(crate) findings: Vec<EvaluatedFinding>,
    pub(crate) active_waivers: Vec<EvaluatedWaiver>,
}

impl Default for DeploymentGateState {
    fn default() -> Self {
        Self {
            config_source: ConfigSource::Unknown,
            profile: None,
            startup_failures: Vec::new(),
            readiness_failures: Vec::new(),
            findings: Vec::new(),
            active_waivers: Vec::new(),
        }
    }
}

impl DeploymentGateState {
    pub(crate) fn evaluate_with_config_source(
        config: &StandaloneRegistryNotaryConfig,
        config_source: ConfigSource,
    ) -> Self {
        // Startup evaluates the configured observation capability only. Live
        // cursor I/O is bounded and performed by readiness/posture handlers.
        let observation = AckObservation::unverified();
        Self::evaluate_with_observation(config, config_source, &observation)
    }

    pub(crate) fn evaluate_current(
        &self,
        config: &StandaloneRegistryNotaryConfig,
        observation: &AckObservation,
    ) -> Self {
        Self::evaluate_with_observation(config, self.config_source, observation)
    }

    fn evaluate_with_observation(
        config: &StandaloneRegistryNotaryConfig,
        config_source: ConfigSource,
        observation: &AckObservation,
    ) -> Self {
        let mut input = config.gate_input_with_ack_observation(observation);
        input.config_unsigned = !matches!(
            config_source,
            ConfigSource::SignedBundleFile | ConfigSource::SignedBundleEndpoint
        );
        let evaluation = evaluate_gates(
            config.deployment.profile,
            &input,
            &config.deployment.waivers,
            &today_utc_date(),
        );
        let GateEvaluation {
            startup_failures,
            readiness_failures,
            findings,
            active_waivers,
        } = evaluation;
        Self {
            config_source,
            profile: config.deployment.profile.map(|profile| profile.as_str()),
            startup_failures,
            readiness_failures,
            findings,
            active_waivers,
        }
    }

    pub(super) fn fail_startup_if_blocked(&self) -> Result<(), StandaloneServerError> {
        if self.startup_failures.is_empty() {
            return Ok(());
        }
        Err(StandaloneServerError::DeploymentGateStartupFailure {
            profile: self.profile.unwrap_or("undeclared").to_string(),
            findings: self.startup_failures.join(", "),
        })
    }

    /// Emit one boot warning for every active or expired waiver. Metadata has
    /// already passed the shared operations validator, so logs expose only the
    /// required reference, optional summary, and expiry.
    pub(super) fn log_boot_waivers(&self) {
        for finding in &self.findings {
            let Some(waiver) = &finding.waiver else {
                continue;
            };
            if finding.status == DeploymentFindingStatus::Waived {
                tracing::warn!(
                    code = "deployment.gate_waived",
                    finding = %finding.id,
                    reference = %waiver.reference,
                    summary = ?waiver.summary,
                    expires = %waiver.expires,
                    "deployment gate finding is suppressed by an active waiver"
                );
            } else if finding.id == FINDING_WAIVER_EXPIRED {
                tracing::warn!(
                    code = "deployment.waiver_expired",
                    finding = %waiver.finding,
                    reference = %waiver.reference,
                    summary = ?waiver.summary,
                    expires = %waiver.expires,
                    "deployment waiver is expired; its gate binds again"
                );
            }
        }
    }

    /// True when a profile is declared, so its gates participate in readiness.
    /// Runtime compilation refuses undeclared profiles before readiness is served.
    pub(crate) fn is_bound(&self) -> bool {
        self.profile.is_some()
    }

    /// True when at least one bound gate reports a readiness failure.
    pub(crate) fn has_readiness_failure(&self) -> bool {
        !self.readiness_failures.is_empty()
    }
}

/// Today's date in UTC as a `YYYY-MM-DD` string, for waiver-expiry comparison.
fn today_utc_date() -> String {
    let now = OffsetDateTime::now_utc().date();
    format!(
        "{:04}-{:02}-{:02}",
        now.year(),
        u8::from(now.month()),
        now.day()
    )
}
