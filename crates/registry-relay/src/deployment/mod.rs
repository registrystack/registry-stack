// SPDX-License-Identifier: Apache-2.0
//! Deployment profile gates.
//!
//! An operator declares one deployment profile in config. The profile is
//! never inferred from environment, hostname, or network position: it is an
//! explicit statement of the assurance level a deployment claims. Each gate
//! binds to a set of profiles and, when its condition holds on a declared
//! profile, contributes a finding at a defined severity.
//!
//! Severities map to three evaluation points:
//!
//! * `startup_fail`: the process refuses to start. Never waivable.
//! * `readiness_fail`: the readiness endpoint reports not-ready; the process
//!   keeps running. Also never waivable: the gate exists to stop traffic when
//!   an evidence guarantee fails, so a waiver must not silently un-fail it.
//! * `finding_error` / `finding_warn`: a posture finding only.
//!
//! A triggered gate can be suppressed by a config waiver that names the
//! finding, carries a free-text reason, and a mandatory expiry date. A waived
//! finding reports status `waived` instead of its severity effect. An expired
//! waiver stops suppressing the finding and additionally raises
//! `deployment.waiver_expired`. `startup_fail` and `readiness_fail` gates are
//! never waivable.
//!
//! When no profile is declared, `deployment.profile_undeclared` is a startup
//! failure. `local` is the explicit opt-out for development.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime};

use registry_platform_ops::{
    evaluate_ack_health, AckHealth, AckObservation, AuditWritePolicy, ConfigSource,
    DeploymentFinding, DeploymentFindingStatus, DeploymentFindingWaiver, DeploymentProfile,
    DeploymentWaiver, GateSeverity, DEFAULT_AUDIT_ACK_MAX_AGE,
};

use crate::config::{AuditSinkConfig, AuthMode, Config};

const AUDIT_ACK_CURSOR_READ_TIMEOUT: Duration = Duration::from_millis(500);
static AUDIT_ACK_CURSOR_READ_PERMIT: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();

fn audit_ack_cursor_read_permit() -> Arc<tokio::sync::Semaphore> {
    Arc::clone(
        AUDIT_ACK_CURSOR_READ_PERMIT.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(1))),
    )
}

/// Finding id emitted when no deployment profile is declared.
pub const PROFILE_UNDECLARED: &str = "deployment.profile_undeclared";

/// Finding id emitted, in addition to the re-triggered gate, when a waiver
/// has passed its expiry date.
pub const WAIVER_EXPIRED: &str = "deployment.waiver_expired";

/// A waiver as declared in config: one finding id, a reason, and a mandatory
/// expiry date in `YYYY-MM-DD` form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WaiverInput {
    pub finding: String,
    pub reason: String,
    pub expires: String,
}

/// Derived, profile-independent inputs that gate conditions read. The caller
/// projects these from the runtime config so gate evaluation stays a pure
/// function over plain facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeploymentFacts {
    /// Admin routes are reachable on a non-loopback (public) bind.
    pub admin_public_exposure: bool,
    /// OpenAPI is served without authentication.
    pub openapi_public: bool,
    /// No ingress rate-limit evidence has been declared by the operator.
    pub rate_limit_evidence_missing: bool,
    /// OIDC auth is enabled.
    pub oidc_enabled: bool,
    /// OIDC `allowed_clients` is empty (any client accepted).
    pub oidc_allowlist_empty: bool,
    /// API-key auth mode is active.
    pub api_key_mode: bool,
    /// No API-key rotation evidence has been declared by the operator.
    pub api_key_rotation_evidence_missing: bool,
    /// Config is a local YAML file rather than a signed governed bundle.
    pub config_unsigned: bool,
    /// No audit sink is configured.
    pub audit_sink_missing: bool,
    /// The audit write policy is availability-first (best effort).
    pub audit_best_effort: bool,
    /// The audit sink is a local rotating file with no off-host shipping
    /// evidence declared: retention is capped by local rotation, and an
    /// attacker with host access can destroy the audit trail.
    pub audit_retention_local_only: bool,
    /// A shipping target is configured (stdout, syslog, or a local file with an
    /// off-host-shipping attestation) and therefore needs a bound ack cursor
    /// under evidence-grade policy.
    pub audit_shipping_target_configured: bool,
    /// An off-host ack cursor path is configured, so runtime shipping progress
    /// can be observed rather than merely declared.
    pub audit_ack_cursor_configured: bool,
    /// The cursor is fresh and its watermark equals the current keyed chain
    /// tail (health `ok`). False for every other observation.
    pub audit_ack_health_ok: bool,
}

/// One gate in the relay catalog.
struct Gate {
    id: &'static str,
    /// Whether the gate's condition holds for the given facts.
    condition: fn(&DeploymentFacts) -> bool,
    /// Severity per profile. `None` means the gate does not bind to that
    /// profile.
    hosted_lab: Option<GateSeverity>,
    production: Option<GateSeverity>,
    evidence_grade: Option<GateSeverity>,
}

impl Gate {
    fn severity_for(&self, profile: DeploymentProfile) -> Option<GateSeverity> {
        match profile {
            // `local` binds no hard gates in the initial catalog.
            DeploymentProfile::Local => None,
            DeploymentProfile::HostedLab => self.hosted_lab,
            DeploymentProfile::Production => self.production,
            DeploymentProfile::EvidenceGrade => self.evidence_grade,
            // The shared enum is `#[non_exhaustive]`; unknown future profiles
            // bind nothing until this catalog is extended for them.
            _ => None,
        }
    }
}

use GateSeverity::{FindingError, FindingWarn, ReadinessFail, StartupFail};

/// The relay findings catalog. Order is stable so posture output is
/// deterministic.
const GATES: &[Gate] = &[
    Gate {
        id: "relay.admin.public_exposure",
        condition: |facts| facts.admin_public_exposure,
        hosted_lab: Some(FindingError),
        production: Some(ReadinessFail),
        evidence_grade: Some(StartupFail),
    },
    Gate {
        id: "relay.openapi.public",
        condition: |facts| facts.openapi_public,
        hosted_lab: Some(FindingWarn),
        production: Some(FindingError),
        evidence_grade: Some(FindingError),
    },
    Gate {
        id: "relay.ingress.rate_limit_missing",
        condition: |facts| facts.rate_limit_evidence_missing,
        hosted_lab: Some(FindingWarn),
        production: Some(FindingError),
        evidence_grade: Some(FindingError),
    },
    Gate {
        id: "relay.oidc.client_allowlist_empty",
        condition: |facts| facts.oidc_enabled && facts.oidc_allowlist_empty,
        hosted_lab: Some(FindingWarn),
        production: Some(FindingError),
        evidence_grade: Some(ReadinessFail),
    },
    Gate {
        id: "relay.auth.api_key_no_rotation_evidence",
        condition: |facts| facts.api_key_mode && facts.api_key_rotation_evidence_missing,
        hosted_lab: Some(FindingWarn),
        production: Some(FindingError),
        evidence_grade: Some(FindingError),
    },
    Gate {
        id: "relay.config.unsigned",
        condition: |facts| facts.config_unsigned,
        hosted_lab: Some(FindingWarn),
        production: Some(FindingError),
        evidence_grade: Some(StartupFail),
    },
    Gate {
        id: "relay.audit.sink_missing",
        condition: |facts| facts.audit_sink_missing,
        hosted_lab: Some(FindingError),
        production: Some(ReadinessFail),
        evidence_grade: Some(StartupFail),
    },
    Gate {
        id: "relay.audit.best_effort",
        condition: |facts| facts.audit_best_effort,
        // The natural hosted_lab binding for a best-effort audit policy is an
        // info-level finding, but the shared `GateSeverity` vocabulary has no
        // `info` level. Binding it at `finding_warn` here would overstate the
        // concern for a lab, so the hosted_lab binding is intentionally omitted
        // until the shared severity vocabulary gains an info level (a cross-repo
        // vocabulary decision tracked outside this catalog).
        hosted_lab: None,
        production: Some(FindingWarn),
        evidence_grade: Some(ReadinessFail),
    },
    Gate {
        id: "relay.audit.retention_local_only",
        condition: |facts| facts.audit_retention_local_only,
        // A local file sink caps retention and lets an attacker with host
        // access destroy the trail; the audit hash chain also cannot detect
        // leading or trailing truncation of a local-only log, so off-host
        // shipping (plus its attestation) is the completeness evidence that
        // clears this gate. Under production this is only a warn, so that
        // warning is the operator's single signal.
        //
        // Stdout and syslog sinks are exempt: stdout retention is the
        // orchestrator's log pipeline's concern, and syslog forwarding is the
        // syslog daemon's own surface. Only a local rotating file sink caps
        // retention in a way this gate can observe.
        hosted_lab: None,
        production: Some(FindingWarn),
        evidence_grade: Some(StartupFail),
    },
    Gate {
        id: "relay.audit.shipping_unverified",
        condition: |facts| {
            facts.audit_shipping_target_configured && !facts.audit_ack_cursor_configured
        },
        // A shipping target is configured, but nothing observes shipper
        // progress. Configure
        // `deployment.evidence.audit_ack_cursor_path` so the shipper's cursor
        // becomes observed evidence. This warns under production and refuses
        // evidence-grade startup because the observation capability is absent.
        hosted_lab: None,
        production: Some(FindingWarn),
        evidence_grade: Some(StartupFail),
    },
    Gate {
        id: "relay.audit.shipping_stale",
        condition: |facts| facts.audit_ack_cursor_configured && !facts.audit_ack_health_ok,
        // An ack cursor is configured, so shipping is observed, but the
        // observation is not healthy: the cursor is stale, missing, unsafe,
        // malformed, or not bound to the live keyed chain tail. Any non-`ok`
        // health trips the gate. Escalates to readiness_fail under
        // evidence_grade so traffic stops until shipping is restored.
        hosted_lab: None,
        production: Some(FindingError),
        evidence_grade: Some(ReadinessFail),
    },
];

/// Outcome of evaluating the catalog against one profile.
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct GateEvaluation {
    /// All findings, in catalog order, with profile findings first followed by
    /// the framework findings (`deployment.profile_undeclared`,
    /// `deployment.waiver_expired`).
    pub findings: Vec<DeploymentFinding>,
    /// Active (non-expired) waivers, including ones whose gate is not
    /// currently triggered.
    pub active_waivers: Vec<DeploymentWaiver>,
    /// Finding ids whose triggered severity is `startup_fail` and are not
    /// suppressed. A non-empty list means the process must refuse to start.
    pub startup_failures: Vec<String>,
    /// Finding ids whose triggered severity is `readiness_fail` and are not
    /// suppressed. A non-empty list means readiness must report not-ready.
    pub readiness_failures: Vec<String>,
}

impl GateEvaluation {
    pub fn has_startup_failure(&self) -> bool {
        !self.startup_failures.is_empty()
    }

    pub fn has_readiness_failure(&self) -> bool {
        !self.readiness_failures.is_empty()
    }
}

/// Evaluate the relay gate catalog.
///
/// `today` is the current date in `YYYY-MM-DD` form, compared lexically
/// against each waiver's `expires` date (ISO 8601 dates sort lexically).
pub fn evaluate(
    profile: Option<DeploymentProfile>,
    facts: &DeploymentFacts,
    waivers: &[WaiverInput],
    today: &str,
) -> GateEvaluation {
    let Some(profile) = profile else {
        // An undeclared profile is not a valid boot profile. `local` is the
        // explicit development opt-out.
        return GateEvaluation {
            findings: vec![DeploymentFinding {
                id: PROFILE_UNDECLARED.to_string(),
                severity: StartupFail,
                status: DeploymentFindingStatus::Active,
                waiver: None,
            }],
            active_waivers: Vec::new(),
            startup_failures: vec![PROFILE_UNDECLARED.to_string()],
            readiness_failures: Vec::new(),
        };
    };

    let mut evaluation = GateEvaluation::default();

    for gate in GATES {
        let Some(severity) = gate.severity_for(profile) else {
            continue;
        };
        if !(gate.condition)(facts) {
            continue;
        }

        // A waivable, triggered gate may be suppressed by a matching waiver.
        // `startup_fail` and `readiness_fail` are never waivable.
        let waivable = severity_is_waivable(severity);
        let waiver = if waivable {
            waivers.iter().find(|waiver| waiver.finding == gate.id)
        } else {
            None
        };

        match waiver {
            Some(waiver) if !is_expired(waiver, today) => {
                evaluation.findings.push(DeploymentFinding {
                    id: gate.id.to_string(),
                    severity,
                    status: DeploymentFindingStatus::Waived,
                    waiver: Some(DeploymentFindingWaiver {
                        reason: waiver.reason.clone(),
                        expires: waiver.expires.clone(),
                    }),
                });
            }
            _ => {
                // No waiver, or an expired waiver: the gate's severity effect
                // applies. Record the effect for startup / readiness.
                evaluation.findings.push(DeploymentFinding {
                    id: gate.id.to_string(),
                    severity,
                    status: DeploymentFindingStatus::Active,
                    waiver: None,
                });
                match severity {
                    StartupFail => evaluation.startup_failures.push(gate.id.to_string()),
                    ReadinessFail => evaluation.readiness_failures.push(gate.id.to_string()),
                    FindingError | FindingWarn => {}
                    _ => {}
                }
            }
        }
    }

    // Active waivers are reported regardless of whether their gate currently
    // triggers, so Trust Operations can aggregate and review them. Expired
    // waivers raise `deployment.waiver_expired` and are dropped from the
    // active list.
    let mut expired_findings = Vec::new();
    for waiver in waivers {
        if is_expired(waiver, today) {
            expired_findings.push(DeploymentFinding {
                id: WAIVER_EXPIRED.to_string(),
                severity: FindingError,
                status: DeploymentFindingStatus::Active,
                waiver: Some(DeploymentFindingWaiver {
                    reason: waiver.reason.clone(),
                    expires: waiver.expires.clone(),
                }),
            });
        } else {
            evaluation.active_waivers.push(DeploymentWaiver {
                finding: waiver.finding.clone(),
                reason: waiver.reason.clone(),
                expires: waiver.expires.clone(),
            });
        }
    }
    evaluation.findings.extend(expired_findings);

    evaluation
}

/// Returns the catalog's `&'static str` id for `id` when it names a catalog
/// gate. Framework finding ids (`deployment.profile_undeclared`,
/// `deployment.waiver_expired`) are not catalog gates and return `None`.
pub fn catalog_gate_id(id: &str) -> Option<&'static str> {
    GATES
        .iter()
        .map(|gate| gate.id)
        .find(|gate_id| *gate_id == id)
}

/// The severity `gate_id` binds under `profile`, or `None` when the gate is
/// unbound at that profile (including an undeclared profile) or `gate_id` is
/// not a catalog gate. Config validation reads this to reject, at load, a
/// waiver whose gate cannot be waived under the active profile instead of
/// silently dropping it.
pub fn gate_severity_for_profile(
    gate_id: &str,
    profile: Option<DeploymentProfile>,
) -> Option<GateSeverity> {
    let profile = profile?;
    GATES
        .iter()
        .find(|gate| gate.id == gate_id)
        .and_then(|gate| gate.severity_for(profile))
}

/// Whether a triggered gate at `severity` can be suppressed by a waiver.
/// Only the posture findings `finding_warn` and `finding_error` are waivable.
/// Both hard gates are non-waivable: `startup_fail` means running at all would
/// falsify the profile claim, and `readiness_fail` gates exist to stop traffic
/// when an evidence guarantee fails, so a waiver must not silently un-fail them.
/// This mirrors Notary's `GateSeverity::is_waivable` and is the single
/// definition of waivability shared by gate evaluation and load-time waiver
/// validation. The severities are matched explicitly, so a future
/// `GateSeverity` variant fails closed as non-waivable until this function is
/// extended to classify it deliberately.
pub fn severity_is_waivable(severity: GateSeverity) -> bool {
    match severity {
        FindingWarn | FindingError => true,
        ReadinessFail | StartupFail => false,
        // `GateSeverity` is `#[non_exhaustive]`; an unclassified future variant
        // must never default to waivable.
        _ => false,
    }
}

/// Operator remediation for a waiver that names a hard, non-waivable gate
/// (`readiness_fail` or `startup_fail` under the active profile). Every gate
/// that can be non-waivable under some profile names its own concrete lever to
/// clear the underlying condition, since a waiver can never suppress it. An
/// unmatched id (a gate that is only ever waivable, or an unknown id) falls back
/// to generic guidance.
pub fn hard_gate_remediation(gate_id: &str) -> &'static str {
    match gate_id {
        "relay.admin.public_exposure" => {
            "this gate cannot be waived under the active profile; bind the admin listener to a \
             loopback address (server.admin_bind) so admin routes are not reachable off-host"
        }
        "relay.oidc.client_allowlist_empty" => {
            "this gate cannot be waived under the active profile; populate \
             auth.oidc.allowed_clients so only known clients are accepted"
        }
        "relay.config.unsigned" => {
            "this gate cannot be waived under the active profile; load config from a signed \
             governed bundle instead of a local YAML file"
        }
        "relay.audit.sink_missing" => {
            "this gate cannot be waived under the active profile; configure a durable audit sink"
        }
        "relay.audit.best_effort" => {
            "this gate cannot be waived under the active profile; set audit.write_policy to a \
             durability-first policy instead of availability-first (best effort)"
        }
        "relay.audit.retention_local_only" => {
            "this gate cannot be waived under the active profile; ship audit events off-host and \
             set deployment.evidence.audit_offhost_shipping: true, or use a non-local audit sink"
        }
        "relay.audit.shipping_unverified" => {
            "this gate cannot be waived under the active profile; configure \
             deployment.evidence.audit_ack_cursor_path to the fresh cursor maintained by the \
             off-host audit shipper"
        }
        "relay.audit.shipping_stale" => {
            "this gate cannot be waived under the active profile; restore off-host shipping so the \
             writer refreshes the ack cursor, widen deployment.evidence.audit_ack_max_age_secs if \
             the freshness window is unrealistic, or repair \
             deployment.evidence.audit_ack_cursor_path if it names the wrong cursor"
        }
        _ => "fix the underlying condition; this gate cannot be waived under the active profile",
    }
}

/// A waiver is expired once `today` is strictly past its `expires` date. The
/// expiry day itself is still covered. ISO 8601 dates compare correctly with
/// lexical string ordering.
fn is_expired(waiver: &WaiverInput, today: &str) -> bool {
    today > waiver.expires.as_str()
}

/// Project the runtime config into the profile-independent facts the gates
/// read.
///
/// `config_source` is the provenance source of the loaded config: a signed
/// governed bundle clears `relay.config.unsigned`; a local YAML file does not,
/// and neither does unknown provenance (which fails closed as unsigned). Relay
/// always configures an audit sink, so `audit_sink_missing` is always false
/// here; the gate remains in the catalog for completeness.
pub fn facts_from_config(config: &Config, config_source: ConfigSource) -> DeploymentFacts {
    // Boot-time evaluation is deliberately configuration-only. A configured
    // cursor clears the static shipping_unverified gate; live readiness and
    // posture sample the cursor through their bounded async path before they
    // can clear shipping_stale. This prevents startup from blocking on a
    // stalled filesystem while keeping gate predicates pure.
    let observation = AckObservation::unverified();
    facts_from_config_with_ack_observation(config, config_source, &observation)
}

/// Project deployment facts from one already sampled and chain-bound cursor
/// observation so readiness and posture can remain internally consistent.
pub fn facts_from_config_with_ack_observation(
    config: &Config,
    config_source: ConfigSource,
    observation: &AckObservation,
) -> DeploymentFacts {
    DeploymentFacts {
        admin_public_exposure: admin_public_exposure(config),
        openapi_public: !config.server.openapi_requires_auth,
        rate_limit_evidence_missing: !config.deployment.evidence.ingress_rate_limit,
        oidc_enabled: config.auth.mode == AuthMode::Oidc,
        oidc_allowlist_empty: config
            .auth
            .oidc
            .as_ref()
            .map(|oidc| oidc.allowed_clients.is_empty())
            .unwrap_or(true),
        api_key_mode: config.auth.mode == AuthMode::ApiKey,
        api_key_rotation_evidence_missing: !config.deployment.evidence.api_key_rotation,
        // Only a genuine signed bundle clears `relay.config.unsigned`. A local
        // file is unsigned, and so is unknown provenance: an unrecognized source
        // must fail closed rather than silently clear the gate.
        config_unsigned: !matches!(
            config_source,
            ConfigSource::SignedBundleFile | ConfigSource::SignedBundleEndpoint
        ),
        audit_sink_missing: false,
        audit_best_effort: config.audit.write_policy == AuditWritePolicy::AvailabilityFirst,
        audit_retention_local_only: matches!(config.audit.sink, AuditSinkConfig::File { .. })
            && !config.deployment.evidence.audit_offhost_shipping,
        audit_shipping_target_configured: !matches!(
            config.audit.sink,
            AuditSinkConfig::File { .. }
        ) || config.deployment.evidence.audit_offhost_shipping,
        audit_ack_cursor_configured: config.deployment.evidence.audit_ack_cursor_path.is_some(),
        audit_ack_health_ok: observation.health == AckHealth::Ok,
    }
}

/// Read the operator's audit off-host ack cursor and evaluate its freshness.
///
/// The cursor path and freshness window are the operator declarations in
/// `deployment.evidence`; `audit_ack_max_age_secs` defaults to
/// [`DEFAULT_AUDIT_ACK_MAX_AGE`] when unset. This performs the cursor
/// filesystem read (sampling `SystemTime::now()`); with no cursor path
/// configured the observation is [`AckHealth::Unverified`]. Runtime handlers
/// use the bounded variant below; offline doctor output uses this synchronous
/// sampler and remains unverified without a live chain tail.
pub fn audit_ack_observation(config: &Config) -> AckObservation {
    let path = config.deployment.evidence.audit_ack_cursor_path.as_deref();
    let max_age = config
        .deployment
        .evidence
        .audit_ack_max_age_secs
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_AUDIT_ACK_MAX_AGE);
    evaluate_ack_health(path, SystemTime::now(), max_age)
}

/// Sample the ack cursor without letting a stalled filesystem block a public
/// async handler or create an unbounded queue of blocking workers.
///
/// One process-wide permit is moved into the blocking task. If a read times
/// out, the task keeps the permit until the operating-system call eventually
/// returns, so later probes fail closed without spawning more stuck workers.
pub async fn audit_ack_observation_bounded(config: &Config) -> AckObservation {
    let Some(path) = config.deployment.evidence.audit_ack_cursor_path.clone() else {
        return AckObservation::unverified();
    };
    let max_age = config
        .deployment
        .evidence
        .audit_ack_max_age_secs
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_AUDIT_ACK_MAX_AGE);
    bounded_ack_cursor_read(
        audit_ack_cursor_read_permit(),
        AUDIT_ACK_CURSOR_READ_TIMEOUT,
        move || evaluate_ack_health(Some(path.as_path()), SystemTime::now(), max_age),
    )
    .await
}

async fn bounded_ack_cursor_read<F>(
    semaphore: Arc<tokio::sync::Semaphore>,
    deadline: Duration,
    read: F,
) -> AckObservation
where
    F: FnOnce() -> AckObservation + Send + 'static,
{
    let permit = match semaphore.try_acquire_owned() {
        Ok(permit) => permit,
        Err(tokio::sync::TryAcquireError::Closed) => {
            return AckObservation::invalid("ack cursor read worker is unavailable");
        }
        Err(tokio::sync::TryAcquireError::NoPermits) => {
            return AckObservation::invalid("ack cursor read is still in progress");
        }
    };
    let worker = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        read()
    });
    match tokio::time::timeout(deadline, worker).await {
        Ok(Ok(observation)) => observation,
        Ok(Err(_)) => AckObservation::invalid("ack cursor read worker failed"),
        Err(_) => AckObservation::invalid("ack cursor read timed out"),
    }
}

/// Map an ack [`AckObservation`] onto the posture `shipping_health` and
/// `shipping_observed_at` fields, shared by posture emission and the doctor
/// report so they report identical semantics.
///
/// `shipping_health` is `None` (serialized as null) when no shipping target is
/// declared; otherwise the observed health string. `"unverified"` means no
/// cursor is configured or a fresh cursor has not been bound to a live keyed
/// chain. `shipping_observed_at` is the cursor's `acked_at` whenever a target
/// is declared and its timestamp was contract-valid, else `None`.
pub fn shipping_health_fields(
    observation: &AckObservation,
    shipping_target_configured: bool,
) -> (Option<&'static str>, Option<String>) {
    if shipping_target_configured {
        (
            Some(observation.health.as_str()),
            observation.acked_at.clone(),
        )
    } else {
        (None, None)
    }
}

/// Admin routes are "publicly exposed" when the admin listener is bound to a
/// non-loopback address, making it reachable beyond the local host. An absent
/// admin listener or a loopback bind is not an exposure.
fn admin_public_exposure(config: &Config) -> bool {
    config
        .server
        .admin_bind
        .is_some_and(|addr| !addr.ip().is_loopback())
}

/// Project the declared config waivers into the evaluation input shape.
pub fn waivers_from_config(config: &Config) -> Vec<WaiverInput> {
    config
        .deployment
        .waivers
        .iter()
        .map(|waiver| WaiverInput {
            finding: waiver.finding.clone(),
            reason: waiver.reason.clone(),
            expires: waiver.expires.clone(),
        })
        .collect()
}

/// Today's date in `YYYY-MM-DD` (UTC), used to compare against waiver expiry.
pub fn today_utc() -> String {
    use time::format_description::well_known::Iso8601;
    use time::OffsetDateTime;

    let format = Iso8601::DATE;
    OffsetDateTime::now_utc()
        .date()
        .format(&format)
        .expect("ISO 8601 date formats")
}

#[cfg(test)]
mod tests {
    use super::*;

    const FUTURE: &str = "2999-01-01";
    const PAST: &str = "2000-01-01";
    const TODAY: &str = "2026-06-13";

    /// Facts with no condition triggering. Each gate test flips exactly the
    /// fact it cares about.
    fn clean_facts() -> DeploymentFacts {
        DeploymentFacts {
            admin_public_exposure: false,
            openapi_public: false,
            rate_limit_evidence_missing: false,
            oidc_enabled: false,
            oidc_allowlist_empty: false,
            api_key_mode: false,
            api_key_rotation_evidence_missing: false,
            config_unsigned: false,
            audit_sink_missing: false,
            audit_best_effort: false,
            audit_retention_local_only: false,
            audit_shipping_target_configured: false,
            audit_ack_cursor_configured: false,
            audit_ack_health_ok: true,
        }
    }

    #[tokio::test]
    async fn bounded_cursor_reader_times_out_and_keeps_single_worker_permit() {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(1));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        let first_semaphore = Arc::clone(&semaphore);
        let first = tokio::spawn(async move {
            bounded_ack_cursor_read(first_semaphore, Duration::from_millis(25), move || {
                started_tx.send(()).expect("reader start is observed");
                release_rx.recv().expect("reader is released");
                AckObservation::unverified()
            })
            .await
        });
        tokio::time::timeout(Duration::from_secs(1), started_rx)
            .await
            .expect("blocking cursor reader starts in time")
            .expect("blocking cursor reader starts");

        let timed_out = first.await.expect("bounded read task joins");
        assert_eq!(timed_out.health, AckHealth::Invalid);
        assert_eq!(
            timed_out.detail.as_deref(),
            Some("ack cursor read timed out")
        );

        let queued = bounded_ack_cursor_read(
            Arc::clone(&semaphore),
            Duration::from_millis(25),
            AckObservation::unverified,
        )
        .await;
        assert_eq!(queued.health, AckHealth::Invalid);
        assert_eq!(
            queued.detail.as_deref(),
            Some("ack cursor read is still in progress")
        );

        release_tx.send(()).expect("blocking reader releases");
        let _permit = tokio::time::timeout(Duration::from_secs(1), semaphore.acquire())
            .await
            .expect("reader releases the permit")
            .expect("semaphore remains open");
    }

    fn finding_ids(evaluation: &GateEvaluation) -> Vec<String> {
        evaluation.findings.iter().map(|f| f.id.clone()).collect()
    }

    fn finding<'a>(evaluation: &'a GateEvaluation, id: &str) -> &'a DeploymentFinding {
        evaluation
            .findings
            .iter()
            .find(|f| f.id == id)
            .unwrap_or_else(|| panic!("missing finding {id}"))
    }

    #[test]
    fn catalog_gate_id_resolves_catalog_gates_only() {
        assert_eq!(
            catalog_gate_id("relay.config.unsigned"),
            Some("relay.config.unsigned")
        );
        assert_eq!(catalog_gate_id(PROFILE_UNDECLARED), None);
        assert_eq!(catalog_gate_id(WAIVER_EXPIRED), None);
        assert_eq!(catalog_gate_id("not.a.gate"), None);
    }

    #[test]
    fn undeclared_profile_is_startup_failure() {
        // Even with every risky fact set, the framework finding is the startup
        // blocker. Operators must choose `local` to opt out in development.
        let facts = DeploymentFacts {
            admin_public_exposure: true,
            openapi_public: true,
            rate_limit_evidence_missing: true,
            oidc_enabled: true,
            oidc_allowlist_empty: true,
            api_key_mode: true,
            api_key_rotation_evidence_missing: true,
            config_unsigned: true,
            audit_sink_missing: true,
            audit_best_effort: true,
            audit_retention_local_only: true,
            audit_shipping_target_configured: true,
            audit_ack_cursor_configured: true,
            audit_ack_health_ok: false,
        };
        let evaluation = evaluate(None, &facts, &[], TODAY);
        assert_eq!(finding_ids(&evaluation), vec![PROFILE_UNDECLARED]);
        assert_eq!(
            finding(&evaluation, PROFILE_UNDECLARED).severity,
            StartupFail
        );
        assert_eq!(
            evaluation.startup_failures,
            vec![PROFILE_UNDECLARED.to_string()]
        );
        assert!(evaluation.has_startup_failure());
        assert!(!evaluation.has_readiness_failure());
        assert!(evaluation.active_waivers.is_empty());
    }

    #[test]
    fn local_profile_binds_no_hard_gates_when_clean() {
        let evaluation = evaluate(Some(DeploymentProfile::Local), &clean_facts(), &[], TODAY);
        assert!(evaluation.findings.is_empty());
        assert!(!evaluation.has_startup_failure());
        assert!(!evaluation.has_readiness_failure());
    }

    #[test]
    fn local_profile_does_not_trigger_relay_gates() {
        // `local` binds no gates in the initial catalog; risky facts are
        // silent under it.
        let facts = DeploymentFacts {
            admin_public_exposure: true,
            config_unsigned: true,
            audit_sink_missing: true,
            ..clean_facts()
        };
        let evaluation = evaluate(Some(DeploymentProfile::Local), &facts, &[], TODAY);
        assert!(evaluation.findings.is_empty());
    }

    #[test]
    fn admin_public_exposure_escalates_across_profiles() {
        let facts = DeploymentFacts {
            admin_public_exposure: true,
            ..clean_facts()
        };
        let id = "relay.admin.public_exposure";

        let hosted = evaluate(Some(DeploymentProfile::HostedLab), &facts, &[], TODAY);
        assert_eq!(finding(&hosted, id).severity, FindingError);
        assert!(!hosted.has_readiness_failure());

        let production = evaluate(Some(DeploymentProfile::Production), &facts, &[], TODAY);
        assert_eq!(finding(&production, id).severity, ReadinessFail);
        assert_eq!(production.readiness_failures, vec![id.to_string()]);

        let evidence = evaluate(Some(DeploymentProfile::EvidenceGrade), &facts, &[], TODAY);
        assert_eq!(finding(&evidence, id).severity, StartupFail);
        assert_eq!(evidence.startup_failures, vec![id.to_string()]);
    }

    #[test]
    fn admin_public_exposure_silent_when_not_exposed() {
        // Non-triggering case across every bound profile.
        for profile in [
            DeploymentProfile::HostedLab,
            DeploymentProfile::Production,
            DeploymentProfile::EvidenceGrade,
        ] {
            let evaluation = evaluate(Some(profile), &clean_facts(), &[], TODAY);
            assert!(
                !finding_ids(&evaluation).contains(&"relay.admin.public_exposure".to_string()),
                "unexpected admin exposure finding under {profile:?}"
            );
        }
    }

    #[test]
    fn openapi_public_triggers_and_clears() {
        let facts = DeploymentFacts {
            openapi_public: true,
            ..clean_facts()
        };
        let id = "relay.openapi.public";
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::HostedLab), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingWarn
        );
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::Production), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingError
        );
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::EvidenceGrade), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingError
        );
        // Non-triggering.
        let clean = evaluate(
            Some(DeploymentProfile::Production),
            &clean_facts(),
            &[],
            TODAY,
        );
        assert!(!finding_ids(&clean).contains(&id.to_string()));
    }

    #[test]
    fn rate_limit_missing_triggers_and_clears() {
        let facts = DeploymentFacts {
            rate_limit_evidence_missing: true,
            ..clean_facts()
        };
        let id = "relay.ingress.rate_limit_missing";
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::HostedLab), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingWarn
        );
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::Production), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingError
        );
        let clean = evaluate(
            Some(DeploymentProfile::Production),
            &clean_facts(),
            &[],
            TODAY,
        );
        assert!(!finding_ids(&clean).contains(&id.to_string()));
    }

    #[test]
    fn oidc_allowlist_empty_only_when_oidc_enabled() {
        let id = "relay.oidc.client_allowlist_empty";
        // Empty allowlist but OIDC disabled: no finding.
        let disabled = DeploymentFacts {
            oidc_enabled: false,
            oidc_allowlist_empty: true,
            ..clean_facts()
        };
        let evaluation = evaluate(Some(DeploymentProfile::Production), &disabled, &[], TODAY);
        assert!(!finding_ids(&evaluation).contains(&id.to_string()));

        // OIDC enabled with empty allowlist: escalates.
        let enabled = DeploymentFacts {
            oidc_enabled: true,
            oidc_allowlist_empty: true,
            ..clean_facts()
        };
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::HostedLab), &enabled, &[], TODAY),
                id
            )
            .severity,
            FindingWarn
        );
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::Production), &enabled, &[], TODAY),
                id
            )
            .severity,
            FindingError
        );
        let evidence = evaluate(Some(DeploymentProfile::EvidenceGrade), &enabled, &[], TODAY);
        assert_eq!(finding(&evidence, id).severity, ReadinessFail);
        assert_eq!(evidence.readiness_failures, vec![id.to_string()]);
    }

    #[test]
    fn api_key_rotation_evidence_only_when_api_key_mode() {
        let id = "relay.auth.api_key_no_rotation_evidence";
        let not_api_key = DeploymentFacts {
            api_key_mode: false,
            api_key_rotation_evidence_missing: true,
            ..clean_facts()
        };
        let evaluation = evaluate(
            Some(DeploymentProfile::Production),
            &not_api_key,
            &[],
            TODAY,
        );
        assert!(!finding_ids(&evaluation).contains(&id.to_string()));

        let api_key = DeploymentFacts {
            api_key_mode: true,
            api_key_rotation_evidence_missing: true,
            ..clean_facts()
        };
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::HostedLab), &api_key, &[], TODAY),
                id
            )
            .severity,
            FindingWarn
        );
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::Production), &api_key, &[], TODAY),
                id
            )
            .severity,
            FindingError
        );
    }

    #[test]
    fn config_unsigned_startup_fails_under_evidence_grade() {
        let facts = DeploymentFacts {
            config_unsigned: true,
            ..clean_facts()
        };
        let id = "relay.config.unsigned";
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::HostedLab), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingWarn
        );
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::Production), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingError
        );
        let evidence = evaluate(Some(DeploymentProfile::EvidenceGrade), &facts, &[], TODAY);
        assert_eq!(finding(&evidence, id).severity, StartupFail);
        assert_eq!(evidence.startup_failures, vec![id.to_string()]);
    }

    #[test]
    fn audit_sink_missing_escalates() {
        let facts = DeploymentFacts {
            audit_sink_missing: true,
            ..clean_facts()
        };
        let id = "relay.audit.sink_missing";
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::HostedLab), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingError
        );
        let production = evaluate(Some(DeploymentProfile::Production), &facts, &[], TODAY);
        assert_eq!(finding(&production, id).severity, ReadinessFail);
        let evidence = evaluate(Some(DeploymentProfile::EvidenceGrade), &facts, &[], TODAY);
        assert_eq!(finding(&evidence, id).severity, StartupFail);
        assert!(evidence.has_startup_failure());
    }

    #[test]
    fn audit_best_effort_binds_production_and_evidence_only() {
        let facts = DeploymentFacts {
            audit_best_effort: true,
            ..clean_facts()
        };
        let id = "relay.audit.best_effort";
        let hosted = evaluate(Some(DeploymentProfile::HostedLab), &facts, &[], TODAY);
        assert!(!finding_ids(&hosted).contains(&id.to_string()));
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::Production), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingWarn
        );
        let evidence = evaluate(Some(DeploymentProfile::EvidenceGrade), &facts, &[], TODAY);
        assert_eq!(finding(&evidence, id).severity, ReadinessFail);
        assert_eq!(evidence.readiness_failures, vec![id.to_string()]);
    }

    #[test]
    fn audit_retention_local_only_binds_production_and_evidence_only() {
        let facts = DeploymentFacts {
            audit_retention_local_only: true,
            ..clean_facts()
        };
        let id = "relay.audit.retention_local_only";
        let local = evaluate(Some(DeploymentProfile::Local), &facts, &[], TODAY);
        assert!(!finding_ids(&local).contains(&id.to_string()));
        let hosted = evaluate(Some(DeploymentProfile::HostedLab), &facts, &[], TODAY);
        assert!(!finding_ids(&hosted).contains(&id.to_string()));
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::Production), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingWarn
        );
        let evidence = evaluate(Some(DeploymentProfile::EvidenceGrade), &facts, &[], TODAY);
        assert_eq!(finding(&evidence, id).severity, StartupFail);
        assert_eq!(evidence.startup_failures, vec![id.to_string()]);
        // Non-triggering: clean facts never surface the finding.
        let clean = evaluate(
            Some(DeploymentProfile::Production),
            &clean_facts(),
            &[],
            TODAY,
        );
        assert!(!finding_ids(&clean).contains(&id.to_string()));
    }

    #[test]
    fn audit_retention_local_only_production_finding_is_waivable() {
        let facts = DeploymentFacts {
            audit_retention_local_only: true,
            ..clean_facts()
        };
        let id = "relay.audit.retention_local_only";
        let waivers = [WaiverInput {
            finding: id.to_string(),
            reason: "synthetic test waiver".to_string(),
            expires: FUTURE.to_string(),
        }];
        let evaluation = evaluate(Some(DeploymentProfile::Production), &facts, &waivers, TODAY);
        assert_eq!(
            finding(&evaluation, id).status,
            DeploymentFindingStatus::Waived
        );
        assert_eq!(evaluation.active_waivers.len(), 1);
        assert_eq!(evaluation.active_waivers[0].finding, id);
    }

    #[test]
    fn shipping_unverified_escalates_when_declared_external_without_cursor() {
        // Off-host shipping is declared but no ack cursor observes it: warn
        // under production, startup_fail under evidence_grade, and unbound at
        // hosted_lab.
        let facts = DeploymentFacts {
            audit_shipping_target_configured: true,
            audit_ack_cursor_configured: false,
            ..clean_facts()
        };
        let id = "relay.audit.shipping_unverified";
        let hosted = evaluate(Some(DeploymentProfile::HostedLab), &facts, &[], TODAY);
        assert!(!finding_ids(&hosted).contains(&id.to_string()));
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::Production), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingWarn
        );
        let evidence = evaluate(Some(DeploymentProfile::EvidenceGrade), &facts, &[], TODAY);
        assert_eq!(finding(&evidence, id).severity, StartupFail);
        assert_eq!(evidence.startup_failures, vec![id.to_string()]);
        assert!(evidence.has_startup_failure());
        assert!(!evidence.has_readiness_failure());
    }

    #[test]
    fn shipping_unverified_silent_when_cursor_configured_or_not_declared() {
        let id = "relay.audit.shipping_unverified";
        // A cursor is configured: shipping is observed, so unverified is silent.
        let with_cursor = DeploymentFacts {
            audit_shipping_target_configured: true,
            audit_ack_cursor_configured: true,
            ..clean_facts()
        };
        let evaluation = evaluate(
            Some(DeploymentProfile::Production),
            &with_cursor,
            &[],
            TODAY,
        );
        assert!(!finding_ids(&evaluation).contains(&id.to_string()));
        // Shipping is not declared_external (e.g. stdout sink): unverified is
        // silent even without a cursor.
        let not_declared = DeploymentFacts {
            audit_shipping_target_configured: false,
            audit_ack_cursor_configured: false,
            ..clean_facts()
        };
        let evaluation = evaluate(
            Some(DeploymentProfile::EvidenceGrade),
            &not_declared,
            &[],
            TODAY,
        );
        assert!(!finding_ids(&evaluation).contains(&id.to_string()));
    }

    #[test]
    fn shipping_stale_escalates_when_cursor_unhealthy() {
        // A cursor is configured but its observed health is not `ok`: error
        // under production, readiness_fail under evidence_grade, unbound at
        // hosted_lab. Fail closed on any non-ok health.
        let facts = DeploymentFacts {
            audit_ack_cursor_configured: true,
            audit_ack_health_ok: false,
            ..clean_facts()
        };
        let id = "relay.audit.shipping_stale";
        let hosted = evaluate(Some(DeploymentProfile::HostedLab), &facts, &[], TODAY);
        assert!(!finding_ids(&hosted).contains(&id.to_string()));
        assert_eq!(
            finding(
                &evaluate(Some(DeploymentProfile::Production), &facts, &[], TODAY),
                id
            )
            .severity,
            FindingError
        );
        let evidence = evaluate(Some(DeploymentProfile::EvidenceGrade), &facts, &[], TODAY);
        assert_eq!(finding(&evidence, id).severity, ReadinessFail);
        assert_eq!(evidence.readiness_failures, vec![id.to_string()]);
        assert!(evidence.has_readiness_failure());
    }

    #[test]
    fn shipping_stale_silent_when_cursor_healthy_or_absent() {
        let id = "relay.audit.shipping_stale";
        // Healthy cursor: silent.
        let healthy = DeploymentFacts {
            audit_ack_cursor_configured: true,
            audit_ack_health_ok: true,
            ..clean_facts()
        };
        let evaluation = evaluate(Some(DeploymentProfile::EvidenceGrade), &healthy, &[], TODAY);
        assert!(!finding_ids(&evaluation).contains(&id.to_string()));
        // No cursor configured at all: the stale gate does not bind (only the
        // unverified gate can bind in that case), even if health_ok is false.
        let no_cursor = DeploymentFacts {
            audit_ack_cursor_configured: false,
            audit_ack_health_ok: false,
            ..clean_facts()
        };
        let evaluation = evaluate(
            Some(DeploymentProfile::EvidenceGrade),
            &no_cursor,
            &[],
            TODAY,
        );
        assert!(!finding_ids(&evaluation).contains(&id.to_string()));
    }

    #[test]
    fn shipping_stale_readiness_fail_is_non_waivable() {
        // Under evidence_grade `relay.audit.shipping_stale` is readiness_fail,
        // which is non-waivable: a waiver must not suppress it and readiness
        // still fails.
        let facts = DeploymentFacts {
            audit_ack_cursor_configured: true,
            audit_ack_health_ok: false,
            ..clean_facts()
        };
        let id = "relay.audit.shipping_stale";
        let waivers = [WaiverInput {
            finding: id.to_string(),
            reason: "synthetic stale-shipping waiver".to_string(),
            expires: FUTURE.to_string(),
        }];
        let evaluation = evaluate(
            Some(DeploymentProfile::EvidenceGrade),
            &facts,
            &waivers,
            TODAY,
        );
        let f = finding(&evaluation, id);
        assert_eq!(f.status, DeploymentFindingStatus::Active);
        assert_eq!(f.severity, ReadinessFail);
        assert!(evaluation.has_readiness_failure());
        assert_eq!(evaluation.readiness_failures, vec![id.to_string()]);
        // The waiver is still listed as active for review; it does not suppress.
        assert_eq!(evaluation.active_waivers.len(), 1);
    }

    #[test]
    fn active_waiver_suppresses_finding_and_reports_waived() {
        let facts = DeploymentFacts {
            openapi_public: true,
            ..clean_facts()
        };
        let waivers = [WaiverInput {
            finding: "relay.openapi.public".to_string(),
            reason: "synthetic test waiver".to_string(),
            expires: FUTURE.to_string(),
        }];
        let evaluation = evaluate(Some(DeploymentProfile::Production), &facts, &waivers, TODAY);
        let f = finding(&evaluation, "relay.openapi.public");
        assert_eq!(f.status, DeploymentFindingStatus::Waived);
        assert_eq!(f.severity, FindingError);
        assert_eq!(
            f.waiver.as_ref().unwrap().reason,
            "synthetic test waiver".to_string()
        );
        // An active waiver is reported in the waivers list.
        assert_eq!(evaluation.active_waivers.len(), 1);
        assert_eq!(evaluation.active_waivers[0].finding, "relay.openapi.public");
        assert!(!finding_ids(&evaluation).contains(&WAIVER_EXPIRED.to_string()));
    }

    #[test]
    fn waiver_does_not_suppress_readiness_fail() {
        // A readiness_fail gate is non-waivable: readiness gates stop traffic
        // when an evidence guarantee fails, so a waiver must not silently
        // un-fail them. `relay.admin.public_exposure` is readiness_fail under
        // production.
        let facts = DeploymentFacts {
            admin_public_exposure: true,
            ..clean_facts()
        };
        let id = "relay.admin.public_exposure";
        let waivers = [WaiverInput {
            finding: id.to_string(),
            reason: "synthetic readiness waiver".to_string(),
            expires: FUTURE.to_string(),
        }];
        let evaluation = evaluate(Some(DeploymentProfile::Production), &facts, &waivers, TODAY);
        // The waiver does not suppress the finding: it stays active and
        // readiness still fails.
        let f = finding(&evaluation, id);
        assert_eq!(f.status, DeploymentFindingStatus::Active);
        assert_eq!(f.severity, ReadinessFail);
        assert!(evaluation.has_readiness_failure());
        assert_eq!(evaluation.readiness_failures, vec![id.to_string()]);
        // The waiver is still listed as active for review; it simply does not
        // suppress the gate.
        assert_eq!(evaluation.active_waivers.len(), 1);
    }

    #[test]
    fn expired_waiver_retriggers_and_raises_waiver_expired() {
        let facts = DeploymentFacts {
            openapi_public: true,
            ..clean_facts()
        };
        let waivers = [WaiverInput {
            finding: "relay.openapi.public".to_string(),
            reason: "synthetic expired waiver".to_string(),
            expires: PAST.to_string(),
        }];
        let evaluation = evaluate(Some(DeploymentProfile::Production), &facts, &waivers, TODAY);
        // The underlying finding re-triggers as active at its real severity.
        let f = finding(&evaluation, "relay.openapi.public");
        assert_eq!(f.status, DeploymentFindingStatus::Active);
        assert_eq!(f.severity, FindingError);
        // The waiver no longer counts as active.
        assert!(evaluation.active_waivers.is_empty());
        // And a separate waiver_expired error is raised.
        assert_eq!(finding(&evaluation, WAIVER_EXPIRED).severity, FindingError);
    }

    #[test]
    fn startup_fail_is_never_waivable() {
        let facts = DeploymentFacts {
            config_unsigned: true,
            ..clean_facts()
        };
        let waivers = [WaiverInput {
            finding: "relay.config.unsigned".to_string(),
            reason: "synthetic attempt to waive a startup gate".to_string(),
            expires: FUTURE.to_string(),
        }];
        let evaluation = evaluate(
            Some(DeploymentProfile::EvidenceGrade),
            &facts,
            &waivers,
            TODAY,
        );
        // The waiver is ignored for a startup_fail gate: the finding stays
        // active and startup still fails.
        let f = finding(&evaluation, "relay.config.unsigned");
        assert_eq!(f.status, DeploymentFindingStatus::Active);
        assert!(evaluation.has_startup_failure());
        // The waiver is, however, still listed as active for review; it simply
        // does not suppress the gate.
        assert_eq!(evaluation.active_waivers.len(), 1);
    }

    #[test]
    fn waiver_on_expiry_day_still_suppresses() {
        let facts = DeploymentFacts {
            openapi_public: true,
            ..clean_facts()
        };
        let waivers = [WaiverInput {
            finding: "relay.openapi.public".to_string(),
            reason: "synthetic boundary waiver".to_string(),
            expires: TODAY.to_string(),
        }];
        let evaluation = evaluate(Some(DeploymentProfile::Production), &facts, &waivers, TODAY);
        assert_eq!(
            finding(&evaluation, "relay.openapi.public").status,
            DeploymentFindingStatus::Waived
        );
    }

    fn minimal_config() -> Config {
        serde_saphyr::from_str(
            r#"
server:
  bind: "127.0.0.1:8080"
catalog:
  title: "Test Registry"
  base_url: "https://data.example.test"
  publisher: "Test Ministry"
auth:
  mode: api_key
  api_keys: []
audit:
  sink: stdout
datasets: []
"#,
        )
        .expect("config parses")
    }

    #[test]
    fn config_unsigned_fact_classifies_sources_fail_closed() {
        let config = minimal_config();
        // A local file is unsigned.
        assert!(facts_from_config(&config, ConfigSource::LocalFile).config_unsigned);
        // Unknown provenance fails closed: it counts as unsigned, so the
        // `relay.config.unsigned` gate fires rather than silently clearing.
        assert!(facts_from_config(&config, ConfigSource::Unknown).config_unsigned);
        // Only a genuine signed bundle clears the gate.
        assert!(!facts_from_config(&config, ConfigSource::SignedBundleFile).config_unsigned);
        assert!(!facts_from_config(&config, ConfigSource::SignedBundleEndpoint).config_unsigned);
    }

    #[test]
    fn gate_severity_for_profile_resolves_binding() {
        // The retention gate warns under production and is a startup failure
        // under evidence_grade; it is unbound under hosted_lab and local.
        let id = "relay.audit.retention_local_only";
        assert_eq!(
            gate_severity_for_profile(id, Some(DeploymentProfile::Production)),
            Some(FindingWarn)
        );
        assert_eq!(
            gate_severity_for_profile(id, Some(DeploymentProfile::EvidenceGrade)),
            Some(StartupFail)
        );
        assert_eq!(
            gate_severity_for_profile(id, Some(DeploymentProfile::HostedLab)),
            None
        );
        assert_eq!(
            gate_severity_for_profile(id, Some(DeploymentProfile::Local)),
            None
        );
        // An undeclared profile or an unknown gate binds nothing.
        assert_eq!(gate_severity_for_profile(id, None), None);
        assert_eq!(
            gate_severity_for_profile("not.a.gate", Some(DeploymentProfile::EvidenceGrade)),
            None
        );
    }

    #[test]
    fn severity_is_waivable_only_for_findings() {
        // Only posture findings are waivable. Both hard gates (readiness_fail
        // and startup_fail) are non-waivable, matching Notary's semantics.
        assert!(severity_is_waivable(FindingWarn));
        assert!(severity_is_waivable(FindingError));
        assert!(!severity_is_waivable(ReadinessFail));
        assert!(!severity_is_waivable(StartupFail));
    }

    #[test]
    fn hard_gate_remediation_covers_every_non_waivable_gate() {
        // The audit retention gate names its off-host levers.
        let audit = hard_gate_remediation("relay.audit.retention_local_only");
        assert!(audit.contains("audit_offhost_shipping"));
        assert!(audit.contains("non-local audit sink"));
        assert!(audit.contains("cannot be waived under the active profile"));
        // Every other gate that can be non-waivable under some profile
        // (readiness_fail or startup_fail) gets its own actionable lever, not
        // the audit-retention specifics.
        for (gate_id, needle) in [
            ("relay.admin.public_exposure", "admin_bind"),
            ("relay.oidc.client_allowlist_empty", "allowed_clients"),
            ("relay.config.unsigned", "signed"),
            ("relay.audit.sink_missing", "durable audit sink"),
            ("relay.audit.best_effort", "write_policy"),
            ("relay.audit.shipping_unverified", "audit_ack_cursor_path"),
            ("relay.audit.shipping_stale", "audit_ack_max_age_secs"),
        ] {
            let remediation = hard_gate_remediation(gate_id);
            assert!(
                remediation.contains(needle),
                "remediation for {gate_id} should mention {needle}: {remediation}"
            );
            assert!(
                remediation.contains("cannot be waived under the active profile"),
                "remediation for {gate_id} should state non-waivability: {remediation}"
            );
            assert!(
                !remediation.contains("audit_offhost_shipping"),
                "only the retention gate names the off-host lever: {remediation}"
            );
        }
        // An unmatched gate id falls back to the generic guidance.
        assert_eq!(
            hard_gate_remediation("not.a.gate"),
            "fix the underlying condition; this gate cannot be waived under the active profile"
        );
    }
}
