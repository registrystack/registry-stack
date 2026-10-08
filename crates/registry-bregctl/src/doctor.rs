// SPDX-License-Identifier: Apache-2.0
//! Base Registry Engine configured startup dependency verification.

use std::path::Path;

use registry_breg::startup::{check, CheckedStartup, StartupError};
use registry_breg::{Diagnostic, DiagnosticSeverity};

/// The startup dependencies `prepare()` checks, in the order it checks them.
/// Doctor only reports success once every one of these has passed, so this is
/// what the passing report counts and names, one line per dependency.
pub(crate) const CHECKED_DEPENDENCIES: [&str; 10] = [
    "runtimeConfig",
    "package",
    "database",
    "audit",
    "cursor",
    "authentication.oidc",
    "eventDestinations",
    "reviewBindings",
    "authentication",
    "fieldEncryption",
];

/// A doctor run that refused: its diagnostics, and whether the runtime
/// configuration file itself was refused rather than a dependency it names.
pub(crate) struct DoctorRefusal {
    pub(crate) diagnostics: Vec<Diagnostic>,
    pub(crate) runtime_configuration: bool,
}

/// Run the startup dependency check without binding a listener, keeping only
/// the PostgreSQL baseline advisories and the role mode it decided. It verifies the dependencies
/// preparation opens and intentionally owns no parallel readiness logic; the
/// audit destination is checked as writable rather than opened, so doctor runs
/// beside a serving process that holds it.
pub(crate) fn run(runtime_config: &Path) -> Result<CheckedStartup, DoctorRefusal> {
    if !runtime_config.is_absolute() {
        return Err(DoctorRefusal {
            diagnostics: vec![diagnostic(
                "startup.runtime_config.path_invalid",
                "runtimeConfig",
                "the runtime configuration path must be absolute",
            )],
            runtime_configuration: true,
        });
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| DoctorRefusal {
            diagnostics: vec![diagnostic(
                "startup.runtime.unavailable",
                "runtime",
                "the startup preparation runtime is unavailable",
            )],
            runtime_configuration: false,
        })?;
    runtime
        .block_on(check(runtime_config))
        .map_err(startup_refusal)
}

/// A refused runtime file reports every reader diagnostic, or the one rule
/// the runtime decides itself, unchanged; any other refusal names its one
/// startup cause.
fn startup_refusal(error: StartupError) -> DoctorRefusal {
    let runtime_configuration = matches!(error, StartupError::RuntimeConfig(_));
    let diagnostics = match error {
        StartupError::RuntimeConfig(cause) => crate::runtime_config_diagnostics(&cause),
        other => vec![startup_diagnostic(other)],
    };
    DoctorRefusal {
        diagnostics,
        runtime_configuration,
    }
}

fn startup_diagnostic(error: StartupError) -> Diagnostic {
    if let StartupError::FieldPatternSyntax {
        entity_id,
        field_id,
    } = error
    {
        return diagnostic(
            "breg.field.pattern-syntax-invalid",
            &format!("entities[{entity_id}].fields[{field_id}].pattern"),
            "the persisted field pattern has invalid PostgreSQL ARE syntax; correct the expression and rerun schema-test before packaging; a failed activation requires restoration of the pre-activation backup before changing the pinned target",
        );
    }
    if let StartupError::ReviewAuthorityMissing {
        authority,
        retained_submissions,
    } = error
    {
        let noun = if retained_submissions == 1 {
            "submission"
        } else {
            "submissions"
        };
        return diagnostic(
            "startup.review_authority.missing",
            &format!("/reviewAuthorities/{authority}"),
            &format!(
                "runtime review authority `{authority}` is absent but required by \
                 {retained_submissions} retained review {noun}; restore the exact authority and \
                 producer binding, reconcile or complete those requests through the source \
                 request and review-authority workflows, then remove the binding and rerun \
                 doctor; \
                 accepted reviews do not time out"
            ),
        );
    }
    if let StartupError::InstanceIdChangedWithPendingDeliveries {
        stored_source,
        configured_instance_id,
        pending_deliveries,
    } = error
    {
        let noun = if pending_deliveries == 1 {
            "delivery was"
        } else {
            "deliveries were"
        };
        return diagnostic(
            "startup.instance_id.pending_deliveries",
            "identity.instanceId",
            &format!(
                "{pending_deliveries} pending webhook {noun} captured under event source \
                 `{stored_source}`, but identity.instanceId `{configured_instance_id}` derives \
                 another source and the delivery worker would dead-letter them; restore the \
                 previous identity.instanceId until those deliveries drain, then change it and \
                 rerun doctor"
            ),
        );
    }
    if let StartupError::RetainedWebhookBindings {
        retained_deliveries,
    } = error
    {
        let noun = if retained_deliveries == 1 {
            "delivery requires"
        } else {
            "deliveries require"
        };
        return diagnostic(
            "startup.webhook.retained_bindings",
            "eventDestinations",
            &format!(
                "{retained_deliveries} retained webhook {noun} a superseded destination or local-handler binding; run `bregctl webhook list` to identify rows where bindingActive is false, then either restore each exact binding until its work drains or explicitly discard each delivery with its current generation; stop the runtime before discarding pending work, and retry an active lease only after it expires"
            ),
        );
    }
    // The package refusal carries its own closed-vocabulary cause. Name it
    // inside the one package check instead of collapsing every package fault
    // into the same sentence; both vocabularies are value free.
    if let StartupError::PackageRefused(cause) = error {
        return diagnostic(
            "startup.package.refused",
            "package",
            &format!("the runtime package was refused: {cause}"),
        );
    }
    if let StartupError::PackageEnvelopeRefused(cause) = error {
        return diagnostic("startup.package.refused", "package", &cause);
    }
    // The writer's own refusal names the rule and the recovery step, and
    // never a path or a secret.
    if let StartupError::AuditDestination(reason) = error {
        return diagnostic(
            "startup.audit.refused",
            "audit",
            &format!("the audit destination was refused: {reason}"),
        );
    }
    let (code, path, message) = match error {
        StartupError::RuntimeConfig(_) => {
            unreachable!("startup_refusal reports every runtime configuration diagnostic")
        }
        StartupError::PackageRefused(_)
        | StartupError::PackageEnvelopeRefused(_)
        | StartupError::AuditDestination(_) => {
            unreachable!("handled above")
        }
        StartupError::ReviewAuthorityMissing { .. }
        | StartupError::InstanceIdChangedWithPendingDeliveries { .. } => {
            unreachable!("handled above")
        }
        StartupError::DatabaseConnection => (
            "startup.database.connection_refused",
            "database",
            "the database connection was refused",
        ),
        StartupError::FieldPatternSyntax { .. } => unreachable!("handled before match"),
        StartupError::DatabaseUnready => (
            "startup.database.unready",
            "database",
            "the database is not ready for the runtime package",
        ),
        StartupError::DatabaseUninitialized => (
            "startup.database.uninitialized",
            "database",
            "the database records no activated package: run bregctl apply --package DIR --initial to activate the first package",
        ),
        StartupError::UnrecognizedDatabase => (
            "startup.database.unrecognized",
            "database",
            "the database holds registry state this release does not recognise: a release reads only the state its predecessor wrote, so upgrade the database one release at a time",
        ),
        StartupError::DatabaseIdentityMismatch => (
            "startup.database.identity_mismatch",
            "database",
            "the database records a different database id than identity.databaseId: point database.runtimeUrlRef at the database it names or correct identity.databaseId",
        ),
        StartupError::ActivePackageMismatch => (
            "startup.package.not_active",
            "package",
            "the database has not activated the package at package.root: run bregctl plan --package DIR then bregctl apply --package DIR",
        ),
        StartupError::InstanceClaimMismatch => (
            "startup.instance_claim.mismatch",
            "database",
            "the database is not the instance the Registry's claim names, as a restored copy is: once the original is retired, run bregctl instance-claim adopt",
        ),
        StartupError::RuntimeWriteAuthority => (
            "startup.runtime_role.can_write",
            "database",
            "the runtime role can write the activation ledger or the registry state: run bregctl apply --package DIR to name the object and the fix",
        ),
        StartupError::RuntimeGrantsMissing => (
            "startup.runtime_role.grants_missing",
            "database",
            "the runtime role is missing grants the active package gives it: run bregctl apply --package DIR to reissue them",
        ),
        StartupError::RoleModeChanged => (
            "startup.role_mode.changed",
            "database",
            "the database was activated for a separate runtime role but the runtime file names one role: run bregctl apply --package DIR to activate it for one role",
        ),
        StartupError::Audit => (
            "startup.audit.refused",
            "audit",
            "the audit profile was refused: the hash key must resolve",
        ),
        StartupError::Cursor => (
            "startup.cursor.refused",
            "cursor",
            "the cursor profile was refused",
        ),
        // The dependency reports one refusal for its whole key source, so the
        // sentence names the closed set of causes without naming any value.
        StartupError::Oidc => (
            "startup.oidc.refused",
            "authentication.oidc",
            "the OIDC key source was refused: from this host the configured issuer must be reachable, must present a TLS certificate this host trusts, and must publish a key set holding at least one key for the configured algorithms",
        ),
        StartupError::Authentication => (
            "startup.authentication.refused",
            "authentication",
            "the authentication profile was refused: check the claim mapping, the accepted algorithms, and the audience against the package this runtime serves",
        ),
        StartupError::EventDestinations => (
            "startup.event_destinations.refused",
            "eventDestinations",
            "the event destination bindings were refused",
        ),
        StartupError::RetainedWebhookBindings { .. } => unreachable!(
            "retained webhook binding diagnostics return before the generic mapping"
        ),
        StartupError::ReviewBindings => (
            "startup.review_bindings.refused",
            "reviewBindings",
            "the retained review authority or executor bindings were refused",
        ),
        StartupError::AttachmentStorage => (
            "startup.attachment_storage.refused",
            "attachmentStorage",
            "the attachment binding was refused: check attachmentStorage and attachmentVerification credentials and endpoints, disabled S3 versioning, and the registry's pinned backend and verification policy",
        ),
        StartupError::FieldEncryption => (
            "startup.field_encryption.refused",
            "fieldEncryption",
            "the field-encryption key state was refused: an active package with encrypted fields requires a configured fieldEncryption provider that answers, and a stored key row the provider can unwrap",
        ),
        StartupError::FieldEncryptionCustody => (
            "startup.field_encryption.custody_refused",
            "fieldEncryption",
            "the field-encryption data-key custody was refused: a databaseInitializationEnvironment other than local requires the transit provider; localFile data keys are development-only",
        ),
        StartupError::Listener => (
            "startup.listener.refused",
            "listener",
            "the listener configuration was refused",
        ),
        StartupError::Shutdown => (
            "startup.shutdown.refused",
            "shutdown",
            "the shutdown configuration was refused",
        ),
        StartupError::BackgroundTaskStopped => (
            "startup.background_task.stopped",
            "backgroundTask",
            "a background task stopped before shutdown was requested",
        ),
        StartupError::Logging => (
            "startup.logging.refused",
            "logging",
            "the operational logging configuration was refused",
        ),
    };
    diagnostic(code, path, message)
}

fn diagnostic(code: &str, path: &str, message: &str) -> Diagnostic {
    Diagnostic {
        severity: DiagnosticSeverity::Error,
        code: code.to_owned(),
        path: path.to_owned(),
        message: message.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_breg::package::PackageError;
    use registry_breg::runtime_config::RuntimeConfigError;
    use std::collections::HashSet;

    #[test]
    fn checked_dependencies_is_pinned_to_startups_own_vocabulary() {
        // `CHECKED_DEPENDENCIES` is a hand-typed success-report vocabulary.
        // Tie it to `startup_diagnostic`'s own failure-path vocabulary so the
        // two cannot silently drift apart: collect the path every distinctly
        // checked `StartupError` variant reports, and assert the resulting
        // set is exactly `CHECKED_DEPENDENCIES`'s set. The `RuntimeConfig`
        // case contributes the literal "runtimeConfig": it covers all 27
        // `RuntimeConfigError` causes as one stage, already exercised by
        // `runtime_config_causes_are_named_the_way_verify_already_names_them`.
        //
        // Three `StartupError` variants are left out of the iterated set
        // because `prepare()` never constructs them as a distinct check:
        // - `Shutdown` is only constructed inside `serve_until_shutdown`,
        //   `shutdown_signal`, and `first_shutdown_signal` (startup.rs); none
        //   of those run inside `prepare()`, and doctor never calls `serve()`.
        // - `Logging` is only constructed inside `operational_log_level`
        //   (startup.rs), which only `main.rs` calls, before `prepare()` or
        //   `serve()` run.
        // - `Listener` is reachable from `prepare()`, but only through
        //   `map_runtime_config_error`'s
        //   `RuntimeConfigError::InvalidMetricsListener => StartupError::Listener`
        //   arm, fired during the same `load_runtime_config()` parse that
        //   produces every other `RuntimeConfigError`. It names no check
        //   `prepare()` performs separately from `runtimeConfig`, so counting
        //   it here would double-count that one stage under a second name.
        let distinctly_checked = [
            StartupError::PackageRefused(PackageError::Integrity),
            StartupError::DatabaseConnection,
            StartupError::DatabaseUnready,
            StartupError::DatabaseUninitialized,
            StartupError::UnrecognizedDatabase,
            StartupError::InstanceClaimMismatch,
            StartupError::RuntimeWriteAuthority,
            StartupError::RuntimeGrantsMissing,
            StartupError::RoleModeChanged,
            StartupError::DatabaseIdentityMismatch,
            StartupError::ActivePackageMismatch,
            StartupError::Audit,
            StartupError::Cursor,
            StartupError::Oidc,
            StartupError::Authentication,
            StartupError::EventDestinations,
            StartupError::FieldEncryption,
            StartupError::FieldEncryptionCustody,
            StartupError::ReviewBindings,
        ];

        let reported_paths: HashSet<String> = distinctly_checked
            .into_iter()
            .map(|error| startup_diagnostic(error).path)
            .chain(std::iter::once("runtimeConfig".to_owned()))
            .collect();
        let checked_dependencies: HashSet<String> = CHECKED_DEPENDENCIES
            .into_iter()
            .map(str::to_owned)
            .collect();

        assert_eq!(
            reported_paths, checked_dependencies,
            "CHECKED_DEPENDENCIES must name exactly the checks prepare() can \
             distinctly fail; update it (or the exclusions documented above) \
             when they diverge"
        );
    }

    #[test]
    fn checked_dependencies_has_no_duplicate_entries() {
        let mut seen = HashSet::new();
        for dependency in CHECKED_DEPENDENCIES {
            assert!(
                seen.insert(dependency),
                "duplicate entry in CHECKED_DEPENDENCIES: {dependency}"
            );
        }
    }

    #[test]
    fn native_pattern_failure_preserves_the_authored_address_and_recovery_guidance() {
        let diagnostic = startup_diagnostic(StartupError::FieldPatternSyntax {
            entity_id: "entry".to_owned(),
            field_id: "identifier".to_owned(),
        });
        assert_eq!(diagnostic.code, "breg.field.pattern-syntax-invalid");
        assert_eq!(
            diagnostic.path,
            "entities[entry].fields[identifier].pattern"
        );
        for repair in [
            "correct the expression",
            "schema-test",
            "backup",
            "pinned target",
        ] {
            assert!(diagnostic.message.contains(repair));
        }
        assert!(!diagnostic.message.contains("registry_data"));
        assert!(!diagnostic.message.contains("breg_pattern_"));
    }

    #[test]
    fn missing_review_authority_names_the_binding_count_and_supported_recovery() {
        let diagnostic = startup_diagnostic(StartupError::ReviewAuthorityMissing {
            authority: "casework-retained".to_owned(),
            retained_submissions: 2,
        });
        assert_eq!(diagnostic.code, "startup.review_authority.missing");
        assert_eq!(diagnostic.path, "/reviewAuthorities/casework-retained");
        for detail in [
            "casework-retained",
            "2 retained review submissions",
            "exact authority and producer binding",
            "source request and review-authority workflows",
            "rerun doctor",
            "do not time out",
        ] {
            assert!(
                diagnostic.message.contains(detail),
                "missing diagnostic detail {detail}: {}",
                diagnostic.message
            );
        }
    }

    #[test]
    fn retained_webhooks_name_the_bounded_recovery_path() {
        let diagnostic = startup_diagnostic(StartupError::RetainedWebhookBindings {
            retained_deliveries: 2,
        });
        assert_eq!(diagnostic.code, "startup.webhook.retained_bindings");
        assert_eq!(diagnostic.path, "eventDestinations");
        for detail in [
            "2 retained webhook deliveries require",
            "bregctl webhook list",
            "bindingActive is false",
            "restore each exact binding",
            "explicitly discard",
            "stop the runtime",
            "active lease",
        ] {
            assert!(
                diagnostic.message.contains(detail),
                "missing diagnostic detail {detail}: {}",
                diagnostic.message
            );
        }
    }

    #[test]
    fn instance_id_change_with_pending_deliveries_names_both_identifiers_and_the_recovery() {
        let diagnostic = startup_diagnostic(StartupError::InstanceIdChangedWithPendingDeliveries {
            stored_source: "urn:registrystack:registry:licences:instance:previous".to_owned(),
            configured_instance_id: "renamed".to_owned(),
            pending_deliveries: 1,
        });
        assert_eq!(diagnostic.code, "startup.instance_id.pending_deliveries");
        assert_eq!(diagnostic.path, "identity.instanceId");
        for detail in [
            "1 pending webhook delivery was",
            "`urn:registrystack:registry:licences:instance:previous`",
            "identity.instanceId `renamed`",
            "dead-letter",
            "restore the previous identity.instanceId until those deliveries drain",
        ] {
            assert!(
                diagnostic.message.contains(detail),
                "missing diagnostic detail {detail}: {}",
                diagnostic.message
            );
        }
    }

    #[test]
    fn startup_value_disclosure_threat_is_enforced_by_a_closed_negative_class_mapping() {
        let cases = [
            (
                StartupError::PackageRefused(PackageError::Integrity),
                "startup.package.refused",
                "package",
            ),
            (
                StartupError::DatabaseConnection,
                "startup.database.connection_refused",
                "database",
            ),
            (
                StartupError::DatabaseUnready,
                "startup.database.unready",
                "database",
            ),
            (
                StartupError::DatabaseUninitialized,
                "startup.database.uninitialized",
                "database",
            ),
            (
                StartupError::UnrecognizedDatabase,
                "startup.database.unrecognized",
                "database",
            ),
            (
                StartupError::InstanceClaimMismatch,
                "startup.instance_claim.mismatch",
                "database",
            ),
            (
                StartupError::RuntimeWriteAuthority,
                "startup.runtime_role.can_write",
                "database",
            ),
            (
                StartupError::RuntimeGrantsMissing,
                "startup.runtime_role.grants_missing",
                "database",
            ),
            (
                StartupError::RoleModeChanged,
                "startup.role_mode.changed",
                "database",
            ),
            (StartupError::Audit, "startup.audit.refused", "audit"),
            (
                StartupError::AuditDestination("the audit file could not be opened".to_owned()),
                "startup.audit.refused",
                "audit",
            ),
            (StartupError::Cursor, "startup.cursor.refused", "cursor"),
            (
                StartupError::Oidc,
                "startup.oidc.refused",
                "authentication.oidc",
            ),
            (
                StartupError::Authentication,
                "startup.authentication.refused",
                "authentication",
            ),
            (
                StartupError::EventDestinations,
                "startup.event_destinations.refused",
                "eventDestinations",
            ),
            (
                StartupError::FieldEncryption,
                "startup.field_encryption.refused",
                "fieldEncryption",
            ),
            (
                StartupError::FieldEncryptionCustody,
                "startup.field_encryption.custody_refused",
                "fieldEncryption",
            ),
            (
                StartupError::ReviewBindings,
                "startup.review_bindings.refused",
                "reviewBindings",
            ),
            (
                StartupError::Listener,
                "startup.listener.refused",
                "listener",
            ),
            (
                StartupError::Shutdown,
                "startup.shutdown.refused",
                "shutdown",
            ),
            (
                StartupError::BackgroundTaskStopped,
                "startup.background_task.stopped",
                "backgroundTask",
            ),
            (StartupError::Logging, "startup.logging.refused", "logging"),
        ];

        for (error, expected_code, expected_path) in cases {
            let rendered_dependency_error = error.to_string();
            let diagnostic = startup_diagnostic(error);
            assert_eq!(diagnostic.code, expected_code);
            assert_eq!(diagnostic.path, expected_path);
            assert!(!diagnostic.message.contains(&rendered_dependency_error));
        }
    }

    #[test]
    fn package_causes_are_named_inside_the_one_package_refusal() {
        // A stale runtime that refuses the package this project builds must be
        // diagnosable: the supervisor's report names which package check
        // failed. The code and path stay the ones `CHECKED_DEPENDENCIES`
        // names, so the single package stage keeps reporting under one name.
        let causes = [
            PackageError::UnsafePath,
            PackageError::Bounds,
            PackageError::Read,
            PackageError::CanonicalJson,
            PackageError::Closure,
            PackageError::Integrity,
            PackageError::Binding,
            PackageError::Derivation,
            PackageError::MigrationPlan,
            PackageError::Permissions,
            PackageError::Envelope,
        ];
        let mut messages = HashSet::new();
        for cause in &causes {
            let diagnostic = startup_diagnostic(StartupError::PackageRefused(cause.clone()));
            assert_eq!(diagnostic.code, "startup.package.refused");
            assert_eq!(diagnostic.path, "package");
            assert!(
                diagnostic.message.ends_with(&cause.to_string()),
                "{} does not name {cause}",
                diagnostic.message
            );
            assert!(
                messages.insert(diagnostic.message),
                "two package causes report the same message"
            );
        }
        assert_eq!(messages.len(), causes.len());
    }

    #[test]
    fn a_database_that_runs_another_package_or_database_id_names_the_next_command() {
        let database = startup_diagnostic(StartupError::DatabaseIdentityMismatch);
        assert_eq!(database.code, "startup.database.identity_mismatch");
        assert_eq!(database.path, "database");
        assert!(database.message.contains("identity.databaseId"));

        let package = startup_diagnostic(StartupError::ActivePackageMismatch);
        assert_eq!(package.code, "startup.package.not_active");
        assert_eq!(package.path, "package");
        assert!(package.message.contains("bregctl plan --package DIR"));
        assert!(package.message.contains("bregctl apply --package DIR"));
    }

    #[test]
    fn runtime_config_causes_are_named_by_their_breg_runtime_codes() {
        // Every closed-vocabulary configuration cause `RuntimeConfigError`
        // carries is named by its own `breg.runtime.*` code and pointer,
        // matching `bregctl verify`, instead of collapsing into one generic
        // runtime-configuration refusal.
        let cases = [
            (
                RuntimeConfigError::InvalidBinding,
                "breg.runtime.invalid-binding",
                "",
            ),
            (
                RuntimeConfigError::InvalidListener,
                "breg.runtime.invalid-listener",
                "/listener",
            ),
            (
                RuntimeConfigError::InvalidMetricsListener,
                "breg.runtime.invalid-metrics-listener",
                "/metricsListener",
            ),
            (
                RuntimeConfigError::InvalidSecretProvider,
                "breg.runtime.invalid-secret-provider",
                "/secretProviders",
            ),
            (
                RuntimeConfigError::SecretProviderRootUnavailable,
                "breg.runtime.secret-provider-root-unavailable",
                "/secretProviders/file/root",
            ),
            (
                RuntimeConfigError::UnsafeSecretProviderRoot,
                "breg.runtime.unsafe-secret-provider-root",
                "/secretProviders/file/root",
            ),
            (
                RuntimeConfigError::InvalidDatabase,
                "breg.runtime.invalid-database",
                "/database",
            ),
            (
                RuntimeConfigError::InvalidPackage,
                "breg.runtime.invalid-package",
                "/package",
            ),
            (
                RuntimeConfigError::PackageRootUnavailable,
                "breg.runtime.package-root-unavailable",
                "/package/root",
            ),
            (
                RuntimeConfigError::UnsafePackageRoot,
                "breg.runtime.unsafe-package-root",
                "/package/root",
            ),
            (
                RuntimeConfigError::InvalidOidc,
                "breg.runtime.invalid-oidc",
                "/authentication/oidc",
            ),
            (
                RuntimeConfigError::InvalidOidcLeeway,
                "breg.runtime.invalid-oidc-leeway",
                "/authentication/oidc/leewayMilliseconds",
            ),
            (
                RuntimeConfigError::InvalidAudit,
                "breg.runtime.invalid-audit",
                "/audit",
            ),
            (
                RuntimeConfigError::InvalidCursor,
                "breg.runtime.invalid-cursor",
                "/cursor",
            ),
            (
                RuntimeConfigError::InvalidEventDestination,
                "breg.runtime.invalid-event-destination",
                "/eventDestinations",
            ),
            (
                RuntimeConfigError::InvalidFieldEncryption,
                "breg.runtime.invalid-field-encryption",
                "/fieldEncryption",
            ),
            (
                RuntimeConfigError::InvalidBounds,
                "breg.runtime.invalid-bounds",
                "/operationalTimeouts",
            ),
            (RuntimeConfigError::Secret, "breg.runtime.secret", ""),
        ];

        for (cause, expected_code, expected_path) in cases {
            let message = cause.to_string();
            let refusal = startup_refusal(StartupError::RuntimeConfig(cause));
            assert!(refusal.runtime_configuration);
            let [diagnostic] = refusal.diagnostics.as_slice() else {
                panic!("one runtime rule reports one diagnostic");
            };
            assert_eq!(diagnostic.code, expected_code);
            assert_eq!(diagnostic.path, expected_path);
            assert!(diagnostic
                .message
                .starts_with(&format!("{message}; next: ")));
        }
    }

    #[test]
    fn a_refused_runtime_file_reports_every_reader_diagnostic_unchanged() {
        use registry_breg::runtime_config::{
            parse_runtime_config_with_env, RUNTIME_CONFIG_API_VERSION, RUNTIME_CONFIG_KIND,
        };
        let refused = parse_runtime_config_with_env(
            &format!(
                "apiVersion: {RUNTIME_CONFIG_API_VERSION}\nkind: {RUNTIME_CONFIG_KIND}\nlistenr: {{}}\naudt: {{}}\n"
            ),
            |_| None,
        )
        .expect_err("unknown keys are refused");
        let refusal = startup_refusal(StartupError::RuntimeConfig(refused));
        assert!(refusal.runtime_configuration);
        let unknown = refusal
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "config.unknown-key")
            .map(|diagnostic| diagnostic.path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(unknown, ["/listenr", "/audt"]);
        assert!(refusal
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.message.contains("; next: ")));
    }

    #[test]
    fn authentication_dependency_refusals_name_the_causes_an_operator_checks() {
        let key_source = startup_diagnostic(StartupError::Oidc);
        assert_eq!(key_source.code, "startup.oidc.refused");
        assert_eq!(key_source.path, "authentication.oidc");
        for cause in ["reachable", "TLS", "key set", "issuer"] {
            assert!(
                key_source.message.contains(cause),
                "{cause}: {}",
                key_source.message
            );
        }

        let profile = startup_diagnostic(StartupError::Authentication);
        assert_eq!(profile.code, "startup.authentication.refused");
        assert_eq!(profile.path, "authentication");
        for cause in ["claim", "algorithm", "audience"] {
            assert!(
                profile.message.contains(cause),
                "{cause}: {}",
                profile.message
            );
        }

        for diagnostic in [key_source, profile] {
            assert!(!diagnostic.message.contains("http"));
            assert!(!diagnostic.message.contains("://"));
        }
    }
}
