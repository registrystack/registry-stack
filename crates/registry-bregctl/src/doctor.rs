// SPDX-License-Identifier: Apache-2.0
//! Base Registry Engine configured startup dependency verification.

use std::path::Path;

use registry_breg::runtime_config::RuntimeConfigError;
use registry_breg::startup::{prepare, StartupError};
use registry_breg::{Diagnostic, DiagnosticSeverity};

/// Run startup preparation without binding a listener and discard its unbound
/// prepared state. This verifies only the dependencies preparation currently
/// opens and intentionally owns no parallel readiness logic.
pub(crate) fn run(runtime_config: &Path) -> Result<(), Diagnostic> {
    if !runtime_config.is_absolute() {
        return Err(diagnostic(
            "startup.runtime_config.path_invalid",
            "runtimeConfig",
            "the runtime configuration path must be absolute",
        ));
    }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_| {
            diagnostic(
                "startup.runtime.unavailable",
                "runtime",
                "the startup preparation runtime is unavailable",
            )
        })?;
    runtime
        .block_on(prepare(runtime_config))
        .map(drop)
        .map_err(startup_diagnostic)
}

fn startup_diagnostic(error: StartupError) -> Diagnostic {
    // The runtime configuration carries its own closed-vocabulary cause; name
    // it the way `bregctl verify` already names it instead of collapsing every
    // configuration mistake into one generic refusal.
    if let StartupError::RuntimeConfig(cause) = error {
        return runtime_config_diagnostic(cause);
    }
    let (code, path, message) = match error {
        StartupError::RuntimeConfig(_) => unreachable!("handled above"),
        StartupError::PackageRefused => (
            "startup.package.refused",
            "package",
            "the runtime package was refused",
        ),
        StartupError::DatabaseConnection => (
            "startup.database.connection_refused",
            "database",
            "the database connection was refused",
        ),
        StartupError::DatabaseUnready => (
            "startup.database.unready",
            "database",
            "the database is not ready for the runtime package",
        ),
        StartupError::Audit => (
            "startup.audit.refused",
            "audit",
            "the audit profile was refused",
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
        StartupError::Logging => (
            "startup.logging.refused",
            "logging",
            "the operational logging configuration was refused",
        ),
    };
    diagnostic(code, path, message)
}

/// Names a runtime configuration cause the same way `bregctl verify` already
/// names it: the closed-vocabulary code and path `RuntimeConfigError` carries,
/// prefixed for this command instead of `verify`'s.
fn runtime_config_diagnostic(error: RuntimeConfigError) -> Diagnostic {
    let metadata = error.metadata();
    diagnostic(
        &format!("startup.{}", metadata.code()),
        metadata.path(),
        &error.to_string(),
    )
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

    #[test]
    fn startup_value_disclosure_threat_is_enforced_by_a_closed_negative_class_mapping() {
        let cases = [
            (
                StartupError::PackageRefused,
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
            (StartupError::Audit, "startup.audit.refused", "audit"),
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
                StartupError::Listener,
                "startup.listener.refused",
                "listener",
            ),
            (
                StartupError::Shutdown,
                "startup.shutdown.refused",
                "shutdown",
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
    fn runtime_config_causes_are_named_the_way_verify_already_names_them() {
        // Every closed-vocabulary configuration cause `RuntimeConfigError`
        // carries is named by its own code and path, matching `bregctl verify`,
        // instead of collapsing into one generic runtime-configuration refusal.
        let cases = [
            (
                RuntimeConfigError::Unavailable,
                "startup.runtime_config.unavailable",
                "/",
            ),
            (
                RuntimeConfigError::UnsafeFile,
                "startup.runtime_config.unsafe_file",
                "/",
            ),
            (
                RuntimeConfigError::Bounds,
                "startup.runtime_config.bounds",
                "/",
            ),
            (
                RuntimeConfigError::EnvExpansion,
                "startup.runtime_config.env_expansion",
                "/",
            ),
            (
                RuntimeConfigError::Document,
                "startup.runtime_config.document",
                "/",
            ),
            (
                RuntimeConfigError::InvalidApiVersion,
                "startup.runtime_config.invalid_api_version",
                "/apiVersion",
            ),
            (
                RuntimeConfigError::InvalidKind,
                "startup.runtime_config.invalid_kind",
                "/kind",
            ),
            (
                RuntimeConfigError::GovernedMember,
                "startup.runtime_config.governed_member",
                "/",
            ),
            (
                RuntimeConfigError::InvalidBinding,
                "startup.runtime_config.invalid_binding",
                "/",
            ),
            (
                RuntimeConfigError::InvalidListener,
                "startup.runtime_config.invalid_listener",
                "/listener",
            ),
            (
                RuntimeConfigError::InvalidMetricsListener,
                "startup.runtime_config.invalid_metrics_listener",
                "/metricsListener",
            ),
            (
                RuntimeConfigError::InvalidSecretProvider,
                "startup.runtime_config.invalid_secret_provider",
                "/secretProviders",
            ),
            (
                RuntimeConfigError::SecretProviderRootUnavailable,
                "startup.runtime_config.secret_provider_root_unavailable",
                "/secretProviders/file/root",
            ),
            (
                RuntimeConfigError::UnsafeSecretProviderRoot,
                "startup.runtime_config.unsafe_secret_provider_root",
                "/secretProviders/file/root",
            ),
            (
                RuntimeConfigError::InvalidDatabase,
                "startup.runtime_config.invalid_database",
                "/database",
            ),
            (
                RuntimeConfigError::InvalidPackage,
                "startup.runtime_config.invalid_package",
                "/package",
            ),
            (
                RuntimeConfigError::PackageRootUnavailable,
                "startup.runtime_config.package_root_unavailable",
                "/package/root",
            ),
            (
                RuntimeConfigError::UnsafePackageRoot,
                "startup.runtime_config.unsafe_package_root",
                "/package/root",
            ),
            (
                RuntimeConfigError::TrustAnchorUnavailable,
                "startup.runtime_config.trust_anchor_unavailable",
                "/package/trustAnchorPath",
            ),
            (
                RuntimeConfigError::UnsafeTrustAnchor,
                "startup.runtime_config.unsafe_trust_anchor",
                "/package/trustAnchorPath",
            ),
            (
                RuntimeConfigError::InvalidOidc,
                "startup.runtime_config.invalid_oidc",
                "/authentication/oidc",
            ),
            (
                RuntimeConfigError::InvalidOidcLeeway,
                "startup.runtime_config.invalid_oidc_leeway",
                "/authentication/oidc/leewayMilliseconds",
            ),
            (
                RuntimeConfigError::InvalidAudit,
                "startup.runtime_config.invalid_audit",
                "/audit",
            ),
            (
                RuntimeConfigError::InvalidCursor,
                "startup.runtime_config.invalid_cursor",
                "/cursor",
            ),
            (
                RuntimeConfigError::InvalidEventDestination,
                "startup.runtime_config.invalid_event_destination",
                "/eventDestinations",
            ),
            (
                RuntimeConfigError::InvalidBounds,
                "startup.runtime_config.invalid_bounds",
                "/operationalTimeouts",
            ),
            (
                RuntimeConfigError::Secret,
                "startup.runtime_config.secret",
                "/",
            ),
        ];

        for (cause, expected_code, expected_path) in cases {
            let diagnostic = startup_diagnostic(StartupError::RuntimeConfig(cause));
            assert_eq!(diagnostic.code, expected_code);
            assert_eq!(diagnostic.path, expected_path);
            assert_eq!(diagnostic.message, cause.to_string());
        }
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
