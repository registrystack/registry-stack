// SPDX-License-Identifier: Apache-2.0
//! Registry Server configured startup dependency verification.

use std::path::Path;

use registry_server::startup::{prepare, StartupError};
use registry_server::{Diagnostic, DiagnosticSeverity};

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
    let (code, path, message) = match error {
        StartupError::RuntimeConfig => (
            "startup.runtime_config.refused",
            "runtimeConfig",
            "the runtime configuration was refused",
        ),
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
                StartupError::RuntimeConfig,
                "startup.runtime_config.refused",
                "runtimeConfig",
            ),
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
