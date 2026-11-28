// SPDX-License-Identifier: Apache-2.0

//! `schedulingctl provision`: the shared command over Scheduling's
//! runtime file. The file's two database URLs name the roles, the database
//! and both passwords, so nothing is written twice.

use std::path::Path;

use registry_platform_config::describe_secret_failure;
use registry_platform_provision::{ProductDatabase, ProvisionInput, SchemaLayout};
use registry_platform_yaml::Diagnostic;
use registry_scheduling::config::{startup_report, RuntimeConfig};
use registry_scheduling_core::SCHEDULING_RUNTIME_KIND;
use zeroize::Zeroizing;

/// Scheduling keeps its tables in `public`. `provision` gives the migration role
/// USAGE and CREATE on it and the runtime role USAGE, directly. It needs no
/// extension.
fn product() -> ProductDatabase {
    ProductDatabase {
        product: "scheduling",
        layout: SchemaLayout::PublicForMigration,
        btree_gist: false,
        spatial: None,
    }
}

fn refused(code: &str, path: &str, message: String, action: &str) -> Box<Diagnostic> {
    let mut diagnostic = Diagnostic::error(code, path, message, action);
    diagnostic.artifact = Some(SCHEDULING_RUNTIME_KIND.to_owned());
    Box::new(diagnostic)
}

/// Reads the runtime file exactly as `apply` does and resolves the two
/// database URLs and the CA behind `database.caBundleRef`.
pub(crate) fn load(
    path: &Path,
    declared: registry_platform_config::DeclaredPosture,
) -> Result<ProvisionInput, Vec<Diagnostic>> {
    let refuse = |code: &str, path: &str, message: String, action: &str| {
        vec![*refused(code, path, message, action)]
    };
    let absolute = std::path::absolute(path).map_err(|_| {
        refuse(
            "config.unresolvable",
            "arguments",
            "the --runtime-config path could not be resolved against the working directory"
                .to_owned(),
            "Pass --runtime-config as a path that exists.",
        )
    })?;
    let config =
        RuntimeConfig::load(&absolute, declared).map_err(|error| {
            match startup_report(&absolute, &error, declared) {
                Some(report) => report.into_diagnostics(),
                None => refuse(
                    "config.refused",
                    "",
                    error.to_string(),
                    "Correct the runtime file, then run provision again.",
                ),
            }
        })?;
    let secrets = config.secret_providers.resolver().map_err(|error| {
        refuse(
            "config.refused",
            "/secretProviders",
            error.to_string(),
            "Correct secretProviders in the runtime file, then run provision again.",
        )
    })?;
    let resolve = |member: &str, reference: &str| {
        secrets.resolve(reference).map_err(|error| {
            refuse(
                "config.refused",
                &format!("/database/{member}"),
                describe_secret_failure(&format!("database.{member}"), reference, &error),
                "Check the secret provider and that the secret exists, then run provision again.",
            )
        })
    };
    let url = |member: &str, reference: &str| {
        let secret = resolve(member, reference)?;
        std::str::from_utf8(secret.expose_secret())
            .map(|text| Zeroizing::new(text.trim().to_owned()))
            .map_err(|_| {
                refuse(
                    "config.refused",
                    &format!("/database/{member}"),
                    format!("database.{member} is not UTF-8 text"),
                    "Put a PostgreSQL URL in the secret, then run provision again.",
                )
            })
    };
    let migration_url = url("migrationUrlRef", &config.database.migration_url_ref)?;
    let runtime_url = url("runtimeUrlRef", &config.database.runtime_url_ref)?;
    let ca_pem = config
        .database
        .ca_bundle_ref
        .as_deref()
        .map(|reference| resolve("caBundleRef", reference))
        .transpose()?
        .map(|secret| secret.expose_secret().to_vec());
    Ok(ProvisionInput {
        product: product(),
        migration_url,
        runtime_url,
        ca_pem,
    })
}
