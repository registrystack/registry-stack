// SPDX-License-Identifier: Apache-2.0
//! `caseworkctl provision`: creates the migration and runtime roles and the
//! database from the two URLs in the runtime file, so each credential is
//! written once. The shared command owns the flags, the plan and the report.

use std::path::Path;
use std::process::ExitCode;

use registry_casework::{secret_resolver, RuntimeConfig};
use registry_platform_config::{describe_secret_failure, DeclaredPosture, SecretResolver};
use registry_platform_provision::cli::OutputFormat;
use registry_platform_provision::{
    run_provision, ProductDatabase, ProvisionArgs, ProvisionInput, SchemaLayout,
};
use registry_platform_yaml::Diagnostic;
use zeroize::Zeroizing;

const SECRET_ACTION: &str =
    "Provision a runtime-readable secret through the configured provider and retry provision.";

/// Runs the command with this tool's global `--format`.
pub(crate) fn run(args: ProvisionArgs, json: bool, declared: DeclaredPosture) -> ExitCode {
    let format = if json {
        OutputFormat::Json
    } else {
        OutputFormat::Human
    };
    run_provision(
        "caseworkctl",
        registry_platform_buildinfo::DISPLAY_VERSION,
        &args,
        format,
        declared,
        |path| load(path, declared),
    )
}

fn load(path: &Path, declared: DeclaredPosture) -> Result<ProvisionInput, Vec<Diagnostic>> {
    let config = RuntimeConfig::load(path, declared).map_err(|error| {
        if let Some(diagnostics) = error.load_diagnostics().filter(|items| !items.is_empty()) {
            return diagnostics.to_vec();
        }
        vec![Diagnostic::error(
            error.code(),
            format!("runtime.yaml:{}", error.pointer()),
            "The runtime configuration was refused.",
            error.suggested_action(),
        )]
    })?;
    let config = config.config;
    let secrets = secret_resolver(&config).map_err(|_| {
        vec![Diagnostic::error(
            "casework.runtime.secret-unavailable",
            "runtime.yaml:/secretProviders",
            "The secret provider configuration is invalid.",
            SECRET_ACTION,
        )]
    })?;
    let database = &config.database;
    let migration_url = text_secret(
        &secrets,
        "database.migrationUrlRef",
        "/database/migrationUrlRef",
        &database.migration_url_ref,
    )
    .map_err(|diagnostic| vec![*diagnostic])?;
    let runtime_url = text_secret(
        &secrets,
        "database.runtimeUrlRef",
        "/database/runtimeUrlRef",
        &database.runtime_url_ref,
    )
    .map_err(|diagnostic| vec![*diagnostic])?;
    let ca_pem = database
        .ca_bundle_ref
        .as_deref()
        .map(|reference| {
            secrets
                .resolve(reference)
                .map(|secret| secret.expose_secret().to_vec())
                .map_err(|error| {
                    vec![*secret_diagnostic(
                        "database.caBundleRef",
                        "/database/caBundleRef",
                        reference,
                        &error,
                    )]
                })
        })
        .transpose()?;
    Ok(ProvisionInput {
        product: ProductDatabase {
            product: "casework",
            layout: SchemaLayout::PublicForMigration,
            btree_gist: false,
            spatial: None,
        },
        migration_url,
        runtime_url,
        ca_pem,
    })
}

fn text_secret(
    secrets: &SecretResolver,
    field: &str,
    pointer: &str,
    reference: &str,
) -> Result<Zeroizing<String>, Box<Diagnostic>> {
    let secret = secrets
        .resolve(reference)
        .map_err(|error| secret_diagnostic(field, pointer, reference, &error))?;
    let text = std::str::from_utf8(secret.expose_secret()).map_err(|_| {
        Box::new(Diagnostic::error(
            "casework.runtime.secret-unavailable",
            format!("runtime.yaml:{pointer}"),
            format!("{field}: the secret value must be non-empty text"),
            SECRET_ACTION,
        ))
    })?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn secret_diagnostic(
    field: &str,
    pointer: &str,
    reference: &str,
    error: &registry_platform_config::SecretError,
) -> Box<Diagnostic> {
    Box::new(Diagnostic::error(
        "casework.runtime.secret-unavailable",
        format!("runtime.yaml:{pointer}"),
        describe_secret_failure(field, reference, error),
        SECRET_ACTION,
    ))
}
