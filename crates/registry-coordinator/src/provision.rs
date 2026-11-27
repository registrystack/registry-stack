// SPDX-License-Identifier: Apache-2.0
//! `coordinatorctl provision`: the database, roles and grants `apply` expects.
//!
//! The shared runner reads the role names, database and passwords from the
//! two URLs this module resolves out of the runtime file, so nothing is
//! written twice. `apply` creates the schema the runtime file's `namespace`
//! names, so provisioning gives the migration role `CREATE` on the database
//! and the runtime role `CONNECT`, and leaves every other grant to `apply`.

use std::path::Path;
use std::process::ExitCode;

use registry_platform_config::SecretResolver;
use registry_platform_provision::cli::{
    run_provision, OutputFormat, ProvisionArgs, ProvisionInput,
};
use registry_platform_provision::{ProductDatabase, SchemaLayout};
use registry_platform_yaml::Diagnostic;
use zeroize::Zeroizing;

use crate::runtime::RuntimeConfig;

/// The diagnostic code the runtime file's own refusals carry.
const RUNTIME_CONFIG_REFUSED: &str = "coordinator.runtime-config.refused";

/// Runs the verb. The shared runner owns a runtime of its own, so it runs off
/// the service's executor threads.
pub(crate) async fn run(args: ProvisionArgs, format: OutputFormat) -> ExitCode {
    match tokio::task::spawn_blocking(move || {
        run_provision(
            "coordinatorctl",
            registry_platform_buildinfo::DISPLAY_VERSION,
            &args,
            format,
            load,
        )
    })
    .await
    {
        Ok(exit) => exit,
        Err(_) => {
            eprintln!("coordinatorctl provision stopped unexpectedly");
            ExitCode::from(3)
        }
    }
}

fn load(path: &Path) -> Result<ProvisionInput, Box<Diagnostic>> {
    let path = crate::cli::absolute_runtime_path(path).map_err(|error| first_diagnostic(&error))?;
    let runtime = RuntimeConfig::load(&path).map_err(|error| first_diagnostic(&error))?;
    let resolver = runtime.secret_providers.resolver().map_err(|_| {
        refusal(
            "/secretProviders",
            "the secret providers could not be set up",
            "Correct the secretProviders block of the runtime file.",
        )
    })?;
    let database = &runtime.database;
    let migration_url = secret_text(
        &resolver,
        &database.migration_url_ref,
        "/database/migrationUrlRef",
    )?;
    let runtime_url = secret_text(
        &resolver,
        &database.runtime_url_ref,
        "/database/runtimeUrlRef",
    )?;
    let ca_pem = match &database.ca_bundle_ref {
        Some(reference) => Some(
            secret_text(&resolver, reference, "/database/caBundleRef")?
                .as_bytes()
                .to_vec(),
        ),
        None => None,
    };
    Ok(ProvisionInput {
        product: ProductDatabase {
            product: "coordinator",
            layout: SchemaLayout::CreatedByApply,
            btree_gist: false,
            spatial: None,
        },
        migration_url,
        runtime_url,
        ca_pem,
    })
}

fn secret_text(
    resolver: &SecretResolver,
    reference: &str,
    pointer: &str,
) -> Result<Zeroizing<String>, Box<Diagnostic>> {
    let secret = resolver.resolve(reference).map_err(|_| {
        refusal(
            pointer,
            "the referenced secret could not be read",
            "Make the secret the runtime file names available to this command.",
        )
    })?;
    let text = std::str::from_utf8(secret.expose_secret()).map_err(|_| {
        refusal(
            pointer,
            "the referenced secret is not UTF-8 text",
            "Supply a UTF-8 PostgreSQL URL or PEM file.",
        )
    })?;
    Ok(Zeroizing::new(text.to_owned()))
}

fn refusal(pointer: &str, message: &str, action: &str) -> Box<Diagnostic> {
    Box::new(Diagnostic::error(
        RUNTIME_CONFIG_REFUSED,
        pointer,
        message,
        action,
    ))
}

/// The decisive finding of a runtime-file refusal.
fn first_diagnostic(error: &crate::error::CoordinatorError) -> Box<Diagnostic> {
    let report = error.report();
    let diagnostics = report.diagnostics();
    Box::new(
        diagnostics
            .iter()
            .find(|diagnostic| diagnostic.severity == registry_platform_yaml::Severity::Error)
            .or_else(|| diagnostics.first())
            .cloned()
            .unwrap_or_else(|| {
                *refusal(
                    "",
                    "the runtime file was refused",
                    "Correct the runtime file.",
                )
            }),
    )
}
