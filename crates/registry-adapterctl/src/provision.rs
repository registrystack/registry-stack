// SPDX-License-Identifier: Apache-2.0

//! `adapterctl provision`: the shared command over the Adapter's runtime
//! file. The file's two database URLs name the roles, the database and both
//! passwords, so nothing is written twice.

use std::path::Path;

use registry_adapter_core::{
    AdapterRuntimeConfig, ADAPTER_REMOVED_KEYS, ADAPTER_RUNTIME_API_VERSION, ADAPTER_RUNTIME_KIND,
};
use registry_platform_config::{
    describe_secret_failure, RuntimeConfigLoader, RuntimeEnvelope, SecretProvider, SecretResolver,
};
use registry_platform_provision::{ProductDatabase, ProvisionInput, SchemaLayout};
use registry_platform_yaml::Diagnostic;
use zeroize::Zeroizing;

/// The Adapter keeps its tables in the schema on the migration role's search
/// path, handed to the migration role, and needs no extension.
fn product() -> ProductDatabase {
    ProductDatabase {
        product: "adapter",
        layout: SchemaLayout::PublicForMigration,
        btree_gist: false,
        spatial: None,
    }
}

fn refused(code: &str, path: &str, message: String, action: &str) -> Box<Diagnostic> {
    let mut diagnostic = Diagnostic::error(code, path, message, action);
    diagnostic.artifact = Some(ADAPTER_RUNTIME_KIND.to_owned());
    Box::new(diagnostic)
}

/// Reads the runtime file exactly as `adapter serve` does and resolves the
/// two database URLs and the CA behind `database.caBundleRef`.
pub(crate) fn load(path: &Path) -> Result<ProvisionInput, Box<Diagnostic>> {
    let absolute = std::fs::canonicalize(path).map_err(|_| {
        refused(
            "config.unresolvable",
            "arguments",
            "the --runtime-config path could not be read".to_owned(),
            "Pass --runtime-config as a path to the runtime file.",
        )
    })?;
    let config = RuntimeConfigLoader::new_without_posture(RuntimeEnvelope {
        api_version: ADAPTER_RUNTIME_API_VERSION,
        kind: ADAPTER_RUNTIME_KIND,
    })
    .removed_keys(ADAPTER_REMOVED_KEYS)
    .load::<AdapterRuntimeConfig>(&absolute)
    .map_err(|error| Box::new(error.deciding_diagnostic().clone()))?
    .config;
    let secrets = match config.secret_providers.as_ref() {
        Some(providers) => providers.resolver(),
        None => SecretResolver::new([SecretProvider::Environment], ""),
    }
    .map_err(|error| {
        refused(
            "config.refused",
            "/secretProviders",
            error.to_string(),
            "Correct secretProviders in the runtime file, then run provision again.",
        )
    })?;
    let resolve = |member: &str, reference: &str| {
        secrets.resolve(reference).map_err(|error| {
            refused(
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
                refused(
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
