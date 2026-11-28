// SPDX-License-Identifier: Apache-2.0

//! `bregctl provision`: the shared command over the Registry runtime file.
//! The file's two database URLs name the roles, the database and both
//! passwords, so nothing is written twice. With `--package` the command also
//! plans the PostGIS steps a spatial package needs.

use std::path::Path;

use registry_breg::generated_ddl::POSTGIS_EXTENSION_SCHEMA;
use registry_breg::package::load_package;
use registry_breg::postgres::{
    spatial_bbox_role, MANAGED_SCHEMAS, MIN_POSTGIS_MAJOR, MIN_POSTGIS_MINOR,
};
use registry_breg::runtime_config::{
    load_runtime_config, RuntimeConfig, RuntimeConfigError, RUNTIME_CONFIG_KIND,
};
use registry_platform_provision::{ProductDatabase, ProvisionInput, SchemaLayout, Spatial};
use registry_platform_yaml::Diagnostic;
use zeroize::Zeroizing;

fn refused(code: &str, path: &str, message: String, action: &str) -> Box<Diagnostic> {
    let mut diagnostic = Diagnostic::error(code, path, message, action);
    diagnostic.artifact = Some(RUNTIME_CONFIG_KIND.to_owned());
    Box::new(diagnostic)
}

fn runtime_file_refused(file: &Path, error: &RuntimeConfigError) -> Box<Diagnostic> {
    match error.diagnostics(Some(file)).into_iter().next() {
        Some(diagnostic) => Box::new(diagnostic),
        None => refused(
            "config.refused",
            "",
            error.to_string(),
            "Correct the runtime file, then run provision again.",
        ),
    }
}

/// The database a package needs from the server beyond the managed schemas:
/// PostGIS and the bounding-box role when the package stores polygons or
/// answers bounding-box queries. The role is named after the runtime role, as
/// the Registry runtime and `rstack dev` name it.
fn spatial(config: &RuntimeConfig, package: &Path) -> Result<Option<Spatial>, Box<Diagnostic>> {
    let verified = load_package(package, &config.package_load_context()).map_err(|error| {
        refused(
            "config.refused",
            "arguments",
            format!("the --package directory could not be loaded: {error}"),
            "Pass --package as a package that bregctl package built, or run provision without it.",
        )
    })?;
    Ok(verified.registry().ddl().requires_postgis.then(|| Spatial {
        schema: POSTGIS_EXTENSION_SCHEMA.to_owned(),
        bbox_role: spatial_bbox_role(config.database().roles().runtime())
            .as_str()
            .to_owned(),
        minimum_postgis: (MIN_POSTGIS_MAJOR, MIN_POSTGIS_MINOR),
    }))
}

/// Reads the runtime file exactly as `apply` does and resolves the two
/// database URLs and the CA behind `database.caBundleRef`.
pub(crate) fn load(
    posture: registry_platform_config::DeclaredPosture,
    path: &Path,
    package: Option<&Path>,
) -> Result<ProvisionInput, Box<Diagnostic>> {
    let absolute = std::path::absolute(path).map_err(|_| {
        refused(
            "config.unresolvable",
            "arguments",
            "the --runtime-config path could not be resolved against the working directory"
                .to_owned(),
            "Pass --runtime-config as a path that exists.",
        )
    })?;
    let config = load_runtime_config(&absolute, posture)
        .map_err(|error| runtime_file_refused(&absolute, &error))?;
    // The same checks `apply` makes: each URL parses and logs in as the role
    // the file names for it.
    config
        .migration_database_connection_config()
        .and_then(|_| config.runtime_database_connection_config())
        .map_err(|error| runtime_file_refused(&absolute, &error))?;
    let secrets = config
        .secret_resolver()
        .map_err(|error| runtime_file_refused(&absolute, &error))?;
    let resolve = |member: &str, reference| {
        secrets.resolve_reference(reference).map_err(|_| {
            refused(
                "config.refused",
                &format!("/database/{member}"),
                format!("database.{member} could not be read from its secret provider"),
                "Check the secret provider and that the secret exists, then run provision again.",
            )
        })
    };
    let url = |member: &str, reference| {
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
    let database = config.database();
    let migration_url = url("migrationUrlRef", database.migration_url_ref())?;
    let runtime_url = url("runtimeUrlRef", database.runtime_url_ref())?;
    let ca_pem = database
        .ca_bundle_ref()
        .map(|reference| resolve("caBundleRef", reference))
        .transpose()?
        .map(|secret| secret.expose_secret().to_vec());
    let spatial = package
        .map(|package| spatial(&config, package))
        .transpose()?
        .flatten();
    Ok(ProvisionInput {
        product: ProductDatabase {
            product: "breg",
            layout: SchemaLayout::Owned(MANAGED_SCHEMAS.iter().map(|s| (*s).to_owned()).collect()),
            btree_gist: true,
            spatial,
        },
        migration_url,
        runtime_url,
        ca_pem,
    })
}
