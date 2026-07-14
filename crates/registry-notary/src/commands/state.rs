// SPDX-License-Identifier: Apache-2.0
//! Explicit PostgreSQL correctness-state installation and attestation.

use crate::*;

pub(crate) async fn state_install(
    config_path: &Path,
    args: StateInstallArgs,
) -> Result<(), Box<dyn std::error::Error>> {
    let loaded = load_server_config(config_path, false)?;
    if loaded.config.state.storage != STATE_STORAGE_POSTGRESQL {
        return Err("state install requires state.storage = postgresql".into());
    }
    let state_config = registry_notary_server::state_plane::PostgresStatePlaneConfig::try_from(
        &loaded.config.state.postgresql,
    )?;
    let owner_role =
        registry_notary_server::state_plane::OwnerDatabaseRole::parse(args.owner_role)?;
    let runtime_role =
        registry_notary_server::state_plane::RuntimeDatabaseRole::parse(args.runtime_role)?;
    let mut connection =
        registry_notary_server::state_plane::NotaryPostgresOperatorConnection::connect(
            &state_config,
            &args.migration_url_env,
        )
        .await?;
    let attestation = registry_notary_server::state_plane::install_postgres_state_plane_v1(
        connection.client_mut(),
        &owner_role,
        &runtime_role,
    )
    .await?;
    println!("{}", state_install_completion(attestation));
    Ok(())
}

pub(crate) async fn state_doctor(config_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let loaded = load_server_config(config_path, false).map_err(|_| {
        state_doctor_error(
            registry_notary_server::state_plane::NotaryPostgresStatePlaneReadiness::ConfigurationInvalid,
        )
    })?;
    if loaded.config.state.storage != STATE_STORAGE_POSTGRESQL {
        return Err(state_doctor_error(
            registry_notary_server::state_plane::NotaryPostgresStatePlaneReadiness::ConfigurationInvalid,
        ));
    }
    let preauthorization_enabled =
        loaded.config.oid4vci.enabled && loaded.config.oid4vci.pre_authorized_code.enabled;
    let attestation = registry_notary_server::state_plane::attest_postgres_state_plane_runtime(
        &loaded.config.state,
        preauthorization_enabled,
    )
    .await
    .map_err(state_doctor_error)?;
    println!("{}", state_doctor_completion(attestation));
    Ok(())
}

fn state_install_completion(
    attestation: registry_notary_server::state_plane::PostgresStatePlaneAttestation,
) -> String {
    format!(
        "registry-notary PostgreSQL state installation or attestation complete: schema_version={} postgres_major={}",
        attestation.schema_version, attestation.server_major
    )
}

fn state_doctor_completion(
    attestation: registry_notary_server::state_plane::PostgresStatePlaneAttestation,
) -> String {
    format!(
        "registry-notary PostgreSQL state ready: schema_version={} postgres_major={}",
        attestation.schema_version, attestation.server_major
    )
}

fn state_doctor_error(
    readiness: registry_notary_server::state_plane::NotaryPostgresStatePlaneReadiness,
) -> Box<dyn std::error::Error> {
    format!(
        "registry-notary PostgreSQL state is not ready: {}",
        readiness.doctor_component_code()
    )
    .into()
}

#[cfg(test)]
#[path = "state/tests.rs"]
mod tests;
