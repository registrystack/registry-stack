use super::*;

#[test]
fn state_install_cli_requires_explicit_roles_and_migration_url_env() {
    let args = Args::try_parse_from([
        "registry-notary",
        "--config",
        "notary.yaml",
        "state",
        "install",
        "--migration-url-env",
        "REGISTRY_NOTARY_POSTGRES_MIGRATOR_URL",
        "--owner-role",
        "registry_notary_owner",
        "--runtime-role",
        "registry_notary_runtime",
    ])
    .expect("state install arguments parse");
    let Some(Command::State {
        command: StateCommand::Install(install),
    }) = args.command
    else {
        panic!("expected state install command");
    };
    assert_eq!(
        install.migration_url_env,
        "REGISTRY_NOTARY_POSTGRES_MIGRATOR_URL"
    );
    assert_eq!(install.owner_role, "registry_notary_owner");
    assert_eq!(install.runtime_role, "registry_notary_runtime");
}

#[test]
fn state_doctor_cli_parses() {
    let args = Args::try_parse_from([
        "registry-notary",
        "--config",
        "notary.yaml",
        "state",
        "doctor",
    ])
    .expect("state doctor arguments parse");
    assert!(matches!(
        args.command,
        Some(Command::State {
            command: StateCommand::Doctor
        })
    ));
}

#[test]
fn state_command_output_reports_attested_versions_without_claiming_every_install_mutates() {
    let attestation = registry_notary_server::state_plane::PostgresStatePlaneAttestation {
        server_major: 18,
        schema_version: 1,
    };
    assert_eq!(
        state_install_completion(attestation),
        "registry-notary PostgreSQL state installation or attestation complete: schema_version=1 postgres_major=18"
    );
    assert_eq!(
        state_doctor_completion(attestation),
        "registry-notary PostgreSQL state ready: schema_version=1 postgres_major=18"
    );
}

#[test]
fn state_doctor_failures_use_only_closed_value_free_component_codes() {
    use registry_notary_server::state_plane::NotaryPostgresStatePlaneReadiness as Readiness;

    let cases = [
        (Readiness::ConfigurationInvalid, "configuration_invalid"),
        (Readiness::DatabaseUnavailable, "database_unavailable"),
        (Readiness::UnsupportedServerMajor, "database_unavailable"),
        (Readiness::DatabaseNotWritable, "database_unavailable"),
        (Readiness::UnsafeDurability, "database_unavailable"),
        (Readiness::SchemaIncompatible, "schema_incompatible"),
        (Readiness::RoleIncompatible, "role_incompatible"),
        (Readiness::Shutdown, "database_unavailable"),
    ];
    for (readiness, expected) in cases {
        assert_eq!(
            state_doctor_error(readiness).to_string(),
            format!("registry-notary PostgreSQL state is not ready: {expected}")
        );
    }
}
