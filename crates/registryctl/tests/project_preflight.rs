// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

#[path = "../src/project_authoring/preflight.rs"]
mod preflight;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};

use preflight::{
    run_offline_preflight_with_secret_lookup, OfflinePreflightInput, PreflightAttemptState,
    PreflightCheckState, PreflightContact, PreflightDiagnosticCode, PreflightFieldAddress,
    PreflightGenerationState, PreflightMode, PreflightRuntimeFileKind, PreflightSecretConsumer,
    PreflightStaticCapability, PreflightStatus, PreflightWriteState, ProjectPreflightReportV1,
    MAX_PREFLIGHT_CHECKS, MAX_PREFLIGHT_DIAGNOSTICS,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

const SCHEMA: &str =
    include_str!("../schemas/project-reports/registryctl.project_preflight.v1.schema.json");
const FIXTURE: &str =
    include_str!("fixtures/project-reports/registryctl.project_preflight.v1.json");

fn parse(input: &str) -> Value {
    serde_json::from_str(input).expect("JSON parses")
}

fn validator() -> jsonschema::JSONSchema {
    jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&parse(SCHEMA))
        .expect("Draft 2020-12 schema compiles")
}

fn assert_schema_valid(document: &Value) {
    if let Err(errors) = validator().validate(document) {
        let details = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("document should validate: {details:?}");
    }
}

fn assert_schema_invalid(document: &Value) {
    assert!(
        validator().validate(document).is_err(),
        "document should not validate"
    );
}

fn address(file: &str, pointer: &str) -> PreflightFieldAddress {
    PreflightFieldAddress::new(file, pointer).expect("test address is valid")
}

fn validated_input() -> OfflinePreflightInput {
    let mut input =
        OfflinePreflightInput::new("country-registry", "production").expect("valid input");
    let project = address("registry-stack.yaml", "");
    let environment = address("environments/production.yaml", "");
    input.record_static_validation(PreflightStaticCapability::ProjectModel, [project.clone()]);
    input.record_static_validation(
        PreflightStaticCapability::EnvironmentCompleteness,
        [project.clone(), environment.clone()],
    );
    input.record_static_validation(
        PreflightStaticCapability::OriginRelationships,
        [environment.clone()],
    );
    input.record_static_validation(PreflightStaticCapability::NonWideningBounds, [environment]);
    input
}

fn run_with(
    input: OfflinePreflightInput,
    values: &BTreeMap<String, OsString>,
) -> ProjectPreflightReportV1 {
    run_offline_preflight_with_secret_lookup(input, &|name: &str| values.get(name).cloned())
}

#[test]
fn canonical_fixture_validates_and_roundtrips_exactly() {
    let document = parse(FIXTURE);
    assert_schema_valid(&document);
    let decoded: ProjectPreflightReportV1 =
        serde_json::from_value(document.clone()).expect("fixture decodes");
    assert_eq!(
        serde_json::to_value(&decoded).expect("fixture re-encodes"),
        document
    );
    assert_eq!(decoded.status, PreflightStatus::Ready);
    assert_eq!(decoded.execution.mode, PreflightMode::Offline);
    assert_eq!(decoded.execution.contact, PreflightContact::None);
    assert_eq!(
        decoded.execution.network,
        PreflightAttemptState::NotAttempted
    );
    assert_eq!(
        decoded.execution.build_output,
        PreflightWriteState::NotWritten
    );
}

#[test]
fn schema_and_dto_reject_root_and_deep_unknown_fields() {
    let mut root = parse(FIXTURE);
    root["future"] = json!(true);
    assert_schema_invalid(&root);
    assert!(serde_json::from_value::<ProjectPreflightReportV1>(root).is_err());

    let mut nested = parse(FIXTURE);
    nested["secret_checks"][0]["runtime_value"] = json!("must never appear");
    assert_schema_invalid(&nested);
    assert!(serde_json::from_value::<ProjectPreflightReportV1>(nested).is_err());

    let mut address_unknown = parse(FIXTURE);
    address_unknown["runtime_files"][0]["addresses"][0]["absolute_path"] =
        json!("/run/secrets/country.pem");
    assert_schema_invalid(&address_unknown);
    assert!(serde_json::from_value::<ProjectPreflightReportV1>(address_unknown).is_err());
}

#[test]
fn schema_rejects_invalid_addresses_versions_states_and_generation_claims() {
    let mut wrong_version = parse(FIXTURE);
    wrong_version["schema_version"] = json!("registryctl.project_preflight.v2");
    assert_schema_invalid(&wrong_version);

    let mut absolute = parse(FIXTURE);
    absolute["runtime_files"][0]["addresses"][0]["file"] = json!("/run/secrets/country.pem");
    assert_schema_invalid(&absolute);

    let mut invalid_pointer = parse(FIXTURE);
    invalid_pointer["runtime_files"][0]["addresses"][0]["pointer"] = json!("/bad~escape");
    assert_schema_invalid(&invalid_pointer);

    let mut open_state = parse(FIXTURE);
    open_state["runtime_files"][0]["state"] = json!("probably_available");
    assert_schema_invalid(&open_state);

    let mut inferred_generation = parse(FIXTURE);
    inferred_generation["runtime_files"][1]["generation"] = json!("declared");
    assert_schema_invalid(&inferred_generation);
}

#[test]
fn secret_missing_whitespace_and_present_states_never_expose_names_or_values() {
    const MISSING_NAME: &str = "PREFLIGHT_SENTINEL_MISSING_NAME";
    const EMPTY_NAME: &str = "PREFLIGHT_SENTINEL_EMPTY_NAME";
    const PRESENT_NAME: &str = "PREFLIGHT_SENTINEL_PRESENT_NAME";
    const PRESENT_VALUE: &str = "PREFLIGHT_SENTINEL_SECRET_VALUE";

    let mut input = validated_input();
    input
        .add_secret_reference(
            MISSING_NAME,
            PreflightSecretConsumer::SourceBearerToken,
            address(
                "environments/production.yaml",
                "/integrations/alpha/source/credential/token",
            ),
        )
        .expect("missing reference records");
    input
        .add_secret_reference(
            EMPTY_NAME,
            PreflightSecretConsumer::IssuanceSigningKey,
            address("environments/production.yaml", "/issuance/signing_key"),
        )
        .expect("empty reference records");
    input
        .add_secret_reference(
            PRESENT_NAME,
            PreflightSecretConsumer::CallerApiKeyFingerprint,
            address(
                "environments/production.yaml",
                "/callers/health/api_key_fingerprint",
            ),
        )
        .expect("present reference records");
    let values = BTreeMap::from([
        (EMPTY_NAME.to_string(), OsString::from(" \t\n")),
        (PRESENT_NAME.to_string(), OsString::from(PRESENT_VALUE)),
    ]);

    let debug_input = format!("{input:?}");
    let report = run_with(input, &values);
    let serialized = serde_json::to_string(&report).expect("report serializes");
    let debug_report = format!("{report:?}");
    for sentinel in [MISSING_NAME, EMPTY_NAME, PRESENT_NAME, PRESENT_VALUE] {
        assert!(!debug_input.contains(sentinel));
        assert!(!serialized.contains(sentinel));
        assert!(!debug_report.contains(sentinel));
    }
    assert_eq!(
        report
            .secret_checks
            .iter()
            .map(|check| check.state)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            PreflightCheckState::Available,
            PreflightCheckState::Missing,
            PreflightCheckState::Empty,
        ])
    );
    assert_eq!(report.status, PreflightStatus::NotReady);
}

#[test]
fn duplicate_secret_reference_is_looked_up_once_and_keeps_sorted_multi_addresses() {
    const DUPLICATE_NAME: &str = "PREFLIGHT_DUPLICATE_REFERENCE";
    let mut input = validated_input();
    for (consumer, pointer) in [
        (
            PreflightSecretConsumer::SourceOauthClientSecret,
            "/integrations/zeta/source/credential/client_secret",
        ),
        (
            PreflightSecretConsumer::SourceBearerToken,
            "/integrations/alpha/source/credential/token",
        ),
        (
            PreflightSecretConsumer::SourceBearerToken,
            "/integrations/alpha/source/credential/token",
        ),
    ] {
        input
            .add_secret_reference(
                DUPLICATE_NAME,
                consumer,
                address("environments/production.yaml", pointer),
            )
            .expect("duplicate reference records");
    }
    let lookups = AtomicUsize::new(0);
    let report = run_offline_preflight_with_secret_lookup(input, &|name: &str| {
        assert_eq!(name, DUPLICATE_NAME);
        lookups.fetch_add(1, Ordering::SeqCst);
        None
    });

    assert_eq!(lookups.load(Ordering::SeqCst), 1);
    assert_eq!(report.secret_checks.len(), 1);
    assert_eq!(report.secret_checks[0].addresses.len(), 2);
    assert_eq!(report.secret_checks[0].consumers.len(), 2);
    assert!(
        report.secret_checks[0].addresses[0] < report.secret_checks[0].addresses[1],
        "addresses are canonical and sorted"
    );
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.addresses.len() == 2)
        .expect("one diagnostic carries the full shared identity");
    assert_eq!(diagnostic.addresses, report.secret_checks[0].addresses);
}

#[cfg(unix)]
#[test]
fn runtime_files_close_missing_empty_regular_symlink_and_unsafe_modes() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    let directory = tempfile::tempdir().expect("temporary directory");
    let regular = directory.path().join("regular.pem");
    let empty = directory.path().join("empty.pem");
    let unsafe_public = directory.path().join("unsafe-public.pem");
    let unsafe_private = directory.path().join("unsafe-private.token");
    let oversized = directory.path().join("oversized.pem");
    let symlink_path = directory.path().join("link.pem");
    let missing = directory.path().join("missing.pem");
    fs::write(&regular, b"certificate").expect("regular file writes");
    fs::write(&empty, b"").expect("empty file writes");
    fs::write(&unsafe_public, b"certificate").expect("unsafe public file writes");
    fs::write(&unsafe_private, b"token").expect("unsafe private file writes");
    fs::File::create(&oversized)
        .expect("oversized file creates")
        .set_len(1024 * 1024 + 1)
        .expect("oversized file extends");
    fs::set_permissions(&regular, fs::Permissions::from_mode(0o600)).expect("regular mode sets");
    fs::set_permissions(&empty, fs::Permissions::from_mode(0o600)).expect("empty mode sets");
    fs::set_permissions(&unsafe_public, fs::Permissions::from_mode(0o666))
        .expect("unsafe public mode sets");
    fs::set_permissions(&unsafe_private, fs::Permissions::from_mode(0o640))
        .expect("unsafe private mode sets");
    fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600))
        .expect("oversized mode sets");
    symlink(&regular, &symlink_path).expect("symlink creates");

    let mut input = validated_input();
    for (path, kind, pointer) in [
        (
            regular.as_path(),
            PreflightRuntimeFileKind::SourceCa,
            "/integrations/regular/source/ca/file",
        ),
        (
            empty.as_path(),
            PreflightRuntimeFileKind::SourceMtlsCertificate,
            "/integrations/empty/source/mtls/certificate_file",
        ),
        (
            missing.as_path(),
            PreflightRuntimeFileKind::SourceOauthCa,
            "/integrations/missing/source/oauth/ca/file",
        ),
        (
            symlink_path.as_path(),
            PreflightRuntimeFileKind::SourceJwksCa,
            "/integrations/symlink/source/jwks/ca/file",
        ),
        (
            unsafe_public.as_path(),
            PreflightRuntimeFileKind::RelayStateRootCertificate,
            "/relay_state/postgresql/root_certificate_path",
        ),
        (
            unsafe_private.as_path(),
            PreflightRuntimeFileKind::NotaryToRelayToken,
            "/notary_relay/token_file",
        ),
        (
            oversized.as_path(),
            PreflightRuntimeFileKind::SourceJwksMtlsCertificate,
            "/integrations/oversized/source/jwks/mtls/certificate_file",
        ),
    ] {
        input
            .add_runtime_file(path, kind, address("environments/production.yaml", pointer))
            .expect("runtime file records");
    }

    let report = run_with(input, &BTreeMap::new());
    let states = report
        .runtime_files
        .iter()
        .map(|check| (check.kind, check.state))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        states[&PreflightRuntimeFileKind::SourceCa],
        PreflightCheckState::Available
    );
    assert_eq!(
        states[&PreflightRuntimeFileKind::SourceMtlsCertificate],
        PreflightCheckState::Empty
    );
    assert_eq!(
        states[&PreflightRuntimeFileKind::SourceOauthCa],
        PreflightCheckState::Missing
    );
    assert_eq!(
        states[&PreflightRuntimeFileKind::SourceJwksCa],
        PreflightCheckState::NotRegular
    );
    assert_eq!(
        states[&PreflightRuntimeFileKind::RelayStateRootCertificate],
        PreflightCheckState::UnsafeMode
    );
    assert_eq!(
        states[&PreflightRuntimeFileKind::NotaryToRelayToken],
        PreflightCheckState::UnsafeMode
    );
    assert_eq!(
        states[&PreflightRuntimeFileKind::SourceJwksMtlsCertificate],
        PreflightCheckState::NotRegular
    );
}

#[cfg(unix)]
#[test]
fn public_trust_and_private_material_apply_distinct_unix_modes() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().expect("temporary directory");
    let shared = directory.path().join("shared-material");
    fs::write(&shared, b"bounded material").expect("file writes");
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o644)).expect("mode sets");

    let mut input = validated_input();
    input
        .add_runtime_file(
            &shared,
            PreflightRuntimeFileKind::SourceCa,
            address(
                "environments/production.yaml",
                "/integrations/alpha/source/ca/file",
            ),
        )
        .expect("public trust records");
    input
        .add_runtime_file(
            &shared,
            PreflightRuntimeFileKind::NotaryToRelayToken,
            address("environments/production.yaml", "/notary_relay/token_file"),
        )
        .expect("private material records");

    let report = run_with(input, &BTreeMap::new());
    let states = report
        .runtime_files
        .iter()
        .map(|check| (check.kind, check.state))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        states[&PreflightRuntimeFileKind::SourceCa],
        PreflightCheckState::Available
    );
    assert_eq!(
        states[&PreflightRuntimeFileKind::NotaryToRelayToken],
        PreflightCheckState::UnsafeMode
    );
}

#[cfg(unix)]
#[test]
fn entity_provider_files_enforce_private_posture_and_relay_default_size_bound() {
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    let directory = tempfile::tempdir().expect("temporary directory");
    let relay_sized = directory.path().join("relay-sized.csv");
    let shared = directory.path().join("shared.xlsx");
    let oversized = directory.path().join("oversized.parquet");
    let symlink_target = directory.path().join("target.parquet");
    let symlink_path = directory.path().join("link.parquet");
    fs::File::create(&relay_sized)
        .expect("Relay-sized file creates")
        .set_len(1024 * 1024 + 1)
        .expect("Relay-sized file extends");
    fs::write(&shared, b"workbook").expect("shared file writes");
    fs::File::create(&oversized)
        .expect("oversized entity file creates")
        .set_len(256 * 1024 * 1024 + 1)
        .expect("oversized entity file extends");
    fs::write(&symlink_target, b"parquet").expect("symlink target writes");
    fs::set_permissions(&relay_sized, fs::Permissions::from_mode(0o600))
        .expect("Relay-sized mode sets");
    fs::set_permissions(&shared, fs::Permissions::from_mode(0o644)).expect("shared mode sets");
    fs::set_permissions(&oversized, fs::Permissions::from_mode(0o600))
        .expect("oversized mode sets");
    fs::set_permissions(&symlink_target, fs::Permissions::from_mode(0o600))
        .expect("symlink target mode sets");
    symlink(&symlink_target, &symlink_path).expect("symlink creates");

    let mut input = validated_input();
    for (path, kind, pointer) in [
        (
            relay_sized.as_path(),
            PreflightRuntimeFileKind::EntityCsv,
            "/entities/csv/provider/path",
        ),
        (
            shared.as_path(),
            PreflightRuntimeFileKind::EntityXlsx,
            "/entities/xlsx/provider/path",
        ),
        (
            oversized.as_path(),
            PreflightRuntimeFileKind::EntityParquet,
            "/entities/oversized/provider/path",
        ),
        (
            symlink_path.as_path(),
            PreflightRuntimeFileKind::EntityParquet,
            "/entities/symlink/provider/path",
        ),
    ] {
        input
            .add_runtime_file(path, kind, address("environments/production.yaml", pointer))
            .expect("entity provider file records");
    }

    let report = run_with(input, &BTreeMap::new());
    let states = report
        .runtime_files
        .iter()
        .map(|check| (check.addresses[0].pointer.as_str(), check.state))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        states["/entities/csv/provider/path"],
        PreflightCheckState::Available,
        "entity files may use Relay's larger default source-file bound"
    );
    assert_eq!(
        states["/entities/xlsx/provider/path"],
        PreflightCheckState::UnsafeMode,
        "entity files are private material"
    );
    assert_eq!(
        states["/entities/oversized/provider/path"],
        PreflightCheckState::NotRegular
    );
    assert_eq!(
        states["/entities/symlink/provider/path"],
        PreflightCheckState::NotRegular
    );
}

#[cfg(unix)]
#[test]
fn undeclared_generations_are_never_inferred_for_state_roots_or_workload_token() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().expect("temporary directory");
    let path = directory.path().join("material");
    fs::write(&path, b"material").expect("file writes");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("mode sets");

    let mut input = validated_input();
    for (kind, pointer) in [
        (
            PreflightRuntimeFileKind::SourceCa,
            "/integrations/alpha/source/ca/file",
        ),
        (
            PreflightRuntimeFileKind::RelayStateRootCertificate,
            "/relay_state/postgresql/root_certificate_path",
        ),
        (
            PreflightRuntimeFileKind::NotaryStateRootCertificate,
            "/notary_state/postgresql/root_certificate_path",
        ),
        (
            PreflightRuntimeFileKind::NotaryToRelayToken,
            "/notary_relay/token_file",
        ),
    ] {
        input
            .add_runtime_file(
                &path,
                kind,
                address("environments/production.yaml", pointer),
            )
            .expect("runtime file records");
    }

    let report = run_with(input, &BTreeMap::new());
    let generations = report
        .runtime_files
        .iter()
        .map(|check| (check.kind, check.generation))
        .collect::<BTreeMap<_, _>>();
    assert_eq!(
        generations[&PreflightRuntimeFileKind::SourceCa],
        PreflightGenerationState::Declared
    );
    for kind in [
        PreflightRuntimeFileKind::RelayStateRootCertificate,
        PreflightRuntimeFileKind::NotaryStateRootCertificate,
        PreflightRuntimeFileKind::NotaryToRelayToken,
    ] {
        assert_eq!(generations[&kind], PreflightGenerationState::NotDeclared);
    }
}

#[test]
fn offline_boundary_has_no_network_or_external_process_surface() {
    let authored_endpoints = [
        "https://source.country.invalid",
        "https://issuer.country.invalid/jwks",
        "https://relay.country.invalid",
    ];
    assert!(authored_endpoints
        .iter()
        .all(|endpoint| endpoint.contains(".invalid")));

    let source = include_str!("../src/project_authoring/preflight.rs");
    for forbidden_surface in [
        "TcpStream",
        "ToSocketAddrs",
        "ureq::",
        "reqwest::",
        "Command::new",
        "std::process",
    ] {
        assert!(
            !source.contains(forbidden_surface),
            "offline preflight must not gain the {forbidden_surface} surface"
        );
    }

    let report = run_with(validated_input(), &BTreeMap::new());
    assert_eq!(report.execution.contact, PreflightContact::None);
    assert_eq!(
        report.execution.network,
        PreflightAttemptState::NotAttempted
    );
    assert_eq!(
        report.execution.live_reachability,
        PreflightAttemptState::NotAttempted
    );
    assert_eq!(
        report.execution.external_processes,
        PreflightAttemptState::NotAttempted
    );
}

#[test]
fn command_adapter_keeps_invalid_endpoints_offline_and_has_no_build_side_effects() {
    const SECRET_NAMES: [&str; 4] = [
        "PREFLIGHT_COMMAND_CLIENT_ID",
        "PREFLIGHT_COMMAND_CLIENT_SECRET",
        "PREFLIGHT_COMMAND_ISSUER_KEY",
        "PREFLIGHT_COMMAND_CALLER_FINGERPRINT",
    ];
    let directory = tempfile::tempdir().expect("temporary directory");
    let project = directory.path().join("project");
    copy_tree(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/project-authoring/opencrvs")
            .as_path(),
        &project,
    );
    let environment_file = project.join("environments/local.yaml");
    let original = fs::read_to_string(&environment_file).expect("environment reads");
    let missing_token = directory.path().join("missing-workload-token");
    let authored = original
        .replace("CIVIL_REGISTRY_CLIENT_ID", SECRET_NAMES[0])
        .replace("CIVIL_REGISTRY_CLIENT_SECRET", SECRET_NAMES[1])
        .replace("REGISTRY_NOTARY_ISSUER_JWK", SECRET_NAMES[2])
        .replace("BIRTH_VERIFIER_TOKEN_HASH", SECRET_NAMES[3])
        .replace(
            "/run/secrets/relay-workload-token",
            missing_token.to_str().expect("temporary path is UTF-8"),
        );
    fs::write(&environment_file, authored).expect("environment writes");
    let fixture_path = project.join("integrations/birth-record/fixtures/match.yaml");
    let fixture_before = fs::read(&fixture_path).expect("fixture reads");

    let report = registryctl::preflight_registry_project(&registryctl::ProjectPreflightOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
    })
    .expect("offline preflight returns a closed report");
    let serialized = serde_json::to_string(&report).expect("report serializes");

    assert_eq!(report.secret_checks.len(), SECRET_NAMES.len());
    assert_eq!(report.runtime_files.len(), 1);
    assert_eq!(
        report.runtime_files[0].state,
        registryctl::PreflightCheckState::Missing
    );
    assert_eq!(
        report.execution.network,
        registryctl::PreflightAttemptState::NotAttempted
    );
    assert_eq!(
        report.execution.fixture_execution,
        registryctl::PreflightAttemptState::NotAttempted
    );
    assert_eq!(
        report.execution.build_output,
        registryctl::PreflightWriteState::NotWritten
    );
    assert!(!project.join(".registry-stack").exists());
    assert_eq!(
        fs::read(&fixture_path).expect("fixture rereads"),
        fixture_before
    );
    for forbidden in SECRET_NAMES.into_iter().chain([
        "https://civil-registry.invalid",
        "https://identity.civil-registry.invalid",
        "https://trust.civil-registry.invalid",
        missing_token.to_str().expect("temporary path is UTF-8"),
    ]) {
        assert!(
            !serialized.contains(forbidden),
            "report must not expose {forbidden}"
        );
    }
}

#[cfg(unix)]
#[test]
fn command_adapter_checks_csv_xlsx_and_parquet_entity_provider_paths() {
    use std::os::unix::fs::PermissionsExt as _;

    for (provider_type, extension, kind) in [
        (
            "csv",
            "csv",
            registryctl::PreflightRuntimeFileKind::EntityCsv,
        ),
        (
            "xlsx",
            "xlsx",
            registryctl::PreflightRuntimeFileKind::EntityXlsx,
        ),
        (
            "parquet",
            "parquet",
            registryctl::PreflightRuntimeFileKind::EntityParquet,
        ),
    ] {
        let directory = tempfile::tempdir().expect("temporary directory");
        let project = directory.path().join(format!("{provider_type}-project"));
        copy_tree(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/project-authoring/relay-only-materialization")
                .as_path(),
            &project,
        );
        let provider_path = if provider_type == "xlsx" {
            project.join("data/people.xlsx")
        } else {
            directory.path().join(format!("people.{extension}"))
        };
        if let Some(parent) = provider_path.parent() {
            fs::create_dir_all(parent).expect("provider parent creates");
        }
        let provider = match provider_type {
            "csv" => format!(
                "{{ type: csv, path: {}, header_row: 1 }}",
                provider_path.display()
            ),
            "xlsx" => "{ type: xlsx, project_file: data/people.xlsx, path: /var/lib/registry/people.xlsx, sheet: data, header_row: 1, data_range: 'A1:B6' }".to_string(),
            "parquet" => format!("{{ type: parquet, path: {} }}", provider_path.display()),
            _ => unreachable!("provider table is closed"),
        };
        let environment_file = project.join("environments/local.yaml");
        let original = fs::read_to_string(&environment_file).expect("environment reads");
        let mut authored = original.replace(
            "    provider: { type: csv, path: /var/lib/registry/people.csv, header_row: 1 }",
            &format!("    provider: {provider}"),
        );
        if provider_type == "xlsx" {
            authored = authored.replace(
                "    columns: { person_id: subject_key, status: status_code }",
                "    columns: { person_id: id, status: name }",
            );
        }
        assert_ne!(authored, original, "provider fixture replacement applies");
        fs::write(&environment_file, authored).expect("environment writes");

        let options = registryctl::ProjectPreflightOptions {
            project_directory: project,
            environment: "local".to_string(),
        };
        if provider_type == "xlsx" {
            let error = registryctl::preflight_registry_project(&options)
                .expect_err("missing project workbook fails before preflight reporting");
            assert_eq!(
                format!("{error:#}"),
                "workbook source input is missing or unreadable"
            );
        } else {
            let missing = registryctl::preflight_registry_project(&options)
                .expect("missing preflight reports");
            assert_eq!(missing.status, registryctl::PreflightStatus::NotReady);
            assert_eq!(missing.runtime_files.len(), 1);
            assert_eq!(missing.runtime_files[0].kind, kind);
            assert_eq!(
                missing.runtime_files[0].generation,
                registryctl::PreflightGenerationState::Declared
            );
            assert_eq!(
                missing.runtime_files[0].state,
                registryctl::PreflightCheckState::Missing
            );
            assert_eq!(missing.runtime_files[0].addresses.len(), 1);
            assert_eq!(
                missing.runtime_files[0].addresses[0].file.as_str(),
                "environments/local.yaml"
            );
            assert_eq!(
                missing.runtime_files[0].addresses[0].pointer.as_str(),
                "/entities/people/provider/path"
            );
            assert!(missing.diagnostics.iter().any(|diagnostic| {
                diagnostic.code == registryctl::PreflightDiagnosticCode::RuntimeFileMissing
                    && diagnostic.addresses == missing.runtime_files[0].addresses
            }));
            assert_schema_valid(
                &serde_json::to_value(&missing).expect("missing report serializes"),
            );
        }

        if provider_type == "xlsx" {
            fs::copy(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../registry-relay/tests/fixtures_xlsx/simple.xlsx"),
                &provider_path,
            )
            .expect("valid provider workbook copies");
        } else {
            fs::write(&provider_path, b"bounded entity data").expect("provider file writes");
        }
        fs::set_permissions(&provider_path, fs::Permissions::from_mode(0o600))
            .expect("provider mode sets");
        let available =
            registryctl::preflight_registry_project(&options).expect("available preflight reports");
        assert_eq!(available.status, registryctl::PreflightStatus::Ready);
        assert_eq!(available.runtime_files.len(), 1);
        assert_eq!(available.runtime_files[0].kind, kind);
        assert_eq!(
            available.runtime_files[0].state,
            registryctl::PreflightCheckState::Available
        );
        assert!(available.diagnostics.is_empty());
        assert_schema_valid(
            &serde_json::to_value(&available).expect("available report serializes"),
        );
    }
}

#[cfg(unix)]
#[test]
fn preflight_reads_only_declared_runtime_files_and_has_no_fixture_or_build_side_effects() {
    use std::os::unix::fs::PermissionsExt as _;

    let directory = tempfile::tempdir().expect("temporary directory");
    let fixture = directory.path().join("fixture.yaml");
    let build_marker = directory.path().join("build-output.json");
    let runtime = directory.path().join("declared.pem");
    fs::write(&fixture, b"fixture sentinel").expect("fixture writes");
    fs::write(&build_marker, b"build sentinel").expect("build marker writes");
    fs::write(&runtime, b"certificate").expect("runtime file writes");
    fs::set_permissions(&runtime, fs::Permissions::from_mode(0o600)).expect("mode sets");
    let before = directory_snapshot(directory.path());

    let mut input = validated_input();
    input
        .add_runtime_file(
            &runtime,
            PreflightRuntimeFileKind::SourceCa,
            address(
                "environments/production.yaml",
                "/integrations/alpha/source/ca/file",
            ),
        )
        .expect("runtime file records");
    let report = run_with(input, &BTreeMap::new());

    assert_eq!(directory_snapshot(directory.path()), before);
    assert_eq!(
        fs::read(&fixture).expect("fixture reads"),
        b"fixture sentinel"
    );
    assert_eq!(
        fs::read(&build_marker).expect("build marker reads"),
        b"build sentinel"
    );
    assert_eq!(
        report.execution.fixture_execution,
        PreflightAttemptState::NotAttempted
    );
    assert_eq!(
        report.execution.build_output,
        PreflightWriteState::NotWritten
    );
}

#[test]
fn project_workbook_is_validated_read_only_and_digest_bound_when_runtime_is_not_ready() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let project = directory.path().join("spreadsheet-project");
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/project-starters/spreadsheet"),
        &project,
    );
    let workbook_relative = "data/public_works_projects.xlsx";
    let workbook = project.join(workbook_relative);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&workbook, fs::Permissions::from_mode(0o600))
            .expect("workbook mode sets");
    }
    let workbook_bytes = fs::read(&workbook).expect("workbook reads");
    let before = directory_snapshot(&project);

    let preflight =
        registryctl::preflight_registry_project(&registryctl::ProjectPreflightOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
        })
        .expect("valid workbook passes preflight");
    assert_eq!(preflight.status, registryctl::PreflightStatus::NotReady);
    assert!(preflight.runtime_files.iter().any(|check| {
        check.kind == registryctl::PreflightRuntimeFileKind::EntityXlsx
            && check.state == registryctl::PreflightCheckState::Available
    }));
    assert_eq!(
        directory_snapshot(&project),
        before,
        "preflight workbook validation must be read-only"
    );

    let execution_context =
        registryctl::ProjectExecutionContext::new(env!("CARGO_BIN_EXE_registryctl"))
            .expect("Cargo provides the real registryctl executable");
    registryctl::build_registry_project_with_context(
        &registryctl::ProjectBuildOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            against: None,
            anchor: None,
        },
        &execution_context,
    )
    .expect("valid workbook builds");
    let manifest: Value = serde_json::from_slice(
        &fs::read(project.join(".registry-stack/build/local/artifact-manifest.json"))
            .expect("artifact manifest reads"),
    )
    .expect("artifact manifest parses");
    let workbook_input = manifest["inputs"]
        .as_array()
        .expect("manifest inputs")
        .iter()
        .find(|input| input["path"] == workbook_relative)
        .expect("workbook provenance input");
    assert_eq!(
        workbook_input["digest"],
        format!("sha256:{}", hex::encode(Sha256::digest(&workbook_bytes)))
    );
}

#[test]
fn corrupt_project_workbook_fails_preflight_and_build_without_output() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let project = directory.path().join("spreadsheet-project");
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/project-starters/spreadsheet"),
        &project,
    );
    fs::write(
        project.join("data/public_works_projects.xlsx"),
        b"not an xlsx workbook",
    )
    .expect("corrupt workbook writes");
    let before = directory_snapshot(&project);

    registryctl::preflight_registry_project(&registryctl::ProjectPreflightOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
    })
    .expect_err("corrupt workbook must fail preflight");
    assert_eq!(directory_snapshot(&project), before);

    registryctl::build_registry_project(&registryctl::ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect_err("corrupt workbook must fail build");
    assert_eq!(
        directory_snapshot(&project),
        before,
        "failed build must not publish runtime output"
    );
}

#[test]
fn reports_are_deterministic_capped_and_keep_cross_file_identity() {
    let mut ascending = validated_input();
    let mut descending = validated_input();
    let mut requirements = (0..MAX_PREFLIGHT_CHECKS + 17)
        .map(|index| {
            (
                format!("PREFLIGHT_SECRET_{index:03}"),
                address(
                    if index % 2 == 0 {
                        "environments/production.yaml"
                    } else {
                        "integrations/alpha/integration.yaml"
                    },
                    &format!("/references/{index:03}"),
                ),
            )
        })
        .collect::<Vec<_>>();
    for (name, field) in &requirements {
        ascending
            .add_secret_reference(
                name.clone(),
                PreflightSecretConsumer::SourceBearerToken,
                field.clone(),
            )
            .expect("ascending reference records");
    }
    requirements.reverse();
    for (name, field) in &requirements {
        descending
            .add_secret_reference(
                name.clone(),
                PreflightSecretConsumer::SourceBearerToken,
                field.clone(),
            )
            .expect("descending reference records");
    }

    let left = run_with(ascending, &BTreeMap::new());
    let right = run_with(descending, &BTreeMap::new());
    assert_eq!(
        serde_json::to_value(&left).expect("left serializes"),
        serde_json::to_value(&right).expect("right serializes")
    );
    assert_eq!(left.secret_checks.len(), MAX_PREFLIGHT_CHECKS);
    assert!(left.diagnostics.len() <= MAX_PREFLIGHT_DIAGNOSTICS);
    assert!(left.limits.truncated);
    assert_eq!(left.status, PreflightStatus::NotReady);
    assert!(left
        .diagnostics
        .iter()
        .any(|diagnostic| { diagnostic.code == PreflightDiagnosticCode::ReportCapacityExceeded }));
    assert!(left
        .secret_checks
        .iter()
        .flat_map(|check| &check.addresses)
        .any(|field| field.file.as_str() == "integrations/alpha/integration.yaml"));
}

#[test]
fn all_declared_secret_consumer_classes_have_a_closed_report_identity() {
    let consumers = [
        PreflightSecretConsumer::SourceBasicUsername,
        PreflightSecretConsumer::SourceBasicPassword,
        PreflightSecretConsumer::SourceBearerToken,
        PreflightSecretConsumer::SourceOauthClientId,
        PreflightSecretConsumer::SourceOauthClientSecret,
        PreflightSecretConsumer::SourceApiKeyValue,
        PreflightSecretConsumer::SourceMtlsPrivateKey,
        PreflightSecretConsumer::SourceOauthMtlsPrivateKey,
        PreflightSecretConsumer::SourceJwksMtlsPrivateKey,
        PreflightSecretConsumer::EntityPostgresConnection,
        PreflightSecretConsumer::IssuanceSigningKey,
        PreflightSecretConsumer::CallerApiKeyFingerprint,
        PreflightSecretConsumer::Oid4vciClientSigningKey,
        PreflightSecretConsumer::Oid4vciAccessTokenSigningKey,
        PreflightSecretConsumer::Oid4vciSensitiveStateKey,
    ];
    assert_eq!(consumers.len(), 15);
    let serialized = consumers
        .iter()
        .map(|consumer| serde_json::to_string(consumer).expect("consumer serializes"))
        .collect::<BTreeSet<_>>();
    assert_eq!(serialized.len(), consumers.len());
    assert!(!serialized.iter().any(|value| value.contains("image")));
}

#[test]
fn invalid_addresses_and_runtime_paths_fail_without_echoing_values() {
    for (file, pointer) in [
        ("/absolute/environment.yaml", ""),
        ("../environment.yaml", ""),
        ("environments/local.yaml", "not-a-pointer"),
        ("environments/local.yaml", "/bad~escape"),
    ] {
        let error = PreflightFieldAddress::new(file, pointer).expect_err("address fails closed");
        let rendered = format!("{error:?} {error}");
        assert!(!rendered.contains(file));
        if !pointer.is_empty() {
            assert!(!rendered.contains(pointer));
        }
    }

    let mut input = validated_input();
    let unsafe_path = "/tmp/../host-sensitive-file";
    let error = input
        .add_runtime_file(
            unsafe_path,
            PreflightRuntimeFileKind::SourceCa,
            address(
                "environments/production.yaml",
                "/integrations/alpha/source/ca/file",
            ),
        )
        .expect_err("runtime path fails closed");
    let rendered = format!("{error:?} {error}");
    assert!(!rendered.contains(unsafe_path));
}

fn directory_snapshot(directory: &Path) -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(directory)
        .expect("directory reads")
        .map(|entry| {
            let entry = entry.expect("entry reads");
            let name = entry.file_name().into_string().expect("test name is UTF-8");
            let bytes = if entry.file_type().expect("file type reads").is_file() {
                fs::read(entry.path()).expect("file reads")
            } else {
                Vec::new()
            };
            (name, bytes)
        })
        .collect()
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("destination creates");
    for entry in fs::read_dir(source).expect("source directory reads") {
        let entry = entry.expect("source entry reads");
        let destination_path = destination.join(entry.file_name());
        if entry.file_type().expect("source file type reads").is_dir() {
            copy_tree(&entry.path(), &destination_path);
        } else {
            fs::copy(entry.path(), destination_path).expect("source file copies");
        }
    }
}
