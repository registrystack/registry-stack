//! Source transport assurance through the captured Evidence startup boundary.

#![cfg(unix)]
#![allow(
    clippy::disallowed_methods,
    reason = "tests read a reviewed package fixture and the published YAML contract, never operator configuration"
)]

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use registry_evidence::bundle::{evidence_package_limits, DeploymentInputs};
use registry_evidence::pack_source::{build_sources, PackSourceError};
use registry_evidence::secrets::{SecretProvider, SecretResolver};
use tempfile::TempDir;

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../products/evidence/reference/request-adapter/deployment-projects/dhis2-tracker-evidence",
    )
}

fn copy_fixture_tree(source: &Path, target: &Path) {
    fs::create_dir(target).expect("fixture directory is copied");
    for entry in fs::read_dir(source).expect("fixture directory is readable") {
        let entry = entry.expect("fixture entry is readable");
        if entry.file_name() == registry_platform_config::SUM_FILE
            || entry.file_name() == registry_platform_config::REVISION_FILE
        {
            continue;
        }
        let destination = target.join(entry.file_name());
        if entry
            .file_type()
            .expect("fixture entry type is readable")
            .is_dir()
        {
            copy_fixture_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("fixture file is copied");
        }
    }
}

fn make_read_only(path: &Path) {
    for entry in fs::read_dir(path).expect("fixture bundle is readable") {
        let entry = entry.expect("fixture entry is readable");
        let child = entry.path();
        if entry
            .file_type()
            .expect("fixture entry type is readable")
            .is_dir()
        {
            make_read_only(&child);
        } else {
            fs::set_permissions(child, fs::Permissions::from_mode(0o444))
                .expect("fixture bundle file becomes read-only");
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o555))
        .expect("fixture bundle directory becomes read-only");
}

fn replace_once(document: String, old: &str, new: &str) -> String {
    assert_eq!(document.matches(old).count(), 1, "fixture marker is unique");
    document.replacen(old, new, 1)
}

struct PreparedDeployment {
    _temporary: TempDir,
    deployment: DeploymentInputs,
    secrets: Arc<SecretResolver>,
    secret_root: PathBuf,
}

fn prepare_deployment(assurance: &str, base_url: &str) -> PreparedDeployment {
    let temporary = tempfile::tempdir().expect("temporary deployment root");
    let bundle_root = temporary.path().join("bundle");
    let secret_root = temporary.path().join("secrets");
    fs::create_dir(&secret_root).expect("empty secret root is created");
    fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
        .expect("empty secret root is owner-only");
    copy_fixture_tree(&fixture_root().join("bundle"), &bundle_root);

    let bundle_path = bundle_root.join("evidence.yaml");
    let bundle = fs::read_to_string(&bundle_path).expect("fixture bundle is readable");
    let bundle = replace_once(
        bundle,
        "assuranceProfile: evidence-grade",
        &format!("assuranceProfile: {assurance}"),
    );
    let bundle = replace_once(bundle, "https://dhis2.gov.example", base_url);
    let bundle = bundle.replace("        tlsTrustProfile: government-internal-pki\n", "");
    fs::write(&bundle_path, bundle).expect("fixture bundle is rebound");
    registry_platform_config::write_sum_file(
        &bundle_root,
        None,
        &evidence_package_limits(),
        "evidencectl package",
    )
    .expect("fixture package envelope is refreshed");
    make_read_only(&bundle_root);

    let runtime_path = temporary.path().join("runtime.yaml");
    let runtime = fs::read_to_string(fixture_root().join("runtime.yaml"))
        .expect("fixture runtime is readable");
    let runtime = replace_once(
        runtime,
        "  root: /etc/registry-evidence/bundle",
        &format!("  root: {}", bundle_root.display()),
    );
    let runtime = replace_once(
        runtime,
        "    root: /run/secrets/registry-evidence",
        &format!("    root: {}", secret_root.display()),
    );
    let runtime = replace_once(
        runtime,
        "  path: /var/lib/registry-evidence/audit/evidence.jsonl",
        &format!("  path: {}", temporary.path().join("audit.jsonl").display()),
    );
    let runtime = replace_once(runtime, "https://dhis2.gov.example", base_url);
    let runtime = runtime.replace("        tlsTrustProfile: government-internal-pki\n", "");
    let runtime = runtime.replace(
        "    outboundTls:\n      trustProfiles:\n        government-internal-pki:\n          caBundleFile: /etc/registry-evidence/ca/government-internal.pem\n",
        "",
    );
    let runtime = if assurance == "local" {
        replace_once(
            runtime,
            "signer:\n  type: transit\n  unixSocketPath: /run/registry-evidence/transit-proxy.sock\n  mount: transit\n  keyName: evidence-signing\n  keyVersion: 7\n  attemptTimeoutMilliseconds: 2000",
            "signer:\n  type: local-jwk\n  privateKeyRef: secret:file/evidence-signing",
        )
    } else {
        runtime
    };
    fs::write(&runtime_path, runtime).expect("fixture runtime is rebound");
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o444))
        .expect("fixture runtime is immutable");

    let deployment = DeploymentInputs::load(&runtime_path).expect("deployment inputs load");
    let secrets = Arc::new(
        SecretResolver::new([SecretProvider::File], &secret_root)
            .expect("empty secret resolver initializes"),
    );
    PreparedDeployment {
        _temporary: temporary,
        deployment,
        secrets,
        secret_root,
    }
}

fn assert_secrets_unread(prepared: &PreparedDeployment) {
    assert_eq!(
        fs::read_dir(&prepared.secret_root)
            .expect("secret root remains readable")
            .count(),
        0,
        "source compilation must not materialize or resolve credentials"
    );
}

fn bundle_contract_validator() -> jsonschema::JSONSchema {
    let schema: serde_norway::Value = serde_norway::from_slice(include_bytes!(
        "../../../products/evidence/contracts/bundle.schema.yaml"
    ))
    .expect("bundle contract is YAML");
    let schema = serde_json::to_value(schema).expect("bundle contract converts to JSON");
    jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .should_validate_formats(true)
        .compile(&schema)
        .expect("bundle contract compiles")
}

fn dhis2_bundle_contract(assurance: &str, base_url: &str) -> serde_json::Value {
    let fixture: serde_norway::Value = serde_norway::from_slice(
        &fs::read(fixture_root().join("bundle/evidence.yaml"))
            .expect("DHIS2 bundle fixture is readable"),
    )
    .expect("DHIS2 bundle fixture is YAML");
    let mut fixture = serde_json::to_value(fixture).expect("DHIS2 bundle fixture converts to JSON");
    fixture["assuranceProfile"] = assurance.into();
    fixture["sourceConnections"]["population-tracker"]["endpoints"][0]["baseUrl"] = base_url.into();
    fixture
}

#[test]
fn bundle_contract_matches_source_transport_assurance() {
    let validator = bundle_contract_validator();
    for (assurance, base_url) in [
        ("production", "HtTpS://Dhis2.Gov.Example/registry/api"),
        ("evidence-grade", "HTTPS://DHIS2.GOV.EXAMPLE/registry/api"),
        ("local", "http://127.0.0.1:19091/registry/api"),
        ("local", "http://[::1]:19091/registry/api"),
    ] {
        let instance = dhis2_bundle_contract(assurance, base_url);
        let failures = validator
            .validate(&instance)
            .err()
            .into_iter()
            .flatten()
            .map(|error| error.to_string())
            .collect::<Vec<_>>();
        assert!(
            failures.is_empty(),
            "bundle contract refused {assurance} source {base_url}: {failures:?}"
        );
    }

    for (assurance, base_url) in [
        ("production", "http://127.0.0.1:19091/registry/api"),
        ("evidence-grade", "HtTp://127.0.0.1:19091/registry/api"),
        ("local", "HtTp://127.0.0.1:19091/registry/api"),
        ("local", "http://localhost:19091/registry/api"),
        ("local", "http://10.0.0.1:19091/registry/api"),
        ("local", "http://127.0.0.1:19091/registry?tenant=one"),
        (
            "production",
            "https://dhis2.gov.example/registry?tenant=one",
        ),
        ("local", "https://dhis2.gov.example/registry#fragment"),
    ] {
        assert!(
            !validator.is_valid(&dhis2_bundle_contract(assurance, base_url)),
            "bundle contract accepted prohibited {assurance} source {base_url}"
        );
    }
}

#[test]
fn deployable_profiles_refuse_mixed_case_plain_http_before_credentials() {
    for assurance in ["production", "evidence-grade"] {
        let prepared = prepare_deployment(assurance, "HtTp://127.0.0.1:19091");
        let result = build_sources(
            prepared.deployment.bundle(),
            prepared.deployment.runtime(),
            &prepared.secrets,
        );
        assert!(
            matches!(result, Err(PackSourceError::Plan)),
            "{assurance} accepted a mixed-case plain-HTTP source transport"
        );
        assert_secrets_unread(&prepared);
    }
}

#[test]
fn deployable_profiles_accept_mixed_case_https_and_host_spelling() {
    for assurance in ["production", "evidence-grade"] {
        let prepared = prepare_deployment(assurance, "HtTpS://Dhis2.Gov.Example");
        build_sources(
            prepared.deployment.bundle(),
            prepared.deployment.runtime(),
            &prepared.secrets,
        )
        .unwrap_or_else(|error| panic!("{assurance} refused HTTPS spelling: {error}"));
        assert_secrets_unread(&prepared);
    }
}

#[test]
fn local_authenticated_http_is_limited_to_canonical_numeric_loopback() {
    for accepted in ["http://127.0.0.1:19091", "http://[::1]:19091"] {
        let prepared = prepare_deployment("local", accepted);
        build_sources(
            prepared.deployment.bundle(),
            prepared.deployment.runtime(),
            &prepared.secrets,
        )
        .unwrap_or_else(|error| panic!("local loopback source {accepted} failed: {error}"));
        assert_secrets_unread(&prepared);
    }

    for refused in [
        "HtTp://127.0.0.1:19091",
        "http://localhost:19091",
        "http://10.0.0.1:19091",
    ] {
        let prepared = prepare_deployment("local", refused);
        assert!(
            matches!(
                build_sources(
                    prepared.deployment.bundle(),
                    prepared.deployment.runtime(),
                    &prepared.secrets,
                ),
                Err(PackSourceError::Plan)
            ),
            "local authenticated source accepted non-canonical or non-loopback HTTP: {refused}"
        );
        assert_secrets_unread(&prepared);
    }
}

#[test]
fn source_base_url_refuses_query_and_fragment_before_credentials() {
    for (assurance, refused) in [
        (
            "evidence-grade",
            "https://dhis2.gov.example/registry?tenant=one",
        ),
        (
            "evidence-grade",
            "https://dhis2.gov.example/registry#fragment",
        ),
        ("local", "http://127.0.0.1:19091/registry?tenant=one"),
        ("local", "http://127.0.0.1:19091/registry#fragment"),
    ] {
        let prepared = prepare_deployment(assurance, refused);
        assert!(
            matches!(
                build_sources(
                    prepared.deployment.bundle(),
                    prepared.deployment.runtime(),
                    &prepared.secrets,
                ),
                Err(PackSourceError::Plan)
            ),
            "{assurance} source accepted a query or fragment: {refused}"
        );
        assert_secrets_unread(&prepared);
    }
}

#[test]
fn source_startup_refuses_noncanonical_base_paths_before_source_effects() {
    let mut accepted = Vec::new();
    for base_url in [
        "https://dhis2.gov.example/a/../b",
        "http://127.0.0.1:19091/a//b",
        "https://dhis2.gov.example/a;b",
        "https://dhis2.gov.example/%ZZ",
        "https://dhis2.gov.example/%7e",
    ] {
        let prepared = prepare_deployment("local", base_url);
        if !matches!(
            build_sources(
                prepared.deployment.bundle(),
                prepared.deployment.runtime(),
                &prepared.secrets,
            ),
            Err(PackSourceError::Plan)
        ) {
            accepted.push(base_url);
        }
        assert_secrets_unread(&prepared);
    }
    assert!(
        accepted.is_empty(),
        "startup admitted noncanonical base paths: {accepted:?}"
    );
}

#[test]
fn bundle_contract_requires_connection_owners_and_explicit_anonymous_local_origin() {
    let validator = bundle_contract_validator();
    let mut accepted = Vec::new();
    let mut absent = dhis2_bundle_contract("local", "http://127.0.0.1:19091");
    absent.as_object_mut().unwrap().remove("sourceConnections");
    if validator.is_valid(&absent) {
        accepted.push("missing connection owners");
    }
    let mut empty = absent.clone();
    empty["sourceConnections"] = serde_json::json!({});
    if validator.is_valid(&empty) {
        accepted.push("empty connection owners");
    }
    for base_url in [
        "http://127.0.0.1",
        "http://127.0.0.1:0",
        "http://127.0.0.1:19091/registry",
        "https://dhis2.gov.example",
    ] {
        let mut instance = dhis2_bundle_contract("local", base_url);
        let endpoint = &mut instance["sourceConnections"]["population-tracker"]["endpoints"][0];
        endpoint["authentication"] = serde_json::json!({"type":"none"});
        endpoint["clientIdentity"] = "forbidden".into();
        if validator.is_valid(&instance) {
            accepted.push(base_url);
        }
    }
    assert!(
        accepted.is_empty(),
        "contract admitted incomplete owners/origins: {accepted:?}"
    );
    let mut valid = dhis2_bundle_contract("local", "http://127.0.0.1:19091");
    let endpoint = &mut valid["sourceConnections"]["population-tracker"]["endpoints"][0];
    endpoint["authentication"] = serde_json::json!({"type":"none"});
    endpoint["clientIdentity"] = "forbidden".into();
    assert!(validator.is_valid(&valid));
}
