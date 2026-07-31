// This seam test uses only the approved-set helpers needed to construct deployment inputs.
#[allow(dead_code)]
mod approved_set_support;
pub use approved_set_support::approved_set;
pub use approved_set_support::{project_authoring, trust, SIGNING_INPUT_MARKER_FILE};

#[path = "../src/release_lock.rs"]
pub mod release_lock;

// This seam includes deployment internals directly without widening Registryctl's public API.
#[allow(dead_code)]
#[path = "../src/deployment.rs"]
mod deployment;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::Mutex;

use approved_set::{
    ApprovedBaselineLanesV1, ApprovedBaselineSetV1, ApprovedLaneV1,
    APPROVED_BASELINE_SET_SCHEMA_ID, APPROVED_BASELINE_SET_SCHEMA_VERSION,
};
use deployment::{
    generate_deployment_package_with_test_inputs, render_deployment_package,
    verify_deployment_package_with_models, verify_deployment_package_with_test_inputs,
    DeploymentBindingV1, DeploymentGenerateRequestV1, DeploymentOwnershipStateV1,
    DeploymentPackageRenderRequestV1, DeploymentPackageVerificationRequestV1, DeploymentPlanV1,
    DeploymentReleaseMetadataV1, EffectiveComposeModelsV1, ExpectedGenerationInputsV1,
    ImageIdentityV1, LockedPostgresqlRuntimeV1, LockedProductRuntimeV1, LockedRuntimeMappingV1,
    ManagedTopologyImagesV1, PackageFreshnessV1, VerifiedDeploymentInputsV1,
};
use registry_platform_crypto::canonicalize_json;
use release_lock::{
    LockedMountSourceV1, LockedOperatorFileFormatV1, LockedOperatorFileV1, LockedRuntimeActionV1,
    LockedRuntimeMountV1, LockedSecretProjectionV1, LockedServiceHardeningV1, OciPlatformV1,
};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};

static PROCESS_PATH_LOCK: Mutex<()> = Mutex::new(());

fn shell_fence_after_heading<'a>(markdown: &'a str, heading: &str, occurrence: usize) -> &'a str {
    let section = markdown
        .split_once(heading)
        .unwrap_or_else(|| panic!("missing Markdown heading {heading}"))
        .1;
    let section = section
        .split_once("\n## ")
        .map_or(section, |(current, _next)| current);
    let mut remainder = section;
    for index in 1..=occurrence {
        remainder = remainder
            .split_once("```sh\n")
            .unwrap_or_else(|| panic!("missing shell fence {occurrence} after {heading}"))
            .1;
        let (block, after) = remainder
            .split_once("\n```")
            .unwrap_or_else(|| panic!("unterminated shell fence after {heading}"));
        if index == occurrence {
            return block;
        }
        remainder = after;
    }
    unreachable!("shell fence occurrence is one-based")
}

struct ProcessPathGuard(Option<OsString>);

impl ProcessPathGuard {
    fn replace(path: &Path) -> Self {
        let previous = std::env::var_os("PATH");
        std::env::set_var("PATH", path);
        Self(previous)
    }
}

impl Drop for ProcessPathGuard {
    fn drop(&mut self) {
        match self.0.take() {
            Some(previous) => std::env::set_var("PATH", previous),
            None => std::env::remove_var("PATH"),
        }
    }
}

fn image(repository: &str, digest_byte: char) -> ImageIdentityV1 {
    ImageIdentityV1::parse(format!(
        "example.invalid/registrystack/{repository}@sha256:{}",
        digest_byte.to_string().repeat(64)
    ))
    .unwrap()
}

fn plan() -> DeploymentPlanV1 {
    DeploymentPlanV1::managed_single_node(&ManagedTopologyImagesV1 {
        relay: image("registry-relay", 'a'),
        relay_platform: OciPlatformV1::LinuxAmd64,
        notary: image("registry-notary", 'b'),
        notary_platform: OciPlatformV1::LinuxAmd64,
        postgresql_state_plane: image("postgresql", 'c'),
        postgresql_state_plane_platform: OciPlatformV1::LinuxAmd64,
    })
}

fn published_port(host_ip: &str, published: u16, target: u16) -> Value {
    json!([{
        "target": target,
        "published": published.to_string(),
        "host_ip": host_ip,
        "protocol": "tcp",
        "mode": "ingress"
    }])
}

fn mount(source: LockedMountSourceV1, target: &str, read_only: bool) -> LockedRuntimeMountV1 {
    LockedRuntimeMountV1 {
        source,
        target: target.to_string(),
        read_only,
    }
}

fn secret(file_id: &str, target: &str, uid: &str) -> LockedSecretProjectionV1 {
    LockedSecretProjectionV1 {
        file_id: file_id.to_string(),
        target: target.to_string(),
        mode: "0400".to_string(),
        uid: uid.to_string(),
        gid: uid.to_string(),
    }
}

fn action(
    command: Vec<String>,
    mounts: Vec<LockedRuntimeMountV1>,
    environment: &str,
    secrets: Vec<LockedSecretProjectionV1>,
) -> LockedRuntimeActionV1 {
    LockedRuntimeActionV1 {
        command,
        mounts,
        environment_files: vec![environment.to_string()],
        secret_files: secrets,
    }
}

fn action_without_operator_inputs(
    command: Vec<String>,
    mounts: Vec<LockedRuntimeMountV1>,
) -> LockedRuntimeActionV1 {
    LockedRuntimeActionV1 {
        command,
        mounts,
        environment_files: Vec::new(),
        secret_files: Vec::new(),
    }
}

fn product_runtime(product: &str, lane: &str) -> LockedProductRuntimeV1 {
    let common = vec![
        mount(LockedMountSourceV1::Bundle, "/run/registry/bundle", true),
        mount(LockedMountSourceV1::Anchor, "/run/registry/anchor", true),
    ];
    let audit = mount(LockedMountSourceV1::Audit, "/var/lib/registry/audit", false);
    let state = mount(
        LockedMountSourceV1::AntiRollbackState,
        "/var/lib/registry/state",
        false,
    );
    let state_read_only = mount(
        LockedMountSourceV1::AntiRollbackState,
        "/var/lib/registry/state",
        true,
    );
    let database_ca = secret(
        "postgresql-tls-certificate",
        "/run/secrets/postgresql-ca.pem",
        "65532",
    );
    let (prepare_secrets, initialize_secrets, serve_secrets) = match lane {
        "relay-public" => (
            vec![],
            vec![],
            vec![
                secret(
                    "relay-public-tls-certificate",
                    "/run/secrets/relay-public-tls.crt",
                    "65532",
                ),
                secret(
                    "relay-public-tls-private-key",
                    "/run/secrets/relay-public-tls.key",
                    "65532",
                ),
            ],
        ),
        "relay-consultation" => (
            vec![database_ca.clone()],
            vec![database_ca.clone()],
            vec![
                database_ca.clone(),
                secret(
                    "relay-consultation-tls-certificate",
                    "/run/secrets/relay-consultation-tls.crt",
                    "65532",
                ),
                secret(
                    "relay-consultation-tls-private-key",
                    "/run/secrets/relay-consultation-tls.key",
                    "65532",
                ),
            ],
        ),
        "notary" => (
            vec![database_ca.clone()],
            vec![],
            vec![
                database_ca,
                secret(
                    "relay-consultation-tls-certificate",
                    "/run/secrets/relay-consultation-ca.pem",
                    "65532",
                ),
                secret(
                    "notary-relay-workload-credential",
                    "/run/secrets/relay-workload-token",
                    "65532",
                ),
                secret(
                    "notary-signing-key",
                    "/run/secrets/notary-signing-key.jwk",
                    "65532",
                ),
                secret(
                    "notary-tls-certificate",
                    "/run/secrets/notary-tls.crt",
                    "65532",
                ),
                secret(
                    "notary-tls-private-key",
                    "/run/secrets/notary-tls.key",
                    "65532",
                ),
            ],
        ),
        _ => unreachable!(),
    };
    let command = |name: &str| vec![format!("/{product}"), name.to_string()];
    let environment = format!("{lane}-environment");
    LockedProductRuntimeV1 {
        serve: action(
            command("serve"),
            [common.clone(), vec![state_read_only.clone(), audit.clone()]].concat(),
            &environment,
            serve_secrets.clone(),
        ),
        prepare_state_store: action(
            command("prepare-state-store"),
            [common.clone(), vec![audit.clone()]].concat(),
            &environment,
            prepare_secrets.clone(),
        ),
        initialize_state: action(
            command("initialize-state"),
            [common.clone(), vec![state.clone(), audit.clone()]].concat(),
            &environment,
            initialize_secrets,
        ),
        preview_state: action_without_operator_inputs(
            command("preview-state"),
            [common.clone(), vec![state_read_only.clone()]].concat(),
        ),
        accept_state: LockedRuntimeActionV1 {
            command: command("accept-state"),
            mounts: [common.clone(), vec![state.clone(), audit.clone()]].concat(),
            environment_files: vec![environment],
            secret_files: vec![],
        },
        verify_state: action_without_operator_inputs(
            command("verify-state"),
            [common, vec![state_read_only]].concat(),
        ),
        health_probe: vec![
            "CMD".to_string(),
            format!("/{product}"),
            "health".to_string(),
        ],
    }
}

fn operator_files() -> Vec<LockedOperatorFileV1> {
    let bootstrap_keys = [
        "REGISTRY_RELAY_MIGRATOR_PASSWORD",
        "REGISTRY_RELAY_RUNTIME_PASSWORD",
        "REGISTRY_RELAY_MAINTENANCE_PASSWORD",
        "REGISTRY_RELAY_READER_PASSWORD",
        "REGISTRY_NOTARY_MIGRATOR_PASSWORD",
        "REGISTRY_NOTARY_RUNTIME_PASSWORD",
        "REGISTRY_NOTARY_MAINTENANCE_PASSWORD",
        "REGISTRY_NOTARY_READER_PASSWORD",
    ];
    deployment::OPERATOR_FILE_IDS
        .iter()
        .map(|id| {
            let format = if id.ends_with("-environment") {
                LockedOperatorFileFormatV1::Dotenv
            } else if id.ends_with("-certificate") {
                LockedOperatorFileFormatV1::PemCertificate
            } else if id.ends_with("-private-key") {
                LockedOperatorFileFormatV1::PemPrivateKey
            } else if *id == "notary-signing-key" {
                LockedOperatorFileFormatV1::JsonWebKey
            } else if *id == "notary-relay-workload-credential" {
                LockedOperatorFileFormatV1::CompactJwt
            } else {
                LockedOperatorFileFormatV1::Opaque
            };
            let postgresql = id.starts_with("postgresql-");
            LockedOperatorFileV1 {
                id: (*id).to_string(),
                format,
                mode: "0600".to_string(),
                allowed_owners: if postgresql {
                    vec!["root:root".to_string(), "999:999".to_string()]
                } else {
                    vec!["root:root".to_string(), "65532:65532".to_string()]
                },
                required_keys: if *id == "postgresql-bootstrap-environment" {
                    bootstrap_keys.map(str::to_string).to_vec()
                } else {
                    vec![]
                },
            }
        })
        .collect()
}

fn runtime() -> LockedRuntimeMappingV1 {
    LockedRuntimeMappingV1 {
        relay_public: product_runtime("registry-relay", "relay-public"),
        relay_consultation: product_runtime("registry-relay", "relay-consultation"),
        notary: product_runtime("registry-notary", "notary"),
        postgresql_state_plane: LockedPostgresqlRuntimeV1 {
            serve: LockedRuntimeActionV1 {
                command: vec!["/postgresql-state-plane".to_string()],
                mounts: vec![mount(
                    LockedMountSourceV1::PostgresqlData,
                    "/var/lib/postgresql/data",
                    false,
                )],
                environment_files: vec![],
                secret_files: vec![
                    secret(
                        "postgresql-admin-password",
                        "/run/secrets/postgresql-admin-password",
                        "999",
                    ),
                    secret(
                        "postgresql-tls-certificate",
                        "/run/secrets/postgresql-tls.crt",
                        "999",
                    ),
                    secret(
                        "postgresql-tls-private-key",
                        "/run/secrets/postgresql-tls.key",
                        "999",
                    ),
                ],
            },
            bootstrap: action(
                vec!["/postgresql-bootstrap".to_string()],
                vec![],
                "postgresql-bootstrap-environment",
                vec![
                    secret(
                        "postgresql-admin-password",
                        "/run/secrets/postgresql-admin-password",
                        "999",
                    ),
                    secret(
                        "postgresql-tls-certificate",
                        "/run/secrets/postgresql-ca.pem",
                        "999",
                    ),
                ],
            ),
            health_probe: vec!["CMD".to_string(), "/postgresql-health".to_string()],
            server_environment: vec![
                "POSTGRES_USER=registry_stack_bootstrap".to_string(),
                "POSTGRES_DB=postgres".to_string(),
                "POSTGRES_PASSWORD_FILE=/run/secrets/postgresql-admin-password".to_string(),
                "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256 --auth-local=trust".to_string(),
            ],
            hardening: LockedServiceHardeningV1 {
                user: "999:999".to_string(),
                read_only_root_filesystem: true,
                cap_drop: vec!["ALL".to_string()],
                security_opt: vec!["no-new-privileges:true".to_string()],
                tmpfs: vec![
                    "/tmp".to_string(),
                    "/var/run/postgresql:uid=999,gid=999,mode=0750".to_string(),
                ],
            },
        },
        operator_files: operator_files(),
    }
}

fn binding() -> DeploymentBindingV1 {
    DeploymentBindingV1::safe_default("registry-test", "production")
}

fn write_source_tree(root: &Path, lane: ApprovedLaneV1) {
    let lane_id = lane.to_string();
    let lane_dir = root.join("approved").join(&lane_id);
    let bundle_dir = lane_dir.join("bundle");
    let anchor_dir = lane_dir;
    fs::create_dir_all(bundle_dir.join("config")).unwrap();
    fs::create_dir_all(bundle_dir.join("descriptors")).unwrap();
    fs::create_dir_all(&anchor_dir).unwrap();
    fs::write(bundle_dir.join("config/config.yaml"), "value-free: true\n").unwrap();
    let environment_key = format!(
        "REGISTRY_{}_TEST_SECRET",
        lane_id.replace('-', "_").to_ascii_uppercase()
    );
    let product = if lane == ApprovedLaneV1::Notary {
        "registry-notary"
    } else {
        "registry-relay"
    };
    fs::write(
        bundle_dir.join("descriptors/secret-consumers.json"),
        serde_json::to_vec(&json!({
            "schema": "registry.project.secret-consumers.v1",
            "product": product,
            "consumers": [{
                "kind": "environment",
                "locator": environment_key,
                "config_pointer": "/audit/hash_secret_env",
            }],
        }))
        .unwrap(),
    )
    .unwrap();
    fs::write(bundle_dir.join("manifest.json"), "{}\n").unwrap();
    fs::write(bundle_dir.join("manifest.sig.json"), "{}\n").unwrap();
    fs::write(anchor_dir.join("anchor.json"), "{}\n").unwrap();
}

struct PackageFixture {
    _temp: tempfile::TempDir,
    package: PathBuf,
    approved_set_file: PathBuf,
    verified_inputs: VerifiedDeploymentInputsV1,
    models: deployment::RenderedComposeModelsV1,
    externally_recorded_root: String,
}

fn package_fixture() -> PackageFixture {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("source");
    fs::create_dir_all(&source).unwrap();
    let approved = source.join("approved-baseline-set.v1.json");
    let release_lock = source.join("registry-release-lock.v1.json");
    for lane in ApprovedLaneV1::ALL {
        write_source_tree(&source, lane);
    }
    let mut approved_set = ApprovedBaselineSetV1 {
        schema_id: APPROVED_BASELINE_SET_SCHEMA_ID.to_string(),
        schema_version: APPROVED_BASELINE_SET_SCHEMA_VERSION.to_string(),
        lanes: ApprovedBaselineLanesV1 {
            relay_public: approved_set_support::entry(
                ApprovedLaneV1::RelayPublic,
                "approved",
                'a',
                'd',
                None,
            ),
            relay_consultation: approved_set_support::entry(
                ApprovedLaneV1::RelayConsultation,
                "approved",
                'b',
                'e',
                Some('c'),
            ),
            notary: approved_set_support::entry(
                ApprovedLaneV1::Notary,
                "approved",
                'c',
                'f',
                Some('c'),
            ),
        },
    };
    let consultation_root = source.join("approved/relay-consultation");
    let mut transition_links = Vec::new();
    for index in 0..2 {
        let predecessor = format!("predecessor-{index}.anchor.json");
        let transition = format!("transition-{index}.json");
        fs::write(
            consultation_root.join(&predecessor),
            format!("{{\"anchor\":{index}}}\n"),
        )
        .unwrap();
        fs::write(
            consultation_root.join(&transition),
            format!("{{\"transition\":{index}}}\n"),
        )
        .unwrap();
        transition_links.push(approved_set::ApprovedAnchorTransitionLinkV1 {
            predecessor_anchor: approved_set_support::portable(format!(
                "approved/relay-consultation/{predecessor}"
            )),
            transition: approved_set_support::portable(format!(
                "approved/relay-consultation/{transition}"
            )),
        });
    }
    approved_set
        .lanes
        .relay_consultation
        .locators
        .anchor_transitions = transition_links;
    fs::write(&approved, approved_set.canonical_bytes().unwrap()).unwrap();
    fs::write(&release_lock, "{\"release\":\"1.0.0\"}\n").unwrap();
    let plan = plan();
    let runtime = runtime();
    let verified_inputs = VerifiedDeploymentInputsV1::from_test_components(
        &approved,
        &release_lock,
        plan.clone(),
        runtime.clone(),
        DeploymentReleaseMetadataV1 {
            generator_release: "registryctl 1.0.0-test".to_string(),
            minimum_compose_version: "2.35.0".to_string(),
            postgresql_major: 17,
        },
        approved_set_support::identity(ApprovedLaneV1::RelayPublic, "deployment-test"),
    )
    .unwrap();
    let package = temp.path().join("registry-stack");
    let report = generate_deployment_package_with_test_inputs(
        DeploymentGenerateRequestV1 {
            approved_set_file: approved.clone(),
            output_dir: package.clone(),
            binding_file: None,
        },
        verified_inputs.clone(),
        None,
    )
    .unwrap();
    PackageFixture {
        _temp: temp,
        package,
        approved_set_file: approved,
        verified_inputs,
        models: report.models,
        externally_recorded_root: report.externally_recorded_closure_sha256,
    }
}

fn updated_inputs(
    fixture: &PackageFixture,
    release: &str,
    postgresql_major: u16,
) -> VerifiedDeploymentInputsV1 {
    let release_lock = fixture
        .approved_set_file
        .parent()
        .unwrap()
        .join(format!("registry-release-lock-{release}.v1.json"));
    fs::write(&release_lock, format!("{{\"release\":\"{release}\"}}\n")).unwrap();
    VerifiedDeploymentInputsV1::from_test_components(
        &fixture.approved_set_file,
        &release_lock,
        plan(),
        runtime(),
        DeploymentReleaseMetadataV1 {
            generator_release: format!("registryctl {release}-test"),
            minimum_compose_version: "2.35.0".to_string(),
            postgresql_major,
        },
        approved_set_support::identity(ApprovedLaneV1::RelayPublic, "deployment-test"),
    )
    .unwrap()
}

fn file_tree(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn collect(root: &Path, current: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for entry in fs::read_dir(current).unwrap() {
            let entry = entry.unwrap();
            let path = entry.path();
            if entry.file_type().unwrap().is_dir() {
                collect(root, &path, files);
            } else {
                files.insert(
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(path).unwrap(),
                );
            }
        }
    }
    let mut files = BTreeMap::new();
    collect(root, root, &mut files);
    files
}

fn sha256_uri(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn recompute_package_local_manifest_for_compose(package: &Path) {
    let manifest_file = package.join("generated/deployment-manifest.v1.json");
    let mut manifest: Value = serde_json::from_slice(&fs::read(&manifest_file).unwrap()).unwrap();
    manifest["generated_files"]["compose.yaml"] = json!(sha256_uri(
        &fs::read(package.join("generated/compose.yaml")).unwrap()
    ));
    let mut closure = manifest.clone();
    closure
        .as_object_mut()
        .unwrap()
        .remove("generated_closure_sha256");
    manifest["generated_closure_sha256"] = json!(sha256_uri(&canonicalize_json(&closure).unwrap()));
    let mut bytes = serde_json::to_vec_pretty(&manifest).unwrap();
    bytes.push(b'\n');
    fs::write(manifest_file, bytes).unwrap();
}

fn verify(
    fixture: &PackageFixture,
    models: &EffectiveComposeModelsV1,
) -> deployment::DeploymentOwnershipReportV1 {
    verify_deployment_package_with_models(
        &DeploymentPackageVerificationRequestV1 {
            package_dir: &fixture.package,
            verified_inputs: &fixture.verified_inputs,
            check_operator_files: false,
            expected_inputs: ExpectedGenerationInputsV1::default(),
        },
        models,
    )
    .unwrap()
}

fn initialization_effective(fixture: &PackageFixture) -> Value {
    deployment::merge_compose_delta(&fixture.models.ordinary, &fixture.models.initialization)
        .unwrap()
}

#[test]
fn deployment_plan_round_trips_the_closed_topology() {
    let plan = plan();
    plan.validate().unwrap();
    let decoded: DeploymentPlanV1 =
        serde_json::from_slice(&serde_json::to_vec(&plan).unwrap()).unwrap();
    assert_eq!(decoded, plan);
    assert_eq!(
        serde_json::from_slice::<DeploymentPlanV1>(&serde_json::to_vec(&decoded).unwrap()).unwrap(),
        plan
    );
}

#[test]
fn portable_documents_reject_unknown_fields_and_unsupported_versions() {
    let mut value = serde_json::to_value(plan()).unwrap();
    value["surprise"] = json!(true);
    assert!(serde_json::from_value::<DeploymentPlanV1>(value).is_err());

    let mut value = serde_json::to_value(plan()).unwrap();
    value["schema_version"] = json!("1.1");
    let decoded: DeploymentPlanV1 = serde_json::from_value(value).unwrap();
    assert!(decoded.validate().is_err());

    assert!(ImageIdentityV1::parse("example.invalid/relay:latest").is_err());
    assert!(
        serde_json::from_value::<ImageIdentityV1>(json!("example.invalid/relay:latest")).is_err()
    );

    let mut value = serde_json::to_value(plan()).unwrap();
    value["workloads"][1]["dependencies"] = json!(["private-namespace-holder"]);
    let decoded: DeploymentPlanV1 = serde_json::from_value(value).unwrap();
    assert!(decoded.validate().is_err());
}

#[test]
fn managed_package_is_current_for_its_generated_models() {
    let fixture = package_fixture();
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: fixture.models.ordinary.clone(),
        initialization: initialization_effective(&fixture),
    };
    let report = verify(&fixture, &effective);
    assert_eq!(
        report.ownership,
        DeploymentOwnershipStateV1::Managed,
        "{:?}",
        report.violations
    );
    assert_eq!(report.package_freshness, PackageFreshnessV1::Current);
    assert!(report.violations.is_empty());
    assert!(report.in_place_regeneration_safe);
    assert!(fixture
        .package
        .join("generated/deployment-plan.v1.json")
        .is_file());
    assert_eq!(
        fs::read(fixture.package.join("generated/deployment-binding.v1.yaml")).unwrap(),
        fs::read(fixture.package.join("binding.yaml")).unwrap()
    );
    assert_eq!(
        fs::read_dir(fixture.package.join("generated/bundles/relay-consultation"),)
            .unwrap()
            .count(),
        1
    );
    assert!(fixture.package.join("operator/secrets").is_dir());
}

#[test]
fn explicit_expected_approved_set_mismatch_is_invalid() {
    let fixture = package_fixture();
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: fixture.models.ordinary.clone(),
        initialization: initialization_effective(&fixture),
    };
    let report = verify_deployment_package_with_models(
        &DeploymentPackageVerificationRequestV1 {
            package_dir: &fixture.package,
            verified_inputs: &fixture.verified_inputs,
            check_operator_files: false,
            expected_inputs: ExpectedGenerationInputsV1 {
                source_approved_baseline_set_sha256: Some(format!("sha256:{}", "f".repeat(64))),
                ..ExpectedGenerationInputsV1::default()
            },
        },
        &effective,
    )
    .unwrap();

    assert_eq!(report.ownership, DeploymentOwnershipStateV1::Invalid);
    assert_eq!(report.package_freshness, PackageFreshnessV1::NotApplicable);
    assert!(!report.in_place_regeneration_safe);
    assert!(
        report
            .violations
            .iter()
            .any(|violation| violation
                .contains("does not match the explicitly expected approved set"))
    );
}

#[test]
fn changed_binding_is_managed_stale_and_safely_regenerable() {
    let fixture = package_fixture();
    let mut binding: DeploymentBindingV1 =
        serde_norway::from_str(&fs::read_to_string(fixture.package.join("binding.yaml")).unwrap())
            .unwrap();
    binding.ports.relay_public = 4343;
    fs::write(
        fixture.package.join("binding.yaml"),
        serde_norway::to_string(&binding).unwrap(),
    )
    .unwrap();
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: fixture.models.ordinary.clone(),
        initialization: initialization_effective(&fixture),
    };
    let report = verify(&fixture, &effective);
    assert_eq!(
        report.ownership,
        DeploymentOwnershipStateV1::Managed,
        "{:?}",
        report.violations
    );
    assert_eq!(report.package_freshness, PackageFreshnessV1::Stale);
    assert!(report.in_place_regeneration_safe);

    let regenerated = generate_deployment_package_with_test_inputs(
        DeploymentGenerateRequestV1 {
            approved_set_file: fixture.approved_set_file.clone(),
            output_dir: fixture.package.clone(),
            binding_file: None,
        },
        fixture.verified_inputs.clone(),
        Some(&fixture.verified_inputs),
    )
    .unwrap();
    assert_eq!(
        regenerated.models.ordinary["services"]["registry-relay-public"]["ports"],
        published_port("127.0.0.1", 4343, 8080)
    );
    let regenerated_report =
        verify_deployment_package_with_test_inputs(&DeploymentPackageVerificationRequestV1 {
            package_dir: &fixture.package,
            verified_inputs: &fixture.verified_inputs,
            check_operator_files: false,
            expected_inputs: ExpectedGenerationInputsV1::default(),
        })
        .unwrap();
    assert_eq!(
        regenerated_report.ownership,
        DeploymentOwnershipStateV1::Managed,
        "{:?}",
        regenerated_report.violations
    );
    assert_eq!(
        regenerated_report.package_freshness,
        PackageFreshnessV1::Current
    );
}

#[test]
fn stale_binding_does_not_trust_recomputed_compose_with_an_extra_service() {
    let fixture = package_fixture();
    let binding_file = fixture.package.join("binding.yaml");
    let mut edited_binding: DeploymentBindingV1 =
        serde_norway::from_slice(&fs::read(&binding_file).unwrap()).unwrap();
    edited_binding.ports.relay_public = 4343;
    fs::write(
        &binding_file,
        serde_norway::to_string(&edited_binding).unwrap(),
    )
    .unwrap();

    let compose_file = fixture.package.join("generated/compose.yaml");
    let mut compose: Value = serde_norway::from_slice(&fs::read(&compose_file).unwrap()).unwrap();
    compose["services"]["arbitrary-extra-service"] = json!({
        "image": "example.invalid/arbitrary@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
        "command": ["/arbitrary"]
    });
    fs::write(&compose_file, serde_norway::to_string(&compose).unwrap()).unwrap();
    recompute_package_local_manifest_for_compose(&fixture.package);

    let report =
        verify_deployment_package_with_test_inputs(&DeploymentPackageVerificationRequestV1 {
            package_dir: &fixture.package,
            verified_inputs: &fixture.verified_inputs,
            check_operator_files: false,
            expected_inputs: ExpectedGenerationInputsV1::default(),
        })
        .unwrap();
    assert_eq!(
        report.ownership,
        DeploymentOwnershipStateV1::Invalid,
        "{:?}",
        report.violations
    );
    assert_eq!(report.package_freshness, PackageFreshnessV1::NotApplicable);
    assert!(report
        .violations
        .iter()
        .any(|violation| violation.contains("ordinary effective model differs")));
}

#[test]
fn generation_binding_projection_is_closed_and_validated_before_use() {
    let fixture = package_fixture();
    let projection_file = fixture.package.join("generated/deployment-binding.v1.yaml");
    let mut projection: Value =
        serde_norway::from_slice(&fs::read(&projection_file).unwrap()).unwrap();
    projection["unreviewed_authority"] = json!(true);
    fs::write(
        projection_file,
        serde_norway::to_string(&projection).unwrap(),
    )
    .unwrap();

    let error =
        verify_deployment_package_with_test_inputs(&DeploymentPackageVerificationRequestV1 {
            package_dir: &fixture.package,
            verified_inputs: &fixture.verified_inputs,
            check_operator_files: false,
            expected_inputs: ExpectedGenerationInputsV1::default(),
        })
        .unwrap_err();
    assert!(error
        .to_string()
        .contains("generation binding projection is not a supported closed document"));
}

#[test]
fn operator_override_is_invalid_and_unsafe_for_regeneration() {
    let fixture = package_fixture();
    fs::write(
        fixture.package.join("operator-override.yaml"),
        "services:\n  registry-relay-public:\n    labels:\n      operator.example/reviewed: \"true\"\n",
    )
    .unwrap();
    let mut ordinary = fixture.models.ordinary.clone();
    ordinary["services"]["registry-relay-public"]["labels"] =
        json!({"operator.example/reviewed": "true"});
    let mut initialization = initialization_effective(&fixture);
    initialization["services"]["registry-relay-public"] =
        ordinary["services"]["registry-relay-public"].clone();
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: ordinary.clone(),
        initialization,
    };
    let report = verify(&fixture, &effective);
    assert_eq!(report.ownership, DeploymentOwnershipStateV1::Invalid);
    assert_eq!(report.package_freshness, PackageFreshnessV1::NotApplicable);
    assert!(report
        .violations
        .iter()
        .any(|violation| violation.contains("move overrides to a parent Compose project")));
    assert!(!report.in_place_regeneration_safe);
}

#[test]
fn edited_generated_file_is_invalid_and_requires_a_new_output() {
    let fixture = package_fixture();
    fs::write(
        fixture.package.join("generated/RUNBOOK.md"),
        "operator edited generated closure\n",
    )
    .unwrap();
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: fixture.models.ordinary.clone(),
        initialization: initialization_effective(&fixture),
    };
    let report = verify(&fixture, &effective);
    assert_eq!(report.ownership, DeploymentOwnershipStateV1::Invalid);
    assert_eq!(report.package_freshness, PackageFreshnessV1::NotApplicable);
    assert!(report
        .violations
        .iter()
        .any(|violation| violation.contains("RUNBOOK.md")));
    assert!(!report.in_place_regeneration_safe);
}

#[test]
fn hard_invariant_changes_are_invalid() {
    let fixture = package_fixture();
    let mut ordinary = fixture.models.ordinary.clone();
    ordinary["services"]["registry-notary"]["command"] = json!(["/operator-command"]);
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: ordinary,
        initialization: initialization_effective(&fixture),
    };
    let report = verify(&fixture, &effective);
    assert_eq!(report.ownership, DeploymentOwnershipStateV1::Invalid);
    assert_eq!(report.package_freshness, PackageFreshnessV1::NotApplicable);
    assert!(report
        .violations
        .iter()
        .any(|violation| violation.contains("locked command")));
    assert!(!report.in_place_regeneration_safe);
}

#[test]
fn supporting_entrypoints_and_required_dependencies_are_hard_invariants() {
    let fixture = package_fixture();
    assert_eq!(
        fixture.models.ordinary["services"]["registry-postgres"]["depends_on"]
            ["registry-postgresql-stage-secrets"]["required"],
        json!(true)
    );
    let mut ordinary = fixture.models.ordinary.clone();
    ordinary["services"]["registry-postgres"]["entrypoint"] = json!(["/operator-entrypoint"]);
    ordinary["services"]["registry-notary"]["depends_on"]["registry-postgres"]["required"] =
        json!(false);
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: ordinary,
        initialization: initialization_effective(&fixture),
    };
    let report = verify(&fixture, &effective);
    assert_eq!(report.ownership, DeploymentOwnershipStateV1::Invalid);
    assert!(report
        .violations
        .iter()
        .any(|violation| violation.contains("registry-postgres changed its locked entrypoint")));
    assert!(report
        .violations
        .iter()
        .any(|violation| violation.contains("registry-notary changed its locked depends_on")));
}

#[test]
fn binding_contains_only_locators_not_secret_values() {
    let binding = binding();
    binding.validate().unwrap();
    let rendered = serde_norway::to_string(&binding).unwrap();
    assert!(!rendered.contains("edge_network_name"));
    assert!(rendered.contains("operator/secrets/notary-signing-key"));
    for lane in ["relay-public", "relay-consultation", "notary"] {
        assert!(rendered.contains(&format!("operator/secrets/{lane}-environment")));
        assert!(!rendered.contains(&format!("{lane}-serve-environment")));
        assert!(!rendered.contains(&format!("{lane}-prepare-environment")));
        assert!(!rendered.contains(&format!("{lane}-initialize-environment")));
    }
    assert!(!rendered.contains("private_key"));
    assert_eq!(binding.certificate_files, BTreeMap::new());
}

#[test]
fn removed_external_edge_binding_is_rejected() {
    let mut rendered = serde_norway::to_string(&binding()).unwrap();
    rendered.push_str("edge_network_name: operator-edge\n");
    let error = serde_norway::from_str::<DeploymentBindingV1>(&rendered).unwrap_err();
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn initialization_is_a_delta_and_prepare_state_has_no_acceptance_authority() {
    let fixture = package_fixture();
    let delta_services = fixture.models.initialization["services"]
        .as_object()
        .expect("initialization services");
    assert_eq!(
        delta_services.keys().cloned().collect::<Vec<_>>(),
        vec![
            "registry-notary-accept-state",
            "registry-notary-actions-stage-secrets",
            "registry-notary-initialize",
            "registry-notary-prepare-state",
            "registry-notary-preview-state",
            "registry-notary-verify-state",
            "registry-postgres",
            "registry-postgres-bootstrap",
            "registry-postgresql-actions-stage-secrets",
            "registry-relay-consultation-accept-state",
            "registry-relay-consultation-actions-stage-secrets",
            "registry-relay-consultation-initialize",
            "registry-relay-consultation-prepare-state",
            "registry-relay-consultation-preview-state",
            "registry-relay-consultation-verify-state",
            "registry-relay-public-accept-state",
            "registry-relay-public-initialize",
            "registry-relay-public-prepare-state",
            "registry-relay-public-preview-state",
            "registry-relay-public-verify-state",
        ]
    );
    for (action_service, stage_service) in [
        (
            "registry-relay-consultation-prepare-state",
            "registry-relay-consultation-actions-stage-secrets",
        ),
        (
            "registry-relay-consultation-initialize",
            "registry-relay-consultation-actions-stage-secrets",
        ),
        (
            "registry-notary-prepare-state",
            "registry-notary-actions-stage-secrets",
        ),
        (
            "registry-postgres-bootstrap",
            "registry-postgresql-actions-stage-secrets",
        ),
    ] {
        assert_eq!(
            delta_services[action_service]["depends_on"][stage_service],
            json!({"condition": "service_completed_successfully", "required": true})
        );
        assert!(fixture.models.ordinary["services"]
            .get(stage_service)
            .is_none());
    }
    for service_name in [
        "registry-relay-consultation-prepare-state",
        "registry-relay-consultation-initialize",
        "registry-notary-prepare-state",
    ] {
        assert_eq!(
            delta_services[service_name]["depends_on"]["registry-postgres"],
            json!({"condition": "service_healthy", "required": true})
        );
        assert_eq!(
            delta_services[service_name]["networks"],
            json!({"registry-runtime": {}})
        );
        assert!(delta_services[service_name].get("network_mode").is_none());
    }
    for service_name in [
        "registry-relay-public-prepare-state",
        "registry-relay-public-initialize",
        "registry-notary-initialize",
    ] {
        assert!(delta_services[service_name]["depends_on"]
            .as_object()
            .unwrap()
            .is_empty());
        assert_eq!(delta_services[service_name]["network_mode"], "none");
        assert!(delta_services[service_name].get("networks").is_none());
    }
    for service in [
        "registry-relay-public-prepare-state",
        "registry-relay-consultation-prepare-state",
        "registry-notary-prepare-state",
    ] {
        let service = &delta_services[service];
        let targets = service["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|mount| mount["target"].as_str())
            .collect::<Vec<_>>();
        assert!(targets.contains(&"/run/registry/bundle"));
        assert!(targets.contains(&"/run/registry/anchor"));
        assert!(targets.contains(&"/var/lib/registry/audit"));
        assert!(!targets.contains(&"/var/lib/registry/state"));
    }
    for service in [
        "registry-relay-public-initialize",
        "registry-relay-consultation-initialize",
        "registry-notary-initialize",
    ] {
        let service = &delta_services[service];
        assert!(service.get("volumes").is_some());
        assert!(service.get("env_file").is_some());
    }
    let expected_runtime = runtime();
    for (service_name, action, expected_state_read_only, expected_audit) in [
        (
            "registry-relay-public-preview-state",
            &expected_runtime.relay_public.preview_state,
            true,
            false,
        ),
        (
            "registry-relay-consultation-preview-state",
            &expected_runtime.relay_consultation.preview_state,
            true,
            false,
        ),
        (
            "registry-notary-preview-state",
            &expected_runtime.notary.preview_state,
            true,
            false,
        ),
        (
            "registry-relay-public-verify-state",
            &expected_runtime.relay_public.verify_state,
            true,
            false,
        ),
        (
            "registry-relay-consultation-verify-state",
            &expected_runtime.relay_consultation.verify_state,
            true,
            false,
        ),
        (
            "registry-notary-verify-state",
            &expected_runtime.notary.verify_state,
            true,
            false,
        ),
        (
            "registry-relay-public-accept-state",
            &expected_runtime.relay_public.accept_state,
            false,
            true,
        ),
        (
            "registry-relay-consultation-accept-state",
            &expected_runtime.relay_consultation.accept_state,
            false,
            true,
        ),
        (
            "registry-notary-accept-state",
            &expected_runtime.notary.accept_state,
            false,
            true,
        ),
    ] {
        let service = &delta_services[service_name];
        assert_eq!(service["command"], json!(action.command));
        let mounts = service["volumes"].as_array().unwrap();
        let state = mounts
            .iter()
            .find(|mount| mount["target"] == "/var/lib/registry/state")
            .unwrap();
        assert_eq!(state["read_only"], expected_state_read_only);
        assert_eq!(
            mounts
                .iter()
                .any(|mount| mount["target"] == "/var/lib/registry/audit"),
            expected_audit
        );
        let secret_mount = mounts
            .iter()
            .find(|mount| mount["target"] == "/run/secrets");
        if service_name.contains("accept") {
            let lane = service_name
                .strip_prefix("registry-")
                .unwrap()
                .strip_suffix("-accept-state")
                .unwrap();
            assert!(secret_mount.is_none());
            assert!(service["depends_on"].as_object().unwrap().is_empty());
            assert_eq!(
                service["env_file"],
                json!([format!("../operator/secrets/{lane}-environment")])
            );
        } else {
            assert!(secret_mount.is_none());
            assert!(service["depends_on"].as_object().unwrap().is_empty());
            assert!(service.get("env_file").is_none());
        }
        assert_eq!(service["network_mode"], "none");
        assert!(service.get("networks").is_none());
    }
    let bootstrap = &delta_services["registry-postgres-bootstrap"];
    assert_eq!(bootstrap["networks"], json!({"registry-runtime": {}}));
    assert_eq!(
        bootstrap["env_file"],
        json!([
            "./postgresql-server.env",
            "../operator/secrets/postgresql-bootstrap-environment"
        ])
    );
    assert!(bootstrap.get("network_mode").is_none());
    assert_eq!(
        bootstrap["depends_on"]["registry-postgres"]["condition"],
        "service_healthy"
    );
    assert_eq!(
        delta_services["registry-postgres"],
        json!({
            "entrypoint": [
                "/bin/bash",
                "-ceu",
                "pgdata=\"$${PGDATA:-/var/lib/postgresql/data}\"\ntest -z \"$$(find \"$$pgdata\" -mindepth 1 -maxdepth 1 -print -quit)\" || { echo 'PostgreSQL data directory is not empty; refusing explicit initialization' >&2; exit 1; }\nexec /usr/local/bin/docker-entrypoint.sh \"$@\"",
                "--"
            ]
        })
    );
    assert_eq!(
        fixture.models.ordinary["services"]["registry-postgres"]["entrypoint"],
        json!([
            "/bin/bash",
            "-ceu",
            "test -s \"$${PGDATA:-/var/lib/postgresql/data}/PG_VERSION\" || { echo 'PostgreSQL data directory is empty; run the explicit initialization workflow first' >&2; exit 1; }\nexec /usr/local/bin/docker-entrypoint.sh \"$@\"",
            "--"
        ])
    );
}

#[test]
fn secret_staging_is_isolated_and_consumers_receive_only_read_only_volumes() {
    let fixture = package_fixture();
    let services = fixture.models.ordinary["services"].as_object().unwrap();
    let expected_stagers = [
        (
            "registry-postgresql-stage-secrets",
            vec![(
                "registry-operator-files-postgresql-serve",
                "/registryctl-stage/output/postgresql-serve",
            )],
            vec![
                "postgresql-admin-password",
                "postgresql-tls-certificate",
                "postgresql-tls-private-key",
            ],
        ),
        (
            "registry-relay-public-stage-secrets",
            vec![(
                "registry-operator-files-relay-public-serve",
                "/registryctl-stage/output/relay-public-serve",
            )],
            vec![
                "relay-public-tls-certificate",
                "relay-public-tls-private-key",
            ],
        ),
        (
            "registry-relay-consultation-stage-secrets",
            vec![(
                "registry-operator-files-relay-consultation-serve",
                "/registryctl-stage/output/relay-consultation-serve",
            )],
            vec![
                "postgresql-tls-certificate",
                "relay-consultation-tls-certificate",
                "relay-consultation-tls-private-key",
            ],
        ),
        (
            "registry-notary-stage-secrets",
            vec![(
                "registry-operator-files-notary-serve",
                "/registryctl-stage/output/notary-serve",
            )],
            vec![
                "notary-relay-workload-credential",
                "notary-signing-key",
                "notary-tls-certificate",
                "notary-tls-private-key",
                "postgresql-tls-certificate",
                "relay-consultation-tls-certificate",
            ],
        ),
    ];
    assert!(services.get("registry-runtime-stage-secrets").is_none());
    for (service_name, expected_outputs, expected_sources) in expected_stagers {
        let stager = &services[service_name];
        assert_eq!(stager["network_mode"], "none");
        assert_eq!(stager["user"], "0:0");
        assert_eq!(stager["cap_drop"], json!(["ALL"]));
        assert_eq!(stager["cap_add"], json!(["CHOWN", "DAC_READ_SEARCH"]));
        assert_eq!(stager["read_only"], true);
        assert_eq!(stager["security_opt"], json!(["no-new-privileges:true"]));
        let mounts = stager["volumes"].as_array().unwrap();
        assert_eq!(mounts.len(), expected_outputs.len());
        assert_eq!(
            mounts
                .iter()
                .map(|mount| {
                    (
                        mount["source"].as_str().unwrap(),
                        mount["target"].as_str().unwrap(),
                    )
                })
                .collect::<Vec<_>>(),
            expected_outputs
        );
        assert!(mounts.iter().all(|mount| mount["read_only"] == false));
        let command = stager["command"][0].as_str().unwrap();
        for (_, target) in expected_outputs {
            assert!(command.contains(&format!("find {target} -mindepth 1 -maxdepth 1 -delete")));
        }
        assert_eq!(
            stager["secrets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|secret| secret["target"].as_str().unwrap())
                .collect::<Vec<_>>(),
            expected_sources
        );
    }
    let initialization = initialization_effective(&fixture);
    let initialization_services = initialization["services"].as_object().unwrap();
    let expected_action_stagers = [
        (
            "registry-postgresql-actions-stage-secrets",
            vec![(
                "registry-operator-files-postgresql-bootstrap",
                "/registryctl-stage/output/postgresql-bootstrap",
            )],
            vec!["postgresql-admin-password", "postgresql-tls-certificate"],
        ),
        (
            "registry-relay-consultation-actions-stage-secrets",
            vec![
                (
                    "registry-operator-files-relay-consultation-prepare",
                    "/registryctl-stage/output/relay-consultation-prepare",
                ),
                (
                    "registry-operator-files-relay-consultation-initialize",
                    "/registryctl-stage/output/relay-consultation-initialize",
                ),
            ],
            vec!["postgresql-tls-certificate"],
        ),
        (
            "registry-notary-actions-stage-secrets",
            vec![(
                "registry-operator-files-notary-prepare",
                "/registryctl-stage/output/notary-prepare",
            )],
            vec!["postgresql-tls-certificate"],
        ),
    ];
    for (service_name, expected_outputs, expected_sources) in expected_action_stagers {
        assert!(
            services.get(service_name).is_none(),
            "ordinary startup must not expose {service_name}"
        );
        for (volume, _) in &expected_outputs {
            assert!(
                fixture.models.ordinary["volumes"].get(volume).is_none(),
                "ordinary startup must not pre-stage action secret volume {volume}"
            );
        }
        let stager = &initialization_services[service_name];
        assert_eq!(stager["network_mode"], "none");
        assert!(stager.get("env_file").is_none());
        assert!(stager.get("networks").is_none());
        assert_eq!(
            stager["volumes"]
                .as_array()
                .unwrap()
                .iter()
                .map(|mount| {
                    (
                        mount["source"].as_str().unwrap(),
                        mount["target"].as_str().unwrap(),
                    )
                })
                .collect::<Vec<_>>(),
            expected_outputs
        );
        assert_eq!(
            stager["secrets"]
                .as_array()
                .unwrap()
                .iter()
                .map(|secret| secret["target"].as_str().unwrap())
                .collect::<Vec<_>>(),
            expected_sources
        );
    }
    for service_name in [
        "registry-postgres",
        "registry-relay-public",
        "registry-relay-consultation",
        "registry-notary",
    ] {
        let service = &services[service_name];
        assert!(service.get("cap_add").is_none());
        assert!(service.get("secrets").is_none());
    }
    for service_name in [
        "registry-postgres",
        "registry-relay-public",
        "registry-relay-consultation",
        "registry-notary",
    ] {
        let secret_mount = services[service_name]["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|mount| mount["target"] == "/run/secrets")
            .unwrap();
        assert_eq!(secret_mount["type"], "volume");
        assert_eq!(secret_mount["read_only"], true);
    }
    assert_eq!(
        services["registry-postgres"]["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|mount| mount["target"] == "/run/secrets")
            .unwrap()["source"],
        "registry-operator-files-postgresql-serve"
    );
    assert_eq!(
        services["registry-relay-public"]["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|mount| mount["target"] == "/run/secrets")
            .unwrap()["source"],
        "registry-operator-files-relay-public-serve"
    );
    assert_eq!(
        services["registry-relay-consultation"]["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|mount| mount["target"] == "/run/secrets")
            .unwrap()["source"],
        "registry-operator-files-relay-consultation-serve"
    );
    assert_eq!(
        services["registry-notary"]["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|mount| mount["target"] == "/run/secrets")
            .unwrap()["source"],
        "registry-operator-files-notary-serve"
    );
}

#[test]
fn secret_stager_cannot_gain_cross_owner_inputs_or_outputs() {
    let fixture = package_fixture();
    let mut ordinary = fixture.models.ordinary.clone();
    let stager = &mut ordinary["services"]["registry-relay-public-stage-secrets"];
    stager["secrets"].as_array_mut().unwrap().push(json!({
        "source": "registry-notary-signing-key",
        "target": "notary-signing-key"
    }));
    stager["volumes"].as_array_mut().unwrap().push(json!({
        "type": "volume",
        "source": "registry-operator-files-notary-serve",
        "target": "/registryctl-stage/cross-action",
        "read_only": false
    }));
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: ordinary,
        initialization: initialization_effective(&fixture),
    };
    let report = verify(&fixture, &effective);
    assert_eq!(report.ownership, DeploymentOwnershipStateV1::Invalid);
    assert!(report.violations.iter().any(|violation| violation.contains(
        "registry-relay-public-stage-secrets changed its exact security-owned service projection"
    )));
}

#[test]
fn package_normalizes_locators_and_mounts_digest_specific_lane_inputs() {
    let fixture = package_fixture();
    let normalized: ApprovedBaselineSetV1 = serde_json::from_slice(
        &fs::read(
            fixture
                .package
                .join("generated/inputs/approved-baseline-set.v1.json"),
        )
        .unwrap(),
    )
    .unwrap();
    for lane in ApprovedLaneV1::ALL {
        let lane_id = lane.to_string();
        let entry = normalized.lanes.get(lane);
        let digest = entry
            .signed_manifest_digest
            .strip_prefix("sha256:")
            .unwrap();
        assert_eq!(
            entry.locators.bundle.as_str(),
            format!("bundles/{lane_id}/{digest}")
        );
        assert!(fixture
            .package
            .join("generated")
            .join(entry.locators.bundle.as_path())
            .join("manifest.json")
            .is_file());
        let service = match lane {
            ApprovedLaneV1::RelayPublic => "registry-relay-public",
            ApprovedLaneV1::RelayConsultation => "registry-relay-consultation",
            ApprovedLaneV1::Notary => "registry-notary",
        };
        let bundle_mount = fixture.models.ordinary["services"][service]["volumes"]
            .as_array()
            .unwrap()
            .iter()
            .find(|mount| mount["target"] == "/run/registry/bundle")
            .unwrap();
        assert_eq!(
            bundle_mount["source"],
            format!("./bundles/{lane_id}/{digest}")
        );
        assert_eq!(bundle_mount["type"], "bind");
        assert_eq!(bundle_mount["read_only"], true);
        assert_eq!(bundle_mount["bind"]["create_host_path"], false);
    }
    let consultation_anchors = fixture.package.join("generated/anchors/relay-consultation");
    assert_eq!(
        fs::read(consultation_anchors.join("previous-anchor.json")).unwrap(),
        fs::read(consultation_anchors.join("history/0001.anchor.json")).unwrap()
    );
    assert_eq!(
        fs::read(consultation_anchors.join("transition.json")).unwrap(),
        fs::read(consultation_anchors.join("history/0001.transition.json")).unwrap()
    );
    for lane in ["relay-public", "notary"] {
        let anchors = fixture.package.join("generated/anchors").join(lane);
        assert!(!anchors.join("previous-anchor.json").exists());
        assert!(!anchors.join("transition.json").exists());
    }
}

#[test]
fn terminal_rotation_pair_is_hash_covered() {
    let fixture = package_fixture();
    fs::write(
        fixture
            .package
            .join("generated/anchors/relay-consultation/transition.json"),
        b"{\"transition\":\"tampered\"}\n",
    )
    .unwrap();
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: fixture.models.ordinary.clone(),
        initialization: initialization_effective(&fixture),
    };
    let report = verify(&fixture, &effective);
    assert_eq!(report.ownership, DeploymentOwnershipStateV1::Invalid);
    assert!(report
        .violations
        .iter()
        .any(|violation| violation.contains("transition.json")));
}

#[test]
fn ordinary_networking_publishes_only_public_applications_on_loopback() {
    let fixture = package_fixture();
    let plan = serde_json::to_value(plan()).unwrap();
    let relationships = plan["workloads"]
        .as_array()
        .unwrap()
        .iter()
        .map(|workload| {
            (
                workload["id"].as_str().unwrap(),
                workload["network_relationships"].clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for relationship in relationships.values() {
        assert_eq!(relationship, &json!(["runtime"]));
    }
    let services = &fixture.models.ordinary["services"];
    assert_eq!(
        fixture.models.ordinary["networks"],
        json!({"registry-runtime": {}})
    );
    assert!(services.get("registry-private-namespace").is_none());
    assert_eq!(
        services["registry-relay-public"]["ports"],
        published_port("127.0.0.1", 4242, 8080)
    );
    assert!(services["registry-relay-consultation"]
        .get("ports")
        .is_none());
    assert_eq!(
        services["registry-notary"]["ports"],
        published_port("127.0.0.1", 4255, 8081)
    );
    assert!(services["registry-postgres"].get("ports").is_none());
    for service_name in [
        "registry-relay-public",
        "registry-relay-consultation",
        "registry-notary",
        "registry-postgres",
    ] {
        assert_eq!(
            services[service_name]["networks"],
            json!({"registry-runtime": {}})
        );
        assert!(services[service_name].get("network_mode").is_none());
    }
    let published = services
        .as_object()
        .unwrap()
        .iter()
        .filter_map(|(name, service)| {
            service
                .get("ports")
                .map(|ports| (name.as_str(), ports.clone()))
        })
        .collect::<Vec<_>>();
    assert_eq!(
        published,
        vec![
            ("registry-notary", published_port("127.0.0.1", 4255, 8081),),
            (
                "registry-relay-public",
                published_port("127.0.0.1", 4242, 8080),
            ),
        ]
    );
    for service in services.as_object().unwrap().values() {
        assert!(service.get("ipc").is_none());
        assert!(service.get("pid").is_none());
        assert!(service
            .get("network_mode")
            .is_none_or(|mode| mode == "none"));
    }
    let initialization = &fixture.models.initialization["services"];
    for service_name in [
        "registry-postgres-bootstrap",
        "registry-relay-consultation-prepare-state",
        "registry-relay-consultation-initialize",
        "registry-notary-prepare-state",
    ] {
        assert_eq!(
            initialization[service_name]["networks"],
            json!({"registry-runtime": {}})
        );
        assert!(initialization[service_name].get("network_mode").is_none());
    }
    for service_name in [
        "registry-relay-public-prepare-state",
        "registry-relay-public-initialize",
        "registry-notary-initialize",
        "registry-relay-public-preview-state",
        "registry-relay-consultation-preview-state",
        "registry-notary-preview-state",
        "registry-relay-public-accept-state",
        "registry-relay-consultation-accept-state",
        "registry-notary-accept-state",
        "registry-relay-public-verify-state",
        "registry-relay-consultation-verify-state",
        "registry-notary-verify-state",
    ] {
        assert!(initialization[service_name].get("networks").is_none());
        assert_eq!(initialization[service_name]["network_mode"], "none");
    }
}

#[test]
fn durable_volumes_are_stable_and_scratch_volumes_are_project_scoped() {
    let fixture = package_fixture();
    let volumes = fixture.models.ordinary["volumes"].as_object().unwrap();
    let package_id = fixture.models.ordinary["name"].as_str().unwrap();
    for name in [
        "registry-postgresql-data",
        "registry-relay-public-state",
        "registry-relay-public-audit",
        "registry-relay-consultation-state",
        "registry-relay-consultation-audit",
        "registry-notary-state",
        "registry-notary-audit",
    ] {
        assert_eq!(
            volumes[name],
            json!({"name": format!("{package_id}_{name}")})
        );
    }
    for (name, volume) in volumes {
        if name.starts_with("registry-operator-files-") {
            assert_eq!(volume, &json!({}), "{name} must stay project-scoped");
        }
    }
}

#[test]
fn generated_services_use_fixed_bounded_local_logging() {
    let fixture = package_fixture();
    let expected = json!({
        "driver": "local",
        "options": {
            "max-size": "10m",
            "max-file": "3"
        }
    });
    for service_name in [
        "registry-relay-public",
        "registry-relay-consultation",
        "registry-notary",
        "registry-postgres",
    ] {
        assert_eq!(
            fixture.models.ordinary["services"][service_name]["logging"],
            expected
        );
    }
    for service_name in [
        "registry-postgres-bootstrap",
        "registry-relay-public-prepare-state",
        "registry-relay-public-initialize",
        "registry-relay-consultation-prepare-state",
        "registry-relay-consultation-initialize",
        "registry-notary-prepare-state",
        "registry-notary-initialize",
        "registry-relay-public-preview-state",
        "registry-relay-consultation-preview-state",
        "registry-notary-preview-state",
        "registry-relay-public-accept-state",
        "registry-relay-consultation-accept-state",
        "registry-notary-accept-state",
        "registry-relay-public-verify-state",
        "registry-relay-consultation-verify-state",
        "registry-notary-verify-state",
    ] {
        assert_eq!(
            fixture.models.initialization["services"][service_name]["logging"],
            expected
        );
    }
    for service_name in [
        "registry-postgresql-stage-secrets",
        "registry-relay-public-stage-secrets",
        "registry-relay-consultation-stage-secrets",
        "registry-notary-stage-secrets",
    ] {
        assert!(fixture.models.ordinary["services"][service_name]
            .get("logging")
            .is_none());
    }
}

#[test]
fn every_managed_service_is_pinned_to_the_signed_linux_amd64_platform() {
    let fixture = package_fixture();
    for model in [&fixture.models.ordinary, &fixture.models.initialization] {
        for (name, service) in model["services"].as_object().unwrap() {
            if name == "registry-postgres" && service.get("image").is_none() {
                continue;
            }
            assert_eq!(
                service["platform"], "linux/amd64",
                "{name} lost its signed platform binding"
            );
        }
    }
}

#[test]
fn top_level_secrets_exclude_environment_files() {
    let fixture = package_fixture();
    let secrets = fixture.models.ordinary["secrets"].as_object().unwrap();
    assert_eq!(secrets.len(), 11);
    for environment in [
        "relay-public-environment",
        "relay-consultation-environment",
        "notary-environment",
        "postgresql-bootstrap-environment",
    ] {
        assert!(!secrets.contains_key(&format!("registry-{environment}")));
    }
}

#[test]
fn exact_mount_source_type_access_and_lane_are_hard_invariants() {
    let fixture = package_fixture();
    for (field, replacement) in [
        (
            "source",
            json!(
                "./bundles/notary/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
            ),
        ),
        ("type", json!("volume")),
        ("read_only", json!(false)),
    ] {
        let mut ordinary = fixture.models.ordinary.clone();
        ordinary["services"]["registry-relay-public"]["volumes"][0][field] = replacement;
        let effective = EffectiveComposeModelsV1 {
            standalone_ordinary: ordinary,
            initialization: initialization_effective(&fixture),
        };
        let report = verify(&fixture, &effective);
        assert_eq!(report.ownership, DeploymentOwnershipStateV1::Invalid);
        assert!(report
            .violations
            .iter()
            .any(|violation| violation.contains("exact security-owned")));
    }
}

#[test]
fn any_effective_service_adaptation_is_invalid() {
    let fixture = package_fixture();
    fs::write(
        fixture.package.join("operator-override.yaml"),
        "services:\n  registry-relay-public:\n    labels:\n      operator.example/reviewed: \"true\"\n    deploy:\n      resources:\n        limits:\n          memory: 512M\n    logging:\n      driver: local\n      options:\n        max-size: 10m\n",
    )
    .unwrap();
    let mut ordinary = fixture.models.ordinary.clone();
    ordinary["services"]["registry-relay-public"]["labels"] =
        json!({"operator.example/reviewed": "true"});
    ordinary["services"]["registry-relay-public"]["deploy"] =
        json!({"resources": {"limits": {"memory": "512M"}}});
    ordinary["services"]["registry-relay-public"]["logging"] =
        json!({"driver": "local", "options": {"max-size": "10m"}});
    let mut initialization = initialization_effective(&fixture);
    initialization["services"]["registry-relay-public"] =
        ordinary["services"]["registry-relay-public"].clone();
    let report = verify(
        &fixture,
        &EffectiveComposeModelsV1 {
            standalone_ordinary: ordinary,
            initialization,
        },
    );
    assert_eq!(report.ownership, DeploymentOwnershipStateV1::Invalid);
    assert!(!report.in_place_regeneration_safe);
}

#[test]
fn generated_closure_is_re_rendered_and_external_root_is_enforced() {
    let fixture = package_fixture();
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: fixture.models.ordinary.clone(),
        initialization: initialization_effective(&fixture),
    };
    let report = verify_deployment_package_with_models(
        &DeploymentPackageVerificationRequestV1 {
            package_dir: &fixture.package,
            verified_inputs: &fixture.verified_inputs,
            check_operator_files: false,
            expected_inputs: ExpectedGenerationInputsV1 {
                externally_recorded_closure_sha256: Some(fixture.externally_recorded_root.clone()),
                ..ExpectedGenerationInputsV1::default()
            },
        },
        &effective,
    )
    .unwrap();
    assert_eq!(
        report.ownership,
        DeploymentOwnershipStateV1::Managed,
        "{:?}",
        report.violations
    );

    let mismatched = verify_deployment_package_with_models(
        &DeploymentPackageVerificationRequestV1 {
            package_dir: &fixture.package,
            verified_inputs: &fixture.verified_inputs,
            check_operator_files: false,
            expected_inputs: ExpectedGenerationInputsV1 {
                externally_recorded_closure_sha256: Some(format!("sha256:{}", "0".repeat(64))),
                ..ExpectedGenerationInputsV1::default()
            },
        },
        &effective,
    )
    .unwrap();
    assert_eq!(mismatched.ownership, DeploymentOwnershipStateV1::Invalid);
}

#[test]
fn renamed_package_verifies_through_dot_path() {
    let mut fixture = package_fixture();
    let restored = fixture
        .package
        .parent()
        .unwrap()
        .join("restored-registry-stack");
    fs::rename(&fixture.package, &restored).unwrap();
    fixture.package = restored.join(".");
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: fixture.models.ordinary.clone(),
        initialization: initialization_effective(&fixture),
    };
    let report = verify_deployment_package_with_models(
        &DeploymentPackageVerificationRequestV1 {
            package_dir: &fixture.package,
            verified_inputs: &fixture.verified_inputs,
            check_operator_files: false,
            expected_inputs: ExpectedGenerationInputsV1 {
                externally_recorded_closure_sha256: Some(fixture.externally_recorded_root.clone()),
                ..ExpectedGenerationInputsV1::default()
            },
        },
        &effective,
    )
    .unwrap();
    assert_eq!(
        report.ownership,
        DeploymentOwnershipStateV1::Managed,
        "{:?}",
        report.violations
    );
    let runbook = fs::read_to_string(fixture.package.join("generated/RUNBOOK.md")).unwrap();
    let package_id = fixture.models.ordinary["name"].as_str().unwrap();
    assert!(runbook.contains(&format!("Package: `{package_id}`")));
    assert!(!runbook.contains("restored-registry-stack"));
}

#[test]
fn manifest_only_tamper_and_nonempty_compose_environment_are_invalid() {
    let fixture = package_fixture();
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: fixture.models.ordinary.clone(),
        initialization: initialization_effective(&fixture),
    };
    let manifest_file = fixture
        .package
        .join("generated/deployment-manifest.v1.json");
    let original_manifest = fs::read(&manifest_file).unwrap();
    let mut manifest: Value = serde_json::from_slice(&original_manifest).unwrap();
    manifest["generator_release"] = json!("tampered-release");
    fs::write(
        &manifest_file,
        format!("{}\n", serde_json::to_string_pretty(&manifest).unwrap()),
    )
    .unwrap();
    let report = verify(&fixture, &effective);
    assert_eq!(report.ownership, DeploymentOwnershipStateV1::Invalid);
    assert!(report
        .violations
        .iter()
        .any(|violation| violation.contains("closure was changed")));
    let externally_checked = verify_deployment_package_with_models(
        &DeploymentPackageVerificationRequestV1 {
            package_dir: &fixture.package,
            verified_inputs: &fixture.verified_inputs,
            check_operator_files: false,
            expected_inputs: ExpectedGenerationInputsV1 {
                externally_recorded_closure_sha256: Some(fixture.externally_recorded_root.clone()),
                ..ExpectedGenerationInputsV1::default()
            },
        },
        &effective,
    )
    .unwrap();
    assert_eq!(
        externally_checked.ownership,
        DeploymentOwnershipStateV1::Invalid
    );

    fs::write(&manifest_file, original_manifest).unwrap();
    fs::write(
        fixture.package.join("generated/compose.empty.env"),
        b"SHOULD_STAY_EMPTY=true\n",
    )
    .unwrap();
    let report = verify(&fixture, &effective);
    assert_eq!(report.ownership, DeploymentOwnershipStateV1::Invalid);
    assert!(report
        .violations
        .iter()
        .any(|violation| violation.contains("compose.empty.env")));
}

#[test]
fn operator_file_checks_are_opt_in_structural_and_value_free() {
    let fixture = package_fixture();
    let sentinel = "OPERATOR_VALUE_SENTINEL_9c7f";
    fs::write(
        fixture.package.join("operator/secrets/unrelated"),
        sentinel.as_bytes(),
    )
    .unwrap();
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: fixture.models.ordinary.clone(),
        initialization: initialization_effective(&fixture),
    };
    let report = verify(&fixture, &effective);
    assert_eq!(report.ownership, DeploymentOwnershipStateV1::Managed);
    assert!(!serde_json::to_string(&report).unwrap().contains(sentinel));

    let report = verify_deployment_package_with_models(
        &DeploymentPackageVerificationRequestV1 {
            package_dir: &fixture.package,
            verified_inputs: &fixture.verified_inputs,
            check_operator_files: true,
            expected_inputs: ExpectedGenerationInputsV1::default(),
        },
        &effective,
    )
    .unwrap();
    assert_eq!(report.ownership, DeploymentOwnershipStateV1::Invalid);
    assert!(!serde_json::to_string(&report).unwrap().contains(sentinel));
    assert!(report
        .violations
        .iter()
        .all(|violation| !violation.contains(sentinel)));
}

#[test]
#[cfg(unix)]
fn operator_file_checks_reject_intermediate_symlink() {
    use std::os::unix::fs::symlink;

    let fixture = package_fixture();
    let external = fixture.package.parent().unwrap().join("external-secrets");
    fs::create_dir(&external).unwrap();
    fs::remove_dir(fixture.package.join("operator/secrets")).unwrap();
    symlink(&external, fixture.package.join("operator/secrets")).unwrap();
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: fixture.models.ordinary.clone(),
        initialization: initialization_effective(&fixture),
    };
    let report = verify_deployment_package_with_models(
        &DeploymentPackageVerificationRequestV1 {
            package_dir: &fixture.package,
            verified_inputs: &fixture.verified_inputs,
            check_operator_files: true,
            expected_inputs: ExpectedGenerationInputsV1::default(),
        },
        &effective,
    )
    .unwrap();
    assert_eq!(report.ownership, DeploymentOwnershipStateV1::Invalid);
    assert!(report
        .violations
        .iter()
        .any(|violation| violation.contains("symbolic-link path component")));
}

#[test]
fn operator_file_checks_reject_intermediate_non_directory() {
    let fixture = package_fixture();
    fs::remove_dir(fixture.package.join("operator/secrets")).unwrap();
    fs::write(
        fixture.package.join("operator/secrets"),
        b"not a directory\n",
    )
    .unwrap();
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: fixture.models.ordinary.clone(),
        initialization: initialization_effective(&fixture),
    };
    let report = verify_deployment_package_with_models(
        &DeploymentPackageVerificationRequestV1 {
            package_dir: &fixture.package,
            verified_inputs: &fixture.verified_inputs,
            check_operator_files: true,
            expected_inputs: ExpectedGenerationInputsV1::default(),
        },
        &effective,
    )
    .unwrap();
    assert_eq!(report.ownership, DeploymentOwnershipStateV1::Invalid);
    assert!(report
        .violations
        .iter()
        .any(|violation| violation.contains("non-directory path component")));
}

#[test]
fn runbook_covers_first_install_start_update_and_recovery_without_reset() {
    let fixture = package_fixture();
    let runbook = fs::read_to_string(fixture.package.join("generated/RUNBOOK.md")).unwrap();
    let inventory: Value = serde_json::from_slice(
        &fs::read(fixture.package.join("generated/operator-files.v1.json")).unwrap(),
    )
    .unwrap();
    for lane in ["relay-public", "relay-consultation", "notary"] {
        let expected_key = format!(
            "REGISTRY_{}_TEST_SECRET",
            lane.replace('-', "_").to_ascii_uppercase()
        );
        let environment = inventory["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|file| file["id"] == format!("{lane}-environment"))
            .unwrap();
        assert_eq!(environment["required_keys"], json!([expected_key.clone()]));
        assert!(
            runbook.contains(expected_key.as_str()),
            "runbook omits the signed environment requirement for {lane}"
        );
    }
    assert!(runbook
        .contains("Environment requirements below come directly from the hash-covered product"));
    for required in [
        "## First installation only",
        "## Ordinary start and stop",
        "## Product or image update",
        "## State recovery",
        "manual abort boundary",
        "new instance identity",
        "Rollback is unsupported",
        "generated.previous/",
        "externally recorded values",
        "## Compose project context",
        "--project-name \"$REGISTRY_STACK_COMPOSE_PROJECT\"",
        "CURRENT_CLOSURE_SHA256=\"<externally-recorded-current-closure-sha256>\"",
        "CANDIDATE_CLOSURE_SHA256=\"<externally-recorded-candidate-closure-sha256>\"",
        "registryctl deploy verify --package \"$CURRENT_PACKAGE\"",
        "registryctl deploy verify --package \"$CANDIDATE_PACKAGE\"",
    ] {
        assert!(
            runbook.contains(required),
            "missing runbook text: {required}"
        );
    }
    for service in [
        "registry-relay-public-verify-state",
        "registry-relay-consultation-verify-state",
        "registry-notary-verify-state",
    ] {
        assert!(runbook.contains(service));
    }
    for line in runbook
        .lines()
        .filter(|line| line.starts_with("docker compose "))
    {
        assert!(
            line.contains("--project-name \"$REGISTRY_STACK_COMPOSE_PROJECT\""),
            "Compose lifecycle command lacks the explicit project context: {line}"
        );
    }
    let serving_stages = [
        "registry-relay-public-stage-secrets",
        "registry-relay-consultation-stage-secrets",
        "registry-notary-stage-secrets",
        "registry-postgresql-stage-secrets",
    ];
    for stage in serving_stages {
        let command = format!("generated/compose.yaml run --rm --no-deps {stage}");
        assert_eq!(
            runbook.matches(&command).count(),
            3,
            "{stage} must run exactly once in each staging command block"
        );
    }
    let action_stages = [
        "registry-relay-consultation-actions-stage-secrets",
        "registry-notary-actions-stage-secrets",
        "registry-postgresql-actions-stage-secrets",
    ];
    for stage in action_stages {
        let command = format!("generated/compose.initialize.yaml run --rm --no-deps {stage}");
        assert_eq!(
            runbook.matches(&command).count(),
            1,
            "{stage} must run exactly once during first installation"
        );
    }
    let ordinary_compose = "docker compose --project-name \"$REGISTRY_STACK_COMPOSE_PROJECT\" --env-file generated/compose.empty.env -f generated/compose.yaml";
    let action_compose = format!("{ordinary_compose} -f generated/compose.initialize.yaml");
    let serving_staging_sequence = serving_stages
        .map(|stage| format!("{ordinary_compose} run --rm --no-deps {stage}"))
        .join("\n");
    let action_staging_sequence = action_stages
        .map(|stage| format!("{action_compose} run --rm --no-deps {stage}"))
        .join("\n");
    let first_install_config =
        format!("{action_compose} config --no-interpolate --no-env-resolution --quiet");
    assert!(runbook.contains(&format!(
        "{first_install_config}\n{action_staging_sequence}\n{action_compose} run --rm registry-postgres-bootstrap"
    )));
    let initialize_notary = runbook.find("registry-notary-initialize").unwrap();
    let first_verify_public = runbook[initialize_notary..]
        .find("registry-relay-public-verify-state")
        .map(|offset| initialize_notary + offset)
        .unwrap();
    let first_verify_consultation = runbook[first_verify_public..]
        .find("registry-relay-consultation-verify-state")
        .map(|offset| first_verify_public + offset)
        .unwrap();
    let first_verify_notary = runbook[first_verify_consultation..]
        .find("registry-notary-verify-state")
        .map(|offset| first_verify_consultation + offset)
        .unwrap();
    assert!(
        initialize_notary < first_verify_public
            && first_verify_public < first_verify_consultation
            && first_verify_consultation < first_verify_notary
    );
    assert!(runbook.contains(&format!(
        "{serving_staging_sequence}\n{ordinary_compose} up --detach --wait --wait-timeout 120"
    )));
    let ordinary_config =
        format!("{ordinary_compose} config --no-interpolate --no-env-resolution --quiet");
    assert!(runbook.contains(&format!(
        "{ordinary_config}\n{action_compose} run --rm --no-deps registry-relay-public-verify-state"
    )));
    let preview_public = runbook.find("registry-relay-public-preview-state").unwrap();
    let current_package_verify = runbook
        .find("registryctl deploy verify --package \"$CURRENT_PACKAGE\"")
        .unwrap();
    let candidate_package_verify = runbook
        .find("registryctl deploy verify --package \"$CANDIDATE_PACKAGE\"")
        .unwrap();
    assert!(
        current_package_verify < candidate_package_verify
            && candidate_package_verify < preview_public
    );
    let preview_consultation = runbook
        .find("registry-relay-consultation-preview-state")
        .unwrap();
    let preview_notary = runbook.find("registry-notary-preview-state").unwrap();
    let stop = runbook[preview_notary..]
        .find("generated/compose.yaml stop")
        .map(|offset| preview_notary + offset)
        .unwrap();
    let accept_public = runbook.find("registry-relay-public-accept-state").unwrap();
    let accept_consultation = runbook
        .find("registry-relay-consultation-accept-state")
        .unwrap();
    let accept_notary = runbook.find("registry-notary-accept-state").unwrap();
    assert!(
        preview_public < preview_consultation
            && preview_consultation < preview_notary
            && preview_notary < stop
            && stop < accept_public
            && accept_public < accept_consultation
            && accept_consultation < accept_notary
    );
    let update_start = runbook[accept_notary..]
        .find("generated/compose.yaml up --detach --wait --wait-timeout 120")
        .map(|offset| accept_notary + offset)
        .unwrap();
    let post_start_verify_public = runbook[update_start..]
        .find("registry-relay-public-verify-state")
        .map(|offset| update_start + offset)
        .unwrap();
    let post_start_verify_consultation = runbook[post_start_verify_public..]
        .find("registry-relay-consultation-verify-state")
        .map(|offset| post_start_verify_public + offset)
        .unwrap();
    let post_start_verify_notary = runbook[post_start_verify_consultation..]
        .find("registry-notary-verify-state")
        .map(|offset| post_start_verify_consultation + offset)
        .unwrap();
    assert!(
        update_start < post_start_verify_public
            && post_start_verify_public < post_start_verify_consultation
            && post_start_verify_consultation < post_start_verify_notary
    );
    assert!(runbook
        .contains("Do not stop any service or accept any lane unless every preview succeeds"));
    assert!(runbook.contains("audit-before-mutation"));
    assert!(!runbook.contains("registry-runtime-stage-secrets"));
    assert!(!runbook.contains("registry-relay-public-serve-stage-secrets"));
    assert!(!runbook.contains("registry-relay-consultation-serve-stage-secrets"));
    assert!(!runbook.contains("registry-notary-serve-stage-secrets"));
    assert!(!runbook.contains("registry-postgresql-serve-stage-secrets"));
    assert!(!runbook.contains("--force"));
}

#[test]
fn public_operator_command_blocks_match_the_generated_runbook() {
    let fixture = package_fixture();
    let runbook = fs::read_to_string(fixture.package.join("generated/RUNBOOK.md")).unwrap();
    let standalone = include_str!(
        "../../../docs/site/src/content/docs/operate/single-node-compose-behind-proxy.mdx"
    );
    let update =
        include_str!("../../../docs/site/src/content/docs/operate/upgrade-and-rollback.mdx");

    assert_eq!(
        shell_fence_after_heading(standalone, "## Initialize each product once", 2),
        shell_fence_after_heading(&runbook, "## First installation only", 1),
    );
    assert_eq!(
        shell_fence_after_heading(standalone, "## Run the package standalone", 1),
        shell_fence_after_heading(&runbook, "## Ordinary start and stop", 1),
    );
    assert_eq!(
        shell_fence_after_heading(
            update,
            "## Preview, accept, verify, and start the candidate",
            1,
        ),
        shell_fence_after_heading(&runbook, "## Product or image update", 2),
    );
}

#[test]
fn production_verifier_succeeds_without_docker() {
    let fixture = package_fixture();
    let unavailable_path = tempfile::tempdir().unwrap();
    assert!(!unavailable_path.path().join("docker").exists());
    let _path_lock = PROCESS_PATH_LOCK.lock().unwrap();
    let _path_guard = ProcessPathGuard::replace(unavailable_path.path());
    let report =
        verify_deployment_package_with_test_inputs(&DeploymentPackageVerificationRequestV1 {
            package_dir: &fixture.package,
            verified_inputs: &fixture.verified_inputs,
            check_operator_files: false,
            expected_inputs: ExpectedGenerationInputsV1 {
                externally_recorded_closure_sha256: Some(fixture.externally_recorded_root.clone()),
                ..ExpectedGenerationInputsV1::default()
            },
        })
        .unwrap();
    assert_eq!(
        report.ownership,
        DeploymentOwnershipStateV1::Managed,
        "{:?}",
        report.violations
    );
    assert_eq!(report.package_freshness, PackageFreshnessV1::Current);
}

#[test]
fn high_level_generation_derives_a_safe_binding_from_signed_identity() {
    let fixture = package_fixture();
    fs::remove_dir_all(&fixture.package).unwrap();
    generate_deployment_package_with_test_inputs(
        DeploymentGenerateRequestV1 {
            approved_set_file: fixture.approved_set_file.clone(),
            output_dir: fixture.package.clone(),
            binding_file: None,
        },
        fixture.verified_inputs.clone(),
        None,
    )
    .unwrap();
    let binding: DeploymentBindingV1 =
        serde_norway::from_slice(&fs::read(fixture.package.join("binding.yaml")).unwrap()).unwrap();
    assert_eq!(binding.environment, "production");
    assert!(binding.package_id.starts_with("registry-"));
    assert_ne!(binding.package_id, "registry-test");
    generate_deployment_package_with_test_inputs(
        DeploymentGenerateRequestV1 {
            approved_set_file: fixture.approved_set_file.clone(),
            output_dir: fixture.package.clone(),
            binding_file: None,
        },
        fixture.verified_inputs.clone(),
        Some(&fixture.verified_inputs),
    )
    .unwrap();
    assert!(!fixture.package.join("generated.previous").exists());
}

#[test]
fn generation_accepts_an_explicit_closed_binding_for_the_signed_identity() {
    let fixture = package_fixture();
    let binding_file = fixture.package.parent().unwrap().join("binding.yaml");
    let mut explicit: DeploymentBindingV1 =
        serde_norway::from_slice(&fs::read(fixture.package.join("binding.yaml")).unwrap()).unwrap();
    explicit.ports.relay_public = 4343;
    fs::write(&binding_file, serde_norway::to_string(&explicit).unwrap()).unwrap();
    fs::remove_dir_all(&fixture.package).unwrap();

    let report = generate_deployment_package_with_test_inputs(
        DeploymentGenerateRequestV1 {
            approved_set_file: fixture.approved_set_file.clone(),
            output_dir: fixture.package.clone(),
            binding_file: Some(binding_file),
        },
        fixture.verified_inputs.clone(),
        None,
    )
    .unwrap();

    assert_eq!(
        report.models.ordinary["services"]["registry-relay-public"]["ports"],
        published_port("127.0.0.1", 4343, 8080)
    );
}

#[test]
fn regeneration_refuses_operator_override_without_mutating_the_package() {
    let fixture = package_fixture();
    let operator_file = fixture.package.join("operator/secrets/operator-kept");
    fs::write(&operator_file, b"operator-owned\n").unwrap();
    let override_file = fixture.package.join("operator-override.yaml");
    fs::write(
        &override_file,
        "services:\n  registry-relay-public:\n    labels:\n      example.owner: operator\n",
    )
    .unwrap();
    let binding_before = fs::read(fixture.package.join("binding.yaml")).unwrap();
    let operator_before = file_tree(&fixture.package.join("operator"));
    let next = updated_inputs(&fixture, "1.0.1", 17);

    let error = generate_deployment_package_with_test_inputs(
        DeploymentGenerateRequestV1 {
            approved_set_file: fixture.approved_set_file.clone(),
            output_dir: fixture.package.clone(),
            binding_file: None,
        },
        next,
        Some(&fixture.verified_inputs),
    )
    .unwrap_err();

    assert!(error.to_string().contains("intact managed package"));
    assert_eq!(
        fs::read(fixture.package.join("binding.yaml")).unwrap(),
        binding_before
    );
    assert_eq!(
        file_tree(&fixture.package.join("operator")),
        operator_before
    );
    assert!(override_file.is_file());
    assert!(!fixture.package.join("generated.previous").exists());
}

#[test]
fn regeneration_verifies_the_older_lock_and_retains_its_generated_closure() {
    let fixture = package_fixture();
    let old_lock = fs::read(
        fixture
            .package
            .join("generated/inputs/registry-release-lock.v1.json"),
    )
    .unwrap();
    let next = updated_inputs(&fixture, "1.0.1", 17);

    generate_deployment_package_with_test_inputs(
        DeploymentGenerateRequestV1 {
            approved_set_file: fixture.approved_set_file.clone(),
            output_dir: fixture.package.clone(),
            binding_file: None,
        },
        next,
        Some(&fixture.verified_inputs),
    )
    .unwrap();

    assert_eq!(
        fs::read(
            fixture
                .package
                .join("generated.previous/inputs/registry-release-lock.v1.json")
        )
        .unwrap(),
        old_lock
    );
    assert_ne!(
        fs::read(
            fixture
                .package
                .join("generated/inputs/registry-release-lock.v1.json")
        )
        .unwrap(),
        old_lock
    );
}

#[test]
fn regeneration_refuses_an_unresolved_preceding_closure() {
    let fixture = package_fixture();
    fs::create_dir(fixture.package.join("generated.previous")).unwrap();
    let next = updated_inputs(&fixture, "1.0.1", 17);
    let error = generate_deployment_package_with_test_inputs(
        DeploymentGenerateRequestV1 {
            approved_set_file: fixture.approved_set_file.clone(),
            output_dir: fixture.package.clone(),
            binding_file: None,
        },
        next,
        Some(&fixture.verified_inputs),
    )
    .unwrap_err();
    assert!(error.to_string().contains("unresolved generated.previous"));
}

#[test]
fn regeneration_refuses_adapted_generator_owned_files() {
    let fixture = package_fixture();
    fs::write(
        fixture.package.join("generated/RUNBOOK.md"),
        b"operator edited generated content\n",
    )
    .unwrap();
    let next = updated_inputs(&fixture, "1.0.1", 17);
    let error = generate_deployment_package_with_test_inputs(
        DeploymentGenerateRequestV1 {
            approved_set_file: fixture.approved_set_file.clone(),
            output_dir: fixture.package.clone(),
            binding_file: None,
        },
        next,
        Some(&fixture.verified_inputs),
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("requires an intact managed package"));
    assert!(!fixture.package.join("generated.previous").exists());
}

#[test]
fn ipv6_loopback_uses_unambiguous_compose_port_syntax() {
    let fixture = package_fixture();
    let binding_file = fixture.package.parent().unwrap().join("ipv6-binding.yaml");
    let mut explicit: DeploymentBindingV1 =
        serde_norway::from_slice(&fs::read(fixture.package.join("binding.yaml")).unwrap()).unwrap();
    explicit.loopback_address = "::1".to_string();
    fs::write(&binding_file, serde_norway::to_string(&explicit).unwrap()).unwrap();
    fs::remove_dir_all(&fixture.package).unwrap();

    let report = generate_deployment_package_with_test_inputs(
        DeploymentGenerateRequestV1 {
            approved_set_file: fixture.approved_set_file.clone(),
            output_dir: fixture.package.clone(),
            binding_file: Some(binding_file),
        },
        fixture.verified_inputs.clone(),
        None,
    )
    .unwrap();

    assert_eq!(
        report.models.ordinary["services"]["registry-relay-public"]["ports"],
        published_port("::1", 4242, 8080)
    );
    assert_eq!(
        report.models.ordinary["services"]["registry-notary"]["ports"],
        published_port("::1", 4255, 8081)
    );
}

#[test]
fn regeneration_refuses_a_postgresql_major_transition_before_staging() {
    let fixture = package_fixture();
    let next = updated_inputs(&fixture, "1.1.0", 18);
    let error = generate_deployment_package_with_test_inputs(
        DeploymentGenerateRequestV1 {
            approved_set_file: fixture.approved_set_file.clone(),
            output_dir: fixture.package.clone(),
            binding_file: None,
        },
        next,
        Some(&fixture.verified_inputs),
    )
    .unwrap_err();
    assert!(error.to_string().contains("PostgreSQL major transition"));
    assert!(!fixture.package.join("generated.previous").exists());
}

#[test]
fn regeneration_does_not_mix_a_binding_change_with_a_release_update() {
    let fixture = package_fixture();
    let binding_file = fixture.package.join("binding.yaml");
    let mut changed: DeploymentBindingV1 =
        serde_norway::from_slice(&fs::read(&binding_file).unwrap()).unwrap();
    changed.durable_volume_prefix = "registry-reviewed-binding".to_string();
    fs::write(&binding_file, serde_norway::to_string(&changed).unwrap()).unwrap();
    let next = updated_inputs(&fixture, "1.0.1", 17);
    let error = generate_deployment_package_with_test_inputs(
        DeploymentGenerateRequestV1 {
            approved_set_file: fixture.approved_set_file.clone(),
            output_dir: fixture.package.clone(),
            binding_file: None,
        },
        next,
        Some(&fixture.verified_inputs),
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("cannot combine a binding change"));
    assert!(!fixture.package.join("generated.previous").exists());
}

fn runtime_parity_checker(package: &Path, payload: &Path) -> Output {
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap();
    Command::new("python3")
        .current_dir(repository)
        .arg(repository.join("release/scripts/check_adopter_compose_contract.py"))
        .arg("--package-root")
        .arg(package)
        .arg("--release-lock-payload")
        .arg(payload)
        .arg("--label")
        .arg("registry-release-lock-runtime-parity")
        .output()
        .unwrap()
}

#[test]
fn python_release_lock_runtime_renders_compose_conformance() {
    let _path_lock = PROCESS_PATH_LOCK.lock().unwrap();
    let fixture = package_fixture();
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .unwrap();
    let payload = fixture
        ._temp
        .path()
        .join("registry-release-lock.payload.json");
    let producer = Command::new("python3")
        .current_dir(repository)
        .arg(repository.join("release/scripts/runtime_parity_payload.py"))
        .arg("--output")
        .arg(&payload)
        .output()
        .unwrap();
    assert!(
        producer.status.success(),
        "payload producer failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&producer.stdout),
        String::from_utf8_lossy(&producer.stderr)
    );

    let payload_bytes = fs::read(&payload).unwrap();
    let payload_text = std::str::from_utf8(&payload_bytes).unwrap();
    for (label, source, replacement, diagnostic) in [
        (
            "product command drift",
            r#""command":["product-action","serve"]"#,
            r#""command":["product-action","drift"]"#,
            "exact supported command",
        ),
        (
            "bootstrap carriage return",
            "export PGPASSWORD",
            r"\rexport PGPASSWORD",
            "bounded closed command",
        ),
        (
            "bootstrap tab",
            "export PGPASSWORD",
            r"\texport PGPASSWORD",
            "bounded closed command",
        ),
        (
            "altered multiline bootstrap",
            "export PGPASSWORD",
            "export PGPASSW0RD",
            "exact reviewed recipe",
        ),
    ] {
        let drifted = payload_text.replacen(source, replacement, 1);
        assert_ne!(drifted, payload_text, "{label}");
        let error =
            release_lock::semantically_admit_release_lock_payload_for_test(drifted.as_bytes())
                .err()
                .unwrap_or_else(|| panic!("{label} must fail semantic admission"));
        assert!(error.to_string().contains(diagnostic), "{label}: {error:#}");
    }
    for (label, lane, action, field, value) in [
        (
            "preview environment",
            "relay_public",
            "preview_state",
            "environment_files",
            json!(["relay-public-environment"]),
        ),
        (
            "verify serving credential",
            "notary",
            "verify_state",
            "secret_files",
            json!([{
                "file_id": "notary-signing-key",
                "target": "/run/secrets/notary-signing-key.jwk",
                "mode": "0400",
                "uid": "65532",
                "gid": "65532"
            }]),
        ),
        (
            "accept serving credential",
            "relay_consultation",
            "accept_state",
            "secret_files",
            json!([{
                "file_id": "relay-consultation-tls-private-key",
                "target": "/run/secrets/relay-consultation-tls.key",
                "mode": "0400",
                "uid": "65532",
                "gid": "65532"
            }]),
        ),
    ] {
        let mut drifted: Value = serde_json::from_slice(&payload_bytes).unwrap();
        drifted["runtime"][lane][action][field] = value;
        let error = release_lock::semantically_admit_release_lock_payload_for_test(
            &serde_json::to_vec(&drifted).unwrap(),
        )
        .err()
        .unwrap_or_else(|| panic!("{label} must fail semantic admission"));
        assert!(
            error.to_string().contains("input projection"),
            "{label}: {error:#}"
        );
    }

    let admitted =
        release_lock::semantically_admit_release_lock_payload_for_test(&payload_bytes).unwrap();
    let verified_inputs =
        VerifiedDeploymentInputsV1::from_semantically_admitted_release_lock_for_test(
            &fixture.approved_set_file,
            &admitted,
            approved_set_support::identity(ApprovedLaneV1::RelayPublic, "runtime-parity"),
        )
        .unwrap();
    let package = fixture._temp.path().join("runtime-parity-package");
    let report = render_deployment_package(&DeploymentPackageRenderRequestV1 {
        output_dir: package.clone(),
        binding: binding(),
        verified_inputs,
    })
    .unwrap();
    assert_eq!(report.manifest.generator_release, "1.0.0");

    let checked = runtime_parity_checker(&package, &payload);
    assert!(
        checked.status.success(),
        "Compose conformance failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&checked.stdout),
        String::from_utf8_lossy(&checked.stderr)
    );

    let compose_path = package.join("generated/compose.yaml");
    let mut compose: Value = serde_norway::from_slice(&fs::read(&compose_path).unwrap()).unwrap();
    compose["services"]["registry-notary"]["command"] = json!(["runtime-drift"]);
    fs::write(&compose_path, serde_norway::to_string(&compose).unwrap()).unwrap();
    let drift = runtime_parity_checker(&package, &payload);
    assert!(!drift.status.success(), "Compose drift was not detected");
    assert!(
        String::from_utf8_lossy(&drift.stderr).contains("wrong ordinary command"),
        "unexpected drift diagnostic:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&drift.stdout),
        String::from_utf8_lossy(&drift.stderr)
    );
}
