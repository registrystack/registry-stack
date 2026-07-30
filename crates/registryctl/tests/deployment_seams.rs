mod approved_set_support;
pub use approved_set_support::approved_set;
pub use approved_set_support::{project_authoring, trust, SIGNING_INPUT_MARKER_FILE};

#[path = "../src/release_lock.rs"]
pub mod release_lock;

#[path = "../src/deployment.rs"]
mod deployment;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use approved_set::{
    ApprovedBaselineLanesV1, ApprovedBaselineSetV1, ApprovedLaneV1,
    APPROVED_BASELINE_SET_SCHEMA_ID, APPROVED_BASELINE_SET_SCHEMA_VERSION,
};
use deployment::{
    generate_deployment_package_with_test_inputs, verify_deployment_package_with_models,
    verify_deployment_package_with_test_inputs, DeploymentBindingV1, DeploymentGenerateRequestV1,
    DeploymentOwnershipStateV1, DeploymentPackageVerificationRequestV1, DeploymentPlanV1,
    DeploymentReleaseMetadataV1, EffectiveComposeModelsV1, ExpectedGenerationInputsV1,
    ImageIdentityV1, LockedPostgresqlRuntimeV1, LockedProductRuntimeV1, LockedRuntimeMappingV1,
    LockedSupportingRuntimeV1, ManagedTopologyImagesV1, PackageFreshnessV1,
    VerifiedDeploymentInputsV1,
};
use release_lock::{
    LockedMountSourceV1, LockedOperatorFileFormatV1, LockedOperatorFileV1, LockedRuntimeActionV1,
    LockedRuntimeMountV1, LockedSecretProjectionV1, LockedServiceHardeningV1,
};
use serde_json::{json, Value};

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
        notary: image("registry-notary", 'b'),
        postgresql_state_plane: image("postgresql", 'c'),
        private_namespace_holder: image("private-namespace", 'd'),
    })
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
    let database_ca = secret(
        "postgresql-tls-certificate",
        "/run/secrets/postgresql-ca.pem",
        "65532",
    );
    let (prepare_secrets, serve_secrets) = match lane {
        "relay-public" => (
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
    LockedProductRuntimeV1 {
        serve: action(
            command("serve"),
            [common.clone(), vec![state.clone(), audit.clone()]].concat(),
            &format!("{lane}-serve-environment"),
            serve_secrets.clone(),
        ),
        prepare_state_store: action(
            command("prepare-state-store"),
            [common.clone(), vec![audit.clone()]].concat(),
            &format!("{lane}-prepare-environment"),
            prepare_secrets.clone(),
        ),
        initialize_state: action(
            command("initialize-state"),
            [common.clone(), vec![state.clone(), audit.clone()]].concat(),
            &format!("{lane}-initialize-environment"),
            prepare_secrets,
        ),
        verify_state: action(
            command("verify-state"),
            [common, vec![state, audit]].concat(),
            &format!("{lane}-serve-environment"),
            serve_secrets,
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
        private_namespace_holder: LockedSupportingRuntimeV1 {
            command: vec!["/private-namespace-holder".to_string()],
            health_probe: vec!["CMD".to_string(), "/namespace-health".to_string()],
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
    fs::create_dir_all(&anchor_dir).unwrap();
    fs::write(bundle_dir.join("config/config.yaml"), "value-free: true\n").unwrap();
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
    let approved_set = ApprovedBaselineSetV1 {
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

fn verify(
    fixture: &PackageFixture,
    models: &EffectiveComposeModelsV1,
) -> deployment::DeploymentOwnershipReportV1 {
    verify_deployment_package_with_models(
        &DeploymentPackageVerificationRequestV1 {
            package_dir: &fixture.package,
            verified_inputs: &fixture.verified_inputs,
            parent_compose_files: &[],
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

fn included_parent(ordinary: &Value) -> Value {
    let mut parent = ordinary.clone();
    parent["services"]["parent-edge-client"] = json!({
        "image": "example.invalid/parent@sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        "networks": {"registry-edge": {}}
    });
    parent
}

#[test]
fn deployment_plan_round_trips_the_packet_zero_topology() {
    let plan = plan();
    plan.validate().unwrap();
    let mut packet: Value = serde_json::from_str(include_str!(
        "../../../release/conformance/adopter-runtime/deployment-plan.probe.v1.json"
    ))
    .unwrap();
    let object = packet.as_object_mut().unwrap();
    object.remove("schema");
    object.insert(
        "schema_id".to_string(),
        json!(deployment::DEPLOYMENT_PLAN_SCHEMA_ID),
    );
    object.insert(
        "schema_version".to_string(),
        json!(deployment::DEPLOYMENT_PLAN_SCHEMA_VERSION),
    );
    let decoded: DeploymentPlanV1 = serde_json::from_value(packet).unwrap();
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
fn managed_package_is_current_for_standalone_and_included_models() {
    let fixture = package_fixture();
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: fixture.models.ordinary.clone(),
        initialization: initialization_effective(&fixture),
        parent: Some(included_parent(&fixture.models.ordinary)),
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
        fs::read_dir(fixture.package.join("generated/bundles/relay-consultation"),)
            .unwrap()
            .count(),
        1
    );
    assert!(fixture.package.join("operator/secrets").is_dir());
}

#[test]
fn changed_binding_is_managed_but_stale() {
    let fixture = package_fixture();
    let mut binding: Value =
        serde_norway::from_str(&fs::read_to_string(fixture.package.join("binding.yaml")).unwrap())
            .unwrap();
    binding["ports"]["relay_public"] = json!(4343);
    fs::write(
        fixture.package.join("binding.yaml"),
        serde_norway::to_string(&binding).unwrap(),
    )
    .unwrap();
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: fixture.models.ordinary.clone(),
        initialization: initialization_effective(&fixture),
        parent: None,
    };
    let report = verify(&fixture, &effective);
    assert_eq!(
        report.ownership,
        DeploymentOwnershipStateV1::Managed,
        "{:?}",
        report.violations
    );
    assert_eq!(report.package_freshness, PackageFreshnessV1::Stale);
}

#[test]
fn verified_override_is_adapted_and_safe_for_generated_closure_regeneration() {
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
        parent: Some(included_parent(&ordinary)),
    };
    let report = verify(&fixture, &effective);
    assert_eq!(report.ownership, DeploymentOwnershipStateV1::Adapted);
    assert_eq!(report.package_freshness, PackageFreshnessV1::NotApplicable);
    assert_eq!(report.adapted_files, ["operator-override.yaml"]);
    assert!(report.in_place_regeneration_safe);
}

#[test]
fn edited_generated_file_is_adapted_and_requires_a_new_output() {
    let fixture = package_fixture();
    fs::write(
        fixture.package.join("generated/RUNBOOK.md"),
        "operator edited generated closure\n",
    )
    .unwrap();
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: fixture.models.ordinary.clone(),
        initialization: initialization_effective(&fixture),
        parent: None,
    };
    let report = verify(&fixture, &effective);
    assert_eq!(report.ownership, DeploymentOwnershipStateV1::Adapted);
    assert_eq!(report.package_freshness, PackageFreshnessV1::NotApplicable);
    assert!(report
        .adapted_files
        .contains(&"generated/RUNBOOK.md".to_string()));
    assert!(!report.in_place_regeneration_safe);
}

#[test]
fn hard_invariant_changes_and_parent_private_access_are_invalid() {
    let fixture = package_fixture();
    let mut ordinary = fixture.models.ordinary.clone();
    ordinary["services"]["registry-notary"]["command"] = json!(["/operator-command"]);
    let mut parent = included_parent(&ordinary);
    parent["services"]["parent-edge-client"]["networks"] =
        json!({"registry-edge": {}, "registry-private": {}});
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: ordinary,
        initialization: initialization_effective(&fixture),
        parent: Some(parent),
    };
    let report = verify(&fixture, &effective);
    assert_eq!(report.ownership, DeploymentOwnershipStateV1::Invalid);
    assert_eq!(report.package_freshness, PackageFreshnessV1::NotApplicable);
    assert!(report
        .violations
        .iter()
        .any(|violation| violation.contains("locked command")));
    assert!(report
        .violations
        .iter()
        .any(|violation| violation.contains("private product boundary")));
    assert!(!report.in_place_regeneration_safe);
}

#[test]
fn supporting_entrypoints_and_required_dependencies_are_hard_invariants() {
    let fixture = package_fixture();
    assert_eq!(
        fixture.models.ordinary["services"]["registry-postgres"]["depends_on"]
            ["registry-private-namespace"]["required"],
        json!(true)
    );
    let mut ordinary = fixture.models.ordinary.clone();
    ordinary["services"]["registry-postgres"]["entrypoint"] = json!(["/operator-entrypoint"]);
    ordinary["services"]["registry-notary"]["depends_on"]["registry-postgres"]["required"] =
        json!(false);
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: ordinary,
        initialization: initialization_effective(&fixture),
        parent: None,
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
    assert!(rendered.contains("operator/secrets/notary-signing-key"));
    assert!(!rendered.contains("private_key"));
    assert_eq!(binding.certificate_files, BTreeMap::new());
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
            "registry-notary-initialize",
            "registry-notary-prepare-state",
            "registry-postgres-bootstrap",
            "registry-relay-consultation-initialize",
            "registry-relay-consultation-prepare-state",
            "registry-relay-public-initialize",
            "registry-relay-public-prepare-state",
        ]
    );
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
    let bootstrap = &delta_services["registry-postgres-bootstrap"];
    assert_eq!(bootstrap["networks"], json!({"registry-private": {}}));
    assert!(bootstrap.get("network_mode").is_none());
    assert_eq!(
        bootstrap["depends_on"]["registry-postgres"]["condition"],
        "service_healthy"
    );
}

#[test]
fn secret_staging_is_isolated_and_consumers_receive_only_read_only_volumes() {
    let fixture = package_fixture();
    let services = fixture.models.ordinary["services"].as_object().unwrap();
    let stager = &services["registry-runtime-stage-secrets"];
    assert_eq!(stager["network_mode"], "none");
    assert_eq!(stager["user"], "0:0");
    assert_eq!(stager["cap_drop"], json!(["ALL"]));
    assert_eq!(stager["cap_add"], json!(["CHOWN"]));
    assert_eq!(stager["read_only"], true);
    assert_eq!(stager["security_opt"], json!(["no-new-privileges:true"]));
    for service_name in [
        "registry-private-namespace",
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
}

#[test]
fn private_namespace_holder_owns_shared_loopback_port_publication() {
    let fixture = package_fixture();
    let services = &fixture.models.ordinary["services"];
    assert!(services["registry-relay-consultation"]
        .get("ports")
        .is_none());
    assert!(services["registry-notary"].get("ports").is_none());
    assert_eq!(
        services["registry-private-namespace"]["ports"],
        json!([
            "127.0.0.1:4255:4255",
            "127.0.0.1:9243:9243",
            "127.0.0.1:9255:9255"
        ])
    );
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
            parent: None,
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
fn only_narrow_non_security_service_adaptations_are_accepted() {
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
            parent: None,
        },
    );
    assert_eq!(report.ownership, DeploymentOwnershipStateV1::Adapted);
    assert!(report.in_place_regeneration_safe);
}

#[test]
fn generated_closure_is_re_rendered_and_external_root_is_enforced() {
    let fixture = package_fixture();
    let effective = EffectiveComposeModelsV1 {
        standalone_ordinary: fixture.models.ordinary.clone(),
        initialization: initialization_effective(&fixture),
        parent: None,
    };
    let report = verify_deployment_package_with_models(
        &DeploymentPackageVerificationRequestV1 {
            package_dir: &fixture.package,
            verified_inputs: &fixture.verified_inputs,
            parent_compose_files: &[],
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
            parent_compose_files: &[],
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
fn runbook_covers_first_install_start_update_and_recovery_without_reset() {
    let fixture = package_fixture();
    let runbook = fs::read_to_string(fixture.package.join("generated/RUNBOOK.md")).unwrap();
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
    ] {
        assert!(
            runbook.contains(required),
            "missing runbook text: {required}"
        );
    }
    assert!(runbook.contains("'verify-state'"));
    assert!(!runbook.contains("--force"));
}

#[test]
fn packet_zero_compose_contract_passes_at_the_available_compose_version() {
    let status = std::process::Command::new("bash")
        .arg("release/scripts/check_adopter_compose_contract.sh")
        .arg("--current-only")
        .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
        .status()
        .expect("Packet 0 Compose checker starts");
    assert!(status.success(), "Packet 0 Compose checker failed");
}

#[test]
fn production_verifier_owns_real_compose_normalization() {
    let fixture = package_fixture();
    let report =
        verify_deployment_package_with_test_inputs(&DeploymentPackageVerificationRequestV1 {
            package_dir: &fixture.package,
            verified_inputs: &fixture.verified_inputs,
            parent_compose_files: &[],
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
fn production_verifier_parses_local_parent_includes_and_rejects_private_access() {
    let fixture = package_fixture();
    let parent_file = fixture
        .package
        .parent()
        .unwrap()
        .join("parent-compose.yaml");
    fs::write(
        &parent_file,
        format!(
            "include:\n  - {}\nservices:\n  parent-edge-client:\n    image: example.invalid/parent@sha256:{}\n    networks: [registry-edge]\n",
            fixture.package.join("generated/compose.yaml").display(),
            "e".repeat(64),
        ),
    )
    .unwrap();
    let report =
        verify_deployment_package_with_test_inputs(&DeploymentPackageVerificationRequestV1 {
            package_dir: &fixture.package,
            verified_inputs: &fixture.verified_inputs,
            parent_compose_files: std::slice::from_ref(&parent_file),
            expected_inputs: ExpectedGenerationInputsV1::default(),
        })
        .unwrap();
    assert_eq!(
        report.ownership,
        DeploymentOwnershipStateV1::Managed,
        "{:?}",
        report.violations
    );
    assert_eq!(
        report.verification_scope,
        deployment::DeploymentVerificationScopeV1::PackageAndParent
    );

    fs::write(
        &parent_file,
        format!(
            "include:\n  - {}\nservices:\n  parent-private-client:\n    image: example.invalid/parent@sha256:{}\n    networks: [registry-private]\n",
            fixture.package.join("generated/compose.yaml").display(),
            "e".repeat(64),
        ),
    )
    .unwrap();
    let report =
        verify_deployment_package_with_test_inputs(&DeploymentPackageVerificationRequestV1 {
            package_dir: &fixture.package,
            verified_inputs: &fixture.verified_inputs,
            parent_compose_files: std::slice::from_ref(&parent_file),
            expected_inputs: ExpectedGenerationInputsV1::default(),
        })
        .unwrap();
    assert_eq!(report.ownership, DeploymentOwnershipStateV1::Invalid);
    assert!(report
        .violations
        .iter()
        .any(|violation| violation.contains("private product boundary")));
}

#[test]
fn high_level_generation_derives_a_safe_binding_from_signed_identity() {
    let fixture = package_fixture();
    fs::remove_dir_all(&fixture.package).unwrap();
    generate_deployment_package_with_test_inputs(
        DeploymentGenerateRequestV1 {
            approved_set_file: fixture.approved_set_file.clone(),
            output_dir: fixture.package.clone(),
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
        },
        fixture.verified_inputs.clone(),
        Some(&fixture.verified_inputs),
    )
    .unwrap();
    assert!(!fixture.package.join("generated.previous").exists());
}

#[test]
fn regeneration_preserves_binding_operator_and_verified_override_byte_for_byte() {
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
    let override_before = fs::read(&override_file).unwrap();
    let next = updated_inputs(&fixture, "1.0.1", 17);

    generate_deployment_package_with_test_inputs(
        DeploymentGenerateRequestV1 {
            approved_set_file: fixture.approved_set_file.clone(),
            output_dir: fixture.package.clone(),
        },
        next,
        Some(&fixture.verified_inputs),
    )
    .unwrap();

    assert_eq!(
        fs::read(fixture.package.join("binding.yaml")).unwrap(),
        binding_before
    );
    assert_eq!(
        file_tree(&fixture.package.join("operator")),
        operator_before
    );
    assert_eq!(fs::read(override_file).unwrap(), override_before);
    assert!(fixture.package.join("generated.previous").is_dir());
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
        },
        next,
        Some(&fixture.verified_inputs),
    )
    .unwrap_err();
    assert!(error
        .to_string()
        .contains("outside managed or override-only ownership"));
    assert!(!fixture.package.join("generated.previous").exists());
}

#[test]
fn regeneration_refuses_a_postgresql_major_transition_before_staging() {
    let fixture = package_fixture();
    let next = updated_inputs(&fixture, "1.1.0", 18);
    let error = generate_deployment_package_with_test_inputs(
        DeploymentGenerateRequestV1 {
            approved_set_file: fixture.approved_set_file.clone(),
            output_dir: fixture.package.clone(),
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
