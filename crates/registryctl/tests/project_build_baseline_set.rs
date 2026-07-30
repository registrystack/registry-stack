// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use registry_platform_config::ProductAcceptanceLaneV1;
use registryctl::{
    add_config_anchor_key, build_registry_project_with_baselines_and_context,
    build_registry_project_with_context, create_trust_anchor, init_config_anchor,
    init_registry_project, sign_config_bundle, sign_product_bundle, BundleSignOptions,
    ProductBundleSignOptions, ProjectBuildBaselineSetOptions, ProjectBuildOptions,
    ProjectExecutionContext, ProjectInitOptions, ProjectStarter, TrustAnchorCreateOptions,
};

const TEST_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registryctl-test-private-key"}"#;
const TEST_PUBLIC_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registryctl-test-private-key"}"#;

#[derive(Clone)]
struct SignedProductBaseline {
    bundle: PathBuf,
    anchor: PathBuf,
}

fn context() -> ProjectExecutionContext {
    ProjectExecutionContext::new(env!("CARGO_BIN_EXE_registryctl"))
        .expect("Cargo provides the exact registryctl executable")
}

fn initialize_project(root: &Path) -> PathBuf {
    let project = root.join("approved-baseline-project");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: project.clone(),
    })
    .expect("combined starter initializes");
    project
}

fn build_options(project: &Path) -> ProjectBuildOptions {
    ProjectBuildOptions {
        project_directory: project.to_path_buf(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    }
}

fn initial_build(project: &Path) -> PathBuf {
    let report = build_registry_project_with_context(&build_options(project), &context())
        .expect("initial build without an approved baseline succeeds");
    project.join(report.output.expect("build reports its output"))
}

fn sign_product_baseline(
    output: &Path,
    temporary: &Path,
    product: &str,
    product_directory: &str,
    environment: &str,
    suffix: &str,
) -> SignedProductBaseline {
    assert_eq!(environment, "local");
    let lane = match product_directory {
        "relay-public" => ProductAcceptanceLaneV1::RelayPublic,
        "relay-consultation" => ProductAcceptanceLaneV1::RelayConsultation,
        "notary" => ProductAcceptanceLaneV1::Notary,
        _ => panic!("unexpected product signing-input directory"),
    };
    assert_eq!(
        product,
        match lane {
            ProductAcceptanceLaneV1::RelayPublic | ProductAcceptanceLaneV1::RelayConsultation =>
                "registry-relay",
            ProductAcceptanceLaneV1::Notary => "registry-notary",
        }
    );
    let private_key = temporary.join(format!("{suffix}-private.jwk"));
    let public_key = temporary.join(format!("{suffix}-public.jwk"));
    let anchor = temporary.join(format!("{suffix}-anchor.json"));
    let signed = temporary.join(format!("{suffix}-signed"));
    std::fs::write(&private_key, TEST_PRIVATE_JWK).expect("private test key writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mut permissions = std::fs::metadata(&private_key)
            .expect("private key metadata reads")
            .permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&private_key, permissions)
            .expect("private key becomes owner-only");
    }
    std::fs::write(&public_key, TEST_PUBLIC_JWK).expect("public test key writes");
    let input = output.join("signing-inputs").join(product_directory);
    create_trust_anchor(&TrustAnchorCreateOptions {
        lane,
        input: input.clone(),
        public_keys: vec![public_key],
        threshold: 1,
        output_file: anchor.clone(),
    })
    .expect("derived product trust anchor initializes");
    sign_product_bundle(&ProductBundleSignOptions {
        lane,
        input,
        anchor,
        preceding_approved_set: None,
        keys: vec![format!("file:{}", private_key.display())],
        output_dir: signed.clone(),
    })
    .expect("derived product baseline signs");
    SignedProductBaseline {
        bundle: signed.join("bundle"),
        anchor: signed.join("anchor.json"),
    }
}

#[allow(clippy::too_many_arguments)]
fn sign_product_baseline_with_identity(
    output: &Path,
    temporary: &Path,
    product: &str,
    product_directory: &str,
    environment: &str,
    stream: &str,
    instance: &str,
    suffix: &str,
) -> SignedProductBaseline {
    let private_key = temporary.join(format!("{suffix}-private.jwk"));
    let public_key = temporary.join(format!("{suffix}-public.jwk"));
    let anchor = temporary.join(format!("{suffix}-anchor.json"));
    let bundle = temporary.join(format!("{suffix}-bundle"));
    std::fs::write(&private_key, TEST_PRIVATE_JWK).expect("private test key writes");
    std::fs::write(&public_key, TEST_PUBLIC_JWK).expect("public test key writes");
    init_config_anchor(
        &anchor,
        product.to_string(),
        environment.to_string(),
        stream.to_string(),
        instance.to_string(),
    )
    .expect("product trust anchor initializes");
    add_config_anchor_key(&anchor, &public_key, true).expect("product signer is trusted");
    sign_config_bundle(BundleSignOptions {
        input: output.join("private").join(product_directory),
        key: private_key.display().to_string(),
        product: product.to_string(),
        environment: environment.to_string(),
        stream_id: stream.to_string(),
        instance_id: Some(instance.to_string()),
        sequence: 1,
        bundle_id: format!("{suffix}-bundle"),
        out: bundle.clone(),
    })
    .expect("product baseline signs");
    SignedProductBaseline { bundle, anchor }
}

fn sign_common_set(
    output: &Path,
    temporary: &Path,
    suffix: &str,
) -> ProjectBuildBaselineSetOptions {
    let relay = sign_product_baseline(
        output,
        temporary,
        "registry-relay",
        "relay-public",
        "local",
        &format!("{suffix}-relay"),
    );
    let relay_consultation = sign_product_baseline(
        output,
        temporary,
        "registry-relay",
        "relay-consultation",
        "local",
        &format!("{suffix}-relay-consultation"),
    );
    let notary = sign_product_baseline(
        output,
        temporary,
        "registry-notary",
        "notary",
        "local",
        &format!("{suffix}-notary"),
    );
    ProjectBuildBaselineSetOptions {
        relay_against: Some(relay.bundle),
        relay_anchor: Some(relay.anchor),
        relay_consultation_against: Some(relay_consultation.bundle),
        relay_consultation_anchor: Some(relay_consultation.anchor),
        notary_against: Some(notary.bundle),
        notary_anchor: Some(notary.anchor),
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    std::fs::create_dir_all(destination).expect("destination directory creates");
    for entry in std::fs::read_dir(source).expect("source directory reads") {
        let entry = entry.expect("directory entry reads");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry.file_type().expect("entry type reads").is_dir() {
            copy_tree(&source_path, &destination_path);
        } else {
            std::fs::copy(&source_path, &destination_path).expect("fixture file copies");
        }
    }
}

fn assert_value_free_rejection(
    project: &Path,
    baselines: &ProjectBuildBaselineSetOptions,
    temporary: &Path,
) {
    let error = build_registry_project_with_baselines_and_context(
        &build_options(project),
        baselines,
        &context(),
    )
    .expect_err("invalid approved baseline set must fail");
    let message = format!("{error:#}");
    assert!(message.contains("could not establish verified build baselines"));
    for forbidden in [
        "approved-baseline-project",
        "FICTIONAL_REGISTRY_TOKEN",
        temporary.to_str().expect("temporary path is UTF-8"),
    ] {
        assert!(
            !message.contains(forbidden),
            "baseline rejection exposed {forbidden:?}: {message}"
        );
    }
}

#[test]
fn initial_and_common_approved_baseline_builds_are_distinct_and_lineage_is_product_labelled() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let project = initialize_project(temporary.path());
    let output = initial_build(&project);
    let relay_initial =
        std::fs::read(output.join("private/relay-public/approval/project-state.json"))
            .expect("initial Relay approval state reads");
    let relay_consultation_initial =
        std::fs::read(output.join("private/relay-consultation/approval/project-state.json"))
            .expect("initial consultation Relay approval state reads");
    let notary_initial = std::fs::read(output.join("private/notary/approval/project-state.json"))
        .expect("initial Notary approval state reads");
    assert_eq!(relay_initial, relay_consultation_initial);
    assert_eq!(relay_initial, notary_initial);
    let initial_state: serde_json::Value =
        serde_json::from_slice(&relay_initial).expect("initial approval state parses");
    assert_eq!(
        initial_state["schema"],
        "registry.project.approval-state.v4"
    );
    assert!(initial_state["baseline"].is_null());

    let baselines = sign_common_set(&output, temporary.path(), "common");
    let relay_baseline = baselines
        .relay_against
        .as_deref()
        .expect("Relay baseline exists");
    let relay_consultation_baseline = baselines
        .relay_consultation_against
        .as_deref()
        .expect("consultation Relay baseline exists");
    let notary_baseline = baselines
        .notary_against
        .as_deref()
        .expect("Notary baseline exists");
    assert_eq!(
        std::fs::read(relay_baseline.join("approval/project-state.json"))
            .expect("signed Relay approval state reads"),
        std::fs::read(notary_baseline.join("approval/project-state.json"))
            .expect("signed Notary approval state reads")
    );
    assert_eq!(
        std::fs::read(relay_baseline.join("approval/project-state.json"))
            .expect("signed Relay approval state reads"),
        std::fs::read(relay_consultation_baseline.join("approval/project-state.json"))
            .expect("signed consultation Relay approval state reads")
    );
    assert_eq!(
        std::fs::read(relay_baseline.join("approval/review.json"))
            .expect("signed Relay review reads"),
        std::fs::read(notary_baseline.join("approval/review.json"))
            .expect("signed Notary review reads")
    );
    assert_eq!(
        std::fs::read(relay_baseline.join("approval/review.json"))
            .expect("signed Relay review reads"),
        std::fs::read(relay_consultation_baseline.join("approval/review.json"))
            .expect("signed consultation Relay review reads")
    );
    let report = build_registry_project_with_baselines_and_context(
        &build_options(&project),
        &baselines,
        &context(),
    )
    .expect("complete common approved baseline builds");
    assert_eq!(report.baseline, "verified_signed_bundle");

    let next_output = project.join(report.output.expect("reviewed build output is reported"));
    let relay_next =
        std::fs::read(next_output.join("private/relay-public/approval/project-state.json"))
            .expect("next Relay approval state reads");
    let relay_consultation_next =
        std::fs::read(next_output.join("private/relay-consultation/approval/project-state.json"))
            .expect("next consultation Relay approval state reads");
    let notary_next = std::fs::read(next_output.join("private/notary/approval/project-state.json"))
        .expect("next Notary approval state reads");
    assert_eq!(relay_next, relay_consultation_next);
    assert_eq!(relay_next, notary_next);
    let state: serde_json::Value =
        serde_json::from_slice(&relay_next).expect("next approval state parses");
    assert_eq!(
        state["baseline"]["verified_manifests"]["relay"]["acceptance_identity"]["product"],
        "registry-relay"
    );
    assert_eq!(
        state["baseline"]["verified_manifests"]["notary"]["acceptance_identity"]["product"],
        "registry-notary"
    );
    assert_eq!(
        state["baseline"]["verified_manifests"]["relay_consultation"]["acceptance_identity"]
            ["product"],
        "registry-relay"
    );
    let bundle_ids = [
        state["baseline"]["verified_manifests"]["relay"]["bundle_id"]
            .as_str()
            .expect("Relay closure digest"),
        state["baseline"]["verified_manifests"]["relay_consultation"]["bundle_id"]
            .as_str()
            .expect("consultation Relay closure digest"),
        state["baseline"]["verified_manifests"]["notary"]["bundle_id"]
            .as_str()
            .expect("Notary closure digest"),
    ];
    assert!(bundle_ids
        .iter()
        .all(|bundle_id| bundle_id.starts_with("sha256:")));
    assert_eq!(
        bundle_ids
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3,
        "each product lane binds its distinct complete signing-input closure"
    );
}

#[test]
fn partial_swapped_tampered_and_wrong_environment_sets_fail_before_publication() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let project = initialize_project(temporary.path());
    let output = initial_build(&project);
    let original_state =
        std::fs::read(output.join("private/relay-public/approval/project-state.json"))
            .expect("initial approval state reads");
    let baselines = sign_common_set(&output, temporary.path(), "rejection");

    let partial = ProjectBuildBaselineSetOptions {
        relay_against: baselines.relay_against.clone(),
        relay_anchor: baselines.relay_anchor.clone(),
        ..ProjectBuildBaselineSetOptions::default()
    };
    assert_value_free_rejection(&project, &partial, temporary.path());
    assert_eq!(
        std::fs::read(output.join("private/relay-public/approval/project-state.json"))
            .expect("published approval state rereads"),
        original_state
    );

    let swapped = ProjectBuildBaselineSetOptions {
        relay_against: baselines.notary_against.clone(),
        relay_anchor: baselines.notary_anchor.clone(),
        relay_consultation_against: baselines.relay_consultation_against.clone(),
        relay_consultation_anchor: baselines.relay_consultation_anchor.clone(),
        notary_against: baselines.relay_against.clone(),
        notary_anchor: baselines.relay_anchor.clone(),
    };
    assert_value_free_rejection(&project, &swapped, temporary.path());

    let wrong_relay_closure = ProjectBuildBaselineSetOptions {
        relay_consultation_against: baselines.relay_against.clone(),
        relay_consultation_anchor: baselines.relay_anchor.clone(),
        ..baselines.clone()
    };
    assert_value_free_rejection(&project, &wrong_relay_closure, temporary.path());

    let tampered_bundle = temporary.path().join("tampered-relay-bundle");
    copy_tree(
        baselines
            .relay_against
            .as_deref()
            .expect("Relay baseline exists"),
        &tampered_bundle,
    );
    let tampered_state = tampered_bundle.join("approval/project-state.json");
    let mut bytes = std::fs::read(&tampered_state).expect("signed state reads");
    bytes.push(b' ');
    std::fs::write(&tampered_state, bytes).expect("signed state tampers");
    let tampered = ProjectBuildBaselineSetOptions {
        relay_against: Some(tampered_bundle),
        ..baselines.clone()
    };
    assert_value_free_rejection(&project, &tampered, temporary.path());

    let wrong_project_and_stream = sign_product_baseline_with_identity(
        &output,
        temporary.path(),
        "registry-relay",
        "relay-public",
        "local",
        "other-project",
        "fictional-registry-relay",
        "wrong-project-stream-relay",
    );
    let wrong_project_and_stream = ProjectBuildBaselineSetOptions {
        relay_against: Some(wrong_project_and_stream.bundle),
        relay_anchor: Some(wrong_project_and_stream.anchor),
        ..baselines.clone()
    };
    assert_value_free_rejection(&project, &wrong_project_and_stream, temporary.path());

    let wrong_instance = sign_product_baseline_with_identity(
        &output,
        temporary.path(),
        "registry-relay",
        "relay-public",
        "local",
        "fictional-citizen-registry",
        "other-relay-instance",
        "wrong-instance-relay",
    );
    let wrong_instance = ProjectBuildBaselineSetOptions {
        relay_against: Some(wrong_instance.bundle),
        relay_anchor: Some(wrong_instance.anchor),
        ..baselines.clone()
    };
    assert_value_free_rejection(&project, &wrong_instance, temporary.path());

    let wrong_environment = sign_product_baseline_with_identity(
        &output,
        temporary.path(),
        "registry-relay",
        "relay-public",
        "other",
        "fictional-citizen-registry",
        "fictional-registry-relay",
        "wrong-environment-relay",
    );
    let wrong_environment = ProjectBuildBaselineSetOptions {
        relay_against: Some(wrong_environment.bundle),
        relay_anchor: Some(wrong_environment.anchor),
        relay_consultation_against: baselines.relay_consultation_against,
        relay_consultation_anchor: baselines.relay_consultation_anchor,
        notary_against: baselines.notary_against,
        notary_anchor: baselines.notary_anchor,
    };
    assert_value_free_rejection(&project, &wrong_environment, temporary.path());
}

#[test]
fn independently_valid_but_divergent_product_approval_states_are_rejected() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let project = initialize_project(temporary.path());
    let first_output = initial_build(&project);
    let relay = sign_product_baseline(
        &first_output,
        temporary.path(),
        "registry-relay",
        "relay-public",
        "local",
        "divergent-relay",
    );
    let relay_consultation = sign_product_baseline(
        &first_output,
        temporary.path(),
        "registry-relay",
        "relay-consultation",
        "local",
        "divergent-relay-consultation",
    );

    let environment_path = project.join("environments/local.yaml");
    let original_environment =
        std::fs::read_to_string(&environment_path).expect("environment reads");
    let changed_environment = original_environment.replace(
        "https://citizen-registry.invalid",
        "https://reviewed-registry.invalid",
    );
    assert_ne!(changed_environment, original_environment);
    std::fs::write(&environment_path, changed_environment).expect("environment changes");
    let second_output = initial_build(&project);
    let notary = sign_product_baseline(
        &second_output,
        temporary.path(),
        "registry-notary",
        "notary",
        "local",
        "divergent-notary",
    );
    std::fs::write(&environment_path, original_environment).expect("environment restores");

    let divergent = ProjectBuildBaselineSetOptions {
        relay_against: Some(relay.bundle),
        relay_anchor: Some(relay.anchor),
        relay_consultation_against: Some(relay_consultation.bundle),
        relay_consultation_anchor: Some(relay_consultation.anchor),
        notary_against: Some(notary.bundle),
        notary_anchor: Some(notary.anchor),
    };
    assert_value_free_rejection(&project, &divergent, temporary.path());
}

#[test]
fn legacy_v3_relay_baseline_requires_split_lane_re_review() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let project = initialize_project(temporary.path());
    let output = initial_build(&project);
    let legacy_output = temporary.path().join("legacy-v3-output");
    copy_tree(&output, &legacy_output);

    let state_path = legacy_output.join("private/relay-public/approval/project-state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).expect("current approval state reads"))
            .expect("current approval state parses");
    state["schema"] = serde_json::json!("registry.project.approval-state.v3");
    state["generated_closure_digests"]
        .as_object_mut()
        .expect("closure set is an object")
        .remove("relay_consultation");
    let mut state_bytes = serde_json::to_vec_pretty(&state).expect("legacy state serializes");
    state_bytes.push(b'\n');
    for product_directory in ["relay-public", "notary"] {
        for input_kind in ["private", "signing-inputs"] {
            std::fs::write(
                legacy_output
                    .join(input_kind)
                    .join(product_directory)
                    .join("approval/project-state.json"),
                &state_bytes,
            )
            .expect("legacy approval state writes");
        }
    }

    let relay = sign_product_baseline(
        &legacy_output,
        temporary.path(),
        "registry-relay",
        "relay-public",
        "local",
        "legacy-v3-relay",
    );
    let notary = sign_product_baseline(
        &legacy_output,
        temporary.path(),
        "registry-notary",
        "notary",
        "local",
        "legacy-v3-notary",
    );
    let legacy = ProjectBuildBaselineSetOptions {
        relay_against: Some(relay.bundle),
        relay_anchor: Some(relay.anchor),
        relay_consultation_against: None,
        relay_consultation_anchor: None,
        notary_against: Some(notary.bundle),
        notary_anchor: Some(notary.anchor),
    };

    let error = build_registry_project_with_baselines_and_context(
        &build_options(&project),
        &legacy,
        &context(),
    )
    .expect_err("v3 combined Relay baseline cannot prove split consultation lineage");
    let message = format!("{error:#}");
    assert!(message.contains("legacy v1-v3 approved Relay baselines"));
    assert!(message.contains("re-review"));
    assert!(message.contains("separate Relay public and consultation baselines"));
    for forbidden in [
        "approved-baseline-project",
        "FICTIONAL_REGISTRY_TOKEN",
        temporary.path().to_str().expect("temporary path is UTF-8"),
    ] {
        assert!(!message.contains(forbidden));
    }
}
