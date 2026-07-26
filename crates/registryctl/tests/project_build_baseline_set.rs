// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};

use registryctl::{
    add_config_anchor_key, build_registry_project_with_baselines_and_context,
    build_registry_project_with_context, init_config_anchor, init_registry_project,
    sign_config_bundle, BundleSignOptions, ProjectBuildBaselineSetOptions, ProjectBuildOptions,
    ProjectExecutionContext, ProjectInitOptions, ProjectStarter,
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
        format!("{suffix}-stream"),
        format!("{suffix}-instance"),
    )
    .expect("product trust anchor initializes");
    add_config_anchor_key(&anchor, &public_key, true).expect("product signer is trusted");
    sign_config_bundle(BundleSignOptions {
        input: output.join("private").join(product_directory),
        key: private_key.display().to_string(),
        product: product.to_string(),
        environment: environment.to_string(),
        stream_id: format!("{suffix}-stream"),
        instance_id: Some(format!("{suffix}-instance")),
        sequence: 1,
        bundle_id: format!("{suffix}-bundle"),
        out: bundle.clone(),
    })
    .expect("product baseline signs");
    SignedProductBaseline { bundle, anchor }
}

fn sign_common_pair(
    output: &Path,
    temporary: &Path,
    suffix: &str,
) -> ProjectBuildBaselineSetOptions {
    let relay = sign_product_baseline(
        output,
        temporary,
        "registry-relay",
        "relay",
        "local",
        &format!("{suffix}-relay"),
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
    let relay_initial = std::fs::read(output.join("private/relay/approval/project-state.json"))
        .expect("initial Relay approval state reads");
    let notary_initial = std::fs::read(output.join("private/notary/approval/project-state.json"))
        .expect("initial Notary approval state reads");
    assert_eq!(relay_initial, notary_initial);
    let initial_state: serde_json::Value =
        serde_json::from_slice(&relay_initial).expect("initial approval state parses");
    assert_eq!(
        initial_state["schema"],
        "registry.project.approval-state.v3"
    );
    assert!(initial_state["baseline"].is_null());

    let baselines = sign_common_pair(&output, temporary.path(), "common");
    let relay_baseline = baselines
        .relay_against
        .as_deref()
        .expect("Relay baseline exists");
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
        std::fs::read(relay_baseline.join("approval/review.json"))
            .expect("signed Relay review reads"),
        std::fs::read(notary_baseline.join("approval/review.json"))
            .expect("signed Notary review reads")
    );
    let report = build_registry_project_with_baselines_and_context(
        &build_options(&project),
        &baselines,
        &context(),
    )
    .expect("complete common approved baseline builds");
    assert_eq!(report.baseline, "verified_signed_bundle");

    let next_output = project.join(report.output.expect("reviewed build output is reported"));
    let relay_next = std::fs::read(next_output.join("private/relay/approval/project-state.json"))
        .expect("next Relay approval state reads");
    let notary_next = std::fs::read(next_output.join("private/notary/approval/project-state.json"))
        .expect("next Notary approval state reads");
    assert_eq!(relay_next, notary_next);
    let state: serde_json::Value =
        serde_json::from_slice(&relay_next).expect("next approval state parses");
    assert_eq!(
        state["baseline"]["verified_manifests"]["relay"]["product"],
        "registry-relay"
    );
    assert_eq!(
        state["baseline"]["verified_manifests"]["notary"]["product"],
        "registry-notary"
    );
    assert_eq!(
        state["baseline"]["verified_manifests"]["relay"]["bundle_id"],
        "common-relay-bundle"
    );
    assert_eq!(
        state["baseline"]["verified_manifests"]["notary"]["bundle_id"],
        "common-notary-bundle"
    );
}

#[test]
fn partial_swapped_tampered_and_wrong_environment_sets_fail_before_publication() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let project = initialize_project(temporary.path());
    let output = initial_build(&project);
    let original_state = std::fs::read(output.join("private/relay/approval/project-state.json"))
        .expect("initial approval state reads");
    let baselines = sign_common_pair(&output, temporary.path(), "rejection");

    let partial = ProjectBuildBaselineSetOptions {
        relay_against: baselines.relay_against.clone(),
        relay_anchor: baselines.relay_anchor.clone(),
        ..ProjectBuildBaselineSetOptions::default()
    };
    assert_value_free_rejection(&project, &partial, temporary.path());
    assert_eq!(
        std::fs::read(output.join("private/relay/approval/project-state.json"))
            .expect("published approval state rereads"),
        original_state
    );

    let swapped = ProjectBuildBaselineSetOptions {
        relay_against: baselines.notary_against.clone(),
        relay_anchor: baselines.notary_anchor.clone(),
        notary_against: baselines.relay_against.clone(),
        notary_anchor: baselines.relay_anchor.clone(),
    };
    assert_value_free_rejection(&project, &swapped, temporary.path());

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

    let wrong_environment = sign_product_baseline(
        &output,
        temporary.path(),
        "registry-relay",
        "relay",
        "other",
        "wrong-environment-relay",
    );
    let wrong_environment = ProjectBuildBaselineSetOptions {
        relay_against: Some(wrong_environment.bundle),
        relay_anchor: Some(wrong_environment.anchor),
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
        "relay",
        "local",
        "divergent-relay",
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
        notary_against: Some(notary.bundle),
        notary_anchor: Some(notary.anchor),
    };
    assert_value_free_rejection(&project, &divergent, temporary.path());
}
