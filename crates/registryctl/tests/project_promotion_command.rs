// SPDX-License-Identifier: Apache-2.0

use std::path::{Path, PathBuf};
use std::process::Command;

use registryctl::{
    add_config_anchor_key, build_registry_project_with_context, init_config_anchor,
    init_registry_project, promote_registry_project, sign_config_bundle, BundleSignOptions,
    ProjectBuildOptions, ProjectExecutionContext, ProjectInitOptions, ProjectPromotionOptions,
    ProjectPromotionReportV1, ProjectStarter, PromotionBlockingReason, PromotionChangeEffect,
    PromotionChangeKind, PromotionCompatibilityComponent, PromotionCompatibilityState,
    PromotionDisposition, PromotionProductAction, ReviewedCeilingAssessment,
    ReviewedRevisionComparison, TrustResolutionAssessment,
};

const TEST_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registryctl-test-private-key"}"#;
const TEST_PUBLIC_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registryctl-test-private-key"}"#;
const PROMOTION_SCHEMA: &str =
    include_str!("../schemas/project-reports/registry.project.promotion.v1.schema.json");

#[derive(Clone)]
struct SignedProductBaseline {
    bundle: PathBuf,
    anchor: PathBuf,
}

struct SignedBaselines {
    relay: SignedProductBaseline,
    relay_consultation: SignedProductBaseline,
    notary: SignedProductBaseline,
}

fn write(path: &Path, contents: &str) {
    std::fs::write(path, contents).expect("test file writes");
}

fn build_project_output(project: &Path) -> PathBuf {
    let context = ProjectExecutionContext::new(env!("CARGO_BIN_EXE_registryctl"))
        .expect("Cargo provides the exact registryctl executable");
    let build = build_registry_project_with_context(
        &ProjectBuildOptions {
            project_directory: project.to_path_buf(),
            environment: "local".to_owned(),
            against: None,
            anchor: None,
        },
        &context,
    )
    .expect("baseline project builds");
    let reported = build.output.expect("build output is reported");
    let relative = Path::new(&reported);
    assert!(!relative.is_absolute());
    project.join(relative)
}

fn sign_product_baseline(
    output: &Path,
    temporary: &Path,
    product: &str,
    product_directory: &str,
    suffix: &str,
) -> SignedProductBaseline {
    let private_key = temporary.join(format!("promotion-{suffix}-private.jwk"));
    let public_key = temporary.join(format!("promotion-{suffix}-public.jwk"));
    let anchor = temporary.join(format!("promotion-{suffix}-anchor.json"));
    let bundle = temporary.join(format!("promotion-{suffix}-baseline"));
    write(&private_key, TEST_PRIVATE_JWK);
    write(&public_key, TEST_PUBLIC_JWK);
    init_config_anchor(
        &anchor,
        product.to_owned(),
        "local".to_owned(),
        format!("promotion-{suffix}"),
        format!("promotion-{suffix}-instance"),
    )
    .expect("anchor initializes");
    add_config_anchor_key(&anchor, &public_key, true).expect("anchor key adds");
    sign_config_bundle(BundleSignOptions {
        input: output.join("private").join(product_directory),
        key: private_key.display().to_string(),
        product: product.to_owned(),
        environment: "local".to_owned(),
        stream_id: format!("promotion-{suffix}"),
        instance_id: Some(format!("promotion-{suffix}-instance")),
        sequence: 1,
        bundle_id: format!("promotion-{suffix}-baseline"),
        out: bundle.clone(),
    })
    .expect("baseline bundle signs");
    SignedProductBaseline { bundle, anchor }
}

fn signed_baselines(project: &Path, temporary: &Path) -> SignedBaselines {
    let output = build_project_output(project);
    SignedBaselines {
        relay: sign_product_baseline(&output, temporary, "registry-relay", "relay", "relay"),
        relay_consultation: sign_product_baseline(
            &output,
            temporary,
            "registry-relay",
            "relay-consultation",
            "relay-consultation",
        ),
        notary: sign_product_baseline(&output, temporary, "registry-notary", "notary", "notary"),
    }
}

fn promotion_options(project: &Path, baselines: &SignedBaselines) -> ProjectPromotionOptions {
    ProjectPromotionOptions {
        project_directory: project.to_path_buf(),
        environment: "local".to_owned(),
        against: None,
        anchor: None,
        relay_against: Some(baselines.relay.bundle.clone()),
        relay_anchor: Some(baselines.relay.anchor.clone()),
        relay_consultation_against: Some(baselines.relay_consultation.bundle.clone()),
        relay_consultation_anchor: Some(baselines.relay_consultation.anchor.clone()),
        notary_against: Some(baselines.notary.bundle.clone()),
        notary_anchor: Some(baselines.notary.anchor.clone()),
    }
}

fn legacy_promotion_options(
    project: &Path,
    baseline: &SignedProductBaseline,
) -> ProjectPromotionOptions {
    ProjectPromotionOptions {
        project_directory: project.to_path_buf(),
        environment: "local".to_owned(),
        against: Some(baseline.bundle.clone()),
        anchor: Some(baseline.anchor.clone()),
        relay_against: None,
        relay_anchor: None,
        relay_consultation_against: None,
        relay_consultation_anchor: None,
        notary_against: None,
        notary_anchor: None,
    }
}

fn run_promote(project: &Path, baselines: &SignedBaselines, format: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args([
            "promote",
            "--project-dir",
            project.to_str().expect("project path is UTF-8"),
            "--environment",
            "local",
            "--relay-against",
            baselines
                .relay
                .bundle
                .to_str()
                .expect("Relay bundle path is UTF-8"),
            "--relay-anchor",
            baselines
                .relay
                .anchor
                .to_str()
                .expect("Relay anchor path is UTF-8"),
            "--relay-consultation-against",
            baselines
                .relay_consultation
                .bundle
                .to_str()
                .expect("consultation Relay bundle path is UTF-8"),
            "--relay-consultation-anchor",
            baselines
                .relay_consultation
                .anchor
                .to_str()
                .expect("consultation Relay anchor path is UTF-8"),
            "--notary-against",
            baselines
                .notary
                .bundle
                .to_str()
                .expect("Notary bundle path is UTF-8"),
            "--notary-anchor",
            baselines
                .notary
                .anchor
                .to_str()
                .expect("Notary anchor path is UTF-8"),
            "--format",
            format,
        ])
        .env("REGISTRYCTL_NO_UPDATE_CHECK", "1")
        .output()
        .expect("registryctl promote runs")
}

fn run_promote_legacy(
    project: &Path,
    baseline: &SignedProductBaseline,
    format: &str,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args([
            "promote",
            "--project-dir",
            project.to_str().expect("project path is UTF-8"),
            "--environment",
            "local",
            "--against",
            baseline.bundle.to_str().expect("bundle path is UTF-8"),
            "--anchor",
            baseline.anchor.to_str().expect("anchor path is UTF-8"),
            "--format",
            format,
        ])
        .env("REGISTRYCTL_NO_UPDATE_CHECK", "1")
        .output()
        .expect("registryctl promote runs")
}

fn run_check_legacy(project: &Path, baseline: &SignedProductBaseline) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args([
            "check",
            "--project-dir",
            project.to_str().expect("project path is UTF-8"),
            "--environment",
            "local",
            "--against",
            baseline.bundle.to_str().expect("bundle path is UTF-8"),
            "--anchor",
            baseline.anchor.to_str().expect("anchor path is UTF-8"),
            "--format",
            "json",
        ])
        .env("REGISTRYCTL_NO_UPDATE_CHECK", "1")
        .output()
        .expect("registryctl check runs")
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

fn assert_conservative_blocked_report(report: &ProjectPromotionReportV1, forbidden: &[&str]) {
    assert_eq!(report.disposition, PromotionDisposition::Blocked);
    assert_eq!(
        report.reviewed_revision,
        ReviewedRevisionComparison::NotProven
    );
    assert!(report.changes.is_empty());
    assert_eq!(
        report.reviewed_ceiling,
        ReviewedCeilingAssessment::UnresolvedBlocked
    );
    assert_eq!(report.trust, TrustResolutionAssessment::UnresolvedBlocked);
    assert_eq!(
        report
            .compatibility
            .iter()
            .map(|assessment| (assessment.component, assessment.state))
            .collect::<Vec<_>>(),
        vec![
            (
                PromotionCompatibilityComponent::Product,
                PromotionCompatibilityState::Unresolved,
            ),
            (
                PromotionCompatibilityComponent::Capability,
                PromotionCompatibilityState::Unresolved,
            ),
            (
                PromotionCompatibilityComponent::Schema,
                PromotionCompatibilityState::Unresolved,
            ),
            (
                PromotionCompatibilityComponent::Abi,
                PromotionCompatibilityState::Unresolved,
            ),
        ]
    );
    for reason in [
        PromotionBlockingReason::ReviewedRevisionNotProven,
        PromotionBlockingReason::ComparisonEvidenceIncomplete,
        PromotionBlockingReason::ReviewedCeilingUnresolved,
        PromotionBlockingReason::TrustUnresolved,
        PromotionBlockingReason::CompatibilityUnresolved,
    ] {
        assert!(
            report.blocking_reasons.contains(&reason),
            "blocked report lacks {reason:?}"
        );
    }
    assert!(report.required_actions.review_classes.is_empty());
    assert_eq!(
        report.required_actions.re_sign,
        PromotionProductAction::None
    );
    assert_eq!(
        report.required_actions.reactivate,
        PromotionProductAction::None
    );
    assert_eq!(
        report.required_actions.restart,
        PromotionProductAction::None
    );

    let document = serde_json::to_value(report).expect("blocked report serializes");
    let schema: serde_json::Value =
        serde_json::from_str(PROMOTION_SCHEMA).expect("promotion schema parses");
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("promotion schema compiles");
    if let Err(errors) = validator.validate(&document) {
        let details = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("blocked report must validate against the promotion schema: {details:?}");
    }
    let serialized = serde_json::to_string(&document).expect("blocked report JSON serializes");
    let reparsed: ProjectPromotionReportV1 =
        serde_json::from_str(&serialized).expect("blocked report decision evidence validates");
    assert_eq!(&reparsed, report);
    for sentinel in forbidden {
        assert!(
            !serialized.contains(sentinel),
            "blocked report must not contain {sentinel:?}"
        );
    }
}

fn assert_conservative_blocked_cli(output: &std::process::Output, forbidden: &[&str]) {
    assert_eq!(
        output.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: ProjectPromotionReportV1 =
        serde_json::from_slice(&output.stdout).expect("blocked CLI JSON parses");
    assert_conservative_blocked_report(&report, forbidden);

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for sentinel in forbidden {
        assert!(
            !stdout.contains(sentinel) && !stderr.contains(sentinel),
            "blocked CLI output must not contain {sentinel:?}"
        );
    }
}

#[test]
fn promotion_requires_a_verified_reviewed_baseline_without_exposing_project_values() {
    const SECRET_REFERENCE_SENTINEL: &str = "COUNTRY_SECRET_SENTINEL";

    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let project = temporary.path().join("country-promotion-project");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: project.clone(),
    })
    .expect("starter initializes");
    let environment_path = project.join("environments/local.yaml");
    let environment = std::fs::read_to_string(&environment_path).expect("environment reads");
    assert!(environment.contains("FICTIONAL_REGISTRY_TOKEN"));
    let environment = environment.replace("FICTIONAL_REGISTRY_TOKEN", SECRET_REFERENCE_SENTINEL);
    assert!(environment.contains(SECRET_REFERENCE_SENTINEL));
    write(&environment_path, &environment);

    let report = promote_registry_project(&ProjectPromotionOptions {
        project_directory: project,
        environment: "local".to_owned(),
        against: None,
        anchor: None,
        relay_against: None,
        relay_anchor: None,
        relay_consultation_against: None,
        relay_consultation_anchor: None,
        notary_against: None,
        notary_anchor: None,
    })
    .expect("offline promotion report builds");

    assert_eq!(report.disposition, PromotionDisposition::Blocked);
    assert!(report
        .blocking_reasons
        .contains(&PromotionBlockingReason::ReviewedRevisionNotProven));
    assert!(report
        .blocking_reasons
        .contains(&PromotionBlockingReason::TrustUnresolved));

    let serialized = serde_json::to_string(&report).expect("promotion report serializes");
    for sentinel in [
        "country-promotion-project",
        SECRET_REFERENCE_SENTINEL,
        temporary.path().to_str().expect("temporary path is UTF-8"),
    ] {
        assert!(
            !serialized.contains(sentinel),
            "promotion report must not contain {sentinel:?}"
        );
    }
}

#[test]
fn verified_baseline_supports_safe_actions_and_cli_exit_and_format_contracts() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let project = temporary.path().join("promotion-project");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: project.clone(),
    })
    .expect("starter initializes");
    let baselines = signed_baselines(&project, temporary.path());

    let unchanged = run_promote(&project, &baselines, "json");
    assert_eq!(
        unchanged.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&unchanged.stderr)
    );
    let unchanged_json: serde_json::Value =
        serde_json::from_slice(&unchanged.stdout).expect("unchanged JSON output parses");
    assert_eq!(unchanged_json["disposition"], "ready");

    let project_path = project.join("registry-stack.yaml");
    let baseline_project = std::fs::read_to_string(&project_path).expect("project reads");
    let changed_purpose = baseline_project.replace(
        "purpose: public-service-person-verification",
        "purpose: reviewed-public-service-person-verification",
    );
    write(&project_path, &changed_purpose);
    let purpose = promote_registry_project(&promotion_options(&project, &baselines))
        .expect("purpose change compares");
    assert_eq!(
        purpose.disposition,
        PromotionDisposition::ReadyAfterRequiredActions
    );
    assert_eq!(purpose.changes.len(), 1);
    assert_eq!(purpose.changes[0].kind, PromotionChangeKind::Purpose);
    assert_eq!(
        purpose.required_actions.re_sign,
        PromotionProductAction::Notary
    );
    assert_eq!(
        purpose.required_actions.reactivate,
        PromotionProductAction::Notary
    );
    assert_eq!(
        purpose.required_actions.restart,
        PromotionProductAction::Notary
    );
    write(&project_path, &baseline_project);

    let environment_path = project.join("environments/local.yaml");
    let environment = std::fs::read_to_string(&environment_path)
        .expect("environment reads")
        .replace(
            "https://citizen-registry.invalid",
            "https://reviewed-registry.invalid",
        );
    write(&environment_path, &environment);
    let changed = promote_registry_project(&promotion_options(&project, &baselines))
        .expect("safe origin change compares");
    assert_eq!(
        changed.disposition,
        PromotionDisposition::ReadyAfterRequiredActions
    );
    assert_eq!(changed.changes.len(), 1);
    assert_eq!(changed.changes[0].kind, PromotionChangeKind::Origin);
    assert_eq!(
        changed.changes[0].effect,
        PromotionChangeEffect::ChangedWithinReviewedAuthority
    );
    assert_eq!(
        changed.required_actions.re_sign,
        PromotionProductAction::Relay
    );
    assert_eq!(
        changed.required_actions.reactivate,
        PromotionProductAction::Relay
    );
    assert_eq!(
        changed.required_actions.restart,
        PromotionProductAction::Relay
    );

    let changed_json = run_promote(&project, &baselines, "json");
    assert_eq!(changed_json.status.code(), Some(0));
    let changed_json: serde_json::Value =
        serde_json::from_slice(&changed_json.stdout).expect("changed JSON output parses");
    assert_eq!(changed_json["disposition"], "ready_after_required_actions");
    assert_eq!(changed_json["required_actions"]["re_sign"], "relay");
    assert_eq!(changed_json["required_actions"]["restart"], "relay");
    assert_eq!(changed_json["required_actions"]["reactivate"], "relay");

    let changed_human = run_promote(&project, &baselines, "human");
    assert_eq!(
        changed_human.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&changed_human.stderr)
    );
    let human = String::from_utf8(changed_human.stdout).expect("human output is UTF-8");
    assert!(human.contains("Promotion: ReadyAfterRequiredActions"));
    assert!(human.contains("Origin: ChangedWithinReviewedAuthority"));
    assert!(human.contains("Re-sign: Relay"));
    assert!(human.contains("restart: Relay"));
    assert!(human.contains("reactivate: Relay"));

    let authored = std::fs::read_to_string(&project_path)
        .expect("project reads")
        .replace(
            "scopes: [\"evidence:person:read\"]",
            "scopes: [\"evidence:person:read\", \"evidence:person:admin\"]",
        );
    write(&project_path, &authored);
    let environment = std::fs::read_to_string(&environment_path)
        .expect("environment rereads")
        .replace(
            "scopes: [\"evidence:person:read\"]",
            "scopes: [\"evidence:person:read\", \"evidence:person:admin\"]",
        );
    write(&environment_path, &environment);

    let blocked = run_promote(&project, &baselines, "json");
    assert_eq!(blocked.status.code(), Some(1));
    let blocked_json: serde_json::Value =
        serde_json::from_slice(&blocked.stdout).expect("blocked JSON output parses");
    assert_eq!(blocked_json["disposition"], "blocked");
    assert!(blocked_json["blocking_reasons"]
        .as_array()
        .expect("blocking reasons are an array")
        .iter()
        .any(|reason| reason == "policy_widening"));

    let blocked_human = run_promote(&project, &baselines, "human");
    assert_eq!(blocked_human.status.code(), Some(1));
    let blocked_human =
        String::from_utf8(blocked_human.stdout).expect("blocked human output is UTF-8");
    assert!(blocked_human.contains("Promotion: Blocked"));
    assert!(blocked_human.contains("PolicyWidening"));
    assert!(blocked_human.contains("Widened"));
}

#[test]
fn combined_topology_requires_separate_product_owned_baselines() {
    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let project = temporary.path().join("combined-promotion-project");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: project.clone(),
    })
    .expect("starter initializes");
    let baselines = signed_baselines(&project, temporary.path());
    let temporary_path = temporary.path().to_str().expect("temporary path is UTF-8");
    let forbidden = [
        "combined-promotion-project",
        "fictional-citizen-registry",
        "FICTIONAL_REGISTRY_TOKEN",
        "https://citizen-registry.invalid",
        "public-service-person-verification",
        "promotion-notary-baseline",
        temporary_path,
    ];

    let missing_relay = run_promote_legacy(&project, &baselines.notary, "json");
    assert_conservative_blocked_cli(&missing_relay, &forbidden);

    let missing_consultation = promote_registry_project(&ProjectPromotionOptions {
        project_directory: project.clone(),
        environment: "local".to_owned(),
        against: None,
        anchor: None,
        relay_against: Some(baselines.relay.bundle.clone()),
        relay_anchor: Some(baselines.relay.anchor.clone()),
        relay_consultation_against: None,
        relay_consultation_anchor: None,
        notary_against: Some(baselines.notary.bundle.clone()),
        notary_anchor: Some(baselines.notary.anchor.clone()),
    })
    .expect("missing consultation baseline fails closed as a report");
    assert_conservative_blocked_report(&missing_consultation, &forbidden);

    let wrong_owner = promote_registry_project(&ProjectPromotionOptions {
        project_directory: project.clone(),
        environment: "local".to_owned(),
        against: None,
        anchor: None,
        relay_against: Some(baselines.notary.bundle.clone()),
        relay_anchor: Some(baselines.notary.anchor.clone()),
        relay_consultation_against: Some(baselines.relay_consultation.bundle.clone()),
        relay_consultation_anchor: Some(baselines.relay_consultation.anchor.clone()),
        notary_against: Some(baselines.relay.bundle.clone()),
        notary_anchor: Some(baselines.relay.anchor.clone()),
    })
    .expect("wrong-product baselines fail closed as a report");
    assert_conservative_blocked_report(&wrong_owner, &forbidden);
}

#[test]
fn invalid_signed_baselines_fail_closed_with_valid_value_free_reports() {
    const TAMPERED_BASELINE_SENTINEL: &str = "TAMPERED_BASELINE_VALUE_SENTINEL";
    const MALFORMED_PROJECTION_SENTINEL: &str =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    let temporary = tempfile::tempdir().expect("temporary directory creates");
    let project = temporary.path().join("tamper-promotion-project");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: project.clone(),
    })
    .expect("starter initializes");
    let output = build_project_output(&project);
    let baseline = sign_product_baseline(
        &output,
        temporary.path(),
        "registry-notary",
        "notary",
        "notary-valid",
    );

    let tampered_bundle = temporary.path().join("tampered-notary-bundle");
    copy_tree(&baseline.bundle, &tampered_bundle);
    let tampered_state = tampered_bundle.join("approval/project-state.json");
    let mut bytes = std::fs::read(&tampered_state).expect("signed approval state reads");
    bytes.extend_from_slice(TAMPERED_BASELINE_SENTINEL.as_bytes());
    std::fs::write(&tampered_state, bytes).expect("signed approval state tampers");
    let temporary_path = temporary.path().to_str().expect("temporary path is UTF-8");
    let forbidden = [
        "tamper-promotion-project",
        "fictional-citizen-registry",
        "FICTIONAL_REGISTRY_TOKEN",
        "https://citizen-registry.invalid",
        "public-service-person-verification",
        "tampered-notary-bundle",
        "notary-legacy-v1",
        TAMPERED_BASELINE_SENTINEL,
        temporary_path,
    ];
    let tampered_baseline = SignedProductBaseline {
        bundle: tampered_bundle,
        anchor: baseline.anchor.clone(),
    };
    let tampered = run_promote_legacy(&project, &tampered_baseline, "json");
    assert_conservative_blocked_cli(&tampered, &forbidden);
    let tampered_direct =
        promote_registry_project(&legacy_promotion_options(&project, &tampered_baseline))
            .expect("tampered baseline fails closed as a report");
    assert_conservative_blocked_report(&tampered_direct, &forbidden);

    let project_path = project.join("registry-stack.yaml");
    let valid_project = std::fs::read_to_string(&project_path).expect("current project reads");
    let invalid_project =
        valid_project.replace("version: 1", "version: CURRENT_STATE_VALUE_SENTINEL");
    write(&project_path, &invalid_project);
    promote_registry_project(&legacy_promotion_options(&project, &tampered_baseline))
        .expect_err("invalid current state remains an ordinary error");
    let invalid_current = run_promote_legacy(&project, &tampered_baseline, "json");
    assert_eq!(invalid_current.status.code(), Some(1));
    assert!(invalid_current.stdout.is_empty());
    assert!(!invalid_current.stderr.is_empty());
    write(&project_path, &valid_project);

    let approval_path = output.join("private/notary/approval/project-state.json");
    let mut approval: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&approval_path).expect("unsigned approval state reads"),
    )
    .expect("unsigned approval state parses");

    let mut legacy_v2 = approval.clone();
    legacy_v2["schema"] = serde_json::json!("registry.project.approval-state.v2");
    legacy_v2["generated_closure_digests"]
        .as_object_mut()
        .expect("v2 closure set is an object")
        .remove("relay_consultation");
    let mut legacy_v2_bytes =
        serde_json::to_vec_pretty(&legacy_v2).expect("v2 approval state serializes");
    legacy_v2_bytes.push(b'\n');
    std::fs::write(&approval_path, legacy_v2_bytes).expect("v2 approval state writes");
    let legacy_v2_baseline = sign_product_baseline(
        &output,
        temporary.path(),
        "registry-notary",
        "notary",
        "notary-legacy-v2",
    );
    let legacy_v2 = run_check_legacy(&project, &legacy_v2_baseline);
    assert_eq!(
        legacy_v2.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&legacy_v2.stderr)
    );

    let mut legacy = approval.clone();
    legacy["schema"] = serde_json::json!("registry.project.approval-state.v1");
    legacy
        .as_object_mut()
        .expect("legacy state is an object")
        .remove("promotion_projection");
    let mut legacy_bytes =
        serde_json::to_vec_pretty(&legacy).expect("legacy approval state serializes");
    legacy_bytes.push(b'\n');
    std::fs::write(&approval_path, legacy_bytes).expect("legacy approval state writes");
    let legacy_baseline = sign_product_baseline(
        &output,
        temporary.path(),
        "registry-notary",
        "notary",
        "notary-legacy-v1",
    );
    let legacy = run_promote_legacy(&project, &legacy_baseline, "json");
    assert_conservative_blocked_cli(&legacy, &forbidden);
    let legacy_direct =
        promote_registry_project(&legacy_promotion_options(&project, &legacy_baseline))
            .expect("legacy baseline fails closed as a report");
    assert_conservative_blocked_report(&legacy_direct, &forbidden);

    approval["promotion_projection"]["fields"][0]["digest"] =
        serde_json::json!(format!("sha256:{MALFORMED_PROJECTION_SENTINEL}"));
    let mut malformed = serde_json::to_vec_pretty(&approval).expect("approval state serializes");
    malformed.push(b'\n');
    std::fs::write(&approval_path, malformed).expect("malformed projection writes");
    let malformed_projection = sign_product_baseline(
        &output,
        temporary.path(),
        "registry-notary",
        "notary",
        "notary-malformed-projection",
    );
    let malformed = run_promote_legacy(&project, &malformed_projection, "json");
    let malformed_forbidden = [
        "tamper-promotion-project",
        "fictional-citizen-registry",
        "FICTIONAL_REGISTRY_TOKEN",
        "https://citizen-registry.invalid",
        "public-service-person-verification",
        "notary-malformed-projection",
        MALFORMED_PROJECTION_SENTINEL,
        temporary_path,
    ];
    assert_conservative_blocked_cli(&malformed, &malformed_forbidden);
    let malformed_direct =
        promote_registry_project(&legacy_promotion_options(&project, &malformed_projection))
            .expect("malformed baseline fails closed as a report");
    assert_conservative_blocked_report(&malformed_direct, &malformed_forbidden);
}
