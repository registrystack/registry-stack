use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use registry_platform_config::{load_anchor_transition, load_trust_anchor, verify_config_bundle};
use registry_platform_ops::{
    AcceptanceStatePreviewV1, FileAntiRollbackStore, VerifiedAcceptanceStateV1,
};

const CURRENT_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registryctl-test-private-key"}"#;
const CURRENT_PUBLIC_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registryctl-test-private-key"}"#;
const NEXT_PRIVATE_JWK: &str = r#"{"crv":"Ed25519","d":"f4QIxnAyRWzhuBOmNRgvBTE56mWePdsPL0mvCtl8Gys","x":"pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec","kty":"OKP","alg":"EdDSA","kid":"registryctl-test-private-key-2"}"#;
const NEXT_PUBLIC_JWK: &str = r#"{"crv":"Ed25519","x":"pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec","kty":"OKP","alg":"EdDSA","kid":"registryctl-test-private-key-2"}"#;

fn run(args: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_registryctl"))
        .args(args)
        .env_remove("REGISTRYCTL_ENVIRONMENT")
        .output()
        .expect("registryctl runs")
}

fn successful(args: Vec<String>) -> String {
    let output = run(&args);
    assert!(
        output.status.success(),
        "registryctl {args:?} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("registryctl output is UTF-8")
}

fn rejected(args: Vec<String>, expected: &str) {
    let output = run(&args);
    assert!(
        !output.status.success(),
        "registryctl {args:?} unexpectedly succeeded: stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let message = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        message.contains(expected),
        "registryctl {args:?} rejection did not contain {expected:?}: {message}"
    );
}

fn write_private_jwk(path: &Path, document: &str) {
    fs::write(path, document).expect("private JWK writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mut permissions = fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(path, permissions).unwrap();
    }
}

fn create_initial_lane(
    lane: &str,
    signing_inputs: &Path,
    anchors: &Path,
    handoff: &Path,
    public_key: &Path,
    private_key: &Path,
) -> PathBuf {
    let input = signing_inputs.join(lane);
    let anchor = anchors.join(format!("{lane}.json"));
    successful(vec![
        "trust".to_string(),
        "anchor".to_string(),
        "create".to_string(),
        "--lane".to_string(),
        lane.to_string(),
        "--input".to_string(),
        input.display().to_string(),
        "--public-key".to_string(),
        public_key.display().to_string(),
        "--threshold".to_string(),
        "1".to_string(),
        "--output-file".to_string(),
        anchor.display().to_string(),
    ]);
    let output = handoff.join(lane);
    successful(vec![
        "trust".to_string(),
        "bundle".to_string(),
        "sign".to_string(),
        "--lane".to_string(),
        lane.to_string(),
        "--input".to_string(),
        input.display().to_string(),
        "--anchor".to_string(),
        anchor.display().to_string(),
        "--key".to_string(),
        format!("file:{}", private_key.display()),
        "--output-dir".to_string(),
        output.display().to_string(),
    ]);
    output
}

#[test]
fn unchanged_anchor_rotation_is_explicit_authenticated_and_runtime_acceptable() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("project");
    successful(vec![
        "init".to_string(),
        project.display().to_string(),
        "--template".to_string(),
        "http".to_string(),
    ]);
    successful(vec![
        "-C".to_string(),
        project.display().to_string(),
        "build".to_string(),
        "--environment".to_string(),
        "local".to_string(),
    ]);

    let current_private_key = temporary.path().join("current-private.jwk");
    let current_public_key = temporary.path().join("current-public.jwk");
    let next_private_key = temporary.path().join("next-private.jwk");
    let next_public_key = temporary.path().join("next-public.jwk");
    write_private_jwk(&current_private_key, CURRENT_PRIVATE_JWK);
    fs::write(&current_public_key, CURRENT_PUBLIC_JWK).expect("current public JWK writes");
    write_private_jwk(&next_private_key, NEXT_PRIVATE_JWK);
    fs::write(&next_public_key, NEXT_PUBLIC_JWK).expect("next public JWK writes");

    let anchors = temporary.path().join("anchors");
    let handoff = temporary.path().join("handoff");
    fs::create_dir(&anchors).expect("anchor directory creates");
    fs::create_dir(&handoff).expect("handoff directory creates");
    let signing_inputs = project.join(".registry-stack/build/local/signing-inputs");
    let relay_public = create_initial_lane(
        "relay-public",
        &signing_inputs,
        &anchors,
        &handoff,
        &current_public_key,
        &current_private_key,
    );
    let relay_consultation = create_initial_lane(
        "relay-consultation",
        &signing_inputs,
        &anchors,
        &handoff,
        &current_public_key,
        &current_private_key,
    );
    let approved_one = handoff.join("approved-one.json");
    successful(vec![
        "-C".to_string(),
        project.display().to_string(),
        "trust".to_string(),
        "approved-set".to_string(),
        "assemble".to_string(),
        "--environment".to_string(),
        "local".to_string(),
        "--relay-public".to_string(),
        relay_public.display().to_string(),
        "--relay-consultation".to_string(),
        relay_consultation.display().to_string(),
        "--output-file".to_string(),
        approved_one.display().to_string(),
    ]);

    successful(vec![
        "-C".to_string(),
        project.display().to_string(),
        "build".to_string(),
        "--environment".to_string(),
        "local".to_string(),
        "--against".to_string(),
        approved_one.display().to_string(),
        "--rotate-anchor".to_string(),
        "relay-consultation".to_string(),
    ]);
    let rotated_input = signing_inputs.join("relay-consultation");
    assert!(rotated_input.is_dir());
    assert!(!signing_inputs.join("relay-public").exists());
    assert_eq!(
        fs::read(rotated_input.join("config/relay.yaml")).expect("rotated input config reads"),
        fs::read(relay_consultation.join("bundle/config/relay.yaml"))
            .expect("preceding config reads"),
        "an anchor-only build must not manufacture a configuration change"
    );
    for reviewed_file in ["approval/review.json", "approval/project-state.json"] {
        assert_eq!(
            fs::read(rotated_input.join(reviewed_file)).expect("rotated reviewed input reads"),
            fs::read(relay_consultation.join("bundle").join(reviewed_file))
                .expect("preceding reviewed input reads"),
            "an anchor-only build must retain the signed {reviewed_file}"
        );
    }

    let rotation = handoff.join("relay-consultation-rotation");
    successful(vec![
        "trust".to_string(),
        "anchor".to_string(),
        "rotate".to_string(),
        "--current-anchor".to_string(),
        relay_consultation.join("anchor.json").display().to_string(),
        "--next-public-key".to_string(),
        current_public_key.display().to_string(),
        "--next-public-key".to_string(),
        next_public_key.display().to_string(),
        "--next-threshold".to_string(),
        "1".to_string(),
        "--key".to_string(),
        format!("file:{}", current_private_key.display()),
        "--output-dir".to_string(),
        rotation.display().to_string(),
    ]);

    let same_anchor = handoff.join("relay-consultation-same-anchor");
    successful(vec![
        "trust".to_string(),
        "bundle".to_string(),
        "sign".to_string(),
        "--lane".to_string(),
        "relay-consultation".to_string(),
        "--input".to_string(),
        rotated_input.display().to_string(),
        "--anchor".to_string(),
        relay_consultation.join("anchor.json").display().to_string(),
        "--against".to_string(),
        approved_one.display().to_string(),
        "--key".to_string(),
        format!("file:{}", current_private_key.display()),
        "--output-dir".to_string(),
        same_anchor.display().to_string(),
    ]);
    rejected(
        vec![
            "-C".to_string(),
            project.display().to_string(),
            "trust".to_string(),
            "approved-set".to_string(),
            "assemble".to_string(),
            "--environment".to_string(),
            "local".to_string(),
            "--from".to_string(),
            approved_one.display().to_string(),
            "--relay-consultation".to_string(),
            same_anchor.display().to_string(),
            "--output-file".to_string(),
            handoff
                .join("rejected-same-anchor.json")
                .display()
                .to_string(),
        ],
        "retained its preceding anchor",
    );

    let rotated_consultation = handoff.join("relay-consultation-rotated");
    successful(vec![
        "trust".to_string(),
        "bundle".to_string(),
        "sign".to_string(),
        "--lane".to_string(),
        "relay-consultation".to_string(),
        "--input".to_string(),
        rotated_input.display().to_string(),
        "--anchor".to_string(),
        rotation.join("anchor.json").display().to_string(),
        "--against".to_string(),
        approved_one.display().to_string(),
        "--key".to_string(),
        format!("file:{}", next_private_key.display()),
        "--output-dir".to_string(),
        rotated_consultation.display().to_string(),
    ]);
    let approved_two = handoff.join("approved-two.json");
    successful(vec![
        "-C".to_string(),
        project.display().to_string(),
        "trust".to_string(),
        "approved-set".to_string(),
        "assemble".to_string(),
        "--environment".to_string(),
        "local".to_string(),
        "--from".to_string(),
        approved_one.display().to_string(),
        "--relay-consultation".to_string(),
        rotated_consultation.display().to_string(),
        "--output-file".to_string(),
        approved_two.display().to_string(),
    ]);

    let verified_one = verify_config_bundle(
        relay_consultation.join("bundle"),
        relay_consultation.join("anchor.json"),
    )
    .unwrap();
    let verified_two = verify_config_bundle(
        rotated_consultation.join("bundle"),
        rotated_consultation.join("anchor.json"),
    )
    .unwrap();
    let candidate_one = VerifiedAcceptanceStateV1::from_verified_bundle(&verified_one).unwrap();
    let candidate_two = VerifiedAcceptanceStateV1::from_verified_bundle(&verified_two).unwrap();
    let current_anchor = load_trust_anchor(&relay_consultation.join("anchor.json")).unwrap();
    let transition =
        load_anchor_transition(&rotated_consultation.join("anchor-history/0000.transition.json"))
            .unwrap();
    let state_path = temporary
        .path()
        .join("relay-consultation-anti-rollback.json");
    let store = FileAntiRollbackStore::new(&state_path);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime
        .block_on(
            store.commit_acceptance(store.plan_initialize(&candidate_one).unwrap(), |_| async {
                Ok::<(), ()>(())
            }),
        )
        .unwrap();
    assert_eq!(
        store.preview_acceptance(&candidate_two, Some(&current_anchor), Some(&transition),),
        Ok(AcceptanceStatePreviewV1::RotateAnchor)
    );
    let plan = store
        .plan_acceptance(&candidate_two, Some(&current_anchor), Some(&transition))
        .unwrap();
    runtime
        .block_on(store.commit_acceptance(plan, |_| async { Ok::<(), ()>(()) }))
        .unwrap();
    FileAntiRollbackStore::new(&state_path)
        .verify_state(candidate_two.expectation())
        .expect("restart exact-state verification accepts the rotated lane");

    successful(vec![
        "-C".to_string(),
        project.display().to_string(),
        "build".to_string(),
        "--environment".to_string(),
        "local".to_string(),
        "--against".to_string(),
        approved_two.display().to_string(),
        "--rotate-anchor".to_string(),
        "relay-consultation".to_string(),
    ]);
    let stale_rotation = handoff.join("relay-consultation-stale-rotation");
    successful(vec![
        "trust".to_string(),
        "anchor".to_string(),
        "rotate".to_string(),
        "--current-anchor".to_string(),
        relay_consultation.join("anchor.json").display().to_string(),
        "--next-public-key".to_string(),
        current_public_key.display().to_string(),
        "--next-threshold".to_string(),
        "1".to_string(),
        "--key".to_string(),
        format!("file:{}", current_private_key.display()),
        "--output-dir".to_string(),
        stale_rotation.display().to_string(),
    ]);
    rejected(
        vec![
            "trust".to_string(),
            "bundle".to_string(),
            "sign".to_string(),
            "--lane".to_string(),
            "relay-consultation".to_string(),
            "--input".to_string(),
            rotated_input.display().to_string(),
            "--anchor".to_string(),
            stale_rotation.join("anchor.json").display().to_string(),
            "--against".to_string(),
            approved_two.display().to_string(),
            "--key".to_string(),
            format!("file:{}", current_private_key.display()),
            "--output-dir".to_string(),
            handoff
                .join("relay-consultation-rejected-next")
                .display()
                .to_string(),
        ],
        "selected lane anchor is not the next authenticated anchor",
    );
}
