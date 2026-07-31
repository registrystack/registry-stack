use std::fs;
use std::process::{Command, Output};

const TEST_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registryctl-test-private-key"}"#;
const TEST_PUBLIC_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registryctl-test-private-key"}"#;

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

#[test]
fn sign_verify_and_assemble_share_one_signed_artifact_root() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("project");
    successful(vec![
        "init".to_string(),
        project.display().to_string(),
        "--template".to_string(),
        "http".to_string(),
    ]);
    let initial_build = successful(vec![
        "-C".to_string(),
        project.display().to_string(),
        "build".to_string(),
        "--environment".to_string(),
        "local".to_string(),
    ]);
    assert!(
        initial_build.contains("Next: registryctl trust anchor create --help"),
        "{initial_build}"
    );

    let private_key = temporary.path().join("private.jwk");
    let public_key = temporary.path().join("public.jwk");
    fs::write(&private_key, TEST_PRIVATE_JWK).expect("private JWK writes");
    fs::write(&public_key, TEST_PUBLIC_JWK).expect("public JWK writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mut permissions = fs::metadata(&private_key).unwrap().permissions();
        permissions.set_mode(0o600);
        fs::set_permissions(&private_key, permissions).unwrap();
    }

    let anchors = temporary.path().join("anchors");
    let handoff = temporary.path().join("handoff");
    fs::create_dir(&anchors).expect("anchor directory creates");
    fs::create_dir(&handoff).expect("handoff directory creates");
    let signing_inputs = project.join(".registry-stack/build/local/signing-inputs");
    let mut lane_roots = Vec::new();

    for lane in ["relay-public", "relay-consultation", "notary"] {
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

        let artifact_root = handoff.join(lane);
        let sign_output = successful(vec![
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
            artifact_root.display().to_string(),
        ]);
        assert!(
            sign_output.contains(&format!(
                "Next: registryctl trust bundle verify --bundle-dir '{}' --anchor '{}/anchor.json'",
                artifact_root.display(),
                artifact_root.display()
            )),
            "{sign_output}"
        );

        let inspect_output = successful(vec![
            "trust".to_string(),
            "bundle".to_string(),
            "inspect".to_string(),
            "--bundle-dir".to_string(),
            artifact_root.display().to_string(),
        ]);
        assert!(
            inspect_output.contains(&format!("Inspected signed {lane} artifact")),
            "{inspect_output}"
        );
        assert!(!inspect_output.contains("BundleInspectReport"));
        assert!(!inspect_output.contains(&format!("{}/bundle/config", artifact_root.display())));

        let verify_output = successful(vec![
            "trust".to_string(),
            "bundle".to_string(),
            "verify".to_string(),
            "--bundle-dir".to_string(),
            artifact_root.display().to_string(),
            "--anchor".to_string(),
            artifact_root.join("anchor.json").display().to_string(),
        ]);
        assert!(
            verify_output.contains(&format!("Verified signed {lane} artifact")),
            "{verify_output}"
        );
        assert!(verify_output.contains("config=config/"), "{verify_output}");
        assert!(!verify_output.contains("BundleVerifyReport"));
        assert!(!verify_output.contains(&format!("{}/bundle/config", artifact_root.display())));
        assert!(
            verify_output.contains("Next: registryctl trust approved-set assemble --help"),
            "{verify_output}"
        );
        lane_roots.push(artifact_root);
    }

    let approved_set = handoff.join("approved-set.json");
    let assembled = successful(vec![
        "-C".to_string(),
        project.display().to_string(),
        "trust".to_string(),
        "approved-set".to_string(),
        "assemble".to_string(),
        "--environment".to_string(),
        "local".to_string(),
        "--relay-public".to_string(),
        lane_roots[0].display().to_string(),
        "--relay-consultation".to_string(),
        lane_roots[1].display().to_string(),
        "--notary".to_string(),
        lane_roots[2].display().to_string(),
        "--output-file".to_string(),
        approved_set.display().to_string(),
    ]);
    assert!(
        assembled.contains("Assembled approved baseline set"),
        "{assembled}"
    );
    assert!(approved_set.is_file());

    let unchanged_update = successful(vec![
        "-C".to_string(),
        project.display().to_string(),
        "build".to_string(),
        "--environment".to_string(),
        "local".to_string(),
        "--against".to_string(),
        approved_set.display().to_string(),
    ]);
    assert!(
        unchanged_update
            .contains("Next: retain the current approved set; no lane signing input was emitted"),
        "{unchanged_update}"
    );

    let environment_file = project.join("environments/local.yaml");
    let changed_environment = fs::read_to_string(&environment_file)
        .expect("environment reads")
        .replace(
            "https://citizen-registry.invalid",
            "https://citizen-registry-next.invalid",
        );
    fs::write(&environment_file, changed_environment).expect("environment change writes");
    let changed_update = successful(vec![
        "-C".to_string(),
        project.display().to_string(),
        "build".to_string(),
        "--environment".to_string(),
        "local".to_string(),
        "--against".to_string(),
        approved_set.display().to_string(),
    ]);
    assert!(
        changed_update.contains("Next: registryctl trust bundle sign --help"),
        "{changed_update}"
    );
}
