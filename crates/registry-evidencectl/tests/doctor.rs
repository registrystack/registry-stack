#![cfg(unix)]

//! `evidencectl doctor` over a real deployment project.
//!
//! Every filesystem assertion here is about a mode or an owner the Evidence
//! runtime refuses at startup. The filesystem is intentionally assembled as a
//! doctor fixture because `evidencectl new` no longer invents a runnable
//! deployment. No `evidence` binary is involved anywhere in this file:
//! `doctor` is a filesystem walk, and an adopter who cannot yet start the
//! service is exactly the one who needs it. Nothing here prints key material.

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Output},
};

const SECRET_FILES: [&str; 2] = ["audit-hmac-key", "subject-binding-hmac-key"];

/// A value planted inside the very requirement whose acquisition is rendered,
/// in a member the rendering does not read. A report that ever grows into
/// echoing document values fails loudly here instead of quietly.
const CANARY: &str = "s3cr3t-canary-value";

/// The three acquisition forms a bundle can declare, one requirement each.
///
/// Source names and the fact names a member is allowed to read are
/// configuration an adopter writes and a report may state. The derivation
/// parameter beside them is not part of the acquisition, and carries the
/// canary that proves the projection stays narrow.
const DECLARED_ACQUISITIONS: &str = r#"requirements:
  - id: urn:example:doctor:requirement:one-call:v1
    acquisition: {kind: single, source: registry-lookup}
  - id: urn:example:doctor:requirement:two-call:v1
    acquisition: {kind: search-then-fetch, search: person-search, fetch: person-record}
  - id: urn:example:doctor:requirement:fetch-set:v1
    acquisition:
      kind: search-then-fetch-set
      search: civil-record-search
      fetch:
        - {source: union-register, factInputs: [civil_record_reference]}
        - {source: death-register, factInputs: [civil_record_reference]}
      maximumAcquisitionMilliseconds: 8000
    derivation:
      parameters: {survivorship_policy: s3cr3t-canary-value}
"#;

const MATCHING_MINT_CONFIG: &str = r#"version: 1
issuer: https://identity.invalid
signing:
  algorithm: ES256
  jwksPath: /.well-known/jwks.json
accessTokens:
  audiences: [evidence-scaffold]
  claims:
    principal: sub
    requesterTags: evidence_tags
    evidenceAudience: evidence_audience
    grantId: evidence_grant_id
    grantAuthority: evidence_authority
"#;

#[test]
fn doctor_passes_a_frozen_project_and_leaves_the_public_key_beside_it_alone() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    provision(&project);
    provision_bearer_token(&project);

    // `keygen signing` writes the public half into the secret root at 0644 by
    // design. The runtime never resolves it as a secret, so doctor must not
    // report it. A walk of the secret directory would; a walk of the secret
    // references the bundle actually names does not.
    let public_key = project.join("secrets/signing-p256-public.jwk.json");
    assert_eq!(
        mode_of(&public_key),
        0o644,
        "the scaffolded public key is no longer world-readable, so this test proves nothing"
    );

    freeze(&project);
    let output = doctor(&project, &[]);
    unfreeze(&project);

    let stdout = stdout_of(&output);
    assert!(
        output.status.success(),
        "doctor failed on a correctly provisioned project:\n{stdout}{}",
        stderr_of(&output)
    );
    assert!(
        stdout.contains("0 failed"),
        "unexpected doctor summary: {stdout}"
    );
    assert!(
        !stdout.contains("signing-p256-public.jwk.json"),
        "doctor reported the public key that sits beside the private one: {stdout}"
    );
}

#[test]
fn doctor_names_every_artifact_whose_mode_the_runtime_refuses() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    provision(&project);
    provision_bearer_token(&project);
    freeze(&project);

    // One artifact per rule the runtime enforces, each widened past it. A
    // `chmod -R` an operator runs over a project produces exactly this state.
    let refused = [
        "runtime.yaml",
        "bundle/evidence.yaml",
        "secrets",
        "secrets/audit-hmac-key",
        "audit/evidence.jsonl",
    ];
    fs::write(project.join("audit/evidence.jsonl"), "").expect("stage an audit chain");
    for path in refused {
        set_mode(&project.join(path), 0o755);
    }

    let output = doctor(&project, &[]);
    unfreeze(&project);

    let stdout = stdout_of(&output);
    assert!(
        !output.status.success(),
        "doctor passed a project the runtime would refuse:\n{stdout}"
    );
    for path in refused {
        assert!(
            stdout.contains(path),
            "doctor did not report {path}:\n{stdout}"
        );
    }
}

#[test]
fn doctor_accepts_only_the_runtime_owner_only_secret_modes() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    provision(&project);
    provision_bearer_token(&project);
    freeze(&project);
    let secret = project.join("secrets/audit-hmac-key");

    for mode in [0o400, 0o600] {
        set_mode(&secret, mode);
        let output = doctor(&project, &[]);
        assert!(
            output.status.success(),
            "doctor rejected runtime-supported secret mode {mode:04o}:\n{}{}",
            stdout_of(&output),
            stderr_of(&output)
        );
    }

    for mode in [0o000, 0o200, 0o440, 0o500, 0o604, 0o700] {
        set_mode(&secret, mode);
        let output = doctor(&project, &[]);
        let diagnostics = format!("{}{}", stdout_of(&output), stderr_of(&output));
        assert!(
            !output.status.success(),
            "doctor accepted unsupported secret mode {mode:04o}:\n{diagnostics}"
        );
        assert!(
            diagnostics.contains("secrets/audit-hmac-key")
                && diagnostics.contains("requires exactly 0400 or 0600"),
            "doctor did not report unsupported secret mode {mode:04o}:\n{diagnostics}"
        );
    }

    set_mode(&secret, 0o600);
    unfreeze(&project);
}

#[test]
fn doctor_reports_a_secret_the_bundle_references_and_the_project_does_not_hold() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    provision(&project);

    // Every secret but the source bearer token, which the README tells an
    // adopter to obtain from the source system rather than generate. Forgetting
    // it is the ordinary way a project reaches this state.
    freeze(&project);
    let output = doctor(&project, &[]);
    unfreeze(&project);

    let stdout = stdout_of(&output);
    assert!(
        !output.status.success(),
        "doctor passed a project missing a secret the bundle references:\n{stdout}"
    );
    assert!(
        stdout.contains("secrets/source-bearer-token"),
        "doctor did not name the missing secret:\n{stdout}"
    );
}

#[test]
fn doctor_json_puts_one_document_on_stdout_and_the_report_on_stderr() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    provision(&project);
    provision_bearer_token(&project);

    freeze(&project);
    let output = doctor(&project, &["--json"]);
    unfreeze(&project);

    assert!(
        output.status.success(),
        "doctor --json failed on a correctly provisioned project:\n{}",
        stderr_of(&output)
    );
    let stdout = stdout_of(&output);
    let lines: Vec<&str> = stdout.lines().filter(|line| !line.is_empty()).collect();
    assert_eq!(
        lines.len(),
        1,
        "stdout must carry exactly one JSON document: {stdout}"
    );
    let report: serde_json::Value = serde_json::from_str(lines[0]).expect("parse the JSON report");
    assert_eq!(report["passed"], serde_json::Value::Bool(true));
    let checks = report["checks"].as_array().expect("checks array");
    assert!(
        checks.iter().all(|check| check["passed"] == true),
        "a check failed in the JSON report: {stdout}"
    );
    assert!(
        stderr_of(&output).contains("0 failed"),
        "the human report did not reach stderr in JSON mode"
    );
}

#[test]
fn doctor_checks_only_an_explicit_external_mint_config() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    let external_mint = workspace.path().join("mint/mint.yaml");
    provision(&project);
    provision_bearer_token(&project);
    write_mint(&external_mint, MATCHING_MINT_CONFIG);

    // A nested document must not be discovered. The explicit path is the only
    // act that pairs Evidence with Mint.
    write_mint(
        &project.join("mint/mint.yaml"),
        &MATCHING_MINT_CONFIG.replace("https://identity.invalid", "https://nested.invalid"),
    );

    freeze(&project);
    let unpaired = doctor(&project, &[]);
    let paired = doctor(
        &project,
        &[
            "--mint-config",
            external_mint.to_str().expect("Mint config path"),
        ],
    );
    unfreeze(&project);

    assert!(
        unpaired.status.success(),
        "doctor discovered an unrequested Mint config:\n{}{}",
        stdout_of(&unpaired),
        stderr_of(&unpaired)
    );
    assert!(
        !stdout_of(&unpaired).contains("mint compatibility"),
        "unpaired doctor reported a Mint check: {}",
        stdout_of(&unpaired)
    );
    assert!(
        paired.status.success(),
        "doctor rejected matching external Mint config:\n{}{}",
        stdout_of(&paired),
        stderr_of(&paired)
    );
    assert!(
        stdout_of(&paired).contains("PASS: mint compatibility"),
        "paired doctor omitted its compatibility result: {}",
        stdout_of(&paired)
    );
}

#[test]
fn doctor_rejects_an_issuer_mismatch_without_printing_its_value() {
    const SENTINEL: &str = "https://credential-token-selector-source.invalid";

    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    let mint_config = workspace.path().join("mint/mint.yaml");
    provision(&project);
    provision_bearer_token(&project);
    write_mint(
        &mint_config,
        &MATCHING_MINT_CONFIG.replace("https://identity.invalid", SENTINEL),
    );

    freeze(&project);
    let output = doctor(
        &project,
        &[
            "--mint-config",
            mint_config.to_str().expect("Mint config path"),
        ],
    );
    unfreeze(&project);

    let diagnostics = format!("{}{}", stdout_of(&output), stderr_of(&output));
    assert!(
        !output.status.success(),
        "doctor accepted an issuer mismatch: {diagnostics}"
    );
    assert!(
        diagnostics.contains("authentication.issuer"),
        "issuer mismatch did not identify its field: {diagnostics}"
    );
    assert!(
        !diagnostics.contains(SENTINEL),
        "issuer mismatch disclosed the configured value: {diagnostics}"
    );
}

#[test]
fn doctor_reports_every_mint_field_mismatch_without_printing_values() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    let mint_config = workspace.path().join("mint/mint.yaml");
    provision(&project);
    provision_bearer_token(&project);

    let cases = [
        (
            "jwksPath: /.well-known/jwks.json",
            "jwksPath: /credential-token-selector-source-jwks",
            "authentication.jwksUri",
            "/credential-token-selector-source-jwks",
        ),
        (
            "audiences: [evidence-scaffold]",
            "audiences: [credential-token-selector-source-audience]",
            "authentication.audiences",
            "credential-token-selector-source-audience",
        ),
        (
            "algorithm: ES256",
            "algorithm: RS256",
            "authentication.algorithms",
            "RS256",
        ),
        (
            "principal: sub",
            "principal: credential_token_selector_source_principal",
            "authentication.principalClaim",
            "credential_token_selector_source_principal",
        ),
        (
            "requesterTags: evidence_tags",
            "requesterTags: credential_token_selector_source_tags",
            "authentication.requesterTagsClaim",
            "credential_token_selector_source_tags",
        ),
        (
            "evidenceAudience: evidence_audience",
            "evidenceAudience: credential_token_selector_source_audience_claim",
            "authentication.evidenceAudienceClaim",
            "credential_token_selector_source_audience_claim",
        ),
        (
            "grantId: evidence_grant_id",
            "grantId: credential_token_selector_source_grant_id",
            "authentication.grantIdClaim",
            "credential_token_selector_source_grant_id",
        ),
        (
            "grantAuthority: evidence_authority",
            "grantAuthority: credential_token_selector_source_authority",
            "authentication.grantAuthorityClaim",
            "credential_token_selector_source_authority",
        ),
    ];

    for (original, replacement, field, sentinel) in cases {
        let mismatched = replace_once(MATCHING_MINT_CONFIG, original, replacement);
        write_mint(&mint_config, &mismatched);

        freeze(&project);
        let output = doctor(
            &project,
            &[
                "--mint-config",
                mint_config.to_str().expect("Mint config path"),
            ],
        );
        unfreeze(&project);

        let diagnostics = format!("{}{}", stdout_of(&output), stderr_of(&output));
        assert!(
            !output.status.success(),
            "doctor accepted mismatch in {field}: {diagnostics}"
        );
        assert!(
            diagnostics.contains(field),
            "mismatch did not identify {field}: {diagnostics}"
        );
        assert!(
            !diagnostics.contains(sentinel),
            "mismatch in {field} disclosed its configured value: {diagnostics}"
        );
    }
}

#[test]
fn doctor_requires_evidence_to_admit_the_mint_access_token_type() {
    const SENTINEL: &str = "credential-token-selector-source-type";

    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    let mint_config = workspace.path().join("mint/mint.yaml");
    provision(&project);
    provision_bearer_token(&project);
    rewrite_bundle(
        &project,
        "tokenTypes: [at+jwt]",
        &format!("tokenTypes: [{SENTINEL}]"),
    );
    write_mint(&mint_config, MATCHING_MINT_CONFIG);

    freeze(&project);
    let output = doctor(
        &project,
        &[
            "--mint-config",
            mint_config.to_str().expect("Mint config path"),
        ],
    );
    unfreeze(&project);

    let diagnostics = format!("{}{}", stdout_of(&output), stderr_of(&output));
    assert!(!output.status.success(), "doctor accepted {diagnostics}");
    assert!(
        diagnostics.contains("authentication.tokenTypes"),
        "token-type mismatch did not identify its field: {diagnostics}"
    );
    assert!(
        !diagnostics.contains(SENTINEL),
        "token-type mismatch disclosed its configured value: {diagnostics}"
    );
}

#[test]
fn doctor_checks_every_actor_claim_presence_combination() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let mint_config = workspace.path().join("mint/mint.yaml");
    let cases = [
        (None, None, true),
        (Some("shared_actor"), Some("shared_actor"), true),
        (Some("evidence_actor"), None, false),
        (None, Some("mint_actor"), false),
        (Some("evidence_actor"), Some("mint_actor"), false),
    ];

    for (index, (evidence_actor, mint_actor, expected_pass)) in cases.into_iter().enumerate() {
        let project = workspace.path().join(format!("project-{index}"));
        provision(&project);
        provision_bearer_token(&project);
        if let Some(actor) = evidence_actor {
            add_evidence_actor(&project, actor);
        }
        let mut mint = MATCHING_MINT_CONFIG.to_owned();
        if let Some(actor) = mint_actor {
            mint.push_str(&format!("    actor: {actor}\n"));
        }
        write_mint(&mint_config, &mint);

        freeze(&project);
        let output = doctor(
            &project,
            &[
                "--mint-config",
                mint_config.to_str().expect("Mint config path"),
            ],
        );
        unfreeze(&project);

        let diagnostics = format!("{}{}", stdout_of(&output), stderr_of(&output));
        assert_eq!(
            output.status.success(),
            expected_pass,
            "unexpected actor compatibility result: {diagnostics}"
        );
        if !expected_pass {
            assert!(
                diagnostics.contains("authentication.actorClaim"),
                "actor mismatch did not identify its field: {diagnostics}"
            );
            for value in [evidence_actor, mint_actor].into_iter().flatten() {
                assert!(
                    !diagnostics.contains(value),
                    "actor mismatch disclosed its configured value: {diagnostics}"
                );
            }
        }
    }
}

#[test]
fn doctor_accepts_set_order_supersets_custom_jwks_and_matching_actor() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    let mint_config = workspace.path().join("mint/mint.yaml");
    provision(&project);
    provision_bearer_token(&project);

    rewrite_bundle(
        &project,
        "issuer: https://identity.invalid",
        "issuer: https://identity.invalid/",
    );
    rewrite_bundle(
        &project,
        "audiences: [evidence-scaffold]",
        "audiences: [secondary-audience, evidence-scaffold]",
    );
    rewrite_bundle(
        &project,
        "tokenTypes: [at+jwt]",
        "tokenTypes: [application/at+jwt, at+jwt]",
    );
    rewrite_bundle(
        &project,
        "algorithms: [ES256]",
        "algorithms: [RS256, ES256]",
    );
    rewrite_bundle(
        &project,
        "jwksUri: https://identity.invalid/.well-known/jwks.json",
        "jwksUri: https://identity.invalid//custom/jwks.json",
    );
    add_evidence_actor(&project, "shared_actor");

    let mut mint = MATCHING_MINT_CONFIG
        .replace(
            "issuer: https://identity.invalid",
            "issuer: https://identity.invalid/",
        )
        .replace(
            "jwksPath: /.well-known/jwks.json",
            "jwksPath: /custom/jwks.json",
        )
        .replace(
            "audiences: [evidence-scaffold]",
            "audiences: [evidence-scaffold, secondary-audience]",
        );
    mint.push_str("    actor: shared_actor\n");
    write_mint(&mint_config, &mint);

    freeze(&project);
    let output = doctor(
        &project,
        &[
            "--mint-config",
            mint_config.to_str().expect("Mint config path"),
        ],
    );
    unfreeze(&project);

    assert!(
        output.status.success(),
        "doctor rejected mechanically compatible sets and supersets:\n{}{}",
        stdout_of(&output),
        stderr_of(&output)
    );
}

#[test]
fn doctor_applies_mint_protocol_defaults() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    let mint_config = workspace.path().join("mint/mint.yaml");
    provision(&project);
    provision_bearer_token(&project);
    let mint = MATCHING_MINT_CONFIG
        .replace("  jwksPath: /.well-known/jwks.json\n", "")
        .replace("    principal: sub\n", "");
    write_mint(&mint_config, &mint);

    freeze(&project);
    let output = doctor(
        &project,
        &[
            "--mint-config",
            mint_config.to_str().expect("Mint config path"),
        ],
    );
    unfreeze(&project);

    assert!(
        output.status.success(),
        "doctor did not apply Mint's JWKS and principal defaults:\n{}{}",
        stdout_of(&output),
        stderr_of(&output)
    );
}

#[test]
fn doctor_json_aggregates_mismatches_and_redacts_every_value() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    let mint_config = workspace.path().join("mint/mint.yaml");
    provision(&project);
    provision_bearer_token(&project);

    let sentinels = [
        "credential-token-selector-source-audience",
        "RS256",
        "credential_token_selector_source_principal",
    ];
    let mint = MATCHING_MINT_CONFIG
        .replace(
            "audiences: [evidence-scaffold]",
            &format!("audiences: [{}]", sentinels[0]),
        )
        .replace("algorithm: ES256", &format!("algorithm: {}", sentinels[1]))
        .replace("principal: sub", &format!("principal: {}", sentinels[2]));
    write_mint(&mint_config, &mint);

    freeze(&project);
    let output = doctor(
        &project,
        &[
            "--mint-config",
            mint_config.to_str().expect("Mint config path"),
            "--json",
        ],
    );
    unfreeze(&project);

    assert!(!output.status.success(), "doctor accepted three mismatches");
    let stdout = stdout_of(&output);
    let report: serde_json::Value = serde_json::from_str(stdout.trim()).expect("doctor JSON");
    let check = report["checks"]
        .as_array()
        .expect("checks")
        .iter()
        .find(|check| check["name"] == "mint compatibility")
        .expect("Mint compatibility check");
    assert_eq!(
        check["findings"].as_array().expect("findings").len(),
        3,
        "doctor must report every mechanical mismatch in one run: {stdout}"
    );

    let diagnostics = format!("{stdout}{}", stderr_of(&output));
    for field in [
        "authentication.audiences",
        "authentication.algorithms",
        "authentication.principalClaim",
    ] {
        assert!(
            diagnostics.contains(field),
            "aggregate diagnostics omitted {field}: {diagnostics}"
        );
    }
    for sentinel in sentinels {
        assert!(
            !diagnostics.contains(sentinel),
            "JSON or human diagnostics disclosed {sentinel}: {diagnostics}"
        );
    }
}

#[test]
fn doctor_redacts_invalid_paired_documents() {
    const SENTINEL: &str = "credential-token-selector-source-invalid-document";

    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    let mint_config = workspace.path().join("mint/mint.yaml");
    provision(&project);
    provision_bearer_token(&project);
    write_mint(&mint_config, &format!("issuer: {SENTINEL}\nsigning: [\n"));

    freeze(&project);
    let invalid_mint = doctor(
        &project,
        &[
            "--mint-config",
            mint_config.to_str().expect("Mint config path"),
        ],
    );
    unfreeze(&project);
    let mint_diagnostics = format!("{}{}", stdout_of(&invalid_mint), stderr_of(&invalid_mint));
    assert!(!invalid_mint.status.success());
    assert!(
        mint_diagnostics.contains("paired Mint compatibility fields are missing or invalid"),
        "invalid Mint document lacked a stable diagnostic: {mint_diagnostics}"
    );
    assert!(
        !mint_diagnostics.contains(SENTINEL),
        "Mint decoder error disclosed an authored value: {mint_diagnostics}"
    );

    write_mint(&mint_config, MATCHING_MINT_CONFIG);
    rewrite_bundle(
        &project,
        "issuer: https://identity.invalid",
        &format!("issuer: [{SENTINEL}]"),
    );
    freeze(&project);
    let invalid_evidence = doctor(
        &project,
        &[
            "--mint-config",
            mint_config.to_str().expect("Mint config path"),
        ],
    );
    unfreeze(&project);
    let evidence_diagnostics = format!(
        "{}{}",
        stdout_of(&invalid_evidence),
        stderr_of(&invalid_evidence)
    );
    assert!(!invalid_evidence.status.success());
    assert!(
        evidence_diagnostics
            .contains("authentication paired-Mint compatibility fields are missing or invalid"),
        "invalid Evidence binding lacked a stable diagnostic: {evidence_diagnostics}"
    );
    assert!(
        !evidence_diagnostics.contains(SENTINEL),
        "Evidence decoder error disclosed an authored value: {evidence_diagnostics}"
    );
}

#[test]
fn doctor_pairing_is_read_only_and_does_not_inspect_mint_authority_material() {
    const SENTINEL: &str = "credential-token-selector-source-authority-material";

    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    let mint_root = workspace.path().join("mint");
    let mint_config = mint_root.join("mint.yaml");
    provision(&project);
    provision_bearer_token(&project);
    let mut mint = MATCHING_MINT_CONFIG.replace(
        "  jwksPath: /.well-known/jwks.json",
        &format!(
            "  activePublicJwkFile: public-keys/{SENTINEL}.jwk.json\n  jwksPath: /.well-known/jwks.json"
        ),
    );
    mint.push_str("clients:\n  directory: clients\n");
    write_mint(&mint_config, &mint);
    fs::create_dir_all(mint_root.join("secrets")).expect("Mint secrets");
    fs::create_dir_all(mint_root.join("clients")).expect("Mint clients");
    fs::write(mint_root.join("secrets").join(SENTINEL), SENTINEL).expect("private key sentinel");
    fs::write(mint_root.join("clients/client.yaml"), SENTINEL).expect("client sentinel");

    freeze(&project);
    let before = tree_snapshot(workspace.path());
    let output = doctor(
        &project,
        &[
            "--mint-config",
            mint_config.to_str().expect("Mint config path"),
        ],
    );
    let after = tree_snapshot(workspace.path());
    unfreeze(&project);

    assert!(
        output.status.success(),
        "doctor inspected unrelated Mint authority material:\n{}{}",
        stdout_of(&output),
        stderr_of(&output)
    );
    assert!(
        before == after,
        "doctor changed a deployment artifact; snapshot contents are withheld"
    );
    let diagnostics = format!("{}{}", stdout_of(&output), stderr_of(&output));
    assert!(
        !diagnostics.contains(SENTINEL),
        "doctor disclosed Mint authority material: {diagnostics}"
    );
}

#[test]
fn doctor_help_exposes_the_explicit_mint_config_option() {
    let output = evidencectl(&["doctor", "--help"]);
    assert!(output.status.success(), "doctor --help failed");
    assert!(
        stdout_of(&output).contains("--mint-config <PATH>"),
        "doctor help omitted --mint-config: {}",
        stdout_of(&output)
    );
}

/// A bundle declaring a gated acquisition kind states what it needs; the
/// deployment that will serve it decides separately, in a file the bundle
/// author does not write. Evidence refuses the pair with a value-free sentence
/// that names no file, which is correct for a refusal and useless as
/// instructions, so doctor names the file and the entry to add.
#[test]
fn doctor_reports_a_gated_acquisition_kind_the_deployment_did_not_enable() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    provision(&project);
    provision_bearer_token(&project);
    declare_acquisitions(&project);

    freeze(&project);
    let output = doctor(&project, &[]);
    unfreeze(&project);

    let stdout = stdout_of(&output);
    assert!(
        !output.status.success(),
        "doctor passed a project the runtime would refuse:\n{stdout}"
    );
    assert!(
        stdout.contains(
            "runtime.yaml: does not enable the search-then-fetch-set acquisition capability"
        ) && stdout.contains("acquisitionCapabilities: [search-then-fetch-set]"),
        "doctor did not name the file and the entry to add:\n{stdout}"
    );
    assert!(
        !stdout.contains(CANARY),
        "doctor echoed a document value:\n{stdout}"
    );
}

/// The same project, once the operator has made the decision. The frozen
/// Version 1 forms beside it never needed one.
#[test]
fn doctor_passes_once_the_deployment_enables_the_kind_the_bundle_requires() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    provision(&project);
    provision_bearer_token(&project);
    declare_acquisitions(&project);
    enable_acquisition_capability(&project);

    freeze(&project);
    let output = doctor(&project, &[]);
    unfreeze(&project);

    let stdout = stdout_of(&output);
    assert!(
        output.status.success(),
        "doctor failed a project the runtime would accept:\n{stdout}{}",
        stderr_of(&output)
    );
    assert!(
        stdout.contains("0 failed"),
        "unexpected doctor summary: {stdout}"
    );
}

#[test]
fn doctor_reports_both_halves_of_the_source_batch_capability_gate() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    provision(&project);
    provision_bearer_token(&project);
    let bundle_path = project.join("bundle/evidence.yaml");
    let mut bundle = fs::read_to_string(&bundle_path).expect("Evidence configuration");
    bundle.push_str("sources:\n  registry-lookup:\n    batch: {}\n");
    fs::write(&bundle_path, bundle).expect("declare a source batch block");

    freeze(&project);
    let output = doctor(&project, &[]);
    unfreeze(&project);

    let stdout = stdout_of(&output);
    assert!(
        !output.status.success(),
        "doctor passed a source batch block without its two-author gate:\n{stdout}"
    );
    for expected in [
        "bundle/evidence.yaml: does not declare the source-batch acquisition capability a source batch block in it uses",
        "runtime.yaml: does not enable the source-batch acquisition capability a source batch block in this bundle needs",
    ] {
        assert!(
            stdout.contains(expected),
            "doctor did not report {expected:?}:\n{stdout}"
        );
    }
}

/// A capability named twice enables nothing a single naming does not, so it
/// reads as harmless. The runtime does not read it that way: it refuses the
/// deployment because the list must be unique. Doctor reporting PASS on a
/// project that will not start is the one outcome this check exists to
/// prevent.
#[test]
fn doctor_reports_an_acquisition_capability_the_deployment_listed_twice() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    provision(&project);
    provision_bearer_token(&project);
    declare_acquisitions(&project);
    enable_acquisition_capability_twice(&project);

    freeze(&project);
    let output = doctor(&project, &[]);
    unfreeze(&project);

    let stdout = stdout_of(&output);
    assert!(
        !output.status.success(),
        "doctor passed a project the runtime would refuse:\n{stdout}"
    );
    assert!(
        stdout.contains("runtime.yaml: lists the same acquisition capability twice"),
        "doctor did not name the repeated capability entry:\n{stdout}"
    );
}

/// The gate has two halves and the bundle writes one of them. A requirement
/// using the gated kind in a bundle that never declared it is refused at
/// startup even on a deployment that enabled the kind, so a doctor reading only
/// the deployment's half passes a project that will not start.
#[test]
fn doctor_reports_a_gated_acquisition_kind_the_bundle_did_not_declare() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    provision(&project);
    provision_bearer_token(&project);
    declare_acquisitions_stating(&project, "");
    enable_acquisition_capability(&project);

    freeze(&project);
    let output = doctor(&project, &[]);
    unfreeze(&project);

    let stdout = stdout_of(&output);
    assert!(
        !output.status.success(),
        "doctor passed a project the runtime would refuse:\n{stdout}"
    );
    assert!(
        stdout.contains(
            "bundle/evidence.yaml: does not declare the search-then-fetch-set acquisition capability"
        ) && stdout.contains("acquisitionCapabilities: [search-then-fetch-set]"),
        "doctor did not name the file and the entry to add:\n{stdout}"
    );
    assert!(
        !stdout.contains(CANARY),
        "doctor echoed a document value:\n{stdout}"
    );
}

/// A misspelled declaration is the same defect twice over: the name the bundle
/// states is not one this release defines, and the kind its requirement uses
/// stays undeclared. The runtime refuses on the first; an author reading a
/// report that mentioned only the second would go looking in the wrong file.
#[test]
fn doctor_reports_a_bundle_acquisition_capability_this_release_does_not_define() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    provision(&project);
    provision_bearer_token(&project);
    declare_acquisitions_stating(
        &project,
        "acquisitionCapabilities:\n  - search-then-fetch-sets\n",
    );
    enable_acquisition_capability(&project);

    freeze(&project);
    let output = doctor(&project, &[]);
    unfreeze(&project);

    let stdout = stdout_of(&output);
    assert!(
        !output.status.success(),
        "doctor passed a project the runtime would refuse:\n{stdout}"
    );
    assert!(
        stdout.contains(
            "bundle/evidence.yaml: declares an acquisition capability this release does not define"
        ),
        "doctor did not name the undefined capability:\n{stdout}"
    );
    assert!(
        stdout.contains(
            "bundle/evidence.yaml: does not declare the search-then-fetch-set acquisition capability"
        ),
        "doctor did not report the requirement left ungated:\n{stdout}"
    );
}

/// An adopter reading a bundle needs to know what it will call before anything
/// is running: which sources, in what order, and which facts one call hands to
/// the next. All of that is configuration. A fact value is not: it is acquired
/// at request time, and doctor neither holds one nor asks for one.
#[test]
fn doctor_renders_every_call_each_declared_acquisition_will_make() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    provision(&project);
    provision_bearer_token(&project);
    declare_acquisitions(&project);
    enable_acquisition_capability(&project);

    freeze(&project);
    let output = doctor(&project, &["--json"]);
    unfreeze(&project);

    let stderr = stderr_of(&output);
    assert!(
        output.status.success(),
        "doctor --json failed on an enabled project:\n{stderr}"
    );
    for line in [
        "PLAN: urn:example:doctor:requirement:one-call:v1 (single)",
        "    1. registry-lookup (search) reads no prior fact",
        "PLAN: urn:example:doctor:requirement:two-call:v1 (search-then-fetch)",
        "    1. person-search (search) reads no prior fact",
        "    2. person-record (member) reads every fact the search produced",
        "PLAN: urn:example:doctor:requirement:fetch-set:v1 (search-then-fetch-set)",
        "    1. civil-record-search (search) reads no prior fact",
        "    2. union-register (member) reads civil_record_reference",
        "    3. death-register (member) reads civil_record_reference",
    ] {
        assert!(
            stderr.contains(line),
            "doctor did not render {line:?}:\n{stderr}"
        );
    }

    let stdout = stdout_of(&output);
    let report: serde_json::Value = serde_json::from_str(stdout.trim()).expect("the JSON report");
    assert_eq!(
        report["acquisitionPlans"],
        serde_json::json!([
            {
                "requirement": "urn:example:doctor:requirement:one-call:v1",
                "kind": "single",
                "stages": [
                    {"source": "registry-lookup", "role": "search", "inputs": "none"}
                ]
            },
            {
                "requirement": "urn:example:doctor:requirement:two-call:v1",
                "kind": "search-then-fetch",
                "stages": [
                    {"source": "person-search", "role": "search", "inputs": "none"},
                    {"source": "person-record", "role": "member", "inputs": "every-prior-fact"}
                ]
            },
            {
                "requirement": "urn:example:doctor:requirement:fetch-set:v1",
                "kind": "search-then-fetch-set",
                "stages": [
                    {"source": "civil-record-search", "role": "search", "inputs": "none"},
                    {
                        "source": "union-register",
                        "role": "member",
                        "inputs": {"declared": ["civil_record_reference"]}
                    },
                    {
                        "source": "death-register",
                        "role": "member",
                        "inputs": {"declared": ["civil_record_reference"]}
                    }
                ]
            }
        ])
    );
    assert!(
        !stdout.contains(CANARY) && !stderr.contains(CANARY),
        "doctor echoed a document value"
    );
}

/// Assemble the smallest filesystem fixture that names every kind of artifact
/// doctor checks, then generate the private material through the public CLI.
/// The signer a local deployment declares, resolved from the same secret root
/// the bundle's other references use.
const LOCAL_SIGNER: &str =
    "signer:\n  kind: local-jwk\n  privateKeyRef: secret:file/signing-p256-private-jwk\n";

/// The signer a production deployment declares, over a socket that belongs to
/// the target host and exists nowhere in this workspace.
const TRANSIT_SIGNER: &str = "signer:\n  kind: transit\n  unixSocketPath: /run/registry-evidence/transit-proxy.sock\n  mount: transit\n  keyName: evidence-signing\n  keyVersion: 1\n  timeoutMilliseconds: 2000\n";

fn runtime_document(signer: &str) -> String {
    format!("bundleDirectory: bundle\nsecretProviders:\n  file:\n    root: secrets\n{signer}auditStorage:\n  path: audit/evidence.jsonl\n")
}

fn rewrite_runtime(project: &Path, signer: &str) {
    let path = project.join("runtime.yaml");
    let mode = mode_of(&path);
    set_mode(&path, 0o600);
    fs::write(&path, runtime_document(signer)).expect("runtime fixture");
    set_mode(&path, mode);
}

fn use_transit_signer(project: &Path) {
    rewrite_runtime(project, TRANSIT_SIGNER);
}

fn remove_signer(project: &Path) {
    rewrite_runtime(project, "");
}

fn provision(project: &Path) {
    fs::create_dir_all(project.join("bundle")).expect("bundle directory");
    fs::create_dir_all(project.join("audit")).expect("audit directory");
    fs::write(project.join("runtime.yaml"), runtime_document(LOCAL_SIGNER))
        .expect("runtime fixture");
    fs::write(
        project.join("bundle/evidence.yaml"),
        r#"authentication:
  kind: oidc-access-token
  issuer: https://identity.invalid
  audiences: [evidence-scaffold]
  tokenTypes: [at+jwt]
  algorithms: [ES256]
  jwksUri: https://identity.invalid/.well-known/jwks.json
  principalClaim: sub
  requesterTagsClaim: evidence_tags
  evidenceAudienceClaim: evidence_audience
  grantIdClaim: evidence_grant_id
  grantAuthorityClaim: evidence_authority
signing: secret:file/signing-p256-private-jwk
audit: secret:file/audit-hmac-key
subjectBinding: secret:file/subject-binding-hmac-key
sourceToken: secret:file/source-bearer-token
"#,
    )
    .expect("bundle fixture");

    let secrets = project.join("secrets");
    run_ok(&[
        "keygen",
        "signing",
        "--out-dir",
        secrets.to_str().expect("secret root"),
    ]);
    for name in SECRET_FILES {
        let out = secrets.join(name);
        run_ok(&["keygen", "secret", "--out", out.to_str().expect("secret")]);
    }
}

/// Give the fixture bundle one requirement per acquisition form, and the
/// bundle half of the gate the gated form needs.
fn declare_acquisitions(project: &Path) {
    declare_acquisitions_stating(
        project,
        "acquisitionCapabilities:\n  - search-then-fetch-set\n",
    );
}

/// The same requirements, with the bundle half of the gate exactly as written.
///
/// That half is a parameter because the runtime reads it under the same rules
/// as the deployment half, and doctor has to restate both.
fn declare_acquisitions_stating(project: &Path, capabilities: &str) {
    let path = project.join("bundle/evidence.yaml");
    let mut document = fs::read_to_string(&path).expect("Evidence configuration");
    document.push_str(DECLARED_ACQUISITIONS);
    document.push_str(capabilities);
    fs::write(&path, document).expect("declare the acquisitions");
}

/// Record the operator's half of the acquisition gate in the runtime file.
fn enable_acquisition_capability(project: &Path) {
    let path = project.join("runtime.yaml");
    let mut document = fs::read_to_string(&path).expect("runtime configuration");
    document.push_str("acquisitionCapabilities:\n  - search-then-fetch-set\n");
    fs::write(&path, document).expect("enable the acquisition capability");
}

/// Record the same decision twice, which the runtime refuses.
fn enable_acquisition_capability_twice(project: &Path) {
    let path = project.join("runtime.yaml");
    let mut document = fs::read_to_string(&path).expect("runtime configuration");
    document.push_str(
        "acquisitionCapabilities:\n  - search-then-fetch-set\n  - search-then-fetch-set\n",
    );
    fs::write(&path, document).expect("enable the acquisition capability twice");
}

fn write_mint(path: &Path, document: &str) {
    fs::create_dir_all(path.parent().expect("Mint parent")).expect("Mint directory");
    fs::write(path, document).expect("Mint configuration");
}

fn rewrite_bundle(project: &Path, original: &str, replacement: &str) {
    let path = project.join("bundle/evidence.yaml");
    let document = fs::read_to_string(&path).expect("Evidence configuration");
    fs::write(&path, replace_once(&document, original, replacement))
        .expect("rewrite Evidence configuration");
}

fn add_evidence_actor(project: &Path, actor: &str) {
    rewrite_bundle(
        project,
        "  grantAuthorityClaim: evidence_authority",
        &format!("  grantAuthorityClaim: evidence_authority\n  actorClaim: {actor}"),
    );
}

fn replace_once(document: &str, original: &str, replacement: &str) -> String {
    assert_eq!(
        document.matches(original).count(),
        1,
        "fixture must contain exactly one {original:?}"
    );
    document.replacen(original, replacement, 1)
}

fn tree_snapshot(root: &Path) -> Vec<(String, u32, Vec<u8>)> {
    let mut snapshot = Vec::new();
    collect_tree_snapshot(root, root, &mut snapshot);
    snapshot
}

fn collect_tree_snapshot(root: &Path, path: &Path, snapshot: &mut Vec<(String, u32, Vec<u8>)>) {
    let metadata = fs::symlink_metadata(path).expect("snapshot metadata");
    let relative = path
        .strip_prefix(root)
        .expect("snapshot root")
        .display()
        .to_string();
    let mode = metadata.permissions().mode() & 0o7777;
    if metadata.is_dir() {
        snapshot.push((relative, mode, Vec::new()));
        let mut entries: Vec<_> = fs::read_dir(path)
            .expect("snapshot directory")
            .map(|entry| entry.expect("snapshot entry").path())
            .collect();
        entries.sort();
        for entry in entries {
            collect_tree_snapshot(root, &entry, snapshot);
        }
    } else {
        snapshot.push((relative, mode, fs::read(path).expect("snapshot file")));
    }
}

/// The one secret the scaffolded source needs and `provision` leaves out, so a
/// test can choose whether the project is complete.
fn provision_bearer_token(project: &Path) {
    let out = project.join("secrets/source-bearer-token");
    run_ok(&["keygen", "token", "--out", out.to_str().expect("token")]);
}

fn doctor(project: &Path, extra: &[&str]) -> Output {
    let mut arguments = vec![
        "doctor",
        "--project",
        project.to_str().expect("project path"),
    ];
    arguments.extend_from_slice(extra);
    evidencectl(&arguments)
}

fn run_ok(arguments: &[&str]) {
    let output = evidencectl(arguments);
    assert!(
        output.status.success(),
        "evidencectl {} failed: {}",
        arguments[0],
        stderr_of(&output)
    );
}

fn evidencectl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .args(arguments)
        .output()
        .expect("running evidencectl")
}

fn stdout_of(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("utf8 stdout")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("utf8 stderr")
}

fn mode_of(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .expect("artifact metadata")
        .permissions()
        .mode()
        & 0o7777
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("setting a mode");
}

/// The documented freeze: no write bits anywhere in the bundle, and a read-only
/// runtime file. Evidence refuses a deployment input it could write.
fn freeze(project: &Path) {
    set_tree_mode(&project.join("bundle"), 0o555, 0o444);
    set_mode(&project.join("runtime.yaml"), 0o444);
}

/// Restore write permissions so the temporary directory can be removed.
fn unfreeze(project: &Path) {
    set_tree_mode(&project.join("bundle"), 0o755, 0o644);
    set_mode(&project.join("runtime.yaml"), 0o644);
    set_mode(&project.join("secrets"), 0o700);
}

fn set_tree_mode(path: &Path, directory_mode: u32, file_mode: u32) {
    let metadata = fs::symlink_metadata(path).expect("tree entry");
    if metadata.is_dir() {
        set_mode(path, 0o755);
        for entry in fs::read_dir(path).expect("reading a directory") {
            set_tree_mode(
                &entry.expect("tree entry").path(),
                directory_mode,
                file_mode,
            );
        }
        set_mode(path, directory_mode);
    } else {
        set_mode(path, file_mode);
    }
}

/// `doctor` is the command a newcomer reaches for first, and the project they
/// have just authored is not the shape it inspects. The refusal names the
/// shape it needs and both commands that move forward from an editable one.
#[test]
fn doctor_names_the_next_commands_when_the_project_is_still_editable() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("over18");
    let created = evidencectl(&[
        "new",
        project.to_str().expect("project path"),
        "--transport",
        "sqlite-extract",
        "--profile",
        "local",
    ]);
    assert!(created.status.success(), "{}", stderr_of(&created));

    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .arg("doctor")
        .current_dir(&project)
        .output()
        .expect("running evidencectl doctor");

    assert!(
        !output.status.success(),
        "doctor inspects a deployment project only"
    );
    let message = stderr_of(&output);
    assert!(
        message.contains("editable project"),
        "the refusal must name the shape it was handed: {message}"
    );
    assert!(
        message.contains("evidencectl build"),
        "the refusal must name the command that produces a candidate: {message}"
    );
    assert!(
        message.contains("evidencectl fixtures run"),
        "the refusal must name the command that checks an editable project: {message}"
    );
}

#[test]
fn doctor_names_the_build_command_for_a_directory_that_is_neither_shape() {
    let workspace = tempfile::tempdir().expect("tempdir");

    let output = Command::new(env!("CARGO_BIN_EXE_evidencectl"))
        .arg("doctor")
        .current_dir(workspace.path())
        .output()
        .expect("running evidencectl doctor");

    assert!(!output.status.success());
    let message = stderr_of(&output);
    assert!(
        message.contains("deployment project"),
        "the refusal must name the shape it needs: {message}"
    );
    assert!(
        message.contains("evidencectl build"),
        "the refusal must name the command that produces one: {message}"
    );
}

/// An all-green report that never mentions the signer reads as a ready target
/// host. The signer this deployment declares belongs in the report.
#[test]
fn doctor_reports_the_local_signer_it_inspected() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    provision(&project);
    provision_bearer_token(&project);
    freeze(&project);

    let output = doctor(&project, &[]);

    assert!(output.status.success(), "{}", stdout_of(&output));
    let report = stdout_of(&output);
    assert!(
        report.contains("PASS: signer"),
        "the signer belongs among the checks: {report}"
    );
    assert!(
        report.contains("local-jwk"),
        "the report must name the signer kind it inspected: {report}"
    );
}

/// A Transit signer resolves against a provider on the target host, which this
/// walk contacts as it contacts nothing else. Saying so is what keeps the
/// all-green report from reading as a ready host.
#[test]
fn doctor_states_that_a_transit_signer_is_settled_on_the_target_host() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    provision(&project);
    provision_bearer_token(&project);
    use_transit_signer(&project);
    freeze(&project);

    let output = doctor(&project, &[]);

    assert!(output.status.success(), "{}", stdout_of(&output));
    let report = stdout_of(&output);
    assert!(
        report.contains("transit"),
        "the report must name the signer kind it inspected: {report}"
    );
    assert!(
        report.contains("/run/registry-evidence/transit-proxy.sock"),
        "the report must name the provider it did not reach: {report}"
    );
    assert!(
        report.contains("evidence check"),
        "the report must name what settles the signer on the target host: {report}"
    );
}

#[test]
fn doctor_reports_a_runtime_file_that_declares_no_signer() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let project = workspace.path().join("project");
    provision(&project);
    provision_bearer_token(&project);
    remove_signer(&project);
    freeze(&project);

    let output = doctor(&project, &[]);

    assert!(!output.status.success());
    let report = stdout_of(&output);
    assert!(
        report.contains("FAIL: signer"),
        "a runtime file without a signer cannot start: {report}"
    );
}
