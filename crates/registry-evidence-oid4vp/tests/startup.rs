//! What the service refuses to start on, and what the offline file check
//! refuses, each with the shared diagnostic.

mod common;

use common::{Harness, Options};
use registry_evidence_oid4vp::config::{check_file, Oid4vpConfig};
use registry_platform_yaml::Severity;

async fn startup_code(options: Options) -> String {
    let harness = Harness::new(&options).await;
    let error = harness
        .try_service()
        .await
        .expect_err("the service must refuse to start");
    let diagnostic = error.diagnostic();
    assert_eq!(diagnostic.severity, Severity::Error);
    assert!(!diagnostic.message.is_empty());
    assert!(!diagnostic.suggested_action.is_empty());
    assert!(diagnostic.path.starts_with("/clientIdentifier"));
    diagnostic.code.clone()
}

#[tokio::test]
async fn a_certificate_that_does_not_name_the_public_host_is_refused() {
    let code = startup_code(Options {
        sans: vec!["other.example.net".to_owned()],
        ..Options::default()
    })
    .await;
    assert_eq!(code, "evidence.oid4vp.certificate-san-host");
}

#[tokio::test]
async fn the_hash_identifier_does_not_need_the_host_in_the_certificate() {
    let harness = Harness::new(&Options {
        client_identifier: "x509-hash",
        sans: vec!["other.example.net".to_owned()],
        ..Options::default()
    })
    .await;
    harness.try_service().await.expect("x509_hash starts");
}

#[tokio::test]
async fn a_signing_key_that_is_not_the_leaf_key_is_refused() {
    let code = startup_code(Options {
        mismatched_key: true,
        ..Options::default()
    })
    .await;
    assert_eq!(code, "evidence.oid4vp.signing-key-mismatch");
}

#[tokio::test]
async fn an_expired_request_signing_certificate_is_refused() {
    let code = startup_code(Options {
        not_before_year: 2019,
        not_after_year: 2021,
        ..Options::default()
    })
    .await;
    assert_eq!(code, "evidence.oid4vp.certificate-expired");
}

#[tokio::test]
async fn a_certificate_that_is_not_yet_valid_is_refused() {
    let code = startup_code(Options {
        not_before_year: 2080,
        not_after_year: 2090,
        ..Options::default()
    })
    .await;
    assert_eq!(code, "evidence.oid4vp.certificate-not-yet-valid");
}

#[tokio::test]
async fn a_missing_secret_is_refused_without_naming_its_contents() {
    let harness = Harness::new(&Options::default()).await;
    std::fs::remove_file(harness.dir.path().join("secrets/signing.jwk.json")).unwrap();
    let error = harness.try_service().await.expect_err("no signing key");
    assert_eq!(
        error.diagnostic().code,
        "evidence.oid4vp.secret-unavailable"
    );
    assert_eq!(
        error.diagnostic().path,
        "/clientIdentifiers/0/signingKeyRef"
    );
}

fn codes(harness: &Harness) -> Vec<String> {
    check_file(&harness.config_path, false)
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.code.clone())
        .collect()
}

fn edit(harness: &Harness, from: &str, to: &str) {
    let text = std::fs::read_to_string(&harness.config_path).unwrap();
    assert!(text.contains(from), "{from} is in the file");
    std::fs::write(&harness.config_path, text.replacen(from, to, 1)).unwrap();
}

#[tokio::test]
async fn the_unedited_deployment_passes_the_offline_check() {
    let harness = Harness::new(&Options::default()).await;
    assert_eq!(codes(&harness), Vec::<String>::new());
    assert!(Oid4vpConfig::load(&harness.config_path).is_ok());
}

#[tokio::test]
async fn an_empty_policy_identifier_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(&harness, "- id: national-id", "- id: \"\"");
    let codes = codes(&harness);
    assert!(!codes.is_empty());
    assert!(Oid4vpConfig::load(&harness.config_path).is_err());
}

#[tokio::test]
async fn a_duplicate_policy_identifier_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(&harness, "- id: age-check", "- id: national-id");
    assert_eq!(codes(&harness), vec!["config.duplicate-id".to_owned()]);
}

#[tokio::test]
async fn a_file_without_policies_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    let text = std::fs::read_to_string(&harness.config_path).unwrap();
    let start = text.find("policies:").unwrap();
    let end = text.find("sessions:").unwrap();
    std::fs::write(
        &harness.config_path,
        format!("{}policies: []\n{}", &text[..start], &text[end..]),
    )
    .unwrap();
    assert_eq!(
        codes(&harness),
        vec!["evidence.oid4vp.no-policies".to_owned()]
    );
}

#[tokio::test]
async fn a_camel_case_client_identifier_tag_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(&harness, "type: x509-san-dns", "type: x509SanDns");
    assert!(!codes(&harness).is_empty());
}

#[tokio::test]
async fn a_public_base_url_with_a_path_or_plain_http_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(
        &harness,
        &format!("publicBaseUrl: https://{}", common::HOST),
        &format!("publicBaseUrl: https://{}/wallet", common::HOST),
    );
    assert_eq!(
        codes(&harness),
        vec!["evidence.oid4vp.public-base-path".to_owned()]
    );

    edit(
        &harness,
        "publicBaseUrl: https://",
        "publicBaseUrl: http://",
    );
    assert!(codes(&harness).contains(&"evidence.oid4vp.https-required".to_owned()));
}

#[tokio::test]
async fn a_secret_reference_to_a_disabled_provider_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(
        &harness,
        "certificateChainRef: secret:file/chain.pem",
        "certificateChainRef: secret:env/CHAIN",
    );
    assert_eq!(
        codes(&harness),
        vec!["evidence.oid4vp.secret-provider-disabled".to_owned()]
    );
}

#[tokio::test]
async fn an_authority_key_identifier_that_is_not_base64url_is_refused() {
    let harness = Harness::new(&Options {
        trusted_authorities: true,
        ..Options::default()
    })
    .await;
    edit(
        &harness,
        "values: [c2lnbmluZy1rZXktaWRlbnRpZmllcg]",
        "values: [\"not base64!\"]",
    );
    assert!(
        codes(&harness).contains(&"evidence.oid4vp.invalid-authority-key-identifier".to_owned())
    );
}

#[tokio::test]
async fn session_lifetimes_and_limits_have_bounds() {
    let harness = Harness::new(&Options::default()).await;
    edit(&harness, "sessionTtlSeconds: 300", "sessionTtlSeconds: 5");
    assert!(!codes(&harness).is_empty());
    edit(&harness, "sessionTtlSeconds: 5", "sessionTtlSeconds: 300");
    edit(
        &harness,
        "maximumLiveSessions: 64",
        "maximumLiveSessions: 0",
    );
    assert!(!codes(&harness).is_empty());
}

#[tokio::test]
async fn an_empty_claim_path_segment_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(&harness, "- path: [given_name]", "- path: [\"\"]");
    assert!(!codes(&harness).is_empty());
    assert!(Oid4vpConfig::load(&harness.config_path).is_err());
}

#[tokio::test]
async fn a_claim_path_may_repeat_a_name() {
    let harness = Harness::new(&Options::default()).await;
    edit(
        &harness,
        "- path: [given_name]",
        "- path: [address, address]",
    );
    assert_eq!(codes(&harness), Vec::<String>::new());
}

#[tokio::test]
async fn response_and_read_rate_limits_have_bounds() {
    for member in [
        "walletResponsesPerMinute",
        "walletResponseBurst",
        "responsesPerRequestPerMinute",
        "responseBurstPerRequest",
        "evidenceReadsPerMinute",
        "evidenceReadBurst",
    ] {
        for bad in ["0", "99999999999", "-1", "\"fast\""] {
            let harness = Harness::new(&Options::default()).await;
            let text = std::fs::read_to_string(&harness.config_path).unwrap();
            let line = text
                .lines()
                .find(|line| line.trim_start().starts_with(&format!("{member}:")))
                .unwrap_or_else(|| panic!("{member} is in the deployment"))
                .to_owned();
            edit(&harness, &line, &format!("  {member}: {bad}"));
            assert!(!codes(&harness).is_empty(), "{member}: {bad}");
            assert!(
                Oid4vpConfig::load(&harness.config_path).is_err(),
                "{member}: {bad}"
            );
        }
    }
}

#[tokio::test]
async fn the_response_and_read_limits_default_when_omitted() {
    let harness = Harness::new(&Options::default()).await;
    let text = std::fs::read_to_string(&harness.config_path).unwrap();
    let kept: Vec<&str> = text
        .lines()
        .filter(|line| {
            ![
                "walletResponsesPerMinute",
                "walletResponseBurst",
                "responsesPerRequestPerMinute",
                "responseBurstPerRequest",
                "evidenceReadsPerMinute",
                "evidenceReadBurst",
            ]
            .iter()
            .any(|member| line.trim_start().starts_with(&format!("{member}:")))
        })
        .collect();
    std::fs::write(&harness.config_path, kept.join("\n")).unwrap();
    let config = Oid4vpConfig::load(&harness.config_path).expect("defaults apply");
    assert_eq!(config.rate_limits.wallet_responses_per_minute, 600);
    assert_eq!(config.rate_limits.responses_per_request_per_minute, 12);
    assert_eq!(config.rate_limits.evidence_read_burst, 100);
}

#[tokio::test]
async fn a_policy_naming_an_unknown_client_identifier_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(
        &harness,
        "clientIdentifier: haip",
        "clientIdentifier: missing",
    );
    assert_eq!(
        codes(&harness),
        vec!["evidence.oid4vp.unknown-client-identifier".to_owned()]
    );
    assert!(Oid4vpConfig::load(&harness.config_path).is_err());
}

#[tokio::test]
async fn a_client_identifier_no_policy_uses_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(
        &harness,
        "clientIdentifier: inji-registered",
        "clientIdentifier: inji-did",
    );
    assert_eq!(
        codes(&harness),
        vec!["evidence.oid4vp.unused-client-identifier".to_owned()]
    );
}

#[tokio::test]
async fn a_duplicate_client_identifier_id_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(&harness, "- id: inji-registered\n", "- id: inji-did\n");
    assert!(codes(&harness).contains(&"config.duplicate-id".to_owned()));
}

#[tokio::test]
async fn a_policy_must_name_its_client_identifier() {
    let harness = Harness::new(&Options::default()).await;
    edit(&harness, "    clientIdentifier: haip\n", "");
    assert!(!codes(&harness).is_empty());
    assert!(Oid4vpConfig::load(&harness.config_path).is_err());
}

#[tokio::test]
async fn a_did_web_identifier_must_name_the_public_host_alone() {
    for (did, code) in [
        ("did:web:other.example.net", "evidence.oid4vp.did-web-host"),
        (
            "did:web:verifier.example.org%3A8443",
            "evidence.oid4vp.did-web-port-or-path",
        ),
        (
            "did:web:verifier.example.org:users:verifier",
            "evidence.oid4vp.did-web-port-or-path",
        ),
        ("did:key:z6MkExample", "evidence.oid4vp.did-web-invalid"),
        ("did:web:", "evidence.oid4vp.did-web-invalid"),
    ] {
        let harness = Harness::new(&Options::default()).await;
        edit(
            &harness,
            "did: did:web:verifier.example.org",
            &format!("did: \"{did}\""),
        );
        assert_eq!(codes(&harness), vec![code.to_owned()], "{did}");
    }
}

#[tokio::test]
async fn a_did_web_identifier_is_refused_when_the_public_url_has_a_port() {
    let harness = Harness::new(&Options::default()).await;
    edit(
        &harness,
        "publicBaseUrl: https://verifier.example.org",
        "publicBaseUrl: https://verifier.example.org:8443",
    );
    assert_eq!(
        codes(&harness),
        vec!["evidence.oid4vp.did-web-public-port".to_owned()]
    );
}

#[tokio::test]
async fn a_pre_registered_client_id_with_a_colon_is_refused() {
    let harness = Harness::new(&Options::default()).await;
    edit(
        &harness,
        "clientId: evidence-verifier",
        "clientId: x509_san_dns:verifier.example.org",
    );
    assert_eq!(
        codes(&harness),
        vec!["evidence.oid4vp.pre-registered-client-id".to_owned()]
    );
}

#[tokio::test]
async fn a_signing_key_that_is_not_ed25519_is_refused_for_the_inji_identifiers() {
    for (secret, index) in [
        ("did-signing.jwk.json", 1),
        ("registered-signing.jwk.json", 2),
    ] {
        let harness = Harness::new(&Options::default()).await;
        std::fs::write(
            harness.dir.path().join("secrets").join(secret),
            &harness.keys.private_jwk,
        )
        .unwrap();
        let error = harness
            .try_service()
            .await
            .expect_err("a P-256 key cannot sign for Inji");
        assert_eq!(
            error.diagnostic().code,
            "evidence.oid4vp.signing-key-not-ed25519"
        );
        assert_eq!(
            error.diagnostic().path,
            format!("/clientIdentifiers/{index}/signingKeyRef")
        );
    }
}

#[tokio::test]
async fn two_identifiers_with_one_client_id_are_refused_at_startup() {
    let harness = Harness::new(&Options::default()).await;
    edit(
        &harness,
        "type: pre-registered\n    clientId: evidence-verifier",
        "type: decentralized-identifier\n    did: did:web:verifier.example.org",
    );
    assert_eq!(codes(&harness), Vec::<String>::new());
    let code = startup_code_for(&harness).await;
    assert_eq!(code, "evidence.oid4vp.duplicate-client-identifier");
}

async fn startup_code_for(harness: &Harness) -> String {
    harness
        .try_service()
        .await
        .expect_err("the service must refuse to start")
        .diagnostic()
        .code
        .clone()
}
