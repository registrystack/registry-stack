// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_support::*;

#[test]
fn healthcheck_cli_defaults_to_container_health_endpoint() {
    let args = Args::try_parse_from(["registry-notary", "healthcheck"]).expect("args parse");
    let Some(Command::Healthcheck { url, timeout_ms }) = args.command else {
        panic!("expected healthcheck command");
    };

    assert_eq!(url, "http://127.0.0.1:8080/healthz");
    assert_eq!(timeout_ms, 5000);
}

#[test]
fn healthcheck_cli_accepts_url_and_timeout_overrides() {
    let args = Args::try_parse_from([
        "registry-notary",
        "healthcheck",
        "--url",
        "http://127.0.0.1:9000/ready",
        "--timeout-ms",
        "250",
    ])
    .expect("args parse");
    let Some(Command::Healthcheck { url, timeout_ms }) = args.command else {
        panic!("expected healthcheck command");
    };

    assert_eq!(url, "http://127.0.0.1:9000/ready");
    assert_eq!(timeout_ms, 250);
}

#[test]
fn healthcheck_cli_rejects_zero_timeout() {
    let err = Args::try_parse_from(["registry-notary", "healthcheck", "--timeout-ms", "0"])
        .expect_err("zero timeout is rejected");

    assert!(err.to_string().contains("invalid value"));
}

#[test]
fn build_info_cli_parses() {
    let args = Args::try_parse_from(["registry-notary", "build-info"]).expect("args parse");
    assert!(matches!(args.command, Some(Command::BuildInfo)));
}

#[test]
fn build_info_reports_compiled_pkcs11_capability() {
    let info = build_info();
    assert_eq!(info["package"], "registry-notary");
    assert_eq!(
        info["capabilities"]["signing_providers"]["pkcs11"],
        json!(cfg!(feature = "pkcs11"))
    );
    let features = info["build_features"]
        .as_array()
        .expect("build_features is an array");
    assert_eq!(
        features.iter().any(|feature| feature == "pkcs11"),
        cfg!(feature = "pkcs11")
    );
}

#[tokio::test]
async fn healthcheck_succeeds_for_success_status() {
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route("/healthz", get(|| async { StatusCode::OK })));
    let base_url = upstream.server_address().expect("upstream address");
    let url = format!("{}/healthz", base_url.as_str().trim_end_matches('/'));

    run_healthcheck(&url, Duration::from_secs(1))
        .await
        .expect("healthcheck succeeds");
}

#[tokio::test]
async fn healthcheck_fails_for_non_success_status() {
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/healthz",
            get(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        ));
    let base_url = upstream.server_address().expect("upstream address");
    let url = format!("{}/healthz", base_url.as_str().trim_end_matches('/'));

    let err = run_healthcheck(&url, Duration::from_secs(1))
        .await
        .expect_err("healthcheck fails");
    assert!(err.to_string().contains("HTTP 503"));
}
