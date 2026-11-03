// SPDX-License-Identifier: Apache-2.0

//! Process-isolated proof that the optional broker host cannot inherit Ring
//! from an earlier TLS client and silently use it instead of its FIPS provider.
#![cfg(feature = "job-rabbitmq")]

use std::process::Command;

use registry_adapter_job::tls_provider::initialize;

const PROBE: &str = "ADAPTER_TLS_PROVIDER_PROBE";

#[test]
fn broker_provider_policy_is_independent_of_client_construction_order() {
    for mode in ["fresh", "aws-first", "ring-first"] {
        let output = Command::new(std::env::current_exe().expect("current test executable"))
            .args(["--exact", "provider_process_probe", "--nocapture"])
            .env(PROBE, mode)
            .output()
            .expect("run the isolated provider probe");
        assert!(
            output.status.success(),
            "provider probe {mode} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn provider_process_probe() {
    let Ok(mode) = std::env::var(PROBE) else {
        return;
    };
    match mode.as_str() {
        "fresh" => {
            assert!(rustls::crypto::CryptoProvider::get_default().is_none());
            initialize().expect("the broker installs its FIPS provider first");
            initialize().expect("matching initialization is idempotent");
        }
        "aws-first" => {
            rustls::crypto::aws_lc_rs::default_provider()
                .install_default()
                .expect("the first client selects AWS-LC");
            initialize().expect("an existing matching provider is accepted");
        }
        "ring-first" => {
            rustls::crypto::ring::default_provider()
                .install_default()
                .expect("the first client selects Ring");
            let error = initialize().expect_err("a conflicting provider refuses before broker I/O");
            assert_eq!(
                error.to_string(),
                "the Adapter job requires its FIPS TLS provider before constructing clients"
            );
            assert!(!rustls::crypto::CryptoProvider::get_default()
                .expect("the original provider remains installed")
                .fips());
            return;
        }
        _ => panic!("the probe mode is fixed by this test"),
    }
    assert!(rustls::crypto::CryptoProvider::get_default()
        .expect("the provider is installed")
        .fips());
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    assert!(
        config.fips(),
        "the TLS profile retains protocol-level FIPS requirements"
    );
}
