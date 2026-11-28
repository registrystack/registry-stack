// SPDX-License-Identifier: Apache-2.0
//! Bounded probe for the Docker-network OIDC runtime-configuration journey.

use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let path = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("one runtime configuration path is required");
    let config = registry_breg::runtime_config::load_runtime_config(
        &path,
        registry_platform_config::DeclaredPosture {
            posture: registry_platform_config::Posture::Production,
            source: registry_platform_config::PostureSource::Default,
        },
    )
    .expect("the BReg runtime configuration loads");
    let issuers = config
        .authenticator_issuers()
        .await
        .expect("configured issuer discovery is accepted");
    for issuer in &issuers {
        issuer
            .key_source()
            .ensure_key_set()
            .await
            .expect("the discovered same-origin JWKS is fetched");
    }
    println!("allowed");
}
