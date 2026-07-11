// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_support::*;

#[test]
fn bind_override_replaces_config_bind() {
    let mut config = doctor_live_test_config("http://127.0.0.1:1");
    config.server.bind = "127.0.0.1:8081".parse().expect("socket addr parses");

    apply_bind_override(
        &mut config,
        Some("0.0.0.0:8080".parse().expect("socket addr parses")),
    );

    assert_eq!(
        config.server.bind,
        "0.0.0.0:8080"
            .parse::<SocketAddr>()
            .expect("socket addr parses")
    );
}
