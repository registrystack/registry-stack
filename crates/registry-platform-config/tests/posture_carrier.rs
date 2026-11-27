// SPDX-License-Identifier: Apache-2.0
//! Product crates resolve the declared posture through this crate alone.

use std::ffi::OsStr;

use registry_platform_config::{
    declared_from, DeclaredPosture, Posture, PostureError, PostureSource, DEVELOPMENT, POSTURE_ENV,
};

#[test]
fn the_carrier_is_reachable_through_the_config_crate() {
    assert_eq!(POSTURE_ENV, "REGISTRY_STACK_POSTURE");
    assert_eq!(
        declared_from(Some(DEVELOPMENT), None),
        Ok(DeclaredPosture {
            posture: Posture::Development,
            source: PostureSource::Flag,
        })
    );
    let refused = declared_from(None, Some(OsStr::new("Development")))
        .expect_err("the value is case-sensitive");
    assert_eq!(refused, PostureError::InvalidEnvironment);
    assert_eq!(refused.code(), "platform.posture.invalid-value");
    // `declared` reads the process variable; this only proves the name resolves.
    let _: fn(Option<&str>) -> Result<DeclaredPosture, PostureError> =
        registry_platform_config::declared;
}
