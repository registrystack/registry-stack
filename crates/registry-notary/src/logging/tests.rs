// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::test_support::*;

#[test]
fn default_log_filter_is_plain_info() {
    assert_eq!(default_log_filter(), "info");
    assert!(!default_log_filter().contains("debug"));
}

#[test]
fn log_format_env_accepts_text_and_json() {
    let _guard = ENV_LOCK.lock().expect("env lock");
    std::env::remove_var("REGISTRY_NOTARY_LOG_FORMAT");
    assert_eq!(
        log_format_from_env().expect("default is text"),
        LogFormat::Text
    );

    std::env::set_var("REGISTRY_NOTARY_LOG_FORMAT", "json");
    assert_eq!(
        log_format_from_env().expect("json is accepted"),
        LogFormat::Json
    );

    std::env::set_var("REGISTRY_NOTARY_LOG_FORMAT", "text");
    assert_eq!(
        log_format_from_env().expect("text is accepted"),
        LogFormat::Text
    );

    std::env::set_var("REGISTRY_NOTARY_LOG_FORMAT", "pretty");
    let err = log_format_from_env().expect_err("unknown format fails");
    assert!(err.contains("text"));
    assert!(err.contains("json"));

    std::env::remove_var("REGISTRY_NOTARY_LOG_FORMAT");
}
