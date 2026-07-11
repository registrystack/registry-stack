// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn env_file_parses_quotes_export_and_comments() {
    let parsed = parse_env_file(
        r#"
# comment
export API_HASH=sha256:abc # inline
CLIENT_ID="client value"
CLIENT_SECRET='secret value'
"#,
    )
    .expect("env file parses");
    assert_eq!(
        parsed,
        vec![
            ("API_HASH".to_string(), "sha256:abc".to_string()),
            ("CLIENT_ID".to_string(), "client value".to_string()),
            ("CLIENT_SECRET".to_string(), "secret value".to_string()),
        ]
    );
}

#[test]
fn env_file_ignores_quotes_inside_trailing_comments() {
    let parsed = parse_env_file(
        r#"
DOUBLE="client value" # comment with "quote"
SINGLE='secret value' # comment with 'quote'
ESCAPED="client \"quoted\" value" # comment with "quote"
"#,
    )
    .expect("env file parses");
    assert_eq!(
        parsed,
        vec![
            ("DOUBLE".to_string(), "client value".to_string()),
            ("SINGLE".to_string(), "secret value".to_string()),
            ("ESCAPED".to_string(), "client \"quoted\" value".to_string()),
        ]
    );
}

#[test]
fn env_file_rejects_malformed_line_with_line_number() {
    let err = parse_env_file("GOOD=value\nnot valid\n").expect_err("line 2 fails");
    assert_eq!(err.line, 2);
    assert!(err.to_string().contains("line 2"));
}

#[test]
fn env_file_does_not_overwrite_by_default() {
    std::env::set_var("RN_ENV_FILE_NO_OVERWRITE_TEST", "process");
    let report =
        apply_env_file("RN_ENV_FILE_NO_OVERWRITE_TEST=file\n", false).expect("env file applies");
    assert_eq!(
        std::env::var("RN_ENV_FILE_NO_OVERWRITE_TEST").expect("env var exists"),
        "process"
    );
    assert!(report
        .skipped_existing
        .contains("RN_ENV_FILE_NO_OVERWRITE_TEST"));
    std::env::remove_var("RN_ENV_FILE_NO_OVERWRITE_TEST");
}

#[test]
fn env_file_override_replaces_existing_process_value() {
    std::env::set_var("RN_ENV_FILE_OVERRIDE_TEST", "process");
    let report =
        apply_env_file("RN_ENV_FILE_OVERRIDE_TEST=file\n", true).expect("env file applies");
    assert_eq!(
        std::env::var("RN_ENV_FILE_OVERRIDE_TEST").expect("env var exists"),
        "file"
    );
    assert!(report.loaded.contains("RN_ENV_FILE_OVERRIDE_TEST"));
    std::env::remove_var("RN_ENV_FILE_OVERRIDE_TEST");
}
