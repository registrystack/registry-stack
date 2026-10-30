// SPDX-License-Identifier: Apache-2.0

use registry_cli_api::ApiError;

#[test]
fn api_failure_exit_classes_distinguish_refused_input_and_server_failure() {
    assert_eq!(ApiError::Usage("invalid arguments".into()).exit_code(), 2);
    assert_eq!(
        ApiError::Configuration("connection missing".into()).exit_code(),
        1
    );
    assert_eq!(ApiError::Credential.exit_code(), 1);
    assert_eq!(ApiError::HttpStatus(403).exit_code(), 1);
    assert_eq!(ApiError::HttpStatus(503).exit_code(), 3);
    for error in [
        ApiError::Connect,
        ApiError::Timeout,
        ApiError::Exchange,
        ApiError::ResponseTooLarge,
        ApiError::Io,
    ] {
        assert_eq!(error.exit_code(), 3);
    }
}
