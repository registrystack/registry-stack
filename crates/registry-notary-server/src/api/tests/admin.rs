// SPDX-License-Identifier: Apache-2.0
//! Admin API tests.

use super::*;

#[test]
fn posture_problem_response_uses_problem_json() {
    // RFC 9457 problem details must be served as application/problem+json,
    // not application/json.
    let response = posture_unavailable();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .expect("problem response sets a content-type");
    assert_eq!(
        content_type, "application/problem+json",
        "RFC 9457 problem responses must use application/problem+json"
    );
}
