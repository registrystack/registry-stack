// SPDX-License-Identifier: Apache-2.0

use registry_platform_canonical_json::parse_json_strict;
use serde_json::json;

const ADDITIVE_RESPONSE_PROOF: &str =
    "registry-discovery-client::client::tests::real_client_ignores_additive_response_members_at_every_response_level";

#[test]
fn unified_sdk_metadata_names_the_tested_discovery_patch_line_and_proof() {
    let metadata = parse_json_strict(include_bytes!(
        "../../registry-stack-client/compatibility.json"
    ))
    .expect("compatibility metadata is duplicate-free JSON");

    assert_eq!(
        metadata,
        json!({
            "schemaVersion": "registry-stack.sdk-compatibility.v1",
            "sdkPackage": {
                "name": "registry-stack-client",
                "version": env!("CARGO_PKG_VERSION")
            },
            "namespaces": {
                "discovery": {
                    "testedServerBaseline": "0.44.0",
                    "compatibleServerPatchLine": "0.44.x",
                    "responseCompatibility": {
                        "additiveObjectMembers": "ignored-after-duplicate-key-rejection",
                        "unknownProblemCodes": "http-status-only",
                        "proof": ADDITIVE_RESPONSE_PROOF
                    }
                }
            }
        })
    );
}
