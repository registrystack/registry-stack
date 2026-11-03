// SPDX-License-Identifier: Apache-2.0

use registry_adapter_core::{EndpointAuthentication, EndpointBinding};
use registry_adapter_engine::auth::{AuthPlan, AuthPlanFault};
use serde_json::json;

fn binding(endpoint: &str, private_key: bool) -> EndpointBinding {
    let credential = if private_key {
        json!({
            "type":"oauth2-private-key-jwt",
            "tokenEndpoint":endpoint,
            "clientIdRef":"secret:env/UNRESOLVED_CLIENT_ID",
            "clientAssertionKeyRef":"secret:env/UNRESOLVED_ASSERTION_KEY",
            "maximumCacheSeconds":60
        })
    } else {
        json!({
            "type":"oauth2-client-credentials",
            "tokenEndpoint":endpoint,
            "clientIdRef":"secret:env/UNRESOLVED_CLIENT_ID",
            "clientSecretRef":"secret:env/UNRESOLVED_CLIENT_SECRET",
            "credentialPlacement":"form-body",
            "maximumCacheSeconds":60
        })
    };
    serde_json::from_value(json!({
        "endpoint":"provider",
        "baseUrl":"https://source.invalid",
        "credential":credential
    }))
    .expect("the endpoint binding parses before authentication admission")
}

fn authentication(private_key: bool) -> EndpointAuthentication {
    if private_key {
        EndpointAuthentication::Oauth2PrivateKeyJwt {}
    } else {
        EndpointAuthentication::Oauth2ClientCredentials {}
    }
}

#[test]
fn token_endpoint_uri_bytes_are_refused_before_audience_or_credential_use() {
    for private_key in [false, true] {
        for endpoint in [
            "https://issuer.invalid/tokén",
            "https://issuer.invalid/token{raw}",
            "https://issuer.invalid/token%GG",
            "https://issuer.invalid/token%",
        ] {
            let binding = binding(endpoint, private_key);
            let result = AuthPlan::compile(&authentication(private_key), &binding);
            assert!(
                matches!(result, Err(AuthPlanFault::TokenEndpointNotUsable)),
                "token endpoints require exact ASCII URI bytes and complete percent escapes"
            );
        }
    }
}

#[test]
fn explicitly_encoded_token_endpoint_uris_remain_usable_for_both_oauth_kinds() {
    for private_key in [false, true] {
        for endpoint in [
            "https://issuer.invalid/tok%C3%A9n",
            "https://issuer.invalid/token%7Braw%7D",
            "https://issuer.invalid/token%20archive",
            "https://issuer.invalid/token",
        ] {
            AuthPlan::compile(
                &authentication(private_key),
                &binding(endpoint, private_key),
            )
            .expect("an explicitly encoded absolute token URI remains usable");
        }
    }
}
