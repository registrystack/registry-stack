// SPDX-License-Identifier: Apache-2.0

use super::*;

#[test]
fn hash_api_key_uses_runtime_sha256_shape() {
    assert_eq!(
        sha256_hash("api-token"),
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51"
    );
}

#[test]
fn generated_demo_issuer_key_is_parseable() {
    let jwk = demo_issuer_jwk("did:web:localhost#demo").expect("jwk generated");
    PrivateJwk::parse(&jwk).expect("generated JWK parses");
    assert!(!format!("{jwk:?}").contains("[redacted]"));
}
