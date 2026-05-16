// SPDX-License-Identifier: Apache-2.0
//! `did:web` document builder for gateway-mode deployments.
//!
//! In gateway mode (`provenance.issuer.mode: gateway`), registry-relay hosts
//! `/.well-known/did.json`. The document contains the issuer DID, every
//! active verification method (the current signing key), and any retired
//! keys still inside their grace window.
//!
//! Delegated mode does not serve this route: the ministry hosts its own
//! DID Document.

use serde_json::{json, Value};

/// One entry in the `verificationMethod` array.
#[derive(Debug, Clone)]
pub struct VerificationMethodEntry {
    pub id: String,
    pub controller: String,
    pub public_jwk: Value,
}

/// Build the JSON-serialisable W3C DID Document for gateway mode.
///
/// `assertion_method` references only the active key id. Retired keys
/// stay in `verification_method` so cached credentials continue to
/// verify, but they are removed from `assertion_method` (a verifier
/// MUST refuse to accept a fresh credential signed by a retired key).
#[must_use]
pub fn build_did_document(
    issuer_did: &str,
    active: &VerificationMethodEntry,
    retired: &[VerificationMethodEntry],
) -> Value {
    let mut verification_method = Vec::with_capacity(1 + retired.len());
    verification_method.push(verification_method_value(active));
    for entry in retired {
        verification_method.push(verification_method_value(entry));
    }
    json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": issuer_did,
        "verificationMethod": verification_method,
        "assertionMethod": [active.id.clone()],
    })
}

fn verification_method_value(entry: &VerificationMethodEntry) -> Value {
    json!({
        "id": &entry.id,
        "type": "JsonWebKey2020",
        "controller": &entry.controller,
        "publicKeyJwk": &entry.public_jwk,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn document_carries_active_and_retired_methods() {
        let active = VerificationMethodEntry {
            id: "did:web:example#key-1".to_string(),
            controller: "did:web:example".to_string(),
            public_jwk: json!({"kty": "OKP", "crv": "Ed25519", "x": "AAAA"}),
        };
        let retired = vec![VerificationMethodEntry {
            id: "did:web:example#key-0".to_string(),
            controller: "did:web:example".to_string(),
            public_jwk: json!({"kty": "OKP", "crv": "Ed25519", "x": "BBBB"}),
        }];
        let doc = build_did_document("did:web:example", &active, &retired);
        assert_eq!(doc["id"], "did:web:example");
        let methods = doc["verificationMethod"].as_array().unwrap();
        assert_eq!(methods.len(), 2);
        assert_eq!(methods[0]["id"], "did:web:example#key-1");
        assert_eq!(methods[1]["id"], "did:web:example#key-0");
        let assertion = doc["assertionMethod"].as_array().unwrap();
        assert_eq!(assertion.len(), 1);
        assert_eq!(assertion[0], "did:web:example#key-1");
    }
}
