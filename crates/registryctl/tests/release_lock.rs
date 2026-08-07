// SPDX-License-Identifier: Apache-2.0

// This boundary test includes the implementation directly so it can exercise strict parsing
// without widening Registryctl's public API. Other production helpers are intentionally unused.
#[allow(dead_code)]
#[path = "../src/release_lock.rs"]
mod release_lock;

use release_lock::{
    verify_release_lock_for_package, RELEASE_LOCK_SCHEMA_ID, RELEASE_LOCK_SCHEMA_VERSION,
};

#[test]
fn public_boundary_rejects_duplicate_envelope_members() {
    let document = format!(
        r#"{{
          "schema_id":"{RELEASE_LOCK_SCHEMA_ID}",
          "schema_id":"{RELEASE_LOCK_SCHEMA_ID}",
          "schema_version":"{RELEASE_LOCK_SCHEMA_VERSION}",
          "signed_payload":"e30=",
          "sigstore_bundle":{{}}
        }}"#
    );
    let error = verify_release_lock_for_package(document.as_bytes())
        .err()
        .expect("duplicates fail closed");
    assert!(
        error.to_string().contains("strict duplicate-free JSON"),
        "{error:#}"
    );
}

#[test]
fn public_boundary_rejects_unknown_envelope_fields() {
    let document = format!(
        r#"{{
          "schema_id":"{RELEASE_LOCK_SCHEMA_ID}",
          "schema_version":"{RELEASE_LOCK_SCHEMA_VERSION}",
          "signed_payload":"e30=",
          "sigstore_bundle":{{}},
          "extension":true
        }}"#
    );
    let error = verify_release_lock_for_package(document.as_bytes())
        .err()
        .expect("unknown fields fail closed");
    assert!(error.to_string().contains("closed v1 schema"), "{error:#}");
}

#[test]
fn public_boundary_rejects_noncanonical_signed_payload() {
    let noncanonical = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"{ \"schema_id\": \"io.registrystack.registry_release_lock\" }",
    );
    let document = format!(
        r#"{{
          "schema_id":"{RELEASE_LOCK_SCHEMA_ID}",
          "schema_version":"{RELEASE_LOCK_SCHEMA_VERSION}",
          "signed_payload":"{noncanonical}",
          "sigstore_bundle":{{}}
        }}"#
    );
    let error = verify_release_lock_for_package(document.as_bytes())
        .err()
        .expect("noncanonical payload fails closed");
    assert!(
        error.to_string().contains("RFC 8785 canonical JSON"),
        "{error:#}"
    );
}

// A release lock produced before the Registry Notary retirement declares
// schema version 1.0 over a payload shape that no longer exists: the Notary
// image, runtime recipe, and config schema were removed. It has to be refused
// at the envelope, before any signature work, rather than reaching the payload
// parser and failing on a member name.
#[test]
fn public_boundary_rejects_the_pre_retirement_schema_version() {
    let document = format!(
        r#"{{
          "schema_id":"{RELEASE_LOCK_SCHEMA_ID}",
          "schema_version":"1.0",
          "signed_payload":"e30=",
          "sigstore_bundle":{{}}
        }}"#
    );
    let error = verify_release_lock_for_package(document.as_bytes())
        .err()
        .expect("a pre-retirement lock fails closed");
    assert!(
        error.to_string().contains("envelope schema is unsupported"),
        "{error:#}"
    );
}
