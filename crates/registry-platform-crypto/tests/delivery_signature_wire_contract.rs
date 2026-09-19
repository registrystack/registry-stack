// SPDX-License-Identifier: Apache-2.0
//! The Version 1 delivery signature is a wire contract, so it is pinned from
//! outside the crate: a fixed key and fixed fields produce exactly one
//! signature string, and the verifier accepts it.
//!
//! The module name is product-neutral; the bytes it signs are not free to
//! follow it. The signing domain, the length-prefixed field order, and the
//! `v1=` prefix are what a deployed receiver already verifies, so this vector
//! holds them independently of what the module or its callers are called.

use std::time::{Duration, SystemTime};

use registry_platform_crypto::delivery_signature::{sign_v1, verify_v1, SignatureFields};

const KEY: &[u8] = b"webhook-delivery-signing-key-0123456789abcdef";

/// The signature the Version 1 contract produces for [`fields`] under [`KEY`].
const PINNED_SIGNATURE: &str = "v1=OzL5k0ghZJb9nPbb-JOVsroWeanipBlZXbeKDd52RcM";

fn fields() -> SignatureFields<'static> {
    SignatureFields {
        id: "00000000-0000-4000-8000-000000000001",
        source: "urn:registrystack:registry:example:instance:primary",
        event_type: "case-created-v1",
        time: "2026-08-30T00:00:00Z",
        data_schema: "urn:registrystack:registry:example:event:case-created-v1:schema:sha256:aaa",
        generation: "1",
        attempt: "1",
        delivery_time: "2026-08-30T00:00:01Z",
        method: "POST",
        request_target: "/hooks/registry",
        content_type: "application/json",
        idempotency_key: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        body: br#"{"entity":"case","values":{"label":"value"}}"#,
    }
}

fn delivery_time() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_secs(1_788_048_001)
}

#[test]
fn signing_produces_the_pinned_version_one_signature() {
    assert_eq!(sign_v1(KEY, fields()).expect("signs"), PINNED_SIGNATURE);
}

#[test]
fn verifying_accepts_the_pinned_version_one_signature() {
    verify_v1(
        KEY,
        fields(),
        PINNED_SIGNATURE,
        delivery_time(),
        Duration::from_secs(300),
    )
    .expect("verifies");
}
