use std::collections::BTreeMap;

use registry_breg_client::{
    verify_webhook_delivery, BRegWebhookDelivery, BRegWebhookVerificationError,
};

const KEY: &[u8] = b"webhook-delivery-signing-key-0123456789abcdef";
const BODY: &[u8] = br#"{"entity":"case","values":{"label":"value"}}"#;
const SIGNATURE: &str = "v1=OzL5k0ghZJb9nPbb-JOVsroWeanipBlZXbeKDd52RcM";

fn headers() -> BTreeMap<String, String> {
    [
        ("Ce-Specversion", "1.0"),
        ("CE-ID", "00000000-0000-4000-8000-000000000001"),
        (
            "ce-source",
            "urn:registrystack:registry:example:instance:primary",
        ),
        ("ce-type", "case-created-v1"),
        ("ce-time", "2026-08-30T00:00:00Z"),
        (
            "ce-dataschema",
            "urn:registrystack:registry:example:event:case-created-v1:schema:sha256:aaa",
        ),
        ("x-registry-event-generation", "1"),
        ("x-registry-delivery-attempt", "1"),
        ("x-registry-delivery-time", "2026-08-30T00:00:01Z"),
        (
            "idempotency-key",
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        ),
        ("content-type", "application/json"),
        ("x-registry-signature", SIGNATURE),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value.to_owned()))
    .collect()
}

fn delivery<'a>(
    headers: &'a BTreeMap<String, String>,
    body: &'a [u8],
    key: &'a [u8],
) -> BRegWebhookDelivery<'a> {
    BRegWebhookDelivery {
        method: "POST",
        path: "/hooks/registry",
        headers,
        body,
        key,
    }
}

#[test]
fn fixed_vector_verifies_and_returns_exact_delivery() {
    let headers = headers();
    let verified = verify_webhook_delivery(delivery(&headers, BODY, KEY)).unwrap();

    assert_eq!(verified.id, "00000000-0000-4000-8000-000000000001");
    assert_eq!(
        verified.source,
        "urn:registrystack:registry:example:instance:primary"
    );
    assert_eq!(verified.event_type, "case-created-v1");
    assert_eq!(verified.time, "2026-08-30T00:00:00Z");
    assert_eq!(
        verified.data_schema,
        "urn:registrystack:registry:example:event:case-created-v1:schema:sha256:aaa"
    );
    assert_eq!(verified.generation, "1");
    assert_eq!(verified.attempt, "1");
    assert_eq!(verified.delivery_time, "2026-08-30T00:00:01Z");
    assert_eq!(
        verified.idempotency_key,
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    );
    assert_eq!(verified.body, BODY);

    let debug = format!("{verified:?}");
    assert!(!debug.contains(&format!("{:?}", BODY.to_vec())));
    assert!(debug.contains("body_bytes"));
}

#[test]
fn refusal_codes_are_closed_and_value_free() {
    let mut missing = headers();
    missing.remove("ce-type");
    assert_eq!(
        verify_webhook_delivery(delivery(&missing, BODY, KEY)),
        Err(BRegWebhookVerificationError::MissingHeader)
    );

    let mut malformed = headers();
    malformed.insert("x-registry-signature".into(), "v1=truncated".into());
    assert_eq!(
        verify_webhook_delivery(delivery(&malformed, BODY, KEY)),
        Err(BRegWebhookVerificationError::MalformedSignature)
    );

    let mut unsupported = headers();
    unsupported.insert(
        "x-registry-signature".into(),
        SIGNATURE.replacen("v1=", "v2=", 1),
    );
    assert_eq!(
        verify_webhook_delivery(delivery(&unsupported, BODY, KEY)),
        Err(BRegWebhookVerificationError::UnsupportedVersion)
    );

    let mut tampered = headers();
    tampered.insert("ce-type".into(), "case-patched-v1".into());
    assert_eq!(
        verify_webhook_delivery(delivery(&tampered, BODY, KEY)),
        Err(BRegWebhookVerificationError::SignatureMismatch)
    );

    for error in [
        BRegWebhookVerificationError::MissingHeader,
        BRegWebhookVerificationError::MalformedSignature,
        BRegWebhookVerificationError::SignatureMismatch,
        BRegWebhookVerificationError::UnsupportedVersion,
    ] {
        assert!(!error.to_string().contains(SIGNATURE));
        assert!(!error.to_string().contains("case-patched-v1"));
    }
}
