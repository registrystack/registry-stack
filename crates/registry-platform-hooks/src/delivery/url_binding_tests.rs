// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::PermissionsExt;

use registry_platform_config::{
    SecretProvider, MAX_HOOK_ATTEMPTS, MAX_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS,
    MIN_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS,
};

use super::*;

const SCHEDULING_BINDING_SCHEMA: &str = "registry.scheduling-hook-destinations/v1";
const MAXIMUM_PAYLOAD_BYTES: usize = 16 * 1024;

fn destination(url: &str, timeout: u32, attempts: u8) -> UrlHookDestinationConfig {
    serde_json::from_value(json!({
        "url": url,
        "hmacSha256KeyRef": "secret:file/hook-key",
        "attemptTimeoutMilliseconds": timeout,
        "maximumAttempts": attempts,
    }))
    .expect("the test hook destination reads")
}

/// A resolver whose file provider holds a 32-byte `hook-key`.
fn keyed_secrets() -> (tempfile::TempDir, SecretResolver) {
    let directory = tempfile::tempdir().expect("the test secret directory");
    let key_path = directory.path().join("hook-key");
    std::fs::write(&key_path, [0x5a; 32]).expect("write the test hook key");
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
        .expect("restrict the test hook key");
    let secrets = SecretResolver::new([SecretProvider::File], directory.path())
        .expect("the test secret resolver");
    (directory, secrets)
}

fn write_test_key(directory: &tempfile::TempDir, name: &str, bytes: &[u8]) {
    let path = directory.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn a_destination_key_over_64_bytes_names_its_length() {
    let (directory, secrets) = keyed_secrets();
    let mut key = [0; 65];
    key[64] = b'\n';
    write_test_key(&directory, "hook-key", &key);
    let error = activate_url_hook_destination(
        SCHEDULING_BINDING_SCHEMA,
        "events",
        &destination("https://events.example.test/hooks", 5000, 3),
        &secrets,
        MAXIMUM_PAYLOAD_BYTES,
    )
    .unwrap_err()
    .to_string();
    for expected in ["events", "hmacSha256KeyRef", "65 bytes", "newline"] {
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn a_bad_rotation_key_names_its_member_without_printing_key_bytes() {
    let (directory, secrets) = keyed_secrets();
    let mut config = destination("https://events.example.test/hooks", 5000, 3);
    config.previous_hmac_sha256_key_ref =
        Some(registry_platform_config::SecretReference::parse("secret:file/previous").unwrap());
    for (bytes, expected) in [
        (b"x".as_slice(), DeliveryKeyError::TooShort { length: 1 }),
        (b"whsec_test_value".as_slice(), DeliveryKeyError::SecretText),
        (
            [0x5a; 32].as_slice(),
            DeliveryKeyError::PreviousEqualsCurrent,
        ),
    ] {
        write_test_key(&directory, "previous", bytes);
        let error = activate_url_hook_destination(
            SCHEDULING_BINDING_SCHEMA,
            "events",
            &config,
            &secrets,
            MAXIMUM_PAYLOAD_BYTES,
        )
        .unwrap_err();
        assert_eq!(
            error,
            UrlHookActivationError::InvalidSigningKey {
                destination: "events".to_owned(),
                member: PREVIOUS_KEY_MEMBER,
                length: bytes.len(),
                trailing_newline: false,
                source: expected,
            }
        );
        assert!(!error.to_string().contains("whsec_test_value"));
    }
}

#[test]
fn two_destinations_sharing_a_key_are_refused_naming_both() {
    let (directory, secrets) = keyed_secrets();
    write_test_key(&directory, "other-key", &[0; 32]);
    let first = destination("https://events.example.test/hooks", 5000, 3);
    let mut second = first.clone();
    second.previous_hmac_sha256_key_ref = Some(second.hmac_sha256_key_ref.clone());
    second.hmac_sha256_key_ref =
        registry_platform_config::SecretReference::parse("secret:file/other-key").unwrap();
    let configured = BTreeMap::from([("events".into(), first), ("mirror".into(), second)]);
    let error = activate_url_hook_destinations(
        SCHEDULING_BINDING_SCHEMA,
        &configured,
        &secrets,
        MAXIMUM_PAYLOAD_BYTES,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("events.hmacSha256KeyRef"), "{error}");
    assert!(error.contains("mirror.previousHmacSha256KeyRef"), "{error}");
    assert!(!error.contains("hook-key"), "{error}");
}

#[test]
fn adding_a_previous_key_leaves_the_binding_digest_unchanged() {
    let (directory, secrets) = keyed_secrets();
    write_test_key(&directory, "old-key", &[0; 32]);
    let mut config = destination("https://events.example.test/hooks", 5000, 3);
    let activate = |config| {
        activate_url_hook_destinations(
            SCHEDULING_BINDING_SCHEMA,
            &BTreeMap::from([("events".into(), config)]),
            &secrets,
            MAXIMUM_PAYLOAD_BYTES,
        )
        .unwrap()
    };
    let before = activate(config.clone());
    config.previous_hmac_sha256_key_ref =
        Some(registry_platform_config::SecretReference::parse("secret:file/old-key").unwrap());
    let after = activate(config);
    assert_eq!(before.binding_digest, after.binding_digest);
    assert_eq!(
        before.bindings["events"].binding_digest(),
        after.bindings["events"].binding_digest()
    );
}

/// The digests Scheduling recorded before the block moved here. A retained
/// delivery row is refused once its recorded digest stops matching, so the
/// digest shape may not change.
#[test]
fn binding_digests_keep_the_shape_scheduling_records() {
    let (_directory, secrets) = keyed_secrets();
    let configured = BTreeMap::from([
        (
            "appointment-events".to_owned(),
            destination("https://events.example.test/scheduling", 5_000, 8),
        ),
        (
            "audit-mirror".to_owned(),
            destination("http://127.0.0.1:8080/hooks", 250, 3),
        ),
    ]);

    // Resolve the shared fixture reference in isolation for each destination.
    let (bindings, digest_values): (BTreeMap<_, _>, Vec<_>) = configured
        .iter()
        .map(|(id, config)| {
            let (destination, value) = activate_url_hook_destination(
                SCHEDULING_BINDING_SCHEMA,
                id,
                config,
                &secrets,
                MAXIMUM_PAYLOAD_BYTES,
            )
            .unwrap();
            ((id.clone(), Arc::new(destination)), value)
        })
        .unzip();
    let activated = ActivatedUrlHookDestinations {
        bindings,
        binding_digest: canonical_digest(&json!({
            "schemaVersion": SCHEDULING_BINDING_SCHEMA,
            "destinations": digest_values,
        }))
        .unwrap(),
    };
    assert_eq!(
        activated.binding_digest,
        "sha256:6021194b5df3b34eeb31b21c8b3ef448f2d639d3e8393d13b98a8276b5411df0"
    );
    assert_eq!(
        activated.bindings["appointment-events"].binding_digest(),
        "sha256:519db07c7b8250700c34939c5212b9fabf77b2c37c42e72dfa997214e4da985d"
    );
    assert_eq!(
        activated.bindings["audit-mirror"].binding_digest(),
        "sha256:dd0b35e51274ab6a1d2456e9b0520acdf5b68e720a352d0d4819f41090ff7d97"
    );
    let printed = format!("{activated:?}");
    assert!(!printed.contains("events.example.test"), "{printed}");
    assert!(!printed.contains("hook-key"), "{printed}");
}

#[test]
fn the_binding_schema_separates_digest_domains() {
    let (_directory, secrets) = keyed_secrets();
    let configured = BTreeMap::from([(
        "appointment-events".to_owned(),
        destination("https://events.example.test/scheduling", 5_000, 8),
    )]);
    let scheduling = activate_url_hook_destinations(
        SCHEDULING_BINDING_SCHEMA,
        &configured,
        &secrets,
        MAXIMUM_PAYLOAD_BYTES,
    )
    .expect("the destinations activate");
    let other = activate_url_hook_destinations(
        "registry.other-hook-destinations/v1",
        &configured,
        &secrets,
        MAXIMUM_PAYLOAD_BYTES,
    )
    .expect("the destinations activate");
    assert_ne!(scheduling.binding_digest, other.binding_digest);
}

/// Activation refuses an identifier or budget the reader refuses, at each
/// bound's edge; inside the budget a missing key is refused one step later,
/// for its signing material.
#[test]
fn activation_refuses_ids_and_budgets_outside_the_block() {
    let secrets =
        SecretResolver::new([SecretProvider::Environment], "/").expect("the test secret resolver");
    let url = "https://events.example.test/scheduling";
    let mut cases = Vec::new();
    for (timeout, accepted) in [
        (0, false),
        (MIN_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS - 1, false),
        (MIN_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS, true),
        (MAX_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS, true),
        (MAX_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS + 1, false),
        (u32::MAX, false),
    ] {
        cases.push(("events".to_owned(), timeout, 8, accepted));
    }
    for (attempts, accepted) in [
        (0, false),
        (1, true),
        (MAX_HOOK_ATTEMPTS, true),
        (MAX_HOOK_ATTEMPTS + 1, false),
        (u8::MAX, false),
    ] {
        cases.push(("events".to_owned(), 5_000, attempts, accepted));
    }
    for (id, accepted) in [
        ("a".to_owned(), true),
        ("events_2".to_owned(), true),
        ("a".repeat(64), true),
        ("a".repeat(65), false),
        (String::new(), false),
        ("Events".to_owned(), false),
        ("2events".to_owned(), false),
        ("-events".to_owned(), false),
        ("events.v1".to_owned(), false),
        ("\u{e9}v\u{e9}nements".to_owned(), false),
    ] {
        cases.push((id, 5_000, 8, accepted));
    }
    for (id, timeout, attempts, accepted) in cases {
        let mut config = destination(url, 5_000, 8);
        config.attempt_timeout_milliseconds = timeout;
        config.maximum_attempts = attempts;
        let refused = activate_url_hook_destination(
            SCHEDULING_BINDING_SCHEMA,
            &id,
            &config,
            &secrets,
            MAXIMUM_PAYLOAD_BYTES,
        )
        .map(drop)
        .expect_err("no test key resolves");
        let expected = if accepted {
            UrlHookActivationError::SigningKeyUnavailable {
                destination: id.clone(),
                member: CURRENT_KEY_MEMBER,
            }
        } else {
            UrlHookActivationError::DeliveryBudgetWidening
        };
        assert_eq!(refused, expected, "{id:?} {timeout} {attempts}");
    }
}

#[test]
fn activation_refuses_a_url_outside_the_fixed_policy() {
    let (_directory, secrets) = keyed_secrets();
    for url in [
        "http://events.example.test/hooks",
        "https://events.example.test/hooks?token=canary",
        "https://events.example.test/hooks#part",
    ] {
        let refused = activate_url_hook_destination(
            SCHEDULING_BINDING_SCHEMA,
            "events",
            &destination(url, 5_000, 8),
            &secrets,
            MAXIMUM_PAYLOAD_BYTES,
        )
        .map(drop)
        .expect_err("the URL is refused");
        assert_eq!(refused, UrlHookActivationError::InvalidDestination, "{url}");
    }
}

#[tokio::test]
async fn a_key_rotation_keeps_every_retained_delivery_acceptable() {
    use registry_platform_crypto::delivery_signature::{verify, SignedContent, DELIVERY_TOLERANCE};
    use registry_platform_httputil::destination::SignedEventHeaders;
    use std::time::SystemTime;
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
    use tokio::net::TcpListener;

    use crate::delivery::{
        DeliverySignatureFields, DestinationAnswer, HookDestination, SharedUrlDestination,
    };

    const ID: &str = "retained-event";
    const BODY: &[u8] = br#"{"event":"retained"}"#;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut config = destination(
        &format!("http://{}/hook", listener.local_addr().unwrap()),
        5000,
        3,
    );
    let (directory, secrets) = keyed_secrets();
    let k1 = || DeliveryKey::new(&[0x5a; 32]).unwrap();
    let k2 = || DeliveryKey::new(&[0; 32]).unwrap();
    let original_receiver = DeliveryKeys::new(k1(), None).unwrap();
    let rotated_receiver = DeliveryKeys::new(k2(), Some(k1())).unwrap();

    let activate = |config: &UrlHookDestinationConfig| {
        let (destination, _) = activate_url_hook_destination(
            SCHEDULING_BINDING_SCHEMA,
            "events",
            config,
            &secrets,
            MAXIMUM_PAYLOAD_BYTES,
        )
        .unwrap();
        SharedUrlDestination(Arc::new(destination))
    };

    let server = tokio::spawn(async move {
        for (timestamp, response, signature_count) in [
            (1000, "503 Service Unavailable", 1),
            (1001, "200 OK", 2),
            (1002, "200 OK", 1),
        ] {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            assert_eq!(line, "POST /hook HTTP/1.1\r\n");
            let mut headers = BTreeMap::new();
            loop {
                line.clear();
                stream.read_line(&mut line).await.unwrap();
                assert!(!line.is_empty(), "incomplete request");
                if line == "\r\n" {
                    break;
                }
                let (name, value) = line.trim_end().split_once(": ").unwrap();
                assert!(headers.insert(name.to_owned(), value.to_owned()).is_none());
            }
            let mut body = vec![0; BODY.len()];
            stream.read_exact(&mut body).await.unwrap();
            assert_eq!(body, BODY);
            let content = SignedContent {
                id: &headers["webhook-id"],
                timestamp: &headers["webhook-timestamp"],
                signature: &headers["webhook-signature"],
                body: &body,
            };
            assert_eq!(content.id, ID);
            assert_eq!(content.signature.split(' ').count(), signature_count);
            let now = SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp);
            if timestamp <= 1001 {
                assert_eq!(
                    verify(&original_receiver, content, now, DELIVERY_TOLERANCE),
                    Ok(timestamp)
                );
            }
            if timestamp >= 1001 {
                assert_eq!(
                    verify(&rotated_receiver, content, now, DELIVERY_TOLERANCE),
                    Ok(timestamp)
                );
            }
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 {response}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
        }
    });

    let send = |destination: SharedUrlDestination, timestamp: u64| async move {
        let signature = destination
            .sign_delivery(DeliverySignatureFields {
                id: ID,
                timestamp,
                body: BODY,
            })
            .unwrap();
        let request = destination
            .render_delivery(
                SignedEventHeaders {
                    id: ID.as_bytes(),
                    timestamp: timestamp.to_string().as_bytes(),
                    signature: signature.as_bytes(),
                },
                BODY.to_vec(),
            )
            .unwrap();
        destination
            .send_delivery(request, Duration::from_secs(5))
            .await
            .unwrap()
    };

    let original = activate(&config);
    let digest = original.binding_digest().to_owned();
    assert!(matches!(
        send(original, 1000).await,
        DestinationAnswer::NonSuccess { status: 503 }
    ));
    write_test_key(&directory, "previous", &[0x5a; 32]);
    write_test_key(&directory, "hook-key", &[0; 32]);
    config.previous_hmac_sha256_key_ref =
        Some(registry_platform_config::SecretReference::parse("secret:file/previous").unwrap());
    let rotated = activate(&config);
    assert_eq!(rotated.binding_digest(), digest);
    assert!(matches!(
        send(rotated, 1001).await,
        DestinationAnswer::Delivered { .. }
    ));
    config.previous_hmac_sha256_key_ref = None;
    let retired = activate(&config);
    assert_eq!(retired.binding_digest(), digest);
    assert!(matches!(
        send(retired, 1002).await,
        DestinationAnswer::Delivered { .. }
    ));
    server.await.unwrap();
}
