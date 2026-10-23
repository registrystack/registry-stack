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

    let activated = activate_url_hook_destinations(
        SCHEDULING_BINDING_SCHEMA,
        &configured,
        &secrets,
        MAXIMUM_PAYLOAD_BYTES,
    )
    .expect("the pinned destinations activate");

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
            UrlHookActivationError::InvalidSigningMaterial
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
