// SPDX-License-Identifier: Apache-2.0

use std::os::unix::fs::PermissionsExt;

use registry_platform_config::{
    RuntimeConfigLoader, RuntimeEnvelope, SecretProvider, MAX_HOOK_ATTEMPTS,
    MAX_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS, MIN_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS,
};
use registry_platform_httputil::select::DestinationSelectionError;

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
    for expected in [
        "events",
        "hmacSha256KeyRef",
        "65 bytes",
        "trailing newline: true",
    ] {
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
                reason: expected,
            }
        );
        assert!(!error.to_string().contains("whsec_test_value"));
        if expected == DeliveryKeyError::PreviousEqualsCurrent {
            assert_eq!(
                error.to_string(),
                "events.previousHmacSha256KeyRef holds the same bytes as \
                 events.hmacSha256KeyRef. To rotate, write 32 new random bytes to the secret \
                 events.hmacSha256KeyRef references and keep the old bytes behind \
                 events.previousHmacSha256KeyRef."
            );
        }
    }
}

#[test]
fn an_unsafe_secret_keeps_its_value_free_refusal_reason() {
    use std::error::Error as _;

    let (directory, secrets) = keyed_secrets();
    std::fs::set_permissions(
        directory.path().join("hook-key"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let error = activate_url_hook_destination(
        SCHEDULING_BINDING_SCHEMA,
        "events",
        &destination("https://events.example.test/hooks", 5000, 3),
        &secrets,
        MAXIMUM_PAYLOAD_BYTES,
    )
    .unwrap_err();
    let UrlHookActivationError::SigningKeyUnavailable { reason, .. } = &error else {
        panic!("expected secret resolution refusal");
    };
    assert!(matches!(reason, SecretError::UnsafeFile(_)));
    let diagnostic = error.to_string();
    assert!(diagnostic.contains(reason.suggested_action()));
    assert!(!diagnostic.contains("hook-key"));
    assert!(error.source().is_none());
}

#[test]
fn two_destinations_sharing_a_key_are_refused_naming_both() {
    let (directory, secrets) = keyed_secrets();
    write_test_key(&directory, "other-key", &[0; 32]);
    write_test_key(&directory, "third-key", &[1; 32]);
    let shared = SecretReference::parse("secret:file/hook-key").unwrap();
    let other = SecretReference::parse("secret:file/other-key").unwrap();
    let third = SecretReference::parse("secret:file/third-key").unwrap();
    for (first_previous, second_previous) in [(false, false), (false, true), (true, true)] {
        let config = destination("https://events.example.test/hooks", 5000, 3);
        let mut first = config.clone();
        let mut second = config;
        if first_previous {
            first.hmac_sha256_key_ref = other.clone();
            first.previous_hmac_sha256_key_ref = Some(shared.clone());
        }
        if second_previous {
            second.hmac_sha256_key_ref = third.clone();
            second.previous_hmac_sha256_key_ref = Some(shared.clone());
        }
        let error = activate_url_hook_destinations(
            SCHEDULING_BINDING_SCHEMA,
            &BTreeMap::from([("events".into(), first), ("mirror".into(), second)]),
            &secrets,
            MAXIMUM_PAYLOAD_BYTES,
        )
        .unwrap_err();
        let member = |previous| {
            if previous {
                PREVIOUS_KEY_MEMBER
            } else {
                CURRENT_KEY_MEMBER
            }
        };
        assert_eq!(
            error,
            UrlHookActivationError::RepeatedSigningKey {
                first: format!("events.{}", member(first_previous)),
                second: format!("mirror.{}", member(second_previous)),
            }
        );
        assert!(!error.to_string().contains("hook-key"));
        let (first_label, second_label) = (
            format!("events.{}", member(first_previous)),
            format!("mirror.{}", member(second_previous)),
        );
        assert_eq!(
            error.to_string(),
            format!(
                "{first_label} and {second_label} resolve to the same key bytes. Give \
                 {second_label} its own key by writing 32 new random bytes to another secret \
                 and referencing it there."
            )
        );
    }
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
    let (directory, secrets) = keyed_secrets();
    let mut configured = BTreeMap::from([
        (
            "appointment-events".to_owned(),
            destination("https://events.example.test/scheduling", 5_000, 8),
        ),
        (
            "audit-mirror".to_owned(),
            destination("http://127.0.0.1:8080/hooks", 250, 3),
        ),
    ]);

    let mut digest_values = Vec::new();
    for (id, expected) in [
        (
            "appointment-events",
            "sha256:519db07c7b8250700c34939c5212b9fabf77b2c37c42e72dfa997214e4da985d",
        ),
        (
            "audit-mirror",
            "sha256:dd0b35e51274ab6a1d2456e9b0520acdf5b68e720a352d0d4819f41090ff7d97",
        ),
    ] {
        let (binding, value) = activate_url_hook_destination(
            SCHEDULING_BINDING_SCHEMA,
            id,
            &configured[id],
            &secrets,
            MAXIMUM_PAYLOAD_BYTES,
        )
        .unwrap();
        assert_eq!(binding.binding_digest(), expected);
        digest_values.push(value);
    }
    assert_eq!(
        inventory_digest(SCHEDULING_BINDING_SCHEMA, digest_values).unwrap(),
        "sha256:6021194b5df3b34eeb31b21c8b3ef448f2d639d3e8393d13b98a8276b5411df0",
    );

    // The live inventory uses distinct key references and bytes.
    write_test_key(&directory, "mirror-key", &[0; 32]);
    configured
        .get_mut("audit-mirror")
        .unwrap()
        .hmac_sha256_key_ref = SecretReference::parse("secret:file/mirror-key").unwrap();
    let activated = activate_url_hook_destinations(
        SCHEDULING_BINDING_SCHEMA,
        &configured,
        &secrets,
        MAXIMUM_PAYLOAD_BYTES,
    )
    .unwrap();
    assert_eq!(
        activated.binding_digest,
        "sha256:63f9ba0e4c8368aa0a5f82253a3523ed604c0553b8f39c7e349b5277fc962782"
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
                reason: SecretError::ProviderDisabled,
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
    for (url, expected) in [
        (
            "http://events.example.test/hooks",
            UrlHookActivationError::DestinationRefused(
                DestinationSelectionError::PrivateNetworkNotDeclared,
            ),
        ),
        (
            "https://events.example.test/hooks?token=canary",
            UrlHookActivationError::InvalidDestination,
        ),
        (
            "https://events.example.test/hooks#part",
            UrlHookActivationError::InvalidDestination,
        ),
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
        assert_eq!(refused, expected, "{url}");
        assert!(!refused.to_string().contains("canary"), "{refused}");
    }
}

fn declared_destination(
    url: &str,
    transport: Option<&str>,
    ranges: &[&str],
) -> UrlHookDestinationConfig {
    let mut value = json!({
        "url": url,
        "hmacSha256KeyRef": "secret:file/hook-key",
        "allowedPrivateCidrs": ranges,
    });
    if let Some(transport) = transport {
        value["transport"] = json!(transport);
    }
    serde_json::from_value(value).expect("the test hook destination reads")
}

fn activate(
    secrets: &SecretResolver,
    config: &UrlHookDestinationConfig,
) -> Result<(UrlDestination, Value), UrlHookActivationError> {
    activate_url_hook_destination(
        SCHEDULING_BINDING_SCHEMA,
        "events",
        config,
        secrets,
        MAXIMUM_PAYLOAD_BYTES,
    )
}

/// T8 through the shared block: a declared private plain-text destination
/// activates under its ranges, and its binding digest covers both.
#[test]
fn a_private_plain_text_destination_activates_under_its_ranges() {
    let (_directory, secrets) = keyed_secrets();
    let (destination, digest_value) = activate(
        &secrets,
        &declared_destination(
            "http://receiver:9000/hooks",
            Some("private-network-plaintext"),
            &["172.16.0.0/12"],
        ),
    )
    .expect("a declared private plain-text destination activates");
    let policy = format!("{:?}", destination.policy());
    assert!(policy.contains("PrivateServiceHttp"), "{policy}");
    assert!(policy.contains("private_cidr_count: 1"), "{policy}");
    assert_eq!(destination.request_target(), "/hooks");
    assert_eq!(digest_value["transport"], "private-network-plaintext");
    assert_eq!(
        digest_value["allowedPrivateCidrs"],
        json!(["172.16.0.0/12"])
    );
}

/// A retained delivery row is refused once its destination changed, so the
/// ranges and a private plain-text transport enter the binding digest. A
/// transport the URL already implies leaves the digest as it was.
#[test]
fn the_binding_digest_covers_the_ranges_and_private_plain_text_only() {
    let (_directory, secrets) = keyed_secrets();
    let digest = |config: &UrlHookDestinationConfig| {
        activate(&secrets, config)
            .expect("the destination activates")
            .0
            .binding_digest()
            .to_owned()
    };
    let https = "https://events.example.test/scheduling";
    let plain = digest(&declared_destination(https, None, &[]));
    assert_eq!(digest(&destination(https, 5_000, 8)), plain);
    assert_eq!(
        digest(&declared_destination(https, Some("verified-tls"), &[])),
        plain
    );
    assert_ne!(
        digest(&declared_destination(https, None, &["10.0.0.0/8"])),
        plain
    );
    let loopback = "http://127.0.0.1:8080/hooks";
    assert_eq!(
        digest(&declared_destination(
            loopback,
            Some("loopback-plaintext"),
            &[]
        )),
        digest(&declared_destination(loopback, None, &[]))
    );
    let private = |ranges: &[&str]| {
        digest(&declared_destination(
            "http://receiver:9000/hooks",
            Some("private-network-plaintext"),
            ranges,
        ))
    };
    assert_ne!(private(&["10.0.0.0/8"]), private(&["172.16.0.0/12"]));
}

const PRIVATE: Option<&str> = Some("private-network-plaintext");

/// One refused row of the M8 table as the shared block carries it: the
/// configuration, the selector's refusal, and the member the check names.
struct RefusedRow {
    row: &'static str,
    url: &'static str,
    transport: Option<&'static str>,
    ranges: Vec<String>,
    refusal: Option<DestinationSelectionError>,
    code: &'static str,
    member: &'static str,
}

fn refused_rows() -> Vec<RefusedRow> {
    use DestinationSelectionError as E;
    let listed = |ranges: &[&str]| ranges.iter().map(|range| (*range).to_owned()).collect();
    let selector = |error: E| (Some(error), error.code());
    let mut rows = Vec::new();
    for (name, url, transport, ranges, (refusal, code), member) in [
        (
            "T6",
            "http://receiver:9000/hooks",
            None,
            listed(&["10.0.0.0/8"]),
            selector(E::PrivateNetworkNotDeclared),
            "/hook/url",
        ),
        (
            "T7",
            "http://receiver:9000/hooks",
            PRIVATE,
            listed(&[]),
            selector(E::PrivateNetworkRequiresRanges),
            "/hook/transport",
        ),
        (
            "T12",
            "https://receiver/hooks",
            None,
            listed(&["169.254.0.0/16"]),
            selector(E::RangeNotPrivate),
            "/hook/allowedPrivateCidrs/0",
        ),
        (
            "T13",
            "https://receiver/hooks",
            None,
            listed(&["0.0.0.0/0"]),
            selector(E::RangeNotPrivate),
            "/hook/allowedPrivateCidrs/0",
        ),
        (
            "T14",
            "https://receiver/hooks",
            None,
            listed(&["10.0.0.1/8"]),
            selector(E::RangeNotCanonical),
            "/hook/allowedPrivateCidrs/0",
        ),
        (
            "T15",
            "http://receiver:9000/hooks",
            PRIVATE,
            (0..17).map(|n| format!("10.{n}.0.0/16")).collect(),
            selector(E::TooManyRanges),
            "/hook/allowedPrivateCidrs",
        ),
        (
            "T16",
            "https://receiver:8443/hooks",
            PRIVATE,
            listed(&["10.0.0.0/8"]),
            selector(E::TransportSchemeMismatch),
            "/hook/transport",
        ),
        (
            "T17",
            "http://receiver:9000/hooks",
            Some("verified-tls"),
            listed(&[]),
            selector(E::TransportSchemeMismatch),
            "/hook/transport",
        ),
        (
            "T18",
            "http://localhost:9000/hooks",
            PRIVATE,
            listed(&["10.0.0.0/8"]),
            selector(E::TransportHostMismatch),
            "/hook/transport",
        ),
        (
            "T19",
            "http://receiver:9000/hooks",
            Some("loopback-plaintext"),
            listed(&[]),
            selector(E::TransportHostMismatch),
            "/hook/transport",
        ),
        (
            "T20",
            "http://10.1.2.3:9000/hooks",
            PRIVATE,
            listed(&["172.16.0.0/12"]),
            selector(E::LiteralOutsideRanges),
            "/hook/url",
        ),
        (
            "query",
            "https://receiver/hooks?token=canary",
            None,
            listed(&[]),
            (None, "config.invalid-value"),
            "/hook/url",
        ),
        (
            "fragment",
            "https://receiver/hooks#canary",
            None,
            listed(&[]),
            (None, "config.invalid-value"),
            "/hook/url",
        ),
    ] {
        rows.push(RefusedRow {
            row: name,
            url,
            transport,
            ranges,
            refusal,
            code,
            member,
        });
    }
    rows
}

fn row_config(row: &RefusedRow) -> UrlHookDestinationConfig {
    let ranges: Vec<&str> = row.ranges.iter().map(String::as_str).collect();
    declared_destination(row.url, row.transport, &ranges)
}

/// The load rows the shared block can carry, refused at activation even
/// when the product skipped its check. A selector refusal keeps its code.
#[test]
fn activation_refuses_what_the_destination_selector_refuses() {
    let (_directory, secrets) = keyed_secrets();
    for row in refused_rows() {
        let refused = activate(&secrets, &row_config(&row))
            .map(drop)
            .expect_err(row.row);
        match row.refusal {
            Some(error) => {
                assert_eq!(
                    refused,
                    UrlHookActivationError::DestinationRefused(error),
                    "{}",
                    row.row
                );
                assert_eq!(refused.code(), Some(row.code), "{}", row.row);
                let message = refused.to_string();
                assert!(message.contains(error.fix()), "{message}");
                // The fix names "the receiver's range" in fixed words, so the
                // probe is the configured host as written.
                for value in ["receiver:", "receiver/", "10.1.2.3", "169.254", "canary"] {
                    assert!(!message.contains(value), "{}: {message}", row.row);
                }
            }
            None => {
                assert_eq!(
                    refused,
                    UrlHookActivationError::InvalidDestination,
                    "{}",
                    row.row
                );
                assert_eq!(refused.code(), None, "{}", row.row);
            }
        }
    }
}

const HOOK: &str = "/hook";

/// S5: the shared check reports what activation refuses, with the code and
/// the member to change, so a product's check refuses it before startup.
#[test]
fn the_shared_check_reports_what_activation_refuses() {
    let (_directory, secrets) = keyed_secrets();
    for row in refused_rows() {
        let found = check_url_hook_destination(&row_config(&row), HOOK);
        let coded: Vec<(&str, &str)> = found
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect();
        assert_eq!(coded, [(row.code, row.member)], "{}", row.row);
        for diagnostic in &found {
            assert!(!diagnostic.suggested_action.is_empty(), "{}", row.row);
            for value in ["receiver", "10.1.2.3", "169.254", "canary", "localhost"] {
                assert!(
                    !diagnostic.message.contains(value),
                    "{}: {}",
                    row.row,
                    diagnostic.message
                );
            }
        }
    }
    for (url, transport, ranges) in [
        ("https://receiver/hooks", None, &[][..]),
        (
            "https://receiver/hooks",
            Some("verified-tls"),
            &["10.0.0.0/8"][..],
        ),
        ("http://localhost:9000/hooks", None, &[][..]),
        (
            "http://127.0.0.1:9000/hooks",
            Some("loopback-plaintext"),
            &[][..],
        ),
        (
            "http://receiver:9000/hooks",
            PRIVATE,
            &["172.16.0.0/12"][..],
        ),
    ] {
        let config = declared_destination(url, transport, ranges);
        assert!(
            check_url_hook_destination(&config, HOOK).is_empty(),
            "{url}"
        );
        activate(&secrets, &config).unwrap_or_else(|error| panic!("{url}: {error}"));
    }
}

const ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: "registry.registrystack.org/example-runtime/v1alpha1",
    kind: "ExampleRuntimeConfig",
};

#[derive(Debug, serde::Deserialize)]
struct Example {
    hook: UrlHookDestinationConfig,
}

fn check_offline(
    body: &str,
    stand_in_for: fn(&str) -> &'static str,
) -> registry_platform_config::RuntimeFileCheck<Example> {
    let directory = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
    let path = directory.path().join("runtime.yaml");
    std::fs::write(
        &path,
        format!(
            "apiVersion: {}\nkind: {}\nhook:\n{body}",
            ENVELOPE.api_version, ENVELOPE.kind
        ),
    )
    .unwrap();
    RuntimeConfigLoader::new_without_posture(ENVELOPE).check_offline::<Example>(
        &path,
        false,
        stand_in_for,
    )
}

/// The file twin positions each finding at its member, and skips a member
/// that holds an expression the check did not fill.
#[test]
fn the_file_check_positions_findings_and_skips_deferred_members() {
    let file = check_offline(
        "  url: http://receiver:9000/hooks\n  transport: loopback-plaintext\n  hmacSha256KeyRef: secret:file/hook-key\n",
        |_| registry_platform_config::DEFAULT_STAND_IN,
    );
    let config = &file.loaded.as_ref().expect("the file decodes").config.hook;
    let found = check_url_hook_destination_file(config, HOOK, &file, "ExampleRuntimeConfig");
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(
        found[0].code,
        "platform.destination.transport-host-mismatch"
    );
    assert_eq!(found[0].path, "/hook/transport");
    assert_eq!(found[0].artifact.as_deref(), Some("ExampleRuntimeConfig"));
    assert_eq!(found[0].source.as_ref().expect("positioned").line, Some(5));

    // The stand-in would be refused, but the member holds an expression.
    let file = check_offline(
        "  url: \"${HOOK_URL}\"\n  hmacSha256KeyRef: secret:file/hook-key\n",
        |_| "http://receiver:9000/hooks",
    );
    let config = &file.loaded.as_ref().expect("the file decodes").config.hook;
    assert_eq!(
        check_url_hook_destination(config, HOOK)
            .into_iter()
            .map(|diagnostic| diagnostic.code)
            .collect::<Vec<_>>(),
        ["platform.destination.private-network-not-declared"],
        "the stand-in alone is refused"
    );
    let found = check_url_hook_destination_file(config, HOOK, &file, "ExampleRuntimeConfig");
    assert!(found.is_empty(), "{found:?}");
}

#[cfg(feature = "receiver")]
#[tokio::test]
async fn a_key_rotation_keeps_every_retained_delivery_acceptable() {
    use crate::receiver::DeliveryFreshness;
    use crate::{verify_hook_delivery, EnvelopeLimits, HookDelivery, HookEnvelope};
    use registry_platform_httputil::destination::SignedEventHeaders;
    use std::time::SystemTime;
    use tokio::io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader};
    use tokio::net::TcpListener;

    use crate::delivery::{
        DeliverySignatureFields, DestinationAnswer, HookDestination, SharedUrlDestination,
    };

    const ID: &str = "00000000-0000-4000-8000-000000000001";
    let envelope = HookEnvelope {
        id: ID.to_owned(),
        event_type: "case.created".to_owned(),
        source: "urn:example:source".to_owned(),
        time: time::OffsetDateTime::UNIX_EPOCH,
        subject: crate::EventSubject::record("example/case/42", 1),
        dataschema: "urn:example:schema".to_owned(),
        data: json!({"event": "retained"}),
        causation: crate::Causation::root(ID),
    };
    let body = envelope
        .to_canonical_bytes(&EnvelopeLimits::default())
        .unwrap();
    let expected_body = body.clone();
    let body = body.as_slice();
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
    let current_only = DeliveryKeys::new(k2(), None).unwrap();

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
            let mut headers = Vec::new();
            loop {
                line.clear();
                stream.read_line(&mut line).await.unwrap();
                assert!(!line.is_empty(), "incomplete request");
                if line == "\r\n" {
                    break;
                }
                let (name, value) = line.strip_suffix("\r\n").unwrap().split_once(": ").unwrap();
                headers.push((name.to_owned(), value.to_owned()));
            }
            let mut body = vec![0; expected_body.len()];
            stream.read_exact(&mut body).await.unwrap();
            assert_eq!(body, expected_body);
            let freshness = DeliveryFreshness::default_at(
                SystemTime::UNIX_EPOCH + Duration::from_secs(timestamp),
            );
            let check = |headers: &[(String, String)], keys| {
                let verified = verify_hook_delivery(
                    HookDelivery {
                        headers: headers
                            .iter()
                            .map(|(name, value)| (name.as_str(), value.as_bytes())),
                        body: &body,
                        keys,
                    },
                    freshness,
                )
                .unwrap();
                assert_eq!(verified.id, ID);
                assert_eq!(verified.timestamp, timestamp);
                assert_eq!(verified.envelope, envelope);
            };
            let mut first_only = headers.clone();
            let signature = &mut first_only
                .iter_mut()
                .find(|(name, _)| name.eq_ignore_ascii_case("webhook-signature"))
                .unwrap()
                .1;
            assert_eq!(signature.split(' ').count(), signature_count);
            signature.truncate(signature.find(' ').unwrap_or(signature.len()));
            if timestamp <= 1001 {
                check(&headers, &original_receiver);
            }
            if timestamp >= 1001 {
                check(&headers, &rotated_receiver);
            }
            check(
                &first_only,
                if timestamp == 1000 {
                    &original_receiver
                } else {
                    &current_only
                },
            );
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
                body,
            })
            .unwrap();
        let request = destination
            .render_delivery(
                SignedEventHeaders {
                    id: ID.as_bytes(),
                    timestamp: timestamp.to_string().as_bytes(),
                    signature: signature.as_bytes(),
                },
                body.to_vec(),
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
