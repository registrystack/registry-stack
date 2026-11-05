// SPDX-License-Identifier: Apache-2.0

//! Fixed GovStack direct Write protocol and bounded request admission.

pub(crate) mod attachment;
pub(crate) mod metadata;

pub use attachment::WriteCapability;

use crate::engine::component::rest::continuation::ContinuationCodec;
use registry_platform_canonical_json::canonicalize_json;
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WriteInputError {
    IdempotencyKey,
    MalformedPrecondition,
    PreconditionFailed,
    SourceValidator,
    RecordIdentifier,
    CollectionIdentifier,
}

#[derive(Clone)]
pub(crate) struct ValidatorContext<'a> {
    pub registry: &'a str,
    pub collection: &'a str,
    pub record: &'a str,
    pub view: &'a str,
    pub closure: String,
}

/// Admit the exact bounded Structured Field String required by the fixed
/// target. Generic authored facades keep their existing key grammar.
pub(crate) fn parse_idempotency_key(value: &str) -> Result<&str, WriteInputError> {
    let bytes = value.as_bytes();
    if !(3..=202).contains(&bytes.len())
        || bytes.first() != Some(&b'"')
        || bytes.last() != Some(&b'"')
    {
        return Err(WriteInputError::IdempotencyKey);
    }
    let mut index = 1;
    let mut characters = 0;
    while index < bytes.len() - 1 {
        let byte = bytes[index];
        if byte == b'\\' {
            index += 1;
            if index >= bytes.len() - 1 || !matches!(bytes[index], b'"' | b'\\') {
                return Err(WriteInputError::IdempotencyKey);
            }
        } else if !(0x20..=0x7e).contains(&byte) || byte == b'"' {
            return Err(WriteInputError::IdempotencyKey);
        }
        index += 1;
        characters += 1;
    }
    if !(1..=200).contains(&characters) {
        return Err(WriteInputError::IdempotencyKey);
    }
    Ok(value)
}

pub(crate) fn is_strong_etag(value: &str) -> bool {
    let bytes = value.as_bytes();
    (3..=258).contains(&bytes.len())
        && bytes.first() == Some(&b'"')
        && bytes.last() == Some(&b'"')
        && bytes[1..bytes.len() - 1]
            .iter()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x7e))
}

fn framed_hash(domain: &[u8], members: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for member in std::iter::once(domain).chain(members.iter().copied()) {
        hash.update((member.len() as u64).to_be_bytes());
        hash.update(member);
    }
    hash.finalize().into()
}

fn context_digest(context: ValidatorContext<'_>) -> String {
    let bytes = framed_hash(
        b"registry-adapter:govstack-validator:v1",
        &[
            context.registry.as_bytes(),
            context.collection.as_bytes(),
            context.record.as_bytes(),
            context.view.as_bytes(),
            context.closure.as_bytes(),
        ],
    );
    // Native source CAS is the authority. This context discriminator binds
    // the opaque source condition to the selected public representation.
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

// Strength is a source compare-and-commit guarantee, not a spelling rule.
// Provider-specific native syntax is checked by the governed source pack.
fn valid_native_condition(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

pub(crate) fn wrap_validator(
    native: &str,
    context: ValidatorContext<'_>,
    codec: &ContinuationCodec,
) -> Result<String, WriteInputError> {
    if !valid_native_condition(native) {
        return Err(WriteInputError::SourceValidator);
    }
    let token = codec
        .seal_bound_value(context_digest(context).as_bytes(), native.as_bytes())
        .map_err(|_| WriteInputError::SourceValidator)?;
    Ok(format!("\"w2.{token}\""))
}

pub(crate) fn unwrap_validator(
    value: &str,
    context: ValidatorContext<'_>,
    codec: &ContinuationCodec,
) -> Result<String, WriteInputError> {
    if !is_strong_etag(value) {
        return Err(WriteInputError::MalformedPrecondition);
    }
    let token = value
        .strip_prefix("\"w2.")
        .and_then(|value| value.strip_suffix('"'))
        .ok_or(WriteInputError::PreconditionFailed)?;
    let native = codec
        .open_bound_value(context_digest(context).as_bytes(), token)
        .map_err(|_| WriteInputError::PreconditionFailed)?;
    let native = String::from_utf8(native).map_err(|_| WriteInputError::PreconditionFailed)?;
    if !valid_native_condition(&native) {
        return Err(WriteInputError::PreconditionFailed);
    }
    Ok(native)
}

pub(crate) struct WriteReceipt {
    pub body: Value,
    pub etag: String,
    pub location: Option<String>,
}

/// Render one normalized source receipt using the same opaque guard as its
/// companion representation. Hosts separately validate their pinned view.
pub(crate) fn render_receipt(
    result: &crate::engine::exchange::FinalSourceResult,
    context: ValidatorContext<'_>,
    codec: &ContinuationCodec,
    create: bool,
) -> Result<WriteReceipt, WriteInputError> {
    if context.record != result.key {
        return Err(WriteInputError::RecordIdentifier);
    }
    let collection = context.collection;
    let location = record_location(collection, &result.key)?;
    let etag = wrap_validator(&result.native_version, context, codec)?;
    Ok(WriteReceipt {
        body: serde_json::json!({"collectionId": collection, "recordId": result.key, "etag": etag}),
        etag,
        location: create.then_some(location),
    })
}

/// The `/data` member pointers of an Update merge patch whose value is an
/// object, sorted by member name whatever order the map iterates in. The
/// selected Update is a flat merge patch: a source maps each member to one
/// whole-member add or remove, so an object value would replace the stored
/// member rather than merge into it as RFC 7396 requires. Arrays are not
/// listed; RFC 7396 replaces them whole.
pub(crate) fn nested_merge_patch_members(data: &serde_json::Map<String, Value>) -> Vec<String> {
    let mut names: Vec<&String> = data
        .iter()
        .filter(|(_, value)| value.is_object())
        .map(|(name, _)| name)
        .collect();
    names.sort_unstable();
    names
        .into_iter()
        .map(|name| format!("/data/{}", name.replace('~', "~0").replace('/', "~1")))
        .collect()
}

pub(crate) fn request_fingerprint(
    method: &str,
    target: &str,
    media: &str,
    body: &Value,
    condition: Option<&str>,
) -> Result<[u8; 32], registry_platform_canonical_json::JcsError> {
    let canonical = canonicalize_json(body)?;
    Ok(framed_hash(
        b"registry-adapter:govstack-write-request:v1",
        &[
            method.as_bytes(),
            target.as_bytes(),
            media.as_bytes(),
            &canonical,
            condition.unwrap_or_default().as_bytes(),
        ],
    ))
}

/// Namespace a native service-principal key by the trusted caller and logical
/// deployment. Physical request ids and artifact revisions do not change it.
pub(crate) fn source_key_scope(
    issuer: &str,
    caller: &str,
    client: &str,
    deployment: &str,
    method: &str,
    target: &str,
    key: &str,
) -> String {
    framed_hash(
        b"registry-adapter:govstack-source-key:v1",
        &[
            issuer.as_bytes(),
            caller.as_bytes(),
            client.as_bytes(),
            deployment.as_bytes(),
            method.as_bytes(),
            target.as_bytes(),
            key.as_bytes(),
        ],
    )
    .iter()
    .map(|byte| format!("{byte:02x}"))
    .collect()
}

pub(crate) fn record_location(collection: &str, record: &str) -> Result<String, WriteInputError> {
    if collection.is_empty()
        || collection.len() > 128
        || !collection.as_bytes()[0].is_ascii_lowercase()
        || !collection
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(WriteInputError::CollectionIdentifier);
    }
    let encoded = crate::engine::component::http::uri::encode_path_segment(record)
        .filter(|_| record.chars().count() <= super::consultation::MAXIMUM_RECORD_ID_CHARACTERS)
        .ok_or(WriteInputError::RecordIdentifier)?;
    Ok(format!(
        "{}/v1/collections/{collection}/records/{encoded}",
        super::consultation::MOUNT_PATH
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn codec() -> ContinuationCodec {
        use crate::engine::component::rest::continuation::{CursorKey, CursorTtl};
        ContinuationCodec::new(
            CursorKey::new(zeroize::Zeroizing::new(vec![7; 32])).unwrap(),
            None,
            CursorTtl::default(),
        )
    }

    fn context() -> ValidatorContext<'static> {
        ValidatorContext {
            registry: "https://registry.example/registries/people",
            collection: "people",
            record: "r_42",
            view: "person-summary",
            closure: "sha256:example-closure".to_owned(),
        }
    }

    #[test]
    fn nested_merge_patch_members_are_sorted_by_member_name() {
        let mut data = serde_json::Map::new();
        data.insert("zeta".to_owned(), json!({"x": 1}));
        data.insert("name".to_owned(), json!("Ada"));
        data.insert("a/b".to_owned(), json!({}));
        data.insert("tags".to_owned(), json!([{"x": 1}]));
        data.insert("alpha~".to_owned(), json!({"y": 2}));
        assert_eq!(
            nested_merge_patch_members(&data),
            ["/data/a~1b", "/data/alpha~0", "/data/zeta"]
        );
    }

    #[test]
    fn idempotency_keys_follow_the_quoted_structured_field_contract() {
        for value in [r#""a""#, r#""a b""#, r#""a\"b\\c""#] {
            assert_eq!(parse_idempotency_key(value), Ok(value));
        }
        let maximum = format!("\"{}\"", "a".repeat(200));
        assert!(parse_idempotency_key(&maximum).is_ok());
        for value in [
            "a",
            "\"\"",
            "\"é\"",
            "\"a\\nb\"",
            "\"a\" trailing",
            "\"a\n\"",
        ] {
            assert_eq!(
                parse_idempotency_key(value),
                Err(WriteInputError::IdempotencyKey)
            );
        }
        let oversized = format!("\"{}\"", "a".repeat(201));
        assert_eq!(
            parse_idempotency_key(&oversized),
            Err(WriteInputError::IdempotencyKey)
        );
    }

    #[test]
    fn native_conditions_do_not_require_the_sources_to_implement_http_etags() {
        let native = "revision-42";
        let tag = wrap_validator(native, context(), &codec()).expect("opaque source CAS condition");
        assert!(is_strong_etag(&tag));
        assert_eq!(
            unwrap_validator(&tag, context(), &codec()),
            Ok(native.to_owned())
        );
        for invalid in ["", "revision\n42", "revision\u{0085}42"] {
            assert_eq!(
                wrap_validator(invalid, context(), &codec()),
                Err(WriteInputError::SourceValidator)
            );
        }
    }

    #[test]
    fn validators_bind_the_native_condition_to_one_record_view_and_closure() {
        let native = "\"breg-source-version\"";
        let tag =
            wrap_validator(native, context(), &codec()).expect("the source validator is bounded");
        assert!(is_strong_etag(&tag));
        assert!(tag.len() <= 258);
        assert_eq!(
            unwrap_validator(&tag, context(), &codec()),
            Ok(native.to_owned())
        );
        for changed in [
            ValidatorContext {
                registry: "https://registry.example/registries/other",
                ..context()
            },
            ValidatorContext {
                collection: "households",
                ..context()
            },
            ValidatorContext {
                record: "r_43",
                ..context()
            },
            ValidatorContext {
                view: "other-view",
                ..context()
            },
            ValidatorContext {
                closure: "sha256:other-closure".to_owned(),
                ..context()
            },
        ] {
            assert_eq!(
                unwrap_validator(&tag, changed, &codec()),
                Err(WriteInputError::PreconditionFailed)
            );
        }
    }

    #[test]
    fn weak_wildcard_list_and_invalid_etags_are_not_preconditions() {
        for value in [
            "*",
            "W/\"native\"",
            "\"a\", \"b\"",
            "\"\"",
            "\"has space\"",
            "\"é\"",
            "\"a\"\n",
        ] {
            assert!(!is_strong_etag(value), "{value:?}");
            assert_eq!(
                unwrap_validator(value, context(), &codec()),
                Err(WriteInputError::MalformedPrecondition)
            );
        }
        assert_eq!(
            unwrap_validator("\"unknown-valid-tag\"", context(), &codec()),
            Err(WriteInputError::PreconditionFailed)
        );
        let oversized_native = format!("\"{}\"", "a".repeat(127));
        assert_eq!(
            wrap_validator(&oversized_native, context(), &codec()),
            Err(WriteInputError::SourceValidator)
        );
    }

    #[test]
    fn write_fingerprints_use_canonical_json_and_all_declared_semantics() {
        let first = request_fingerprint(
            "PATCH",
            "/govstack/registries/v1/collections/people/records/r_42",
            "application/merge-patch+json",
            &json!({"data": {"a": 1, "b": 2}}),
            Some("\"v1\""),
        )
        .expect("canonical request");
        let reordered: serde_json::Value =
            serde_json::from_str("{ \"data\": { \"b\": 2, \"a\": 1 } }").unwrap();
        assert_eq!(
            first,
            request_fingerprint(
                "PATCH",
                "/govstack/registries/v1/collections/people/records/r_42",
                "application/merge-patch+json",
                &reordered,
                Some("\"v1\"")
            )
            .unwrap()
        );
        for (method, target, media, body, condition) in [
            (
                "POST",
                "/govstack/registries/v1/collections/people/records/r_42",
                "application/merge-patch+json",
                json!({"data": {"a": 1, "b": 2}}),
                Some("\"v1\""),
            ),
            (
                "PATCH",
                "/govstack/registries/v1/collections/people/records/r_43",
                "application/merge-patch+json",
                json!({"data": {"a": 1, "b": 2}}),
                Some("\"v1\""),
            ),
            (
                "PATCH",
                "/govstack/registries/v1/collections/people/records/r_42",
                "application/json",
                json!({"data": {"a": 1, "b": 2}}),
                Some("\"v1\""),
            ),
            (
                "PATCH",
                "/govstack/registries/v1/collections/people/records/r_42",
                "application/merge-patch+json",
                json!({"data": {"a": 1, "b": 3}}),
                Some("\"v1\""),
            ),
            (
                "PATCH",
                "/govstack/registries/v1/collections/people/records/r_42",
                "application/merge-patch+json",
                json!({"data": {"a": 1, "b": 2}}),
                Some("\"v2\""),
            ),
        ] {
            assert_ne!(
                first,
                request_fingerprint(method, target, media, &body, condition).unwrap()
            );
        }
    }

    #[test]
    fn native_keys_separate_callers_and_logical_targets_but_repeat_on_retry() {
        let key = source_key_scope(
            "issuer",
            "caller-a",
            "client",
            "deployment",
            "PATCH",
            "/records/r1",
            "\"key\"",
        );
        assert_eq!(
            key,
            source_key_scope(
                "issuer",
                "caller-a",
                "client",
                "deployment",
                "PATCH",
                "/records/r1",
                "\"key\""
            )
        );
        for (caller, deployment, method, target) in [
            ("caller-b", "deployment", "PATCH", "/records/r1"),
            ("caller-a", "other", "PATCH", "/records/r1"),
            ("caller-a", "deployment", "POST", "/records/r1"),
            ("caller-a", "deployment", "PATCH", "/records/r2"),
        ] {
            assert_ne!(
                key,
                source_key_scope("issuer", caller, "client", deployment, method, target, "\"key\"")
            );
        }
    }

    #[test]
    fn locations_use_the_public_record_uri_and_reject_non_write_identifiers() {
        assert_eq!(
            record_location("people", "r_42"),
            Ok("/govstack/registries/v1/collections/people/records/r_42".to_owned())
        );
        for record in ["", "..", "../r_42", "r/42", "%2f"] {
            assert_eq!(
                record_location("people", record),
                Err(WriteInputError::RecordIdentifier)
            );
        }
        assert_eq!(
            record_location("people", "é"),
            Ok("/govstack/registries/v1/collections/people/records/%C3%A9".to_owned())
        );
        assert_eq!(
            record_location("people", "_starts-with-punctuation"),
            Ok(
                "/govstack/registries/v1/collections/people/records/_starts-with-punctuation"
                    .to_owned()
            )
        );
        assert_eq!(
            record_location("../people", "r_42"),
            Err(WriteInputError::CollectionIdentifier)
        );
    }
}
