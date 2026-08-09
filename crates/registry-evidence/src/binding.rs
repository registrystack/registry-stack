//! Subject and source-entity reference projection.
//!
//! A subject binding is scoped either to the relying party that asked for it or
//! to the public key of the holder that will present it. The two scopes carry
//! separate domain constants so they can never derive the same value.

use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_crypto::hmac_sha256_base64url_no_pad;
use thiserror::Error;

const SUBJECT_DOMAIN: &[u8] = b"registry-evidence/subject-binding/v1";
const HOLDER_DOMAIN: &[u8] = b"registry-evidence/subject-binding/holder/v1";
const ENTITY_DOMAIN: &[u8] = b"registry-evidence/entity-reference/v1";
/// A SHA-256 digest in base64url with no padding, which is what RFC 7638
/// specifies for a JSON Web Key thumbprint.
const THUMBPRINT_CHARS: usize = 43;
const THUMBPRINT_DECODED_BYTES: usize = 32;
const MIN_KEY_BYTES: usize = 32;
const MAX_COMPONENT_BYTES: usize = 8 * 1024;
const MAX_SELECTOR_FIELDS: usize = 16;
const MAX_ENTITY_SEED_BYTES: usize = 512;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SelectorScalar<'a> {
    String(&'a str),
    Date(&'a str),
    Integer(i64),
    Boolean(bool),
    ControlledCode(&'a str),
}

impl fmt::Debug for SelectorScalar<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let form = match self {
            Self::String(_) => "string",
            Self::Date(_) => "date",
            Self::Integer(_) => "integer",
            Self::Boolean(_) => "boolean",
            Self::ControlledCode(_) => "controlled-code",
        };
        formatter
            .debug_struct("SelectorScalar")
            .field("form", &form)
            .field("value", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SelectorField<'a> {
    pub name: &'a str,
    pub value: SelectorScalar<'a>,
}

impl fmt::Debug for SelectorField<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SelectorField")
            .field("name", &self.name)
            .field("value", &self.value)
            .finish()
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BindingError {
    #[error("binding key material is too short")]
    WeakKey,
    #[error("binding key version is invalid")]
    KeyVersion,
    #[error("binding input is empty or exceeds its bound")]
    Component,
    #[error("selector field set is invalid")]
    Fields,
    #[error("selector date is not canonical")]
    Date,
    #[error("entity-reference seed is invalid")]
    EntitySeed,
    #[error("holder key thumbprint is invalid")]
    HolderKey,
}

/// What a subject binding is scoped to. Holding the two alternatives in one
/// enum keeps a holder-bound binding that also carries an audience
/// unrepresentable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubjectBindingScope<'a> {
    /// The relying party the assertion is issued to.
    Audience(&'a str),
    /// The RFC 7638 thumbprint of the holder key the assertion is bound to.
    /// The thumbprint rather than the key document, so serialization variance
    /// cannot fork the binding.
    HolderKeyThumbprint(&'a str),
}

impl<'a> SubjectBindingScope<'a> {
    fn domain_and_value(self) -> Result<(&'static [u8], &'a str), BindingError> {
        match self {
            Self::Audience(audience) => Ok((SUBJECT_DOMAIN, audience)),
            Self::HolderKeyThumbprint(thumbprint) => {
                if !is_canonical_thumbprint(thumbprint) {
                    return Err(BindingError::HolderKey);
                }
                Ok((HOLDER_DOMAIN, thumbprint))
            }
        }
    }
}

pub struct SubjectBindingInput<'a> {
    pub trust_domain: &'a str,
    pub scope: SubjectBindingScope<'a>,
    pub purpose: &'a str,
    pub role: &'a str,
    pub profile: &'a str,
    pub fields: &'a [SelectorField<'a>],
}

pub fn subject_binding(
    key: &[u8],
    key_version: u32,
    input: SubjectBindingInput<'_>,
) -> Result<String, BindingError> {
    validate_key(key, key_version)?;
    if input.fields.is_empty() || input.fields.len() > MAX_SELECTOR_FIELDS {
        return Err(BindingError::Fields);
    }
    let (domain, scope_value) = input.scope.domain_and_value()?;

    let mut canonical = Vec::new();
    push_bytes(&mut canonical, domain)?;
    push_u32(&mut canonical, key_version);
    push_str(&mut canonical, input.trust_domain)?;
    push_str(&mut canonical, scope_value)?;
    push_str(&mut canonical, input.purpose)?;
    push_str(&mut canonical, input.role)?;
    push_str(&mut canonical, input.profile)?;
    push_u32(
        &mut canonical,
        u32::try_from(input.fields.len()).map_err(|_| BindingError::Fields)?,
    );

    for field in input.fields {
        push_str(&mut canonical, field.name)?;
        match field.value {
            SelectorScalar::String(value) => {
                canonical.push(0x01);
                push_str(&mut canonical, value)?;
            }
            SelectorScalar::Date(value) => {
                if !is_canonical_date(value) {
                    return Err(BindingError::Date);
                }
                canonical.push(0x02);
                push_str(&mut canonical, value)?;
            }
            SelectorScalar::Integer(value) => {
                canonical.push(0x03);
                push_str(&mut canonical, &value.to_string())?;
            }
            SelectorScalar::Boolean(value) => {
                canonical.push(0x04);
                push_bytes(&mut canonical, &[u8::from(value)])?;
            }
            SelectorScalar::ControlledCode(value) => {
                canonical.push(0x05);
                push_str(&mut canonical, value)?;
            }
        }
    }

    Ok(format!(
        "urn:evidence:subject:v{key_version}_{}",
        hmac_sha256_base64url_no_pad(key, &canonical)
    ))
}

pub fn entity_reference(
    key: &[u8],
    key_version: u32,
    concept_id: &str,
    audience: &str,
    seed: &[u8],
) -> Result<String, BindingError> {
    validate_key(key, key_version)?;
    if seed.is_empty() || seed.len() > MAX_ENTITY_SEED_BYTES {
        return Err(BindingError::EntitySeed);
    }
    let mut canonical = Vec::new();
    push_bytes(&mut canonical, ENTITY_DOMAIN)?;
    push_u32(&mut canonical, key_version);
    push_str(&mut canonical, concept_id)?;
    push_str(&mut canonical, audience)?;
    push_bytes(&mut canonical, seed)?;
    Ok(format!(
        "urn:evidence:entity:v{key_version}_{}",
        hmac_sha256_base64url_no_pad(key, &canonical)
    ))
}

fn validate_key(key: &[u8], key_version: u32) -> Result<(), BindingError> {
    if key.len() < MIN_KEY_BYTES {
        return Err(BindingError::WeakKey);
    }
    if key_version == 0 {
        return Err(BindingError::KeyVersion);
    }
    Ok(())
}

fn push_str(output: &mut Vec<u8>, input: &str) -> Result<(), BindingError> {
    push_bytes(output, input.as_bytes())
}

fn push_bytes(output: &mut Vec<u8>, input: &[u8]) -> Result<(), BindingError> {
    if input.is_empty() || input.len() > MAX_COMPONENT_BYTES {
        return Err(BindingError::Component);
    }
    let length = u32::try_from(input.len()).map_err(|_| BindingError::Component)?;
    push_u32(output, length);
    output.extend_from_slice(input);
    Ok(())
}

fn push_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_be_bytes());
}

/// Accept only the canonical 43-character unpadded base64url encoding of
/// exactly 32 bytes. Length, alphabet, padding, and a noncanonical final
/// symbol (one that leaves nonzero bits past the encoded 256 bits) all fail.
/// Re-encoding the decoded bytes makes that canonical spelling requirement
/// explicit rather than depending only on the decoder's trailing-bit policy.
fn is_canonical_thumbprint(value: &str) -> bool {
    if value.len() != THUMBPRINT_CHARS
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return false;
    }
    match URL_SAFE_NO_PAD.decode(value) {
        Ok(decoded) => {
            decoded.len() == THUMBPRINT_DECODED_BYTES && URL_SAFE_NO_PAD.encode(decoded) == value
        }
        Err(_) => false,
    }
}

fn is_canonical_date(value: &str) -> bool {
    if value.len() != 10 {
        return false;
    }
    let bytes = value.as_bytes();
    if bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    chrono::NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .map(|date| date.format("%Y-%m-%d").to_string() == value)
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";

    /// A canonical RFC 7638 thumbprint: the unpadded base64url encoding of an
    /// actual 32-byte digest, with no bits left over past that 256th bit.
    const THUMBPRINT: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
    const OTHER_THUMBPRINT: &str = "AwoRGB8mLTQ7QklQV15lbHN6gYiPlp2kq7K5wMfO1dw";
    /// Same length and alphabet as `THUMBPRINT`, but its final symbol leaves
    /// the two bits past the encoded 256th bit set, so it is not the canonical
    /// spelling of the 32-byte digest it resembles.
    const NON_CANONICAL_TRAILING_BITS_THUMBPRINT: &str =
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHhG";

    fn input<'a>(fields: &'a [SelectorField<'a>]) -> SubjectBindingInput<'a> {
        SubjectBindingInput {
            trust_domain: "urn:example:trust",
            scope: SubjectBindingScope::Audience("urn:example:relying-party"),
            purpose: "enrolment",
            role: "subject",
            profile: "person-v1",
            fields,
        }
    }

    fn holder_input<'a>(fields: &'a [SelectorField<'a>]) -> SubjectBindingInput<'a> {
        SubjectBindingInput {
            scope: SubjectBindingScope::HolderKeyThumbprint(THUMBPRINT),
            ..input(fields)
        }
    }

    #[test]
    fn subject_binding_is_stable_and_scoped() {
        let fields = [
            SelectorField {
                name: "name",
                value: SelectorScalar::String("Synthetic Person"),
            },
            SelectorField {
                name: "birth_date",
                value: SelectorScalar::Date("2000-02-29"),
            },
        ];
        let first = subject_binding(KEY, 1, input(&fields)).expect("binding succeeds");
        let second = subject_binding(KEY, 1, input(&fields)).expect("binding succeeds");
        assert_eq!(first, second);
        assert!(first.starts_with("urn:evidence:subject:v1_"));
        assert_eq!(first.len(), "urn:evidence:subject:v1_".len() + 43);

        let mut other_audience = input(&fields);
        other_audience.scope = SubjectBindingScope::Audience("urn:example:other-party");
        assert_ne!(
            first,
            subject_binding(KEY, 1, other_audience).expect("binding succeeds")
        );
    }

    #[test]
    fn holder_bound_binding_is_stable_and_holder_key_scoped() {
        let fields = [SelectorField {
            name: "coordinate",
            value: SelectorScalar::String("same-bytes"),
        }];
        let first = subject_binding(KEY, 1, holder_input(&fields)).expect("binding succeeds");
        let second = subject_binding(KEY, 1, holder_input(&fields)).expect("binding succeeds");
        assert_eq!(first, second);
        assert!(first.starts_with("urn:evidence:subject:v1_"));
        assert_eq!(first.len(), "urn:evidence:subject:v1_".len() + 43);

        let mut other_holder = holder_input(&fields);
        other_holder.scope = SubjectBindingScope::HolderKeyThumbprint(OTHER_THUMBPRINT);
        assert_ne!(
            first,
            subject_binding(KEY, 1, other_holder).expect("binding succeeds")
        );
    }

    /// The two scopes carry their own domain constant, so an audience that
    /// happens to read like a thumbprint can never produce the binding a holder
    /// key of the same text would.
    #[test]
    fn the_audience_and_holder_scopes_never_collide() {
        let fields = [SelectorField {
            name: "coordinate",
            value: SelectorScalar::String("same-bytes"),
        }];
        let mut audience_shaped = input(&fields);
        audience_shaped.scope = SubjectBindingScope::Audience(THUMBPRINT);
        assert_ne!(
            subject_binding(KEY, 1, audience_shaped).expect("binding succeeds"),
            subject_binding(KEY, 1, holder_input(&fields)).expect("binding succeeds")
        );
    }

    #[test]
    fn a_holder_key_thumbprint_that_is_not_canonical_is_refused() {
        let fields = [SelectorField {
            name: "coordinate",
            value: SelectorScalar::String("same-bytes"),
        }];
        for candidate in [
            "",
            "too-short",
            "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGH",
            "0123456789abcdefghijklmnopqrstuvwxyzABCDEF=",
            "0123456789abcdefghijklmnopqrstuvwxyzABCDEF/",
            "0123456789abcdefghijklmnopqrstuvwxyzABCDEF+",
        ] {
            let mut candidate_input = holder_input(&fields);
            candidate_input.scope = SubjectBindingScope::HolderKeyThumbprint(candidate);
            assert_eq!(
                subject_binding(KEY, 1, candidate_input),
                Err(BindingError::HolderKey),
                "{candidate:?} is not a canonical thumbprint"
            );
        }
    }

    #[test]
    fn a_holder_key_thumbprint_with_nonzero_trailing_bits_is_refused() {
        let fields = [SelectorField {
            name: "coordinate",
            value: SelectorScalar::String("same-bytes"),
        }];
        let mut candidate_input = holder_input(&fields);
        candidate_input.scope =
            SubjectBindingScope::HolderKeyThumbprint(NON_CANONICAL_TRAILING_BITS_THUMBPRINT);
        assert_eq!(
            subject_binding(KEY, 1, candidate_input),
            Err(BindingError::HolderKey),
            "a 43-character, alphabet-valid string with nonzero trailing bits is not a \
             canonical thumbprint"
        );
    }

    #[test]
    fn every_holder_bound_scope_component_is_cryptographically_bound() {
        let fields = [SelectorField {
            name: "coordinate",
            value: SelectorScalar::String("same-bytes"),
        }];
        let baseline = subject_binding(KEY, 1, holder_input(&fields)).expect("baseline succeeds");

        let mut changed = holder_input(&fields);
        changed.trust_domain = "urn:example:other-trust";
        assert_ne!(
            baseline,
            subject_binding(KEY, 1, changed).expect("changed trust binding succeeds")
        );
        let mut changed = holder_input(&fields);
        changed.purpose = "other-purpose";
        assert_ne!(
            baseline,
            subject_binding(KEY, 1, changed).expect("changed purpose binding succeeds")
        );
        let mut changed = holder_input(&fields);
        changed.role = "other-role";
        assert_ne!(
            baseline,
            subject_binding(KEY, 1, changed).expect("changed role binding succeeds")
        );
        let mut changed = holder_input(&fields);
        changed.profile = "other-profile";
        assert_ne!(
            baseline,
            subject_binding(KEY, 1, changed).expect("changed profile binding succeeds")
        );
        assert_ne!(
            baseline,
            subject_binding(KEY, 2, holder_input(&fields)).expect("changed key version succeeds")
        );

        let changed_value = [SelectorField {
            name: "coordinate",
            value: SelectorScalar::String("other-bytes"),
        }];
        assert_ne!(
            baseline,
            subject_binding(KEY, 1, holder_input(&changed_value)).expect("changed value succeeds")
        );
    }

    #[test]
    fn subject_binding_is_field_order_sensitive() {
        let fields = [
            SelectorField {
                name: "a",
                value: SelectorScalar::Integer(1),
            },
            SelectorField {
                name: "b",
                value: SelectorScalar::Boolean(true),
            },
        ];
        let reversed = [fields[1], fields[0]];
        assert_ne!(
            subject_binding(KEY, 1, input(&fields)).expect("binding succeeds"),
            subject_binding(KEY, 1, input(&reversed)).expect("binding succeeds")
        );
    }

    #[test]
    fn every_subject_binding_scope_component_is_cryptographically_bound() {
        let fields = [SelectorField {
            name: "coordinate",
            value: SelectorScalar::String("same-bytes"),
        }];
        let baseline = subject_binding(KEY, 1, input(&fields)).expect("baseline binding succeeds");

        let mut changed = input(&fields);
        changed.trust_domain = "urn:example:other-trust";
        assert_ne!(
            baseline,
            subject_binding(KEY, 1, changed).expect("changed trust binding succeeds")
        );
        let mut changed = input(&fields);
        changed.scope = SubjectBindingScope::Audience("urn:example:other-audience");
        assert_ne!(
            baseline,
            subject_binding(KEY, 1, changed).expect("changed audience binding succeeds")
        );
        let mut changed = input(&fields);
        changed.purpose = "other-purpose";
        assert_ne!(
            baseline,
            subject_binding(KEY, 1, changed).expect("changed purpose binding succeeds")
        );
        let mut changed = input(&fields);
        changed.role = "other-role";
        assert_ne!(
            baseline,
            subject_binding(KEY, 1, changed).expect("changed role binding succeeds")
        );
        let mut changed = input(&fields);
        changed.profile = "other-profile";
        assert_ne!(
            baseline,
            subject_binding(KEY, 1, changed).expect("changed profile binding succeeds")
        );
        assert_ne!(
            baseline,
            subject_binding(KEY, 2, input(&fields)).expect("changed key version succeeds")
        );

        let changed_name = [SelectorField {
            name: "other_coordinate",
            value: SelectorScalar::String("same-bytes"),
        }];
        assert_ne!(
            baseline,
            subject_binding(KEY, 1, input(&changed_name)).expect("changed name binding succeeds")
        );
        let changed_type = [SelectorField {
            name: "coordinate",
            value: SelectorScalar::ControlledCode("same-bytes"),
        }];
        assert_ne!(
            baseline,
            subject_binding(KEY, 1, input(&changed_type)).expect("changed type binding succeeds")
        );
        let changed_value = [SelectorField {
            name: "coordinate",
            value: SelectorScalar::String("other-bytes"),
        }];
        assert_ne!(
            baseline,
            subject_binding(KEY, 1, input(&changed_value)).expect("changed value binding succeeds")
        );
    }

    #[test]
    fn entity_reference_is_audience_and_concept_scoped() {
        let first = entity_reference(
            KEY,
            2,
            "urn:example:concept:person",
            "urn:example:audience:a",
            b"protected-source-id",
        )
        .expect("reference succeeds");
        let second = entity_reference(
            KEY,
            2,
            "urn:example:concept:person",
            "urn:example:audience:b",
            b"protected-source-id",
        )
        .expect("reference succeeds");
        assert_ne!(first, second);
        assert!(first.starts_with("urn:evidence:entity:v2_"));
    }

    #[test]
    fn invalid_dates_and_weak_keys_are_rejected() {
        let fields = [SelectorField {
            name: "birth_date",
            value: SelectorScalar::Date("2025-02-29"),
        }];
        assert_eq!(
            subject_binding(KEY, 1, input(&fields)),
            Err(BindingError::Date)
        );
        assert_eq!(
            entity_reference(b"short", 1, "concept", "audience", b"seed"),
            Err(BindingError::WeakKey)
        );
    }

    #[test]
    fn selector_binding_helper_debug_never_exposes_values() {
        let fields = [
            SelectorField {
                name: "alpha",
                value: SelectorScalar::String("selector-debug-canary"),
            },
            SelectorField {
                name: "delta",
                value: SelectorScalar::Integer(8_192_125),
            },
        ];
        let diagnostic = format!("{fields:?}");
        assert!(!diagnostic.contains("selector-debug-canary"));
        assert!(!diagnostic.contains("8192125"));
        assert!(diagnostic.contains("alpha"));
        assert!(diagnostic.contains("[REDACTED]"));
    }
}
