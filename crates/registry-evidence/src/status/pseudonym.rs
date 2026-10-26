//! Selector pseudonyms and holder-key digests.
//!
//! The pseudonym is `HMAC-SHA-256(status pseudonym key, input)`, where the
//! input is a domain tag, the length-prefixed selector profile id, the field
//! count, and each field (name, value type tag, value) framed exactly as the
//! audit pseudonym frames its fields. It carries no binding mode, audience,
//! purpose or role, so a request, a hook projection and an extract row for one
//! subject give one pseudonym.

use std::collections::BTreeMap;
use std::fmt;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::NaiveDate;
use registry_platform_crypto::mac::hmac_sha256;
use serde_json::{Map, Value};
use thiserror::Error;

use super::keys::{HolderDigestKeyRing, KeyVersion, PseudonymKeyRing, StatusKey};
use crate::config::{SelectorField, SelectorProfile, MAX_SAFE_INTEGER};
use crate::model::SelectorValue;
use crate::selector::{
    canonical_uuid, push_component, push_count, ResolvedSelectorField, ResolvedSelectorValue,
    ResolvedSubject,
};

/// Domain tag that opens every status pseudonym input. Its length prefix
/// starts with `0x00`, and an audit pseudonym input always starts with `0x01`
/// or `0x02`, so the two inputs never share a first byte.
const STATUS_PSEUDONYM_DOMAIN: &[u8] = b"registry-evidence/status-pseudonym/v1";

const SHA256_THUMBPRINT_BYTES: usize = 32;

/// The unpadded base64url length of a SHA-256 thumbprint.
const SHA256_THUMBPRINT_BASE64URL_CHARS: usize = 43;

/// Why a selector or a holder key thumbprint cannot be keyed. No variant
/// carries the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Error)]
pub enum PseudonymError {
    #[error("the selector values do not match the selector profile")]
    Selector,
    #[error("the holder key thumbprint is not a base64url SHA-256 JWK thumbprint")]
    Thumbprint,
}

/// One subject's complete selector bundle in its profile's canonical order,
/// ready to be keyed. Values are never formatted.
#[derive(Clone, PartialEq, Eq)]
pub struct StatusSubject {
    selector_profile: String,
    fields: Vec<ResolvedSelectorField>,
}

impl fmt::Debug for StatusSubject {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StatusSubject")
            .field("selector_profile", &self.selector_profile)
            .field("fields", &self.fields.len())
            .finish()
    }
}

impl StatusSubject {
    /// The subject a request resolved, already validated and ordered by the
    /// selector resolver.
    #[must_use]
    pub fn from_resolved(subject: &ResolvedSubject) -> Self {
        Self {
            selector_profile: subject.selector_profile.clone(),
            fields: subject.fields.clone(),
        }
    }

    /// A subject named by a hook projection: a JSON object that carries every
    /// selector field of the profile and may carry other members, such as the
    /// status field, which are ignored.
    pub fn from_json_projection(
        selector_profile_id: &str,
        profile: &SelectorProfile,
        projection: &Map<String, Value>,
    ) -> Result<Self, PseudonymError> {
        Self::from_profile(selector_profile_id, profile, |name| {
            match projection.get(name).ok_or(PseudonymError::Selector)? {
                Value::String(value) => Ok(SelectorValue::String(value.clone())),
                Value::Number(value) => value
                    .as_i64()
                    .map(SelectorValue::Integer)
                    .ok_or(PseudonymError::Selector),
                Value::Bool(value) => Ok(SelectorValue::Boolean(*value)),
                Value::Null | Value::Array(_) | Value::Object(_) => Err(PseudonymError::Selector),
            }
        })
    }

    /// A subject named by a row of typed values, such as a reconciliation
    /// extract row. Columns that are not selector fields are ignored.
    pub fn from_named_values(
        selector_profile_id: &str,
        profile: &SelectorProfile,
        values: &BTreeMap<String, SelectorValue>,
    ) -> Result<Self, PseudonymError> {
        Self::from_profile(selector_profile_id, profile, |name| {
            values.get(name).cloned().ok_or(PseudonymError::Selector)
        })
    }

    /// Read every profile field in declaration order and check it as the
    /// selector resolver does: kind, canonical form, bounds, and the
    /// aggregate byte bound. Codelist membership is not checked here, since
    /// no bundle is at hand; a code outside the codelist gives a pseudonym no
    /// allocation carries, because allocations come from resolved requests.
    fn from_profile(
        selector_profile_id: &str,
        profile: &SelectorProfile,
        mut value_of: impl FnMut(&str) -> Result<SelectorValue, PseudonymError>,
    ) -> Result<Self, PseudonymError> {
        if selector_profile_id.is_empty() {
            return Err(PseudonymError::Selector);
        }
        let mut aggregate_bytes = 0_u64;
        let mut fields = Vec::with_capacity(profile.fields.len());
        for (name, configured) in profile.fields.iter() {
            let value = resolve_value(configured, value_of(name)?)?;
            let value_bytes = match &value {
                ResolvedSelectorValue::String(text)
                | ResolvedSelectorValue::Date(text)
                | ResolvedSelectorValue::ControlledCode(text) => text.len(),
                ResolvedSelectorValue::Integer(number) => number.to_string().len(),
                ResolvedSelectorValue::Boolean(_) => 1,
            };
            aggregate_bytes = u64::try_from(value_bytes)
                .ok()
                .and_then(|bytes| aggregate_bytes.checked_add(bytes))
                .ok_or(PseudonymError::Selector)?;
            fields.push(ResolvedSelectorField {
                name: name.to_owned(),
                value,
            });
        }
        if aggregate_bytes > profile.maximum_aggregate_bytes.get() {
            return Err(PseudonymError::Selector);
        }
        Ok(Self {
            selector_profile: selector_profile_id.to_owned(),
            fields,
        })
    }

    /// The domain tag, then the audit framing of the profile id, the field
    /// count and every field, with no binding mode, audience, purpose or role.
    fn pseudonym_input(&self) -> Result<Vec<u8>, PseudonymError> {
        let selector = |_| PseudonymError::Selector;
        let mut output = Vec::new();
        push_component(&mut output, STATUS_PSEUDONYM_DOMAIN).map_err(selector)?;
        push_component(&mut output, self.selector_profile.as_bytes()).map_err(selector)?;
        push_count(&mut output, self.fields.len()).map_err(selector)?;
        for field in &self.fields {
            push_component(&mut output, field.name.as_bytes()).map_err(selector)?;
            let (tag, value) = match &field.value {
                ResolvedSelectorValue::String(value) => (0x01, value.as_bytes().to_vec()),
                ResolvedSelectorValue::Date(value) => (0x02, value.as_bytes().to_vec()),
                ResolvedSelectorValue::Integer(value) => (0x03, value.to_string().into_bytes()),
                ResolvedSelectorValue::Boolean(value) => (0x04, vec![u8::from(*value)]),
                ResolvedSelectorValue::ControlledCode(value) => (0x05, value.as_bytes().to_vec()),
            };
            output.push(tag);
            push_component(&mut output, &value).map_err(selector)?;
        }
        Ok(output)
    }
}

/// One supplied value checked against its configured field, as the selector
/// resolver checks it, minus codelist membership.
fn resolve_value(
    configured: &SelectorField,
    supplied: SelectorValue,
) -> Result<ResolvedSelectorValue, PseudonymError> {
    match (configured, supplied) {
        (
            SelectorField::String {
                minimum_bytes,
                maximum_bytes,
            },
            SelectorValue::String(value),
        ) if bounded(value.len(), minimum_bytes.get(), maximum_bytes.get()) => {
            Ok(ResolvedSelectorValue::String(value))
        }
        (SelectorField::Uuid {}, SelectorValue::String(value)) if canonical_uuid(&value) => {
            Ok(ResolvedSelectorValue::String(value))
        }
        (SelectorField::Date {}, SelectorValue::String(value)) if canonical_date(&value) => {
            Ok(ResolvedSelectorValue::Date(value))
        }
        (SelectorField::Integer { minimum, maximum }, SelectorValue::Integer(value))
            if (*minimum..=*maximum).contains(&value)
                && value.unsigned_abs() <= MAX_SAFE_INTEGER.unsigned_abs() =>
        {
            Ok(ResolvedSelectorValue::Integer(value))
        }
        (SelectorField::Boolean {}, SelectorValue::Boolean(value)) => {
            Ok(ResolvedSelectorValue::Boolean(value))
        }
        (SelectorField::ControlledCode { maximum_bytes, .. }, SelectorValue::String(value))
            if bounded(value.len(), 1, maximum_bytes.get()) =>
        {
            Ok(ResolvedSelectorValue::ControlledCode(value))
        }
        _ => Err(PseudonymError::Selector),
    }
}

fn bounded(actual: usize, minimum: u64, maximum: u64) -> bool {
    u64::try_from(actual).is_ok_and(|actual| (minimum..=maximum).contains(&actual))
}

/// The one spelling of a date the selector resolver accepts: `YYYY-MM-DD`,
/// a real calendar day, and nothing that formats differently.
fn canonical_date(value: &str) -> bool {
    value.len() == 10
        && NaiveDate::parse_from_str(value, "%Y-%m-%d")
            .is_ok_and(|date| date.format("%Y-%m-%d").to_string() == value)
}

/// A keyed selector pseudonym and the key version it was written under.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct StatusPseudonym {
    key_version: KeyVersion,
    digest: [u8; 32],
}

impl StatusPseudonym {
    #[must_use]
    pub const fn key_version(&self) -> KeyVersion {
        self.key_version
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.digest
    }

    /// Rebuild a pseudonym read back from the ledger.
    #[must_use]
    pub const fn from_parts(key_version: KeyVersion, digest: [u8; 32]) -> Self {
        Self {
            key_version,
            digest,
        }
    }
}

impl fmt::Debug for StatusPseudonym {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StatusPseudonym")
            .field("key_version", &self.key_version)
            .field("digest", &"[REDACTED]")
            .finish()
    }
}

impl PseudonymKeyRing {
    /// The pseudonym under the current key, the one every write uses.
    pub fn pseudonym(&self, subject: &StatusSubject) -> Result<StatusPseudonym, PseudonymError> {
        let input = subject.pseudonym_input()?;
        Ok(keyed_pseudonym(self.ring().current(), &input))
    }

    /// The pseudonym under every key the ring holds, the current key first,
    /// for lookups during a rotation.
    pub fn lookup_pseudonyms(
        &self,
        subject: &StatusSubject,
    ) -> Result<Vec<StatusPseudonym>, PseudonymError> {
        let input = subject.pseudonym_input()?;
        Ok(self
            .ring()
            .keys()
            .map(|key| keyed_pseudonym(key, &input))
            .collect())
    }
}

fn keyed_pseudonym(key: &StatusKey, input: &[u8]) -> StatusPseudonym {
    StatusPseudonym {
        key_version: key.version(),
        digest: hmac_sha256(key.material(), input),
    }
}

/// An RFC 7638 JWK SHA-256 thumbprint of a holder key. It is digested on entry
/// and has no accessor: the raw thumbprint is never stored or returned.
pub struct HolderKeyThumbprint([u8; SHA256_THUMBPRINT_BYTES]);

impl HolderKeyThumbprint {
    /// Parse the base64url (unpadded) form a JWK thumbprint is exchanged in.
    pub fn from_base64url(value: &str) -> Result<Self, PseudonymError> {
        if value.len() != SHA256_THUMBPRINT_BASE64URL_CHARS {
            return Err(PseudonymError::Thumbprint);
        }
        let decoded = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| PseudonymError::Thumbprint)?;
        <[u8; SHA256_THUMBPRINT_BYTES]>::try_from(decoded.as_slice())
            .map(Self)
            .map_err(|_| PseudonymError::Thumbprint)
    }
}

impl fmt::Debug for HolderKeyThumbprint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HolderKeyThumbprint([REDACTED])")
    }
}

/// `HMAC-SHA-256(holder-key digest key, thumbprint)` and the key version it
/// was written under.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HolderKeyDigest {
    key_version: KeyVersion,
    digest: [u8; 32],
}

impl HolderKeyDigest {
    #[must_use]
    pub const fn key_version(&self) -> KeyVersion {
        self.key_version
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.digest
    }
}

impl fmt::Debug for HolderKeyDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HolderKeyDigest")
            .field("key_version", &self.key_version)
            .field("digest", &"[REDACTED]")
            .finish()
    }
}

impl HolderDigestKeyRing {
    /// The digest under the current key, the one every write uses.
    #[must_use]
    pub fn digest(&self, thumbprint: &HolderKeyThumbprint) -> HolderKeyDigest {
        keyed_digest(self.ring().current(), thumbprint)
    }

    /// The digest under every key the ring holds, the current key first, so
    /// a lost-device lookup tries each retained key.
    #[must_use]
    pub fn lookup_digests(&self, thumbprint: &HolderKeyThumbprint) -> Vec<HolderKeyDigest> {
        self.ring()
            .keys()
            .map(|key| keyed_digest(key, thumbprint))
            .collect()
    }
}

fn keyed_digest(key: &StatusKey, thumbprint: &HolderKeyThumbprint) -> HolderKeyDigest {
    HolderKeyDigest {
        key_version: key.version(),
        digest: hmac_sha256(key.material(), &thumbprint.0),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use registry_platform_yaml::BoundedU64;
    use serde_json::{json, Map, Value};
    use zeroize::Zeroizing;

    use super::{HolderKeyThumbprint, PseudonymError, StatusSubject, STATUS_PSEUDONYM_DOMAIN};
    use crate::config::{ArtifactPath, OrderedMap, SelectorField, SelectorProfile, ValueOrigin};
    use crate::model::SelectorValue;
    use crate::selector::{
        ResolvedSelectorField, ResolvedSelectorValue, ResolvedSubject, ResolvedSubjectScope,
    };
    use crate::status::{HolderDigestKeyRing, KeyRing, KeyVersion, PseudonymKeyRing, StatusKey};

    const PROFILE_ID: &str = "person-reference";
    const SUBJECT_REF: &str = "3f1c2b9e-8d4a-4c7e-9b1f-0a2d3c4e5f60";
    const LABEL: &str = "selector-canary-Quillon";

    fn key(version: u32, byte: u8) -> StatusKey {
        StatusKey::new(
            KeyVersion::new(version).unwrap(),
            Zeroizing::new(vec![byte; 32]),
        )
        .unwrap()
    }

    fn pseudonym_ring(byte: u8) -> PseudonymKeyRing {
        PseudonymKeyRing::new(KeyRing::new(key(1, byte), Vec::new()).unwrap())
    }

    // Declared deliberately out of alphabetical order: declaration order is
    // the canonical order, whatever order a projection or a row arrives in.
    fn profile() -> SelectorProfile {
        let mut fields = OrderedMap::default();
        fields.insert("subject_ref".to_owned(), SelectorField::Uuid {});
        fields.insert("issued_on".to_owned(), SelectorField::Date {});
        fields.insert(
            "sequence".to_owned(),
            SelectorField::Integer {
                minimum: -1000,
                maximum: 1000,
            },
        );
        fields.insert("active".to_owned(), SelectorField::Boolean {});
        fields.insert(
            "category".to_owned(),
            SelectorField::ControlledCode {
                codelist: ArtifactPath::parse("codelists/category.yaml").unwrap(),
                codelist_version: "1".to_owned(),
                maximum_bytes: BoundedU64::new(16).unwrap(),
            },
        );
        fields.insert(
            "label".to_owned(),
            SelectorField::String {
                minimum_bytes: BoundedU64::new(1).unwrap(),
                maximum_bytes: BoundedU64::new(64).unwrap(),
            },
        );
        SelectorProfile {
            maximum_aggregate_bytes: BoundedU64::new(512).unwrap(),
            fields,
        }
    }

    fn resolved_subject() -> ResolvedSubject {
        let field = |name: &str, value| ResolvedSelectorField {
            name: name.to_owned(),
            value,
        };
        ResolvedSubject {
            role: "subject".to_owned(),
            selector_profile: PROFILE_ID.to_owned(),
            value_origin: ValueOrigin::Request,
            fields: vec![
                field(
                    "subject_ref",
                    ResolvedSelectorValue::String(SUBJECT_REF.to_owned()),
                ),
                field(
                    "issued_on",
                    ResolvedSelectorValue::Date("2019-04-07".to_owned()),
                ),
                field("sequence", ResolvedSelectorValue::Integer(-42)),
                field("active", ResolvedSelectorValue::Boolean(true)),
                field(
                    "category",
                    ResolvedSelectorValue::ControlledCode("group-b".to_owned()),
                ),
                field("label", ResolvedSelectorValue::String(LABEL.to_owned())),
            ],
        }
    }

    fn hook_projection() -> Map<String, Value> {
        // Members in an arbitrary order, plus the record id and status field
        // a hook projection also carries.
        let Value::Object(projection) = json!({
            "label": LABEL,
            "recordId": "record-canary-Vantrel",
            "active": true,
            "status": {"code": "withdrawn"},
            "category": "group-b",
            "sequence": -42,
            "issued_on": "2019-04-07",
            "subject_ref": SUBJECT_REF,
        }) else {
            unreachable!("the projection is an object")
        };
        projection
    }

    fn extract_row() -> BTreeMap<String, SelectorValue> {
        BTreeMap::from([
            ("active".to_owned(), SelectorValue::Boolean(true)),
            (
                "category".to_owned(),
                SelectorValue::String("group-b".to_owned()),
            ),
            (
                "issued_on".to_owned(),
                SelectorValue::String("2019-04-07".to_owned()),
            ),
            ("label".to_owned(), SelectorValue::String(LABEL.to_owned())),
            ("revision".to_owned(), SelectorValue::Integer(17)),
            ("sequence".to_owned(), SelectorValue::Integer(-42)),
            (
                "subject_ref".to_owned(),
                SelectorValue::String(SUBJECT_REF.to_owned()),
            ),
        ])
    }

    fn three_constructions() -> [StatusSubject; 3] {
        let profile = profile();
        [
            StatusSubject::from_resolved(&resolved_subject()),
            StatusSubject::from_json_projection(PROFILE_ID, &profile, &hook_projection()).unwrap(),
            StatusSubject::from_named_values(PROFILE_ID, &profile, &extract_row()).unwrap(),
        ]
    }

    #[test]
    fn a_request_a_hook_projection_and_an_extract_row_give_one_pseudonym() {
        let ring = pseudonym_ring(0x11);
        let [request, hook, extract] = three_constructions();
        let expected = ring.pseudonym(&request).unwrap();
        assert_eq!(ring.pseudonym(&hook).unwrap(), expected);
        assert_eq!(ring.pseudonym(&extract).unwrap(), expected);
        assert_eq!(expected.key_version().get(), 1);
    }

    #[test]
    fn changing_any_field_the_profile_id_or_the_key_changes_the_pseudonym() {
        let ring = pseudonym_ring(0x11);
        let profile = profile();
        let baseline = ring
            .pseudonym(
                &StatusSubject::from_named_values(PROFILE_ID, &profile, &extract_row()).unwrap(),
            )
            .unwrap();

        let changes: [(&str, SelectorValue); 6] = [
            (
                "subject_ref",
                SelectorValue::String("3f1c2b9e-8d4a-4c7e-9b1f-0a2d3c4e5f61".to_owned()),
            ),
            ("issued_on", SelectorValue::String("2019-04-08".to_owned())),
            ("sequence", SelectorValue::Integer(42)),
            ("active", SelectorValue::Boolean(false)),
            ("category", SelectorValue::String("group-c".to_owned())),
            (
                "label",
                SelectorValue::String("selector-canary-Quillom".to_owned()),
            ),
        ];
        for (name, value) in changes {
            let mut row = extract_row();
            row.insert(name.to_owned(), value);
            let changed = ring
                .pseudonym(&StatusSubject::from_named_values(PROFILE_ID, &profile, &row).unwrap())
                .unwrap();
            assert_ne!(changed, baseline, "changing {name} kept the pseudonym");
        }

        let other_profile = ring
            .pseudonym(
                &StatusSubject::from_named_values("person-reference-2", &profile, &extract_row())
                    .unwrap(),
            )
            .unwrap();
        assert_ne!(other_profile, baseline);

        let other_key = pseudonym_ring(0x12)
            .pseudonym(
                &StatusSubject::from_named_values(PROFILE_ID, &profile, &extract_row()).unwrap(),
            )
            .unwrap();
        assert_ne!(other_key, baseline);
    }

    #[test]
    fn the_input_frames_fields_exactly_as_the_audit_pseudonym_does() {
        let subject = resolved_subject();
        let input = StatusSubject::from_resolved(&subject)
            .pseudonym_input()
            .unwrap();
        // Domain tag, length-prefixed: a four-byte length starting 0x00.
        assert_eq!(input[0], 0x00);
        assert_eq!(
            &input[4..4 + STATUS_PSEUDONYM_DOMAIN.len()],
            STATUS_PSEUDONYM_DOMAIN
        );
        let after_domain = &input[4 + STATUS_PSEUDONYM_DOMAIN.len()..];
        for scope in [
            ResolvedSubjectScope::Audience("https://audience.example".to_owned()),
            ResolvedSubjectScope::HolderKeyThumbprint("thumbprint".to_owned()),
        ] {
            let audit = subject.audit_pseudonym_input(&scope, "purpose").unwrap();
            assert!(matches!(audit[0], 0x01 | 0x02));
            assert_ne!(audit[0], input[0]);
            // Profile id, field count, and fields are byte-for-byte the audit
            // framing, with no role, purpose, audience or binding mode.
            assert!(audit.ends_with(after_domain));
            assert!(!after_domain.windows(7).any(|window| window == b"purpose"));
        }
    }

    #[test]
    fn the_role_and_value_origin_do_not_change_the_pseudonym() {
        let ring = pseudonym_ring(0x11);
        let mut other = resolved_subject();
        other.role = "beneficiary".to_owned();
        other.value_origin = ValueOrigin::AuthenticatedGrant;
        assert_eq!(
            ring.pseudonym(&StatusSubject::from_resolved(&other))
                .unwrap(),
            ring.pseudonym(&StatusSubject::from_resolved(&resolved_subject()))
                .unwrap()
        );
    }

    #[test]
    fn projections_that_do_not_match_the_profile_are_refused() {
        let profile = profile();
        let refused = |name: &str, value: Option<SelectorValue>| {
            let mut row = extract_row();
            match value {
                Some(value) => row.insert(name.to_owned(), value),
                None => row.remove(name),
            };
            StatusSubject::from_named_values(PROFILE_ID, &profile, &row)
        };
        let cases = [
            ("subject_ref", None),
            (
                "subject_ref",
                Some(SelectorValue::String(SUBJECT_REF.to_uppercase())),
            ),
            ("subject_ref", Some(SelectorValue::Integer(1))),
            (
                "issued_on",
                Some(SelectorValue::String("2019-4-07".to_owned())),
            ),
            (
                "issued_on",
                Some(SelectorValue::String("2019-02-30".to_owned())),
            ),
            ("sequence", Some(SelectorValue::Integer(1001))),
            ("sequence", Some(SelectorValue::String("-42".to_owned()))),
            ("active", Some(SelectorValue::Integer(1))),
            ("category", Some(SelectorValue::String(String::new()))),
            ("category", Some(SelectorValue::String("c".repeat(17)))),
            ("label", Some(SelectorValue::String(String::new()))),
            ("label", Some(SelectorValue::String("l".repeat(65)))),
        ];
        for (name, value) in cases {
            assert_eq!(
                refused(name, value.clone()).err(),
                Some(PseudonymError::Selector),
                "{name} accepted"
            );
        }

        let mut projection = hook_projection();
        projection.insert("sequence".to_owned(), json!(-42.5));
        assert_eq!(
            StatusSubject::from_json_projection(PROFILE_ID, &profile, &projection).err(),
            Some(PseudonymError::Selector)
        );
        let mut projection = hook_projection();
        projection.insert("active".to_owned(), Value::Null);
        assert_eq!(
            StatusSubject::from_json_projection(PROFILE_ID, &profile, &projection).err(),
            Some(PseudonymError::Selector)
        );
        assert_eq!(
            StatusSubject::from_named_values("", &profile, &extract_row())
                .and_then(|subject| pseudonym_ring(1).pseudonym(&subject))
                .err(),
            Some(PseudonymError::Selector)
        );
    }

    #[test]
    fn lookups_key_the_subject_under_every_retained_key() {
        let ring = PseudonymKeyRing::new(KeyRing::new(key(3, 3), vec![key(2, 2)]).unwrap());
        let [subject, _, _] = three_constructions();
        let lookups = ring.lookup_pseudonyms(&subject).unwrap();
        let versions: Vec<u32> = lookups
            .iter()
            .map(|value| value.key_version().get())
            .collect();
        assert_eq!(versions, [3, 2]);
        assert_eq!(lookups[0], ring.pseudonym(&subject).unwrap());
        assert_ne!(lookups[0].as_bytes(), lookups[1].as_bytes());
        assert_eq!(
            lookups[1].as_bytes(),
            pseudonym_ring(2).pseudonym(&subject).unwrap().as_bytes()
        );
    }

    fn thumbprint_text(byte: u8) -> String {
        URL_SAFE_NO_PAD.encode([byte; 32])
    }

    #[test]
    fn holder_key_thumbprints_are_unpadded_base64url_sha256_values() {
        assert!(HolderKeyThumbprint::from_base64url(&thumbprint_text(7)).is_ok());
        let refused = [
            String::new(),
            URL_SAFE_NO_PAD.encode([7_u8; 31]),
            URL_SAFE_NO_PAD.encode([7_u8; 33]),
            format!("{}=", thumbprint_text(7)),
            thumbprint_text(7).replace('B', "+"),
        ];
        for value in refused {
            assert_eq!(
                HolderKeyThumbprint::from_base64url(&value).err(),
                Some(PseudonymError::Thumbprint),
                "accepted {value:?}"
            );
        }
    }

    #[test]
    fn holder_key_digests_are_keyed_and_versioned() {
        let ring =
            HolderDigestKeyRing::new(KeyRing::new(key(2, 0x21), vec![key(1, 0x22)]).unwrap());
        let thumbprint = HolderKeyThumbprint::from_base64url(&thumbprint_text(7)).unwrap();
        let digest = ring.digest(&thumbprint);
        assert_eq!(digest.key_version().get(), 2);
        assert_eq!(
            digest.as_bytes(),
            &registry_platform_crypto::mac::hmac_sha256(&[0x21; 32], &[7; 32])
        );
        assert_eq!(digest, ring.digest(&thumbprint));
        let other = HolderKeyThumbprint::from_base64url(&thumbprint_text(8)).unwrap();
        assert_ne!(ring.digest(&other), digest);

        let lookups = ring.lookup_digests(&thumbprint);
        let versions: Vec<u32> = lookups
            .iter()
            .map(|value| value.key_version().get())
            .collect();
        assert_eq!(versions, [2, 1]);
        assert_eq!(lookups[0], digest);
        assert_eq!(
            lookups[1].as_bytes(),
            &registry_platform_crypto::mac::hmac_sha256(&[0x22; 32], &[7; 32])
        );
    }

    #[test]
    fn debug_and_display_carry_no_selector_value_thumbprint_or_digest() {
        let ring = pseudonym_ring(0x11);
        let [subject, _, _] = three_constructions();
        let pseudonym = ring.pseudonym(&subject).unwrap();
        let thumbprint_value = thumbprint_text(7);
        let thumbprint = HolderKeyThumbprint::from_base64url(&thumbprint_value).unwrap();
        let holder = HolderDigestKeyRing::new(KeyRing::new(key(1, 0x21), Vec::new()).unwrap());
        let digest = holder.digest(&thumbprint);
        let rendered = [
            format!("{subject:?}"),
            format!("{pseudonym:?}"),
            format!("{thumbprint:?}"),
            format!("{digest:?}"),
            PseudonymError::Selector.to_string(),
            format!("{:?}", PseudonymError::Selector),
            PseudonymError::Thumbprint.to_string(),
            format!("{:?}", PseudonymError::Thumbprint),
        ];
        let digest_hex: String = digest
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let pseudonym_hex: String = pseudonym
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        for text in rendered {
            for canary in [
                LABEL,
                SUBJECT_REF,
                "group-b",
                "2019-04-07",
                thumbprint_value.as_str(),
                digest_hex.as_str(),
                pseudonym_hex.as_str(),
            ] {
                assert!(!text.contains(canary), "{text} carries {canary}");
            }
        }
    }
}
