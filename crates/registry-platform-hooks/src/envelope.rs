// SPDX-License-Identifier: Apache-2.0

//! The envelope: the one canonical JSON document the library hands a handler,
//! unchanged for every product and every destination kind.
//!
//! The fields are `id`, `type`, `source`, `time`, `subject`, `dataschema`,
//! `data`, and `causation`. Delivery attributes (`attempt`, `generation`,
//! `delivery_time`, `idempotency_key`, `signature`) are deliberately **not**
//! envelope fields and never become them: they stay on the transport headers.
//! The envelope is what the handler reasons over; the attributes are what the
//! worker reasons over. A handler that wants to be idempotent keys on the
//! envelope `id`, which the transport also sends as `idempotency_key`.
//!
//! Causation is consumed by version one, not reserved for later: once a
//! handler can propose a change that commits and fires another hook, event A
//! can cause B can cause A. `causation.hop` against [`HOP_CEILING`] is the
//! guard, and refusals are recorded, never silent.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;

use registry_platform_canonical_json::{canonicalize_json, parse_json_strict, JcsError};

use crate::error::{bounded_token, redacted_message};

/// The payload bound the envelope carries, in bytes.
///
/// The same 2 MiB payload bound the delivery store enforces on a stored
/// envelope. A per-delivery bound can only tighten this, never widen it.
pub const MAX_ENVELOPE_BYTES: usize = 2_097_152;

/// The causation hop ceiling.
///
/// A chain of handlers proposing changes that fire further hooks stops here:
/// the worker refuses to enqueue a hook whose hop would exceed this ceiling,
/// records the refusal as a dead-letter reason, and stops the chain. Earlier
/// commits in the chain stay intact.
pub const HOP_CEILING: u32 = 8;

/// Byte ceilings for one envelope encode or decode.
///
/// The default is [`MAX_ENVELOPE_BYTES`]. A delivery may carry a tighter
/// per-delivery bound; tightening is the only direction available, so the
/// ceiling is not a public field and [`EnvelopeLimits::tightened_to`] clamps a
/// wider request back to [`MAX_ENVELOPE_BYTES`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvelopeLimits {
    max_envelope_bytes: usize,
}

impl EnvelopeLimits {
    /// Tighten the envelope ceiling to `bytes`.
    ///
    /// A request above [`MAX_ENVELOPE_BYTES`] is clamped to it rather than
    /// refused: a per-delivery bound is a tightening, and a caller that asks
    /// for more gets the store's bound, never more than it.
    #[must_use]
    pub const fn tightened_to(bytes: usize) -> Self {
        Self {
            max_envelope_bytes: if bytes < MAX_ENVELOPE_BYTES {
                bytes
            } else {
                MAX_ENVELOPE_BYTES
            },
        }
    }

    /// The effective ceiling in bytes.
    #[must_use]
    pub const fn max_envelope_bytes(&self) -> usize {
        self.max_envelope_bytes
    }
}

impl Default for EnvelopeLimits {
    fn default() -> Self {
        Self {
            max_envelope_bytes: MAX_ENVELOPE_BYTES,
        }
    }
}

/// The product record the triggering change landed on.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct EventSubject {
    /// The record reference, as the product addresses it.
    pub record_reference: String,
    /// The revision the triggering change produced. Revisions start at one, so
    /// a revision of zero or below is refused on both encode and decode, the
    /// same bound the delivery store enforces on a stored envelope.
    pub record_revision: i64,
}

/// Why this event exists: the chain it belongs to and the event that caused it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Causation {
    /// The id of the first event in the chain; equals `id` for a root event.
    /// A later orchestrator correlates on this field. A UUID, like every
    /// event identity on the envelope.
    pub root: String,
    /// The id of the event whose handler proposed the change that produced
    /// this one. Absent for a root event. A UUID when present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    /// 0 for a root event, parent hop + 1 otherwise.
    pub hop: u32,
}

impl Causation {
    /// The causation of a root event: hop 0, no parent, own root.
    #[must_use]
    pub fn root(event_id: &str) -> Self {
        Self {
            root: event_id.to_owned(),
            parent: None,
            hop: 0,
        }
    }

    /// The causation of an event caused by `causing_event_id`, whose handler's
    /// proposal committed and fired this hook.
    ///
    /// # Errors
    ///
    /// Returns [`HookCausationError::HopBeyondCeiling`] when the child's hop
    /// would exceed [`HOP_CEILING`]; the error names the ceiling so the worker
    /// can record it as a dead-letter reason.
    pub fn child(&self, causing_event_id: &str) -> Result<Self, HookCausationError> {
        if self.hop >= HOP_CEILING {
            return Err(HookCausationError::HopBeyondCeiling {
                attempted: self.hop.saturating_add(1),
                ceiling: HOP_CEILING,
            });
        }
        Ok(Self {
            root: self.root.clone(),
            parent: Some(causing_event_id.to_owned()),
            hop: self.hop + 1,
        })
    }
}

/// The hook envelope, one shape for every product and every destination kind.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct HookEnvelope {
    /// Event identity, unique per triggering change. The idempotency key a
    /// remote handler must honor across retries.
    ///
    /// A UUID: the delivery store keys an envelope by a UUID event id, so an
    /// id that is not one could never be stored. Refused on both encode and
    /// decode.
    pub id: String,
    /// The hook's stable contract id.
    #[serde(rename = "type")]
    pub event_type: String,
    /// The producing product and deployment identity.
    pub source: String,
    /// Commit time of the triggering change, RFC 3339.
    ///
    /// Normalized on every serialization: converted to UTC and truncated to
    /// whole milliseconds, so two equal instants written at different offsets
    /// or at finer precision produce identical canonical bytes. The in-memory
    /// value keeps whatever the product gave it; the wire form is the
    /// normalized one.
    #[serde(with = "utc_millisecond_rfc3339")]
    pub time: OffsetDateTime,
    /// The product record reference and revision.
    pub subject: EventSubject,
    /// The product data contract id for `data`.
    pub dataschema: String,
    /// The product projection. Integers that are not exactly representable as
    /// binary64 must be strings; canonical JSON refuses them otherwise.
    pub data: Value,
    /// The chain this event belongs to.
    pub causation: Causation,
}

/// The envelope's normalized wire form for `time`: UTC at whole-millisecond
/// precision, so equal instants encode to equal bytes.
mod utc_millisecond_rfc3339 {
    use serde::{Deserializer, Serializer};
    use time::{OffsetDateTime, UtcOffset};

    /// Nanoseconds in one millisecond, the wire precision.
    const NANOSECONDS_PER_MILLISECOND: u32 = 1_000_000;

    pub(super) fn serialize<S: Serializer>(
        value: &OffsetDateTime,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        let normalized = normalize(*value).map_err(serde::ser::Error::custom)?;
        time::serde::rfc3339::serialize(&normalized, serializer)
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<OffsetDateTime, D::Error> {
        time::serde::rfc3339::deserialize(deserializer)
    }

    /// Convert to UTC and drop everything below the millisecond.
    fn normalize(value: OffsetDateTime) -> Result<OffsetDateTime, time::error::ComponentRange> {
        let utc = value.to_offset(UtcOffset::UTC);
        let millisecond_floor =
            utc.nanosecond() / NANOSECONDS_PER_MILLISECOND * NANOSECONDS_PER_MILLISECOND;
        utc.replace_nanosecond(millisecond_floor)
    }
}

impl HookEnvelope {
    /// Serialize to canonical JSON bytes (RFC 8785).
    ///
    /// # Errors
    ///
    /// Returns [`HookEnvelopeError`] when the identity, revision, or causation
    /// is refused, a number cannot be canonicalized, or the canonical bytes
    /// exceed the configured ceiling.
    pub fn to_canonical_bytes(
        &self,
        limits: &EnvelopeLimits,
    ) -> Result<Vec<u8>, HookEnvelopeError> {
        validate_envelope(self)?;
        let value = serde_json::to_value(self)
            .map_err(|error| HookEnvelopeError::Shape(redacted_message(&error.to_string())))?;
        let bytes = canonicalize_json(&value).map_err(HookEnvelopeError::Canonical)?;
        if bytes.len() > limits.max_envelope_bytes {
            return Err(HookEnvelopeError::PayloadTooLarge {
                size: bytes.len(),
                max: limits.max_envelope_bytes,
            });
        }
        Ok(bytes)
    }

    /// Decode from untrusted envelope bytes.
    ///
    /// The bytes are parsed with the shared strict parser, which rejects
    /// duplicate object members and integer tokens that are not exactly
    /// representable as binary64; the caller remains responsible for bounding
    /// `bytes` first, and the ceiling is checked before any parsing happens.
    /// The bytes must equal their own canonicalization: canonical bytes are
    /// the producer's contract, so a decoder that accepted a second spelling
    /// of the same envelope would accept bytes whose digest no producer can
    /// reproduce.
    ///
    /// # Errors
    ///
    /// Returns [`HookEnvelopeError`] when the bytes exceed the ceiling, are not
    /// strict or canonical JSON, violate the envelope shape, or carry a refused
    /// identity, revision, or causation chain.
    pub fn from_canonical_bytes(
        bytes: &[u8],
        limits: &EnvelopeLimits,
    ) -> Result<Self, HookEnvelopeError> {
        if bytes.len() > limits.max_envelope_bytes {
            return Err(HookEnvelopeError::PayloadTooLarge {
                size: bytes.len(),
                max: limits.max_envelope_bytes,
            });
        }
        let value = parse_json_strict(bytes)?;
        let canonical = canonicalize_json(&value).map_err(HookEnvelopeError::Canonical)?;
        if canonical.as_slice() != bytes {
            return Err(HookEnvelopeError::NotCanonical);
        }
        let envelope: Self = serde_json::from_value(value)
            .map_err(|error| HookEnvelopeError::Shape(redacted_message(&error.to_string())))?;
        validate_envelope(&envelope)?;
        Ok(envelope)
    }
}

/// Refuse an envelope the delivery store could never hold or the chain rules
/// forbid, on the encode and the decode path alike.
fn validate_envelope(envelope: &HookEnvelope) -> Result<(), HookEnvelopeError> {
    if envelope.subject.record_revision <= 0 {
        return Err(HookEnvelopeError::InvalidRevision {
            revision: envelope.subject.record_revision,
        });
    }
    validate_causation(envelope)?;
    Ok(())
}

/// Refuse an unusable event identity or a structurally impossible causation.
///
/// Identity first: every id on the envelope is a UUID, because that is how the
/// delivery store keys an event, so an id that is not one names an event that
/// could never exist. Then the chain guards: a root event has no parent and is
/// its own root; a caused event has a parent that is not itself, chains from a
/// root that is not itself, and never arrives beyond the ceiling, because the
/// hop guard refuses such a child before it is ever enqueued.
fn validate_causation(envelope: &HookEnvelope) -> Result<(), HookCausationError> {
    let causation = &envelope.causation;
    let id = envelope.id.as_str();
    validate_event_id("id", id)?;
    validate_event_id("causation.root", causation.root.as_str())?;
    if let Some(parent) = causation.parent.as_deref() {
        validate_event_id("causation.parent", parent)?;
    }
    if causation.hop == 0 {
        if causation.parent.is_some() {
            return Err(HookCausationError::RootEventCarriesParent { id: id.to_owned() });
        }
        if causation.root != id {
            return Err(HookCausationError::RootEventNotOwnRoot {
                id: id.to_owned(),
                root: causation.root.clone(),
            });
        }
        return Ok(());
    }
    let Some(parent) = causation.parent.as_deref() else {
        return Err(HookCausationError::ChildEventMissingParent { id: id.to_owned() });
    };
    if parent == id {
        return Err(HookCausationError::ChildEventOwnParent { id: id.to_owned() });
    }
    if causation.root == id {
        return Err(HookCausationError::ChildEventNotChainedFromRoot {
            id: id.to_owned(),
            root: causation.root.clone(),
        });
    }
    if causation.hop > HOP_CEILING {
        return Err(HookCausationError::HopBeyondCeiling {
            attempted: causation.hop,
            ceiling: HOP_CEILING,
        });
    }
    Ok(())
}

/// Refuse an event identity that is not a UUID, naming the field that carried
/// it and not the value beyond the display bound.
fn validate_event_id(field: &'static str, id: &str) -> Result<(), HookCausationError> {
    if Uuid::parse_str(id).is_err() {
        return Err(HookCausationError::InvalidEventId {
            field,
            id: id.to_owned(),
        });
    }
    Ok(())
}

/// A structurally impossible causation chain.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum HookCausationError {
    /// An event identity is not a UUID.
    #[error("envelope field `{field}` must be a UUID event id, found `{}`", bounded_token(.id))]
    InvalidEventId { field: &'static str, id: String },
    /// A root event carried a `causation.parent`.
    #[error("root event {} must not carry a causation parent", bounded_token(.id))]
    RootEventCarriesParent { id: String },
    /// A root event named a different event as the chain root.
    #[error(
        "root event {} must be its own causation root, found {}",
        bounded_token(.id),
        bounded_token(.root)
    )]
    RootEventNotOwnRoot { id: String, root: String },
    /// A caused event carried no `causation.parent`.
    #[error("caused event {} requires a causation parent", bounded_token(.id))]
    ChildEventMissingParent { id: String },
    /// An event named itself as its own cause.
    #[error("caused event {} cannot be its own causation parent", bounded_token(.id))]
    ChildEventOwnParent { id: String },
    /// A caused event claimed to be the first event of its own chain.
    #[error(
        "caused event {} must chain from the first event of its chain, found root {}",
        bounded_token(.id),
        bounded_token(.root)
    )]
    ChildEventNotChainedFromRoot { id: String, root: String },
    /// A child's hop would exceed the ceiling. This is the dead-letter reason
    /// the worker records; the chain stops here and earlier commits stay
    /// intact.
    #[error("causation hop {attempted} exceeds the ceiling of {ceiling}")]
    HopBeyondCeiling { attempted: u32, ceiling: u32 },
}

impl HookCausationError {
    /// The stable diagnostic code for this failure.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidEventId { .. } => "hook.causation.invalid_id",
            Self::RootEventCarriesParent { .. } => "hook.causation.root_carries_parent",
            Self::RootEventNotOwnRoot { .. } => "hook.causation.root_not_own_root",
            Self::ChildEventMissingParent { .. } => "hook.causation.child_missing_parent",
            Self::ChildEventOwnParent { .. } => "hook.causation.child_own_parent",
            Self::ChildEventNotChainedFromRoot { .. } => "hook.causation.child_not_chained",
            Self::HopBeyondCeiling { .. } => "hook.causation.hop_beyond_ceiling",
        }
    }
}

/// Failure to encode or decode one hook envelope.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HookEnvelopeError {
    /// The envelope bytes exceed the configured ceiling.
    #[error("envelope of {size} bytes exceeds the {max}-byte ceiling")]
    PayloadTooLarge { size: usize, max: usize },
    /// The envelope is not strict JSON.
    #[error("envelope is not strict JSON: {0}")]
    Json(#[from] registry_platform_canonical_json::StrictJsonError),
    /// The envelope is valid JSON but not canonical.
    #[error("envelope is not canonical JSON")]
    NotCanonical,
    /// The envelope violates the envelope shape. The deserializer message is
    /// redacted and bounded, never the untrusted bytes as they arrived.
    #[error("envelope violates the hook envelope shape: {0}")]
    Shape(String),
    /// A number in the envelope cannot be canonicalized.
    #[error("envelope is not canonicalizable: {0}")]
    Canonical(#[from] JcsError),
    /// The subject revision is not a revision the delivery store could hold.
    #[error("envelope subject revision {revision} must be greater than zero")]
    InvalidRevision { revision: i64 },
    /// The envelope carries an unusable identity or an impossible causation.
    #[error("envelope causation is inconsistent: {0}")]
    Causation(#[from] HookCausationError),
}

impl HookEnvelopeError {
    /// The stable diagnostic code for this failure.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::PayloadTooLarge { .. } => "hook.envelope.payload_too_large",
            Self::Json(_) => "hook.envelope.not_strict_json",
            Self::NotCanonical => "hook.envelope.not_canonical",
            Self::Shape(_) => "hook.envelope.bad_shape",
            Self::Canonical(_) => "hook.envelope.not_canonicalizable",
            Self::InvalidRevision { .. } => "hook.envelope.invalid_revision",
            Self::Causation(error) => error.code(),
        }
    }

    /// The run-time failure category, per the taxonomy's mapping.
    #[must_use]
    pub const fn category(&self) -> crate::error::ErrorCategory {
        match self {
            Self::PayloadTooLarge { .. } => crate::error::ErrorCategory::Resource,
            Self::Json(_)
            | Self::NotCanonical
            | Self::Shape(_)
            | Self::Canonical(_)
            | Self::InvalidRevision { .. } => crate::error::ErrorCategory::Source,
            Self::Causation(_) => crate::error::ErrorCategory::Source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ErrorCategory, MAX_DISPLAYED_TOKEN_BYTES};
    use serde_json::json;
    use std::collections::BTreeSet;
    use time::format_description::well_known::Rfc3339;
    use time::macros::datetime;

    const EVENT_A: &str = "019934b2-1f2e-7c3a-9d4b-6f1e2a3b4c5d";
    const EVENT_B: &str = "019934b2-1f2e-7c3a-9d4b-6f1e2a3b4c5e";

    /// Canonical bytes for an envelope the encoder would refuse, so a decode
    /// test can feed canonical bytes and still assert the refusal it is about.
    fn canonical_bytes_unchecked(envelope: &HookEnvelope) -> Vec<u8> {
        let value = serde_json::to_value(envelope).expect("serializes");
        canonicalize_json(&value).expect("canonicalizes")
    }

    fn envelope() -> HookEnvelope {
        HookEnvelope {
            id: EVENT_A.to_owned(),
            event_type: "birth-registered-followup".to_owned(),
            source: "/products/breg/deployments/prod".to_owned(),
            time: datetime!(2026-09-18 12:00:00 UTC),
            subject: EventSubject {
                record_reference: "breg/person/42".to_owned(),
                record_revision: 7,
            },
            dataschema: "https://breg.example.gov/schemas/person/v3".to_owned(),
            data: json!({"entity": "person", "values": {"familyName": "Kalanni"}}),
            causation: Causation::root(EVENT_A),
        }
    }

    #[test]
    fn encodes_canonical_bytes_with_sorted_names() {
        let limits = EnvelopeLimits::default();
        let bytes = envelope()
            .to_canonical_bytes(&limits)
            .expect("root envelope encodes");
        let encoded = String::from_utf8(bytes).expect("UTF-8");
        // RFC 8785: names ordered by code points, no insignificant whitespace.
        // `type` keeps its CloudEvents spelling.
        assert_eq!(
            encoded,
            concat!(
                r#"{"causation":{"hop":0,"root":"019934b2-1f2e-7c3a-9d4b-6f1e2a3b4c5d"},"#,
                r#""data":{"entity":"person","values":{"familyName":"Kalanni"}},"#,
                r#""dataschema":"https://breg.example.gov/schemas/person/v3","#,
                r#""id":"019934b2-1f2e-7c3a-9d4b-6f1e2a3b4c5d","#,
                r#""source":"/products/breg/deployments/prod","#,
                r#""subject":{"recordReference":"breg/person/42","recordRevision":7},"#,
                r#""time":"2026-09-18T12:00:00Z","#,
                r#""type":"birth-registered-followup"}"#,
            )
        );
    }

    #[test]
    fn round_trips_a_root_envelope() {
        let limits = EnvelopeLimits::default();
        let source = envelope();
        let bytes = source.to_canonical_bytes(&limits).expect("encodes");
        let decoded = HookEnvelope::from_canonical_bytes(&bytes, &limits).expect("decodes");
        assert_eq!(decoded, source);
        let again = decoded.to_canonical_bytes(&limits).expect("re-encodes");
        assert_eq!(again, bytes);
    }

    #[test]
    fn root_causation_is_hop_zero_with_no_parent_and_own_root() {
        let causation = Causation::root(EVENT_A);
        assert_eq!(causation.hop, 0);
        assert_eq!(causation.parent, None);
        assert_eq!(causation.root, EVENT_A);
    }

    #[test]
    fn child_causation_points_at_the_causing_event_and_climbs_one_hop() {
        let root = Causation::root(EVENT_A);
        let child = root.child(EVENT_A).expect("first hop is allowed");
        assert_eq!(child.parent.as_deref(), Some(EVENT_A));
        assert_eq!(child.hop, 1);
        assert_eq!(child.root, EVENT_A);

        let grandchild = child.child(EVENT_B).expect("second hop is allowed");
        assert_eq!(grandchild.parent.as_deref(), Some(EVENT_B));
        assert_eq!(grandchild.hop, 2);
        assert_eq!(grandchild.root, EVENT_A);
    }

    #[test]
    fn the_hop_guard_refuses_a_child_beyond_the_ceiling_and_names_it() {
        let mut causation = Causation::root(EVENT_A);
        for hop in 1..=HOP_CEILING {
            causation = causation
                .child(&format!("event-{hop}"))
                .unwrap_or_else(|_| panic!("hop {hop} is within the ceiling"));
            assert_eq!(causation.hop, hop);
        }
        assert_eq!(causation.hop, HOP_CEILING);

        let error = causation
            .child("event-beyond")
            .expect_err("the chain stops at the ceiling");
        assert_eq!(
            error,
            HookCausationError::HopBeyondCeiling {
                attempted: HOP_CEILING + 1,
                ceiling: HOP_CEILING,
            }
        );
        assert_eq!(error.code(), "hook.causation.hop_beyond_ceiling");
        assert_eq!(
            error.to_string(),
            format!(
                "causation hop {} exceeds the ceiling of {HOP_CEILING}",
                HOP_CEILING + 1
            )
        );
        assert!(
            error.to_string().contains("8"),
            "the ceiling is named: {error}"
        );
    }

    #[test]
    fn a_root_envelope_decodes_and_re_encodes() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.causation = Causation::root(source.id.as_str());
        let bytes = source.to_canonical_bytes(&limits).expect("encodes");
        let decoded = HookEnvelope::from_canonical_bytes(&bytes, &limits).expect("decodes");
        assert_eq!(decoded.causation.hop, 0);
        assert_eq!(
            decoded.to_canonical_bytes(&limits).expect("re-encodes"),
            bytes
        );
    }

    #[test]
    fn an_envelope_at_the_hop_ceiling_decodes_and_re_encodes() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.id = EVENT_B.to_owned();
        source.causation = Causation {
            root: EVENT_A.to_owned(),
            parent: Some(EVENT_A.to_owned()),
            hop: HOP_CEILING,
        };
        let bytes = source
            .to_canonical_bytes(&limits)
            .expect("the ceiling itself is inside the chain");
        let decoded = HookEnvelope::from_canonical_bytes(&bytes, &limits).expect("decodes");
        assert_eq!(decoded.causation.hop, HOP_CEILING);
        assert_eq!(
            decoded.to_canonical_bytes(&limits).expect("re-encodes"),
            bytes
        );
    }

    #[test]
    fn decode_refuses_a_root_event_with_a_parent() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.causation.parent = Some(EVENT_B.to_owned());
        let bytes = canonical_bytes_unchecked(&source);
        let error =
            HookEnvelope::from_canonical_bytes(&bytes, &limits).expect_err("root with parent");
        assert_eq!(error.code(), "hook.causation.root_carries_parent");
        assert_eq!(error.category(), ErrorCategory::Source);
    }

    #[test]
    fn decode_refuses_a_root_event_that_is_not_its_own_root() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.causation.root = EVENT_B.to_owned();
        let bytes = canonical_bytes_unchecked(&source);
        let error =
            HookEnvelope::from_canonical_bytes(&bytes, &limits).expect_err("root must be own root");
        assert_eq!(error.code(), "hook.causation.root_not_own_root");
    }

    #[test]
    fn decode_refuses_a_caused_event_without_a_parent() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.id = EVENT_B.to_owned();
        source.causation = Causation {
            root: EVENT_A.to_owned(),
            parent: None,
            hop: 1,
        };
        let bytes = canonical_bytes_unchecked(&source);
        let error =
            HookEnvelope::from_canonical_bytes(&bytes, &limits).expect_err("child needs parent");
        assert_eq!(error.code(), "hook.causation.child_missing_parent");
    }

    #[test]
    fn decode_refuses_an_event_that_is_its_own_parent() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.id = EVENT_A.to_owned();
        source.causation = Causation {
            root: EVENT_A.to_owned(),
            parent: Some(EVENT_A.to_owned()),
            hop: 1,
        };
        let bytes = canonical_bytes_unchecked(&source);
        let error = HookEnvelope::from_canonical_bytes(&bytes, &limits)
            .expect_err("self-causation is Odoo's write-inside-write");
        assert_eq!(error.code(), "hook.causation.child_own_parent");
    }

    #[test]
    fn decode_refuses_a_caused_event_claiming_to_be_its_own_chain_root() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.id = EVENT_B.to_owned();
        source.causation = Causation {
            root: EVENT_B.to_owned(),
            parent: Some(EVENT_A.to_owned()),
            hop: 1,
        };
        let bytes = canonical_bytes_unchecked(&source);
        let error = HookEnvelope::from_canonical_bytes(&bytes, &limits)
            .expect_err("a caused event cannot be the chain root");
        assert_eq!(error.code(), "hook.causation.child_not_chained");
    }

    #[test]
    fn decode_refuses_an_envelope_beyond_the_hop_ceiling() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.id = EVENT_B.to_owned();
        source.causation = Causation {
            root: EVENT_A.to_owned(),
            parent: Some(EVENT_A.to_owned()),
            hop: HOP_CEILING + 1,
        };
        let bytes = canonical_bytes_unchecked(&source);
        let error = HookEnvelope::from_canonical_bytes(&bytes, &limits)
            .expect_err("nothing enqueues beyond the ceiling");
        assert_eq!(error.code(), "hook.causation.hop_beyond_ceiling");
    }

    #[test]
    fn encode_refuses_an_envelope_beyond_the_hop_ceiling() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.id = EVENT_B.to_owned();
        source.causation = Causation {
            root: EVENT_A.to_owned(),
            parent: Some(EVENT_A.to_owned()),
            hop: HOP_CEILING + 1,
        };
        let error = source.to_canonical_bytes(&limits).expect_err("refused");
        assert_eq!(error.code(), "hook.causation.hop_beyond_ceiling");
    }

    #[test]
    fn decode_refuses_bytes_over_the_default_outbox_bound() {
        let limits = EnvelopeLimits::default();
        let oversized = vec![b' '; MAX_ENVELOPE_BYTES + 1];
        let error = HookEnvelope::from_canonical_bytes(&oversized, &limits)
            .expect_err("the outbox bound is the ceiling");
        assert!(matches!(
            error,
            HookEnvelopeError::PayloadTooLarge { size, max }
                if size == MAX_ENVELOPE_BYTES + 1 && max == MAX_ENVELOPE_BYTES
        ));
        assert_eq!(error.code(), "hook.envelope.payload_too_large");
        assert_eq!(error.category(), ErrorCategory::Resource);
    }

    #[test]
    fn flip_the_envelope_ceiling_at_a_non_default_value() {
        let source = envelope();
        let bytes = source
            .to_canonical_bytes(&EnvelopeLimits::default())
            .expect("the default bound accepts a normal envelope");

        let tight = EnvelopeLimits::tightened_to(bytes.len() - 1);
        let error = source
            .to_canonical_bytes(&tight)
            .expect_err("refused above the non-default ceiling");
        assert!(matches!(
            error,
            HookEnvelopeError::PayloadTooLarge { size, max }
                if size == bytes.len() && max == bytes.len() - 1
        ));
        assert!(
            HookEnvelope::from_canonical_bytes(&bytes, &tight).is_err(),
            "decode refuses above the non-default ceiling too"
        );

        let generous = EnvelopeLimits::tightened_to(bytes.len());
        assert!(
            source.to_canonical_bytes(&generous).is_ok(),
            "accepted below (at) the non-default ceiling"
        );
        assert!(
            HookEnvelope::from_canonical_bytes(&bytes, &generous).is_ok(),
            "decode accepts below (at) the non-default ceiling"
        );
    }

    #[test]
    fn decode_checks_the_ceiling_before_parsing() {
        let limits = EnvelopeLimits::tightened_to(8);
        let error = HookEnvelope::from_canonical_bytes(b"not json at all", &limits)
            .expect_err("size wins before shape");
        assert!(matches!(
            error,
            HookEnvelopeError::PayloadTooLarge { size: 15, max: 8 }
        ));

        let under = HookEnvelope::from_canonical_bytes(b"not json", &limits)
            .expect_err("bytes under the ceiling are parsed");
        assert_eq!(under.code(), "hook.envelope.not_strict_json");
    }

    #[test]
    fn decode_refuses_duplicate_members_anywhere_in_the_envelope() {
        let limits = EnvelopeLimits::default();
        let raw = br#"{"id":"a","id":"b"}"#;
        let error =
            HookEnvelope::from_canonical_bytes(raw, &limits).expect_err("duplicate refused");
        assert_eq!(error.code(), "hook.envelope.not_strict_json");
    }

    #[test]
    fn decode_refuses_integers_that_collapse_in_binary64() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.data = json!({"count": 9007199254740993_u64});
        let error = source
            .to_canonical_bytes(&limits)
            .expect_err("encode refuses");
        assert_eq!(error.code(), "hook.envelope.not_canonicalizable");
        assert_eq!(error.category(), ErrorCategory::Source);
        let raw = br#"{"id":"a","type":"t","source":"s","time":"2026-09-18T12:00:00Z","subject":{"recordReference":"r","recordRevision":1},"dataschema":"d","data":{"count":9007199254740993},"causation":{"hop":0,"root":"a"}}"#;
        let error =
            HookEnvelope::from_canonical_bytes(raw, &limits).expect_err("lossy integer refused");
        assert_eq!(error.code(), "hook.envelope.not_strict_json");
    }

    #[test]
    fn decode_refuses_unknown_envelope_fields() {
        let limits = EnvelopeLimits::default();
        // `attempt` is a delivery attribute; it must never appear on the
        // envelope.
        let raw = br#"{"attempt":3,"causation":{"hop":0,"root":"a"},"data":{},"dataschema":"d","id":"a","source":"s","subject":{"recordReference":"r","recordRevision":1},"time":"2026-09-18T12:00:00Z","type":"t"}"#;
        let error = HookEnvelope::from_canonical_bytes(raw, &limits)
            .expect_err("delivery attributes stay on the transport");
        assert_eq!(error.code(), "hook.envelope.bad_shape");
    }

    #[test]
    fn the_envelope_ceiling_constant_mirrors_the_outbox_table() {
        assert_eq!(MAX_ENVELOPE_BYTES, 2_097_152);
        assert_eq!(EnvelopeLimits::default().max_envelope_bytes(), 2_097_152);
    }

    #[test]
    fn the_envelope_ceiling_can_only_be_tightened() {
        assert_eq!(
            EnvelopeLimits::tightened_to(MAX_ENVELOPE_BYTES + 1).max_envelope_bytes(),
            MAX_ENVELOPE_BYTES,
            "a widened request is clamped to the store's bound"
        );
        assert_eq!(
            EnvelopeLimits::tightened_to(usize::MAX).max_envelope_bytes(),
            MAX_ENVELOPE_BYTES
        );
        assert_eq!(
            EnvelopeLimits::tightened_to(4_096).max_envelope_bytes(),
            4_096,
            "a tightened request is honored"
        );

        // The clamp is enforced, not just reported: bytes over the store's
        // bound are still refused after asking for a wider ceiling.
        let widened = EnvelopeLimits::tightened_to(MAX_ENVELOPE_BYTES * 2);
        let oversized = vec![b' '; MAX_ENVELOPE_BYTES + 1];
        let error = HookEnvelope::from_canonical_bytes(&oversized, &widened)
            .expect_err("the clamp holds on the decode path");
        assert_eq!(error.code(), "hook.envelope.payload_too_large");
    }

    #[test]
    fn the_hop_ceiling_constant_is_eight() {
        assert_eq!(HOP_CEILING, 8);
    }

    #[test]
    fn time_serializes_as_rfc3339() {
        let source = envelope();
        let value = serde_json::to_value(&source).expect("serializes");
        assert_eq!(value["time"], json!("2026-09-18T12:00:00Z"));
        assert!(
            OffsetDateTime::parse("2026-09-18T12:00:00Z", &Rfc3339).is_ok(),
            "the wire form is RFC 3339"
        );
    }

    #[test]
    fn decode_refuses_an_envelope_whose_members_are_out_of_order() {
        let limits = EnvelopeLimits::default();
        let canonical = envelope().to_canonical_bytes(&limits).expect("encodes");
        // A second spelling of the same document: same members, different
        // order, so the digest a producer signed can never be reproduced.
        let value: Value = serde_json::from_slice(&canonical).expect("parses");
        let object = value.as_object().expect("an object");
        let members: Vec<String> = object
            .iter()
            .rev()
            .map(|(name, member)| format!("{}:{member}", Value::String(name.clone())))
            .collect();
        let raw = format!("{{{}}}", members.join(",")).into_bytes();
        assert_ne!(raw, canonical, "the fixture is genuinely reordered");
        assert_eq!(
            serde_json::from_slice::<Value>(&raw).expect("parses"),
            value,
            "the fixture is the same document, spelled differently"
        );
        let error = HookEnvelope::from_canonical_bytes(&raw, &limits)
            .expect_err("canonical bytes are the producer's contract");
        assert_eq!(error.code(), "hook.envelope.not_canonical");
        assert_eq!(error.category(), ErrorCategory::Source);
    }

    #[test]
    fn decode_refuses_insignificant_whitespace() {
        let limits = EnvelopeLimits::default();
        let canonical = envelope().to_canonical_bytes(&limits).expect("encodes");
        let mut spaced = b" ".to_vec();
        spaced.extend_from_slice(&canonical);
        let error = HookEnvelope::from_canonical_bytes(&spaced, &limits)
            .expect_err("canonical bytes carry no insignificant whitespace");
        assert_eq!(error.code(), "hook.envelope.not_canonical");
    }

    #[test]
    fn identity_must_be_a_uuid_on_both_paths() {
        let limits = EnvelopeLimits::default();
        for (field, id, root) in [
            ("id", String::new(), EVENT_A.to_owned()),
            ("id", "not-a-uuid".to_owned(), EVENT_A.to_owned()),
            ("causation.root", EVENT_A.to_owned(), String::new()),
            (
                "causation.root",
                EVENT_A.to_owned(),
                "not-a-uuid".to_owned(),
            ),
        ] {
            let mut source = envelope();
            source.id = id.clone();
            source.causation.root = root.clone();
            let error = source
                .to_canonical_bytes(&limits)
                .expect_err("encode refuses an id the store could not key");
            assert_eq!(error.code(), "hook.causation.invalid_id");
            assert_eq!(error.category(), ErrorCategory::Source);
            assert!(error.to_string().contains(field), "{error}");

            let bytes = canonical_bytes_unchecked(&source);
            let error = HookEnvelope::from_canonical_bytes(&bytes, &limits)
                .expect_err("decode refuses it too");
            assert_eq!(error.code(), "hook.causation.invalid_id");
        }
    }

    #[test]
    fn a_causation_parent_must_be_a_uuid_too() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.id = EVENT_B.to_owned();
        source.causation = Causation {
            root: EVENT_A.to_owned(),
            parent: Some("not-a-uuid".to_owned()),
            hop: 1,
        };
        let error = source.to_canonical_bytes(&limits).expect_err("refused");
        assert_eq!(error.code(), "hook.causation.invalid_id");
        assert!(error.to_string().contains("causation.parent"), "{error}");
    }

    #[test]
    fn a_uuid_identity_and_a_positive_revision_are_accepted() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.subject.record_revision = 1;
        let bytes = source.to_canonical_bytes(&limits).expect("encodes");
        let decoded = HookEnvelope::from_canonical_bytes(&bytes, &limits).expect("decodes");
        assert_eq!(decoded, source);
    }

    #[test]
    fn a_revision_at_or_below_zero_is_refused_on_both_paths() {
        let limits = EnvelopeLimits::default();
        for revision in [0, -1] {
            let mut source = envelope();
            source.subject.record_revision = revision;
            let error = source
                .to_canonical_bytes(&limits)
                .expect_err("encode refuses a revision the store could not hold");
            assert_eq!(error.code(), "hook.envelope.invalid_revision");
            assert_eq!(error.category(), ErrorCategory::Source);
            assert!(
                error.to_string().contains("greater than zero"),
                "the bound is named: {error}"
            );

            let bytes = canonical_bytes_unchecked(&source);
            let error = HookEnvelope::from_canonical_bytes(&bytes, &limits)
                .expect_err("decode refuses it too");
            assert_eq!(error.code(), "hook.envelope.invalid_revision");
        }

        // A revision whose magnitude no longer survives binary64 is refused by
        // canonical JSON before the revision check, so only encode names it.
        let mut source = envelope();
        source.subject.record_revision = i64::MIN;
        let error = source.to_canonical_bytes(&limits).expect_err("refused");
        assert_eq!(error.code(), "hook.envelope.invalid_revision");
    }

    #[test]
    fn equal_instants_at_different_offsets_and_precisions_encode_alike() {
        let limits = EnvelopeLimits::default();
        let mut utc = envelope();
        utc.time = datetime!(2026-09-18 12:00:00.123_456_789 UTC);
        let mut offset = envelope();
        offset.time = datetime!(2026-09-18 14:00:00.123_999_999 +02:00);

        let encoded_utc = utc.to_canonical_bytes(&limits).expect("encodes");
        let encoded_offset = offset.to_canonical_bytes(&limits).expect("encodes");
        assert_eq!(
            String::from_utf8(encoded_utc.clone()).expect("UTF-8"),
            String::from_utf8(encoded_offset).expect("UTF-8"),
            "the same instant encodes to the same bytes at millisecond precision"
        );
        assert!(
            String::from_utf8(encoded_utc)
                .expect("UTF-8")
                .contains(r#""time":"2026-09-18T12:00:00.123Z""#),
            "the wire form is UTC at whole milliseconds"
        );
    }

    #[test]
    fn an_instant_a_millisecond_apart_still_encodes_differently() {
        let limits = EnvelopeLimits::default();
        let mut earlier = envelope();
        earlier.time = datetime!(2026-09-18 12:00:00.250 UTC);
        let mut later = envelope();
        later.time = datetime!(2026-09-18 12:00:00.251 UTC);
        assert_ne!(
            earlier.to_canonical_bytes(&limits).expect("encodes"),
            later.to_canonical_bytes(&limits).expect("encodes"),
            "normalization truncates below the millisecond, not at it"
        );
    }

    #[test]
    fn an_untrusted_identity_never_reaches_display_unbounded() {
        let limits = EnvelopeLimits::default();
        let huge = "x".repeat(1024 * 1024);
        let mut source = envelope();
        source.id = huge.clone();
        let rendered = source
            .to_canonical_bytes(&limits)
            .expect_err("refused")
            .to_string();
        assert!(rendered.len() < 1_024, "{} bytes rendered", rendered.len());
        assert!(
            !rendered.contains(&"x".repeat(MAX_DISPLAYED_TOKEN_BYTES + 1)),
            "no run of the input longer than the token ceiling survives"
        );
    }

    #[test]
    fn an_untrusted_member_name_never_reaches_display_unbounded() {
        let limits = EnvelopeLimits::default();
        let mut object = serde_json::Map::new();
        object.insert("x".repeat(1024 * 1024), json!(1));
        let raw = canonicalize_json(&Value::Object(object)).expect("canonicalizes");
        let rendered = HookEnvelope::from_canonical_bytes(&raw, &limits)
            .expect_err("an unknown member is refused")
            .to_string();
        assert!(rendered.len() < 1_024, "{} bytes rendered", rendered.len());
        assert!(
            !rendered.contains(&"x".repeat(MAX_DISPLAYED_TOKEN_BYTES + 1)),
            "no run of the input longer than the token ceiling survives"
        );
    }

    #[test]
    fn every_causation_code_is_distinct_and_in_its_namespace() {
        let variants = [
            HookCausationError::InvalidEventId {
                field: "id",
                id: String::new(),
            },
            HookCausationError::RootEventCarriesParent { id: String::new() },
            HookCausationError::RootEventNotOwnRoot {
                id: String::new(),
                root: String::new(),
            },
            HookCausationError::ChildEventMissingParent { id: String::new() },
            HookCausationError::ChildEventOwnParent { id: String::new() },
            HookCausationError::ChildEventNotChainedFromRoot {
                id: String::new(),
                root: String::new(),
            },
            HookCausationError::HopBeyondCeiling {
                attempted: 9,
                ceiling: HOP_CEILING,
            },
        ];
        let codes: Vec<&str> = variants.iter().map(HookCausationError::code).collect();
        assert_eq!(
            codes.iter().collect::<BTreeSet<_>>().len(),
            codes.len(),
            "codes are distinct: {codes:?}"
        );
        for code in codes {
            assert!(
                code.starts_with("hook.causation."),
                "{code} is outside the namespace"
            );
        }
    }

    #[test]
    fn every_envelope_code_is_distinct_and_in_its_namespace() {
        let variants = [
            HookEnvelopeError::PayloadTooLarge { size: 1, max: 0 },
            HookEnvelopeError::Json(
                parse_json_strict(b"{").expect_err("a truncated object is not strict JSON"),
            ),
            HookEnvelopeError::NotCanonical,
            HookEnvelopeError::Shape(String::new()),
            HookEnvelopeError::Canonical(
                canonicalize_json(&json!({"count": 9007199254740993_u64}))
                    .expect_err("a lossy integer is not canonicalizable"),
            ),
            HookEnvelopeError::InvalidRevision { revision: 0 },
            HookEnvelopeError::Causation(HookCausationError::HopBeyondCeiling {
                attempted: 9,
                ceiling: HOP_CEILING,
            }),
        ];
        let codes: Vec<&str> = variants.iter().map(HookEnvelopeError::code).collect();
        assert_eq!(
            codes.iter().collect::<BTreeSet<_>>().len(),
            codes.len(),
            "codes are distinct: {codes:?}"
        );
        for code in codes {
            assert!(
                code.starts_with("hook.envelope.") || code.starts_with("hook.causation."),
                "{code} is outside the namespace"
            );
        }
    }
}
