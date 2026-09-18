// SPDX-License-Identifier: Apache-2.0

//! The envelope: the one canonical JSON document the library hands a handler,
//! unchanged for every product and every destination kind.
//!
//! The fields are the design note's table: `id`, `type`, `source`, `time`,
//! `subject`, `dataschema`, `data`, and `causation`. Delivery attributes
//! (`attempt`, `generation`, `delivery_time`, `idempotency_key`, `signature`)
//! are deliberately **not** envelope fields and never become them: they stay on
//! the transport, exactly as `EventDeliveryHeaders` carries them today. The
//! envelope is what the handler reasons over; the attributes are what the
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

use registry_platform_canonical_json::{canonicalize_json, parse_json_strict, JcsError};

/// The outbox payload bound the envelope carries, in bytes.
///
/// Mirrors the `registry_outbox.payload` check today:
/// `octet_length(payload) <= 2097152` (2 MiB). The per-delivery
/// `maximum_payload_bytes` bound from the deliveries table can only tighten
/// this, never widen it.
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
/// The default mirrors today's outbox bound. A delivery may carry a tighter
/// per-delivery `maximum_payload_bytes`; it can only reduce the ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnvelopeLimits {
    /// The maximum envelope size in bytes.
    pub max_envelope_bytes: usize,
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
    /// The revision the triggering change produced.
    pub record_revision: i64,
}

/// Why this event exists: the chain it belongs to and the event that caused it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Causation {
    /// The id of the first event in the chain; equals `id` for a root event.
    /// A later orchestrator correlates on this field.
    pub root: String,
    /// The id of the event whose handler proposed the change that produced
    /// this one. Absent for a root event.
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
    pub id: String,
    /// The hook's stable contract id.
    #[serde(rename = "type")]
    pub event_type: String,
    /// The producing product and deployment identity.
    pub source: String,
    /// Commit time of the triggering change, RFC 3339.
    #[serde(with = "time::serde::rfc3339")]
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

impl HookEnvelope {
    /// Serialize to canonical JSON bytes (RFC 8785).
    ///
    /// # Errors
    ///
    /// Returns [`HookEnvelopeError`] when the causation is structurally
    /// impossible, a number cannot be canonicalized, or the canonical bytes
    /// exceed the configured ceiling.
    pub fn to_canonical_bytes(
        &self,
        limits: &EnvelopeLimits,
    ) -> Result<Vec<u8>, HookEnvelopeError> {
        validate_causation(self)?;
        let value = serde_json::to_value(self).map_err(HookEnvelopeError::Shape)?;
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
    /// Decoding accepts any strict, well-shaped envelope JSON; canonical bytes
    /// are the producer's contract, and [`Self::to_canonical_bytes`] always
    /// produces them.
    ///
    /// # Errors
    ///
    /// Returns [`HookEnvelopeError`] when the bytes exceed the ceiling, are not
    /// strict JSON, violate the envelope shape, or carry structurally
    /// impossible causation.
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
        let envelope: Self = serde_json::from_value(value).map_err(HookEnvelopeError::Shape)?;
        validate_causation(&envelope)?;
        Ok(envelope)
    }
}

/// Refuse structurally impossible causation.
///
/// The guards: a root event has no parent and is its own root; a caused event
/// has a parent that is not itself, chains from a root that is not itself, and
/// never arrives beyond the ceiling, because the hop guard refuses such a
/// child before it is ever enqueued.
fn validate_causation(envelope: &HookEnvelope) -> Result<(), HookCausationError> {
    let causation = &envelope.causation;
    let id = envelope.id.as_str();
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

/// A structurally impossible causation chain.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum HookCausationError {
    /// A root event carried a `causation.parent`.
    #[error("root event {id} must not carry a causation parent")]
    RootEventCarriesParent { id: String },
    /// A root event named a different event as the chain root.
    #[error("root event {id} must be its own causation root, found {root}")]
    RootEventNotOwnRoot { id: String, root: String },
    /// A caused event carried no `causation.parent`.
    #[error("caused event {id} requires a causation parent")]
    ChildEventMissingParent { id: String },
    /// An event named itself as its own cause.
    #[error("caused event {id} cannot be its own causation parent")]
    ChildEventOwnParent { id: String },
    /// A caused event claimed to be the first event of its own chain.
    #[error("caused event {id} must chain from the first event of its chain, found root {root}")]
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
    /// The envelope violates the envelope shape.
    #[error("envelope violates the hook envelope shape: {0}")]
    Shape(#[from] serde_json::Error),
    /// A number in the envelope cannot be canonicalized.
    #[error("envelope is not canonicalizable: {0}")]
    Canonical(#[from] JcsError),
    /// The envelope carries structurally impossible causation.
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
            Self::Shape(_) => "hook.envelope.bad_shape",
            Self::Canonical(_) => "hook.envelope.not_canonicalizable",
            Self::Causation(error) => error.code(),
        }
    }

    /// The run-time failure category, per the taxonomy's mapping.
    #[must_use]
    pub const fn category(&self) -> crate::error::ErrorCategory {
        match self {
            Self::PayloadTooLarge { .. } => crate::error::ErrorCategory::Resource,
            Self::Json(_) | Self::Shape(_) | Self::Canonical(_) => {
                crate::error::ErrorCategory::Source
            }
            Self::Causation(_) => crate::error::ErrorCategory::Source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ErrorCategory;
    use serde_json::json;
    use time::format_description::well_known::Rfc3339;
    use time::macros::datetime;

    fn envelope() -> HookEnvelope {
        HookEnvelope {
            id: "019934b2-1f2e-7c3a-9d4b-6f1e2a3b4c5d".to_owned(),
            event_type: "birth-registered-followup".to_owned(),
            source: "/products/breg/deployments/prod".to_owned(),
            time: datetime!(2026-09-18 12:00:00 UTC),
            subject: EventSubject {
                record_reference: "breg/person/42".to_owned(),
                record_revision: 7,
            },
            dataschema: "https://breg.example.gov/schemas/person/v3".to_owned(),
            data: json!({"entity": "person", "values": {"familyName": "Kalanni"}}),
            causation: Causation::root("019934b2-1f2e-7c3a-9d4b-6f1e2a3b4c5d"),
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
        let causation = Causation::root("event-a");
        assert_eq!(causation.hop, 0);
        assert_eq!(causation.parent, None);
        assert_eq!(causation.root, "event-a");
    }

    #[test]
    fn child_causation_points_at_the_causing_event_and_climbs_one_hop() {
        let root = Causation::root("event-a");
        let child = root.child("event-a").expect("first hop is allowed");
        assert_eq!(child.parent.as_deref(), Some("event-a"));
        assert_eq!(child.hop, 1);
        assert_eq!(child.root, "event-a");

        let grandchild = child.child("event-b").expect("second hop is allowed");
        assert_eq!(grandchild.parent.as_deref(), Some("event-b"));
        assert_eq!(grandchild.hop, 2);
        assert_eq!(grandchild.root, "event-a");
    }

    #[test]
    fn the_hop_guard_refuses_a_child_beyond_the_ceiling_and_names_it() {
        let mut causation = Causation::root("event-a");
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
    fn a_root_envelope_is_the_deepest_allowed_chain_start() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.causation = Causation::root(source.id.as_str());
        let bytes = source.to_canonical_bytes(&limits).expect("encodes");
        assert!(HookEnvelope::from_canonical_bytes(&bytes, &limits).is_ok());
    }

    #[test]
    fn decode_refuses_a_root_event_with_a_parent() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.causation.parent = Some("other-event".to_owned());
        let bytes = serde_json::to_vec(&source).expect("serializes");
        let error =
            HookEnvelope::from_canonical_bytes(&bytes, &limits).expect_err("root with parent");
        assert_eq!(error.code(), "hook.causation.root_carries_parent");
        assert_eq!(error.category(), ErrorCategory::Source);
    }

    #[test]
    fn decode_refuses_a_root_event_that_is_not_its_own_root() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.causation.root = "other-event".to_owned();
        let bytes = serde_json::to_vec(&source).expect("serializes");
        let error =
            HookEnvelope::from_canonical_bytes(&bytes, &limits).expect_err("root must be own root");
        assert_eq!(error.code(), "hook.causation.root_not_own_root");
    }

    #[test]
    fn decode_refuses_a_caused_event_without_a_parent() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.id = "event-b".to_owned();
        source.causation = Causation {
            root: "event-a".to_owned(),
            parent: None,
            hop: 1,
        };
        let bytes = serde_json::to_vec(&source).expect("serializes");
        let error =
            HookEnvelope::from_canonical_bytes(&bytes, &limits).expect_err("child needs parent");
        assert_eq!(error.code(), "hook.causation.child_missing_parent");
    }

    #[test]
    fn decode_refuses_an_event_that_is_its_own_parent() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.id = "event-a".to_owned();
        source.causation = Causation {
            root: "event-a".to_owned(),
            parent: Some("event-a".to_owned()),
            hop: 1,
        };
        let bytes = serde_json::to_vec(&source).expect("serializes");
        let error = HookEnvelope::from_canonical_bytes(&bytes, &limits)
            .expect_err("self-causation is Odoo's write-inside-write");
        assert_eq!(error.code(), "hook.causation.child_own_parent");
    }

    #[test]
    fn decode_refuses_a_caused_event_claiming_to_be_its_own_chain_root() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.id = "event-b".to_owned();
        source.causation = Causation {
            root: "event-b".to_owned(),
            parent: Some("event-a".to_owned()),
            hop: 1,
        };
        let bytes = serde_json::to_vec(&source).expect("serializes");
        let error = HookEnvelope::from_canonical_bytes(&bytes, &limits)
            .expect_err("a caused event cannot be the chain root");
        assert_eq!(error.code(), "hook.causation.child_not_chained");
    }

    #[test]
    fn decode_refuses_an_envelope_beyond_the_hop_ceiling() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.id = "event-b".to_owned();
        source.causation = Causation {
            root: "event-a".to_owned(),
            parent: Some("event-a".to_owned()),
            hop: HOP_CEILING + 1,
        };
        let bytes = serde_json::to_vec(&source).expect("serializes");
        let error = HookEnvelope::from_canonical_bytes(&bytes, &limits)
            .expect_err("nothing enqueues beyond the ceiling");
        assert_eq!(error.code(), "hook.causation.hop_beyond_ceiling");
    }

    #[test]
    fn encode_refuses_an_envelope_beyond_the_hop_ceiling() {
        let limits = EnvelopeLimits::default();
        let mut source = envelope();
        source.id = "event-b".to_owned();
        source.causation = Causation {
            root: "event-a".to_owned(),
            parent: Some("event-a".to_owned()),
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

        let tight = EnvelopeLimits {
            max_envelope_bytes: bytes.len() - 1,
        };
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

        let generous = EnvelopeLimits {
            max_envelope_bytes: bytes.len(),
        };
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
        let limits = EnvelopeLimits {
            max_envelope_bytes: 8,
        };
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
        let bytes = source
            .to_canonical_bytes(&limits)
            .expect_err("encode refuses");
        let _ = bytes;
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
        let raw = br#"{"id":"a","type":"t","source":"s","time":"2026-09-18T12:00:00Z","subject":{"recordReference":"r","recordRevision":1},"dataschema":"d","data":{},"causation":{"hop":0,"root":"a"},"attempt":3}"#;
        let error = HookEnvelope::from_canonical_bytes(raw, &limits)
            .expect_err("delivery attributes stay on the transport");
        assert_eq!(error.code(), "hook.envelope.bad_shape");
    }

    #[test]
    fn the_envelope_ceiling_constant_mirrors_the_outbox_table() {
        assert_eq!(MAX_ENVELOPE_BYTES, 2_097_152);
        assert_eq!(EnvelopeLimits::default().max_envelope_bytes, 2_097_152);
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
}
