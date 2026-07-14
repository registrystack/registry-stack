// SPDX-License-Identifier: Apache-2.0
//! Closed DCI v1 exact-search request and response codec.
//!
//! The codec owns only protocol structure. It does not choose a destination,
//! credential, purpose, source operation, product version, field projection,
//! claim result, or disclosure. A reviewed integration pack supplies the
//! explicit DCI protocol version and all integration-specific constants before a
//! compiled source plan can construct this type.

use registry_platform_crypto::parse_json_strict;
use serde::de;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use ulid::Ulid;
use zeroize::Zeroizing;

const MAX_PROTOCOL_VERSION_BYTES: usize = 16;
const MAX_PROTOCOL_IDENTIFIER_BYTES: usize = 160;
const MAX_SELECTOR_BYTES: usize = 4_096;
const MAX_SIGNATURE_BYTES: usize = 16 * 1024;
const MAX_DCI_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_DCI_RECORD_DEPTH: u8 = 64;
const MAX_DCI_COLLECTION_ITEMS: usize = 4_096;
const MAX_DCI_OBJECT_FIELDS: usize = 1_024;

/// Safe, value-free DCI codec failures.
///
/// No variant carries a selector, response body, native status reason, record,
/// or other source-controlled value, so ordinary diagnostics cannot echo
/// sensitive protocol data.
#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
pub(crate) enum DciCodecError {
    /// The pack did not supply a canonical `major.minor.patch` protocol version.
    #[error("invalid DCI protocol version")]
    InvalidProtocolVersion,
    /// A pack-owned DCI identifier is empty, oversized, or outside the grammar.
    #[error("invalid DCI protocol identifier")]
    InvalidProtocolIdentifier,
    /// A request or response message identifier is not a canonical ULID.
    #[error("invalid DCI message identifier")]
    InvalidMessageId,
    /// The canonical selector is empty, oversized, or contains controls.
    #[error("invalid DCI exact selector")]
    InvalidSelector,
    /// An optional detached signature is empty, oversized, or contains controls.
    #[error("invalid DCI detached signature")]
    InvalidSignature,
    /// Exact DCI search accepts only a source maximum of one or two.
    #[error("DCI requested maximum must be one or two")]
    InvalidRequestedMaximum,
    /// A timestamp could not be encoded or decoded as RFC 3339.
    #[error("invalid DCI timestamp")]
    InvalidTimestamp,
    /// A pack supplied zero or out-of-protocol response/record bounds.
    #[error("invalid DCI response bounds")]
    InvalidResponseBounds,
    /// Deterministic request encoding failed.
    #[error("DCI request could not be encoded")]
    RequestEncodingFailed,
    /// The source response exceeded the pack bound before decoding.
    #[error("DCI response exceeds its byte bound")]
    ResponseTooLarge,
    /// The source response is not the closed DCI v1 envelope.
    #[error("malformed DCI response")]
    MalformedResponse,
    /// A response-declared protocol version differs from the pack pin.
    #[error("DCI response protocol version mismatch")]
    ProtocolVersionMismatch,
    /// Transaction or reference correlation does not match the request.
    #[error("DCI response correlation mismatch")]
    CorrelationMismatch,
    /// The DCI envelope count is not the one expected response entry.
    #[error("DCI response entry count mismatch")]
    ResponseEntryCountMismatch,
    /// Response sender or receiver identity is not bound to the request.
    #[error("DCI response envelope identity mismatch")]
    EnvelopeIdentityMismatch,
    /// Response registry identifiers do not exactly match the request.
    #[error("DCI response registry identity mismatch")]
    RegistryIdentityMismatch,
    /// A response signature was supplied without an in-slice verifier.
    #[error("DCI response signature is not accepted")]
    UnexpectedResponseSignature,
    /// The source returned a non-success protocol status.
    #[error("DCI source returned a non-success status")]
    SourceRejected,
    /// The response claims or contains more records than Relay requested.
    #[error("DCI response exceeds the requested record maximum")]
    ResponseOverRequestedMaximum,
    /// A structural record exceeds pack-declared data-shape bounds.
    #[error("DCI structural record exceeds its declared bounds")]
    RecordOutsideBounds,
}

/// An explicit integration-pack-pinned DCI protocol version.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) struct DciProtocolVersion(Box<str>);

impl DciProtocolVersion {
    /// Return the canonical protocol version string.
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for DciProtocolVersion {
    type Error = DciCodecError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut segments = value.split('.');
        let major = segments.next();
        let minor = segments.next();
        let patch = segments.next();
        let no_more = segments.next().is_none();
        let canonical_segment = |segment: &str, allow_zero: bool| {
            !segment.is_empty()
                && segment.len() <= 3
                && segment.bytes().all(|byte| byte.is_ascii_digit())
                && (segment == "0" || !segment.starts_with('0'))
                && (allow_zero || segment != "0")
        };
        let valid = value.len() <= MAX_PROTOCOL_VERSION_BYTES
            && no_more
            && major.is_some_and(|segment| canonical_segment(segment, false))
            && minor.is_some_and(|segment| canonical_segment(segment, true))
            && patch.is_some_and(|segment| canonical_segment(segment, true));
        valid
            .then(|| Self(value.into()))
            .ok_or(DciCodecError::InvalidProtocolVersion)
    }
}

/// Validate the reviewed, request-invariant portion of one DCI exact profile.
///
/// Artifact validation calls this before compilation so an accepted profile
/// cannot defer malformed protocol constants until its first live request.
#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_profile_constants(
    protocol_version: &str,
    sender_id: &str,
    receiver_id: Option<&str>,
    registry_type: Option<&str>,
    registry_event_type: Option<&str>,
    record_type: Option<&str>,
    identifier_type: &str,
    locale: &str,
    page_number: u16,
) -> Result<(), DciCodecError> {
    DciProtocolVersion::try_from(protocol_version)?;
    validated_protocol_identifier(sender_id)?;
    receiver_id.map(validated_protocol_identifier).transpose()?;
    registry_type
        .map(validated_protocol_identifier)
        .transpose()?;
    registry_event_type
        .map(validated_protocol_identifier)
        .transpose()?;
    record_type.map(validated_protocol_identifier).transpose()?;
    validated_protocol_identifier(identifier_type)?;
    validated_protocol_identifier(locale)?;
    if page_number == 0 {
        return Err(DciCodecError::InvalidRequestedMaximum);
    }
    Ok(())
}

/// The exact source record maximum requested from DCI.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum DciRequestedMaximum {
    /// The product operation independently guarantees a singleton.
    One,
    /// Relay asks for exactly two records to detect ambiguity.
    Two,
}

impl DciRequestedMaximum {
    /// Return the DCI `page_size` and response record ceiling.
    #[must_use]
    pub(crate) const fn get(self) -> u8 {
        match self {
            Self::One => 1,
            Self::Two => 2,
        }
    }
}

impl TryFrom<u8> for DciRequestedMaximum {
    type Error = DciCodecError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            _ => Err(DciCodecError::InvalidRequestedMaximum),
        }
    }
}

/// Pack-declared bounds for one structural DCI record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DciRecordBounds {
    max_record_bytes: usize,
    max_nesting_depth: u8,
    max_collection_items: usize,
    max_object_fields: usize,
}

impl DciRecordBounds {
    /// Validate explicit record bounds against codec hard ceilings.
    pub(crate) fn try_new(
        max_record_bytes: usize,
        max_nesting_depth: u8,
        max_collection_items: usize,
        max_object_fields: usize,
    ) -> Result<Self, DciCodecError> {
        let valid = (1..=MAX_DCI_RESPONSE_BYTES).contains(&max_record_bytes)
            && (1..=MAX_DCI_RECORD_DEPTH).contains(&max_nesting_depth)
            && (1..=MAX_DCI_COLLECTION_ITEMS).contains(&max_collection_items)
            && (1..=MAX_DCI_OBJECT_FIELDS).contains(&max_object_fields);
        valid
            .then_some(Self {
                max_record_bytes,
                max_nesting_depth,
                max_collection_items,
                max_object_fields,
            })
            .ok_or(DciCodecError::InvalidResponseBounds)
    }
}

/// Raw, untrusted construction values for one exact DCI search.
///
/// There is intentionally no `Default`: a reviewed pack must supply the DCI
/// protocol version explicitly, resolving the former manual/runtime omission.
pub(crate) struct DciExactSearchRequestInput<'a> {
    /// Explicit, pack-pinned DCI protocol version.
    pub(crate) protocol_version: &'a str,
    /// Relay-owned canonical ULID used for message, transaction, and reference.
    pub(crate) message_id: &'a str,
    /// Relay-owned request timestamp.
    pub(crate) message_timestamp: OffsetDateTime,
    /// Fixed pack-owned sender identifier.
    pub(crate) sender_id: &'a str,
    /// Optional fixed pack-owned receiver identifier.
    pub(crate) receiver_id: Option<&'a str>,
    /// Optional fixed registry type.
    pub(crate) registry_type: Option<&'a str>,
    /// Optional fixed registry event type.
    pub(crate) registry_event_type: Option<&'a str>,
    /// Optional fixed registry record type.
    pub(crate) record_type: Option<&'a str>,
    /// Fixed identifier type for the exact `idtype-value` query.
    pub(crate) identifier_type: &'a str,
    /// Profile-canonical exact selector.
    pub(crate) selector: &'a str,
    /// Requested source maximum, exactly one or two.
    pub(crate) requested_max: u8,
    /// Reviewed one-based page number for the fixed exact request.
    pub(crate) page_number: u16,
    /// Optional pack-owned detached request signature.
    pub(crate) signature: Option<&'a str>,
}

/// One reviewed component of a structured exact-AND DCI predicate.
pub(crate) struct DciExactAndComponentInput<'a> {
    pub(crate) field: &'a str,
    pub(crate) value: &'a str,
}

/// Raw construction values for a structured exact-AND DCI search.
pub(crate) struct DciExactAndSearchRequestInput<'a> {
    pub(crate) protocol_version: &'a str,
    pub(crate) message_id: &'a str,
    pub(crate) message_timestamp: OffsetDateTime,
    pub(crate) sender_id: &'a str,
    pub(crate) receiver_id: Option<&'a str>,
    pub(crate) registry_type: Option<&'a str>,
    pub(crate) registry_event_type: Option<&'a str>,
    pub(crate) record_type: Option<&'a str>,
    pub(crate) components: &'a [DciExactAndComponentInput<'a>],
    pub(crate) requested_max: u8,
    pub(crate) page_number: u16,
    pub(crate) signature: Option<&'a str>,
}

/// A validated, closed exact DCI request.
///
/// This type intentionally implements neither `Debug` nor `Serialize`. The
/// only serialization path is [`Self::to_json_body`], and the selector and
/// optional signature are zeroized on drop.
pub(crate) struct DciExactSearchRequest {
    protocol_version: DciProtocolVersion,
    message_id: Ulid,
    message_timestamp: OffsetDateTime,
    sender_id: Box<str>,
    receiver_id: Option<Box<str>>,
    registry_type: Option<Box<str>>,
    registry_event_type: Option<Box<str>>,
    record_type: Option<Box<str>>,
    selector: DciRequestSelector,
    requested_max: DciRequestedMaximum,
    page_number: u16,
    signature: Option<Zeroizing<String>>,
}

enum DciRequestSelector {
    IdtypeValue {
        identifier_type: Box<str>,
        value: Zeroizing<String>,
    },
    ExactAnd(Box<[DciExactAndComponent]>),
}

struct DciExactAndComponent {
    field: Box<str>,
    value: Zeroizing<String>,
}

impl DciExactSearchRequest {
    /// Validate a closed exact-search request from reviewed pack values.
    pub(crate) fn try_new(input: DciExactSearchRequestInput<'_>) -> Result<Self, DciCodecError> {
        let protocol_version = DciProtocolVersion::try_from(input.protocol_version)?;
        let message_id = parse_canonical_ulid(input.message_id)?;
        let sender_id = validated_protocol_identifier(input.sender_id)?;
        let receiver_id = input
            .receiver_id
            .map(validated_protocol_identifier)
            .transpose()?;
        let registry_type = input
            .registry_type
            .map(validated_protocol_identifier)
            .transpose()?;
        let registry_event_type = input
            .registry_event_type
            .map(validated_protocol_identifier)
            .transpose()?;
        let record_type = input
            .record_type
            .map(validated_protocol_identifier)
            .transpose()?;
        let identifier_type = validated_protocol_identifier(input.identifier_type)?;

        let selector_valid = !input.selector.is_empty()
            && input.selector.len() <= MAX_SELECTOR_BYTES
            && input
                .selector
                .chars()
                .all(|character| !character.is_control());
        if !selector_valid {
            return Err(DciCodecError::InvalidSelector);
        }

        let requested_max = DciRequestedMaximum::try_from(input.requested_max)?;
        if input.page_number == 0 {
            return Err(DciCodecError::InvalidRequestedMaximum);
        }
        let signature = input
            .signature
            .map(|signature| {
                let valid = !signature.is_empty()
                    && signature.len() <= MAX_SIGNATURE_BYTES
                    && signature.chars().all(|character| !character.is_control());
                valid
                    .then(|| Zeroizing::new(signature.to_owned()))
                    .ok_or(DciCodecError::InvalidSignature)
            })
            .transpose()?;

        Ok(Self {
            protocol_version,
            message_id,
            message_timestamp: input.message_timestamp,
            sender_id,
            receiver_id,
            registry_type,
            registry_event_type,
            record_type,
            selector: DciRequestSelector::IdtypeValue {
                identifier_type,
                value: Zeroizing::new(input.selector.to_owned()),
            },
            requested_max,
            page_number: input.page_number,
            signature,
        })
    }

    /// Validate a stable one-to-eight-component exact-AND predicate.
    pub(crate) fn try_new_exact_and(
        input: DciExactAndSearchRequestInput<'_>,
    ) -> Result<Self, DciCodecError> {
        let protocol_version = DciProtocolVersion::try_from(input.protocol_version)?;
        let message_id = parse_canonical_ulid(input.message_id)?;
        let sender_id = validated_protocol_identifier(input.sender_id)?;
        let receiver_id = input
            .receiver_id
            .map(validated_protocol_identifier)
            .transpose()?;
        let registry_type = input
            .registry_type
            .map(validated_protocol_identifier)
            .transpose()?;
        let registry_event_type = input
            .registry_event_type
            .map(validated_protocol_identifier)
            .transpose()?;
        let record_type = input
            .record_type
            .map(validated_protocol_identifier)
            .transpose()?;
        if !(1..=8).contains(&input.components.len())
            || input
                .components
                .iter()
                .try_fold(0_usize, |total, component| {
                    total.checked_add(component.value.len())
                })
                .is_none_or(|total| total > MAX_SELECTOR_BYTES)
        {
            return Err(DciCodecError::InvalidSelector);
        }
        let mut fields = std::collections::BTreeSet::new();
        let components = input
            .components
            .iter()
            .map(|component| {
                let field = validated_protocol_identifier(component.field)?;
                if !fields.insert(field.clone())
                    || component.value.is_empty()
                    || component.value.len() > MAX_SELECTOR_BYTES
                    || component.value.chars().any(char::is_control)
                {
                    return Err(DciCodecError::InvalidSelector);
                }
                Ok(DciExactAndComponent {
                    field,
                    value: Zeroizing::new(component.value.to_owned()),
                })
            })
            .collect::<Result<Box<[_]>, _>>()?;
        let requested_max = DciRequestedMaximum::try_from(input.requested_max)?;
        if input.page_number == 0 {
            return Err(DciCodecError::InvalidRequestedMaximum);
        }
        let signature = input
            .signature
            .map(|signature| {
                (!signature.is_empty()
                    && signature.len() <= MAX_SIGNATURE_BYTES
                    && signature.chars().all(|character| !character.is_control()))
                .then(|| Zeroizing::new(signature.to_owned()))
                .ok_or(DciCodecError::InvalidSignature)
            })
            .transpose()?;
        Ok(Self {
            protocol_version,
            message_id,
            message_timestamp: input.message_timestamp,
            sender_id,
            receiver_id,
            registry_type,
            registry_event_type,
            record_type,
            selector: DciRequestSelector::ExactAnd(components),
            requested_max,
            page_number: input.page_number,
            signature,
        })
    }

    /// Encode the only accepted DCI request shape with deterministic field order.
    pub(crate) fn to_json_body(&self) -> Result<DciRequestBody, DciCodecError> {
        let message_id = self.message_id.to_string();
        let timestamp = self
            .message_timestamp
            .format(&Rfc3339)
            .map_err(|_| DciCodecError::InvalidTimestamp)?;
        let predicates = match &self.selector {
            DciRequestSelector::ExactAnd(components) => components
                .iter()
                .map(|component| WireExactPredicate {
                    field: component.field.as_ref(),
                    operator: "eq",
                    value: component.value.as_str(),
                })
                .collect::<Vec<_>>(),
            DciRequestSelector::IdtypeValue { .. } => Vec::new(),
        };
        let (query_type, query) = match &self.selector {
            DciRequestSelector::IdtypeValue {
                identifier_type,
                value,
            } => (
                "idtype-value",
                WireExactQuery::IdtypeValue(WireIdTypeValueQuery {
                    identifier_type,
                    value: value.as_str(),
                }),
            ),
            DciRequestSelector::ExactAnd(_) => (
                "exact-and",
                WireExactQuery::ExactAnd(WireExactAndQuery {
                    operator: "and",
                    predicates: &predicates,
                }),
            ),
        };
        let wire = WireRequestEnvelope {
            header: WireRequestHeader {
                version: self.protocol_version.as_str(),
                message_id: &message_id,
                message_ts: &timestamp,
                action: "search",
                sender_id: self.sender_id.as_ref(),
                receiver_id: self.receiver_id.as_deref(),
                total_count: 1,
                is_msg_encrypted: false,
            },
            message: WireRequestMessage {
                transaction_id: &message_id,
                search_request: [WireSearchRequest {
                    reference_id: &message_id,
                    timestamp: &timestamp,
                    search_criteria: WireSearchCriteria {
                        version: self.protocol_version.as_str(),
                        registry_type: self.registry_type.as_deref(),
                        registry_event_type: self.registry_event_type.as_deref(),
                        record_type: self.record_type.as_deref(),
                        query_type,
                        query,
                        pagination: WireRequestPagination {
                            page_size: self.requested_max.get(),
                            page_number: self.page_number,
                        },
                    },
                }],
            },
            signature: self.signature.as_ref().map(|signature| signature.as_str()),
        };
        let mut body = Zeroizing::new(Vec::new());
        serde_json::to_writer(&mut *body, &wire)
            .map_err(|_| DciCodecError::RequestEncodingFailed)?;
        Ok(DciRequestBody(body))
    }

    /// Build selector-free response expectations for the dispatched request.
    pub(crate) fn response_expectation(
        &self,
        max_response_bytes: usize,
        record_bounds: DciRecordBounds,
    ) -> Result<DciResponseExpectation, DciCodecError> {
        if !(1..=MAX_DCI_RESPONSE_BYTES).contains(&max_response_bytes)
            || record_bounds.max_record_bytes > max_response_bytes
        {
            return Err(DciCodecError::InvalidResponseBounds);
        }
        Ok(DciResponseExpectation {
            protocol_version: self.protocol_version.clone(),
            message_id: self.message_id,
            requested_max: self.requested_max,
            max_response_bytes,
            record_bounds,
            sender_id: self.sender_id.clone(),
            receiver_id: self.receiver_id.clone(),
            registry_type: self.registry_type.clone(),
            registry_event_type: self.registry_event_type.clone(),
            record_type: self.record_type.clone(),
        })
    }
}

/// Zeroizing encoded request bytes containing the exact selector.
///
/// The wrapper deliberately has no `Debug`, `Clone`, or serialization
/// implementation. The executor may borrow the bytes for inspection or move
/// the zeroizing allocation directly into the transport renderer.
pub(crate) struct DciRequestBody(Zeroizing<Vec<u8>>);

impl DciRequestBody {
    /// Borrow the encoded body without creating another sensitive allocation.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Consume the body without copying its selector-bearing allocation.
    pub(crate) fn into_zeroizing_bytes(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

fn parse_canonical_ulid(value: &str) -> Result<Ulid, DciCodecError> {
    let parsed = Ulid::from_string(value).map_err(|_| DciCodecError::InvalidMessageId)?;
    (parsed.to_string() == value)
        .then_some(parsed)
        .ok_or(DciCodecError::InvalidMessageId)
}

fn validated_protocol_identifier(value: &str) -> Result<Box<str>, DciCodecError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_PROTOCOL_IDENTIFIER_BYTES
        && value.bytes().all(|byte| {
            matches!(
                byte,
                b'a'..=b'z'
                    | b'A'..=b'Z'
                    | b'0'..=b'9'
                    | b'.'
                    | b'_'
                    | b'-'
                    | b':'
                    | b'/'
            )
        });
    valid
        .then(|| value.into())
        .ok_or(DciCodecError::InvalidProtocolIdentifier)
}

#[derive(Serialize)]
struct WireRequestEnvelope<'a> {
    header: WireRequestHeader<'a>,
    message: WireRequestMessage<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<&'a str>,
}

#[derive(Serialize)]
struct WireRequestHeader<'a> {
    version: &'a str,
    message_id: &'a str,
    message_ts: &'a str,
    action: &'static str,
    sender_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    receiver_id: Option<&'a str>,
    total_count: u8,
    is_msg_encrypted: bool,
}

#[derive(Serialize)]
struct WireRequestMessage<'a> {
    transaction_id: &'a str,
    search_request: [WireSearchRequest<'a>; 1],
}

#[derive(Serialize)]
struct WireSearchRequest<'a> {
    reference_id: &'a str,
    timestamp: &'a str,
    search_criteria: WireSearchCriteria<'a>,
}

#[derive(Serialize)]
struct WireSearchCriteria<'a> {
    version: &'a str,
    #[serde(rename = "reg_type", skip_serializing_if = "Option::is_none")]
    registry_type: Option<&'a str>,
    #[serde(rename = "reg_event_type", skip_serializing_if = "Option::is_none")]
    registry_event_type: Option<&'a str>,
    #[serde(rename = "reg_record_type", skip_serializing_if = "Option::is_none")]
    record_type: Option<&'a str>,
    query_type: &'static str,
    query: WireExactQuery<'a>,
    pagination: WireRequestPagination,
}

#[derive(Serialize)]
#[serde(untagged)]
enum WireExactQuery<'a> {
    IdtypeValue(WireIdTypeValueQuery<'a>),
    ExactAnd(WireExactAndQuery<'a>),
}

#[derive(Serialize)]
struct WireIdTypeValueQuery<'a> {
    #[serde(rename = "type")]
    identifier_type: &'a str,
    value: &'a str,
}

#[derive(Serialize)]
struct WireExactAndQuery<'a> {
    operator: &'static str,
    predicates: &'a [WireExactPredicate<'a>],
}

#[derive(Serialize)]
struct WireExactPredicate<'a> {
    field: &'a str,
    operator: &'static str,
    value: &'a str,
}

#[derive(Serialize)]
struct WireRequestPagination {
    page_size: u8,
    page_number: u16,
}

/// Selector-free expectations used to decode one DCI response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DciResponseExpectation {
    protocol_version: DciProtocolVersion,
    message_id: Ulid,
    requested_max: DciRequestedMaximum,
    max_response_bytes: usize,
    record_bounds: DciRecordBounds,
    sender_id: Box<str>,
    receiver_id: Option<Box<str>>,
    registry_type: Option<Box<str>>,
    registry_event_type: Option<Box<str>>,
    record_type: Option<Box<str>>,
}

/// One bounded structural record returned by DCI.
///
/// The record deliberately has no `Debug`, `Clone`, or serialization
/// implementation. A product pack may consume the plain JSON value for strict
/// schema validation and structural projection, but the codec assigns it no
/// eligibility or disclosure meaning.
pub(crate) struct DciStructuralRecord(Value);

impl DciStructuralRecord {
    /// Borrow the structural record for pack-owned schema validation.
    #[must_use]
    pub(crate) fn as_value(&self) -> &Value {
        &self.0
    }

    /// Consume the wrapper after pack-owned validation.
    #[must_use]
    pub(crate) fn into_value(self) -> Value {
        self.0
    }
}

/// Closed exact-search cardinality result.
pub(crate) enum DciExactSearchOutcome {
    /// The successful source response contained zero records.
    NoMatch,
    /// The successful source response contained exactly one structural record.
    One(DciStructuralRecord),
    /// The source response contained exactly two records; neither is retained.
    AtLeastTwo,
}

/// A decoded response plus transport timestamp metadata.
pub(crate) struct DciExactSearchResponse {
    outcome: DciExactSearchOutcome,
    response_timestamp: OffsetDateTime,
}

impl DciExactSearchResponse {
    /// Return the closed cardinality outcome.
    #[must_use]
    pub(crate) const fn outcome(&self) -> &DciExactSearchOutcome {
        &self.outcome
    }

    /// Consume the response and return its outcome.
    #[must_use]
    pub(crate) fn into_outcome(self) -> DciExactSearchOutcome {
        self.outcome
    }

    /// Return the DCI response-entry timestamp.
    ///
    /// A product pack must separately review its semantics before using it as
    /// source-observation provenance.
    #[must_use]
    pub(crate) const fn response_timestamp(&self) -> OffsetDateTime {
        self.response_timestamp
    }
}

/// Decode a strict, bounded DCI response for one exact request.
pub(crate) fn decode_exact_search_response(
    bytes: &[u8],
    expected: &DciResponseExpectation,
) -> Result<DciExactSearchResponse, DciCodecError> {
    if bytes.len() > expected.max_response_bytes {
        return Err(DciCodecError::ResponseTooLarge);
    }
    let value = parse_json_strict(bytes).map_err(|_| DciCodecError::MalformedResponse)?;
    let envelope: WireResponseEnvelope =
        serde_json::from_value(value).map_err(|_| DciCodecError::MalformedResponse)?;

    if envelope.signature.is_some() {
        return Err(DciCodecError::UnexpectedResponseSignature);
    }
    if envelope.header.status != "succ"
        || envelope.header.action != "on-search"
        || envelope.header.is_msg_encrypted
    {
        return Err(DciCodecError::SourceRejected);
    }
    validate_version(&envelope.header.version, &expected.protocol_version)?;
    parse_canonical_ulid(&envelope.header.message_id)?;
    validate_rfc3339(&envelope.header.message_ts)?;
    if envelope.header.total_count != 1 {
        return Err(DciCodecError::ResponseEntryCountMismatch);
    }
    if envelope.header.sender_id.as_deref() != expected.receiver_id.as_deref()
        || envelope.header.receiver_id.as_deref() != Some(expected.sender_id.as_ref())
    {
        return Err(DciCodecError::EnvelopeIdentityMismatch);
    }
    let expected_message_id = expected.message_id.to_string();
    if envelope.message.transaction_id != expected_message_id
        || envelope.message.search_response.len() != 1
        || envelope
            .message
            .correlation_id
            .as_deref()
            .is_some_and(|correlation_id| correlation_id != expected_message_id)
    {
        return Err(DciCodecError::CorrelationMismatch);
    }

    let mut responses = envelope.message.search_response;
    let response = responses.pop().ok_or(DciCodecError::CorrelationMismatch)?;
    if response.reference_id != expected_message_id {
        return Err(DciCodecError::CorrelationMismatch);
    }
    let response_timestamp = validate_rfc3339(&response.timestamp)?;
    if response.status != "succ"
        || response.status_reason_code.is_some()
        || response.status_reason_message.is_some()
    {
        return Err(DciCodecError::SourceRejected);
    }
    let data = response.data.ok_or(DciCodecError::MalformedResponse)?;
    validate_version(&data.version, &expected.protocol_version)?;
    if data.registry_type.as_deref() != expected.registry_type.as_deref()
        || data.registry_event_type.as_deref() != expected.registry_event_type.as_deref()
        || data.record_type.as_deref() != expected.record_type.as_deref()
    {
        return Err(DciCodecError::RegistryIdentityMismatch);
    }

    let record_count = data.reg_records.len();
    if record_count > usize::from(expected.requested_max.get()) {
        return Err(DciCodecError::ResponseOverRequestedMaximum);
    }
    for record in &data.reg_records {
        validate_structural_record(&record.0, expected.record_bounds)?;
    }

    let outcome = match record_count {
        0 => DciExactSearchOutcome::NoMatch,
        1 => {
            let record = data
                .reg_records
                .into_iter()
                .next()
                .ok_or(DciCodecError::MalformedResponse)?;
            DciExactSearchOutcome::One(DciStructuralRecord(record.0))
        }
        2 if expected.requested_max == DciRequestedMaximum::Two => {
            DciExactSearchOutcome::AtLeastTwo
        }
        2 => return Err(DciCodecError::ResponseOverRequestedMaximum),
        _ => return Err(DciCodecError::ResponseOverRequestedMaximum),
    };

    Ok(DciExactSearchResponse {
        outcome,
        response_timestamp,
    })
}

fn validate_version(observed: &str, expected: &DciProtocolVersion) -> Result<(), DciCodecError> {
    if observed != expected.as_str() {
        return Err(DciCodecError::ProtocolVersionMismatch);
    }
    Ok(())
}

fn validate_rfc3339(value: &str) -> Result<OffsetDateTime, DciCodecError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| DciCodecError::InvalidTimestamp)
}

fn validate_structural_record(
    record: &Value,
    bounds: DciRecordBounds,
) -> Result<(), DciCodecError> {
    let bytes = serde_json::to_vec(record).map_err(|_| DciCodecError::MalformedResponse)?;
    if bytes.len() > bounds.max_record_bytes {
        return Err(DciCodecError::RecordOutsideBounds);
    }
    validate_structural_value(record, 0, bounds)
}

fn validate_structural_value(
    value: &Value,
    depth: u8,
    bounds: DciRecordBounds,
) -> Result<(), DciCodecError> {
    if depth > bounds.max_nesting_depth {
        return Err(DciCodecError::RecordOutsideBounds);
    }
    match value {
        Value::Array(values) => {
            if values.len() > bounds.max_collection_items {
                return Err(DciCodecError::RecordOutsideBounds);
            }
            for value in values {
                validate_structural_value(value, depth.saturating_add(1), bounds)?;
            }
        }
        Value::Object(values) => {
            if values.len() > bounds.max_object_fields {
                return Err(DciCodecError::RecordOutsideBounds);
            }
            for value in values.values() {
                validate_structural_value(value, depth.saturating_add(1), bounds)?;
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResponseEnvelope {
    header: WireResponseHeader,
    message: WireResponseMessage,
    #[serde(default)]
    signature: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResponseHeader {
    version: String,
    message_id: String,
    message_ts: String,
    action: String,
    status: String,
    total_count: u64,
    is_msg_encrypted: bool,
    #[serde(default)]
    sender_id: Option<String>,
    #[serde(default)]
    receiver_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResponseMessage {
    transaction_id: String,
    #[serde(default)]
    correlation_id: Option<String>,
    search_response: Vec<WireSearchResponse>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSearchResponse {
    reference_id: String,
    timestamp: String,
    status: String,
    #[serde(default)]
    status_reason_code: Option<String>,
    #[serde(default)]
    status_reason_message: Option<String>,
    #[serde(default)]
    data: Option<WireResponseData>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResponseData {
    version: String,
    #[serde(default, rename = "reg_type")]
    registry_type: Option<String>,
    #[serde(default, rename = "reg_event_type")]
    registry_event_type: Option<String>,
    #[serde(default, rename = "reg_record_type")]
    record_type: Option<String>,
    reg_records: Vec<StrictRecord>,
}

struct StrictRecord(Value);

impl<'de> Deserialize<'de> for StrictRecord {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        if !value.is_object() {
            return Err(de::Error::custom("DCI record must be an object"));
        }
        Ok(Self(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MESSAGE_ID: &str = "01JZ0000000000000000000000";

    fn request(requested_max: u8) -> DciExactSearchRequest {
        DciExactSearchRequest::try_new(DciExactSearchRequestInput {
            protocol_version: "1.0.0",
            message_id: MESSAGE_ID,
            message_timestamp: OffsetDateTime::parse("2026-07-10T12:00:00Z", &Rfc3339)
                .expect("fixture timestamp"),
            sender_id: "registry-relay",
            receiver_id: Some("registry-source"),
            registry_type: Some("ns:org:RegistryType:Example"),
            registry_event_type: Some("status"),
            record_type: Some("example:Record"),
            identifier_type: "EXTERNAL_ID",
            selector: "EXAMPLE-123",
            requested_max,
            page_number: 1,
            signature: Some("detached-signature-fixture"),
        })
        .expect("valid exact request")
    }

    fn record_bounds() -> DciRecordBounds {
        DciRecordBounds::try_new(8 * 1024, 8, 32, 32).expect("fixture bounds")
    }

    fn expectation(requested_max: u8) -> DciResponseExpectation {
        request(requested_max)
            .response_expectation(32 * 1024, record_bounds())
            .expect("response expectation")
    }

    #[test]
    fn request_matches_deterministic_golden_and_versions_are_explicit() {
        let body = request(2).to_json_body().expect("request serializes");
        let bytes = body.as_bytes();
        let golden =
            include_str!("../../../tests/fixtures/dci/request-idtype-value-v1.json").trim_end();
        assert_eq!(bytes, golden.as_bytes());

        let value: Value = serde_json::from_slice(bytes).expect("request is JSON");
        assert_eq!(value["header"]["version"], "1.0.0");
        assert_eq!(
            value["message"]["search_request"][0]["search_criteria"]["version"],
            "1.0.0"
        );
        assert_eq!(
            value["message"]["search_request"][0]["search_criteria"]["query_type"],
            "idtype-value"
        );
        assert_eq!(
            value["message"]["search_request"][0]["search_criteria"]["pagination"],
            serde_json::json!({"page_size": 2, "page_number": 1})
        );
    }

    #[test]
    fn exact_and_request_keeps_typed_components_structural_and_stable() {
        let components = [
            DciExactAndComponentInput {
                field: "birth_date",
                value: "2001-02-03",
            },
            DciExactAndComponentInput {
                field: "family_name",
                value: "N'Dour",
            },
        ];
        let request = DciExactSearchRequest::try_new_exact_and(DciExactAndSearchRequestInput {
            protocol_version: "1.0.0",
            message_id: MESSAGE_ID,
            message_timestamp: OffsetDateTime::parse("2026-07-10T12:00:00Z", &Rfc3339)
                .expect("fixture timestamp"),
            sender_id: "registry-relay",
            receiver_id: Some("registry-source"),
            registry_type: Some("ns:org:RegistryType:Example"),
            registry_event_type: Some("status"),
            record_type: Some("example:Record"),
            components: &components,
            requested_max: 2,
            page_number: 1,
            signature: None,
        })
        .expect("structured exact request");
        let body = request.to_json_body().expect("request body");
        let value: Value = serde_json::from_slice(body.as_bytes()).expect("JSON request");
        let criteria = &value["message"]["search_request"][0]["search_criteria"];
        assert_eq!(criteria["query_type"], "exact-and");
        assert_eq!(criteria["query"]["operator"], "and");
        assert_eq!(
            criteria["query"]["predicates"],
            serde_json::json!([
                {"field":"birth_date","operator":"eq","value":"2001-02-03"},
                {"field":"family_name","operator":"eq","value":"N'Dour"}
            ])
        );
        assert!(!String::from_utf8_lossy(body.as_bytes()).contains("2001-02-03|N'Dour"));

        let duplicate = [
            DciExactAndComponentInput {
                field: "name",
                value: "one",
            },
            DciExactAndComponentInput {
                field: "name",
                value: "two",
            },
        ];
        assert!(matches!(
            DciExactSearchRequest::try_new_exact_and(DciExactAndSearchRequestInput {
                protocol_version: "1.0.0",
                message_id: MESSAGE_ID,
                message_timestamp: OffsetDateTime::UNIX_EPOCH,
                sender_id: "relay",
                receiver_id: None,
                registry_type: None,
                registry_event_type: None,
                record_type: None,
                components: &duplicate,
                requested_max: 2,
                page_number: 1,
                signature: None,
            }),
            Err(DciCodecError::InvalidSelector)
        ));
    }

    #[test]
    fn request_rejects_implicit_version_noncanonical_ulid_and_unbounded_maximum() {
        let invalid = |protocol_version: &str, message_id: &str, requested_max: u8| {
            DciExactSearchRequest::try_new(DciExactSearchRequestInput {
                protocol_version,
                message_id,
                message_timestamp: OffsetDateTime::UNIX_EPOCH,
                sender_id: "registry-relay",
                receiver_id: None,
                registry_type: None,
                registry_event_type: None,
                record_type: None,
                identifier_type: "EXTERNAL_ID",
                selector: "EXAMPLE-123",
                requested_max,
                page_number: 1,
                signature: None,
            })
        };
        assert!(matches!(
            invalid("", MESSAGE_ID, 2),
            Err(DciCodecError::InvalidProtocolVersion)
        ));
        assert!(matches!(
            invalid("1.0.0", &MESSAGE_ID.to_ascii_lowercase(), 2),
            Err(DciCodecError::InvalidMessageId)
        ));
        assert!(matches!(
            invalid("1.0.0", MESSAGE_ID, 3),
            Err(DciCodecError::InvalidRequestedMaximum)
        ));
    }

    #[test]
    fn decodes_zero_one_and_exactly_two_without_retaining_ambiguous_rows() {
        let zero = decode_exact_search_response(
            include_bytes!("../../../tests/fixtures/dci/response-zero-v1.json"),
            &expectation(2),
        )
        .expect("zero response");
        assert!(matches!(zero.outcome(), DciExactSearchOutcome::NoMatch));

        let one = decode_exact_search_response(
            include_bytes!("../../../tests/fixtures/dci/response-one-v1.json"),
            &expectation(2),
        )
        .expect("one response")
        .into_outcome();
        let DciExactSearchOutcome::One(record) = one else {
            panic!("expected one structural record");
        };
        assert_eq!(record.as_value()["status"], "active");

        let two = decode_exact_search_response(
            include_bytes!("../../../tests/fixtures/dci/response-two-v1.json"),
            &expectation(2),
        )
        .expect("two response");
        assert!(matches!(two.outcome(), DciExactSearchOutcome::AtLeastTwo));
    }

    #[test]
    fn rejects_source_records_over_the_exact_requested_maximum() {
        let three = include_bytes!("../../../tests/fixtures/dci/response-three-v1.json");
        assert_eq!(
            decode_exact_search_response(three, &expectation(2)).err(),
            Some(DciCodecError::ResponseOverRequestedMaximum)
        );
        let two = include_bytes!("../../../tests/fixtures/dci/response-two-v1.json");
        assert_eq!(
            decode_exact_search_response(two, &expectation(1)).err(),
            Some(DciCodecError::ResponseOverRequestedMaximum)
        );
    }

    #[test]
    fn response_entry_count_is_exactly_one_independent_of_record_cardinality() {
        let two_records: Value = serde_json::from_slice(include_bytes!(
            "../../../tests/fixtures/dci/response-two-v1.json"
        ))
        .expect("two-record fixture is JSON");
        assert_eq!(two_records["header"]["total_count"], 1);

        for invalid_count in [0, 2] {
            let response = include_str!("../../../tests/fixtures/dci/response-one-v1.json")
                .replace(
                    "\"total_count\":1",
                    &format!("\"total_count\":{invalid_count}"),
                );
            assert_eq!(
                decode_exact_search_response(response.as_bytes(), &expectation(2)).err(),
                Some(DciCodecError::ResponseEntryCountMismatch)
            );
        }
    }

    #[test]
    fn response_requires_header_and_data_versions() {
        let missing_header = include_str!("../../../tests/fixtures/dci/response-one-v1.json")
            .replacen("\"version\":\"1.0.0\",", "", 1);
        assert_eq!(
            decode_exact_search_response(missing_header.as_bytes(), &expectation(2)).err(),
            Some(DciCodecError::MalformedResponse)
        );

        let missing_data = include_str!("../../../tests/fixtures/dci/response-one-v1.json")
            .replace("\"data\":{\"version\":\"1.0.0\",", "\"data\":{");
        assert_eq!(
            decode_exact_search_response(missing_data.as_bytes(), &expectation(2)).err(),
            Some(DciCodecError::MalformedResponse)
        );
    }

    #[test]
    fn response_binds_message_correlation_and_envelope_identities() {
        let fixture = include_str!("../../../tests/fixtures/dci/response-one-v1.json");
        let bad_message_id =
            fixture.replace("01JZ0000000000000000000001", "01jz0000000000000000000001");
        assert_eq!(
            decode_exact_search_response(bad_message_id.as_bytes(), &expectation(2)).err(),
            Some(DciCodecError::InvalidMessageId)
        );

        let bad_correlation = fixture.replace(
            "\"correlation_id\":\"01JZ0000000000000000000000\"",
            "\"correlation_id\":\"01JZ0000000000000000000002\"",
        );
        assert_eq!(
            decode_exact_search_response(bad_correlation.as_bytes(), &expectation(2)).err(),
            Some(DciCodecError::CorrelationMismatch)
        );

        for response in [
            fixture.replace(
                "\"sender_id\":\"registry-source\"",
                "\"sender_id\":\"wrong-source\"",
            ),
            fixture.replace(
                "\"receiver_id\":\"registry-relay\"",
                "\"receiver_id\":\"wrong-relay\"",
            ),
        ] {
            assert_eq!(
                decode_exact_search_response(response.as_bytes(), &expectation(2)).err(),
                Some(DciCodecError::EnvelopeIdentityMismatch)
            );
        }
    }

    #[test]
    fn response_binds_registry_identity_and_rejects_unverified_signatures() {
        let fixture = include_str!("../../../tests/fixtures/dci/response-one-v1.json");
        let wrong_registry = fixture.replace(
            "\"reg_record_type\":\"example:Record\"",
            "\"reg_record_type\":\"example:DifferentRecord\"",
        );
        assert_eq!(
            decode_exact_search_response(wrong_registry.as_bytes(), &expectation(2)).err(),
            Some(DciCodecError::RegistryIdentityMismatch)
        );

        let missing_event = fixture.replace("\"reg_event_type\":\"status\",", "");
        assert_eq!(
            decode_exact_search_response(missing_event.as_bytes(), &expectation(2)).err(),
            Some(DciCodecError::RegistryIdentityMismatch)
        );

        let signed = format!(
            "{},\"signature\":\"unverified-fixture\"}}",
            fixture
                .trim_end()
                .strip_suffix('}')
                .expect("fixture is an envelope")
        );
        assert_eq!(
            decode_exact_search_response(signed.as_bytes(), &expectation(2)).err(),
            Some(DciCodecError::UnexpectedResponseSignature)
        );
    }

    #[test]
    fn rejects_unknown_transport_controls_and_duplicate_members() {
        let with_pagination = include_str!("../../../tests/fixtures/dci/response-one-v1.json")
            .replace(
                "\"reg_records\"",
                "\"pagination\":{\"page_number\":2},\"reg_records\"",
            );
        assert_eq!(
            decode_exact_search_response(with_pagination.as_bytes(), &expectation(2)).err(),
            Some(DciCodecError::MalformedResponse)
        );

        let duplicate = include_str!("../../../tests/fixtures/dci/response-one-v1.json").replace(
            "\"status\":\"active\"",
            "\"status\":\"active\",\"status\":\"inactive\"",
        );
        assert_eq!(
            decode_exact_search_response(duplicate.as_bytes(), &expectation(2)).err(),
            Some(DciCodecError::MalformedResponse)
        );

        let duplicate_outer = include_str!("../../../tests/fixtures/dci/response-one-v1.json")
            .replace(
                "\"status\":\"succ\",\"total_count\"",
                "\"status\":\"succ\",\"status\":\"succ\",\"total_count\"",
            );
        assert_eq!(
            decode_exact_search_response(duplicate_outer.as_bytes(), &expectation(2)).err(),
            Some(DciCodecError::MalformedResponse)
        );
    }

    #[test]
    fn record_bounds_and_response_versions_fail_closed() {
        let tiny_bounds = DciRecordBounds::try_new(16, 2, 2, 2).expect("tiny bounds");
        let tiny_expectation = request(2)
            .response_expectation(32 * 1024, tiny_bounds)
            .expect("tiny expectation");
        assert_eq!(
            decode_exact_search_response(
                include_bytes!("../../../tests/fixtures/dci/response-one-v1.json"),
                &tiny_expectation,
            )
            .err(),
            Some(DciCodecError::RecordOutsideBounds)
        );

        let fixture = include_str!("../../../tests/fixtures/dci/response-one-v1.json");
        let wrong_header_version =
            fixture.replacen("\"version\":\"1.0.0\"", "\"version\":\"2.0.0\"", 1);
        let wrong_data_version = fixture.replace(
            "\"data\":{\"version\":\"1.0.0\"",
            "\"data\":{\"version\":\"2.0.0\"",
        );
        for response in [wrong_header_version, wrong_data_version] {
            assert_eq!(
                decode_exact_search_response(response.as_bytes(), &expectation(2)).err(),
                Some(DciCodecError::ProtocolVersionMismatch)
            );
        }
    }

    #[test]
    fn errors_never_echo_selector_or_response_content() {
        let malformed = br#"{"selector-secret":"response-secret"}"#;
        let error = decode_exact_search_response(malformed, &expectation(2))
            .err()
            .expect("malformed response fails");
        let diagnostic = format!("{error:?} {error}");
        assert!(!diagnostic.contains("selector-secret"));
        assert!(!diagnostic.contains("response-secret"));
        assert!(!diagnostic.contains("EXAMPLE-123"));
    }
}
