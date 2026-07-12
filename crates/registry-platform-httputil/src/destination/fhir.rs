// SPDX-License-Identifier: Apache-2.0
//! Closed FHIR R4 search-set validation for bounded data responses.

use std::marker::PhantomData;

use registry_platform_canonical_json::parse_json_strict;
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroizing;

use super::sensitive_json::SensitiveJsonValue;
use super::{BoundedDestinationBody, DataDestinationBody};

/// Value-free failures for the closed FHIR R4 search response contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FhirR4SearchError {
    #[error("FHIR R4 response violates the closed search-set contract")]
    ContractViolation,
    #[error("FHIR R4 response exceeds the exact-search cardinality bound")]
    CardinalityViolation,
}

/// Cardinality result from a validated FHIR R4 search-set.
#[must_use = "the validated search cardinality must be handled"]
pub enum FhirR4SearchsetOutcome {
    NoMatch,
    Records(DataDestinationBody),
    Ambiguous,
}

impl std::fmt::Debug for FhirR4SearchsetOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoMatch => formatter.write_str("FhirR4SearchsetOutcome::NoMatch"),
            Self::Records(_) => formatter.write_str("FhirR4SearchsetOutcome::Records([REDACTED])"),
            Self::Ambiguous => formatter.write_str("FhirR4SearchsetOutcome::Ambiguous"),
        }
    }
}

/// Validate and normalize one fixed-resource FHIR R4 search-set before closed
/// projection.
///
/// The operation's path, search parameters, resource type, byte ceiling, and
/// result ceiling are compiler-owned. This primitive does not follow links or
/// expose the raw Bundle. The returned body is a JSON array containing only the
/// validated `entry[].resource` objects, which the ordinary closed JSON decoder
/// consumes as its bounded record sequence.
pub fn normalize_r4_searchset(
    body: DataDestinationBody,
    expected_resource_type: &str,
    max_entries: u8,
) -> Result<FhirR4SearchsetOutcome, FhirR4SearchError> {
    if expected_resource_type.is_empty()
        || expected_resource_type == "Bundle"
        || expected_resource_type == "OperationOutcome"
        || !(1..=2).contains(&max_entries)
    {
        return Err(FhirR4SearchError::ContractViolation);
    }
    let BoundedDestinationBody { bytes, slot: _ } = body;
    let parsed = parse_json_strict(bytes.as_slice())
        .map(SensitiveJsonValue::new)
        .map_err(|_| FhirR4SearchError::ContractViolation)?;
    drop(bytes);
    let parsed = parsed;
    let bundle = parsed
        .value()
        .as_object()
        .ok_or(FhirR4SearchError::ContractViolation)?;
    if bundle.get("resourceType").and_then(Value::as_str) != Some("Bundle")
        || bundle.get("type").and_then(Value::as_str) != Some("searchset")
    {
        return Err(FhirR4SearchError::ContractViolation);
    }
    let next_link = match bundle.get("link") {
        None => false,
        Some(Value::Array(links)) => {
            let mut next = false;
            for link in links {
                let link = link
                    .as_object()
                    .ok_or(FhirR4SearchError::ContractViolation)?;
                let relation = link
                    .get("relation")
                    .and_then(Value::as_str)
                    .ok_or(FhirR4SearchError::ContractViolation)?;
                if link.get("url").and_then(Value::as_str).is_none() {
                    return Err(FhirR4SearchError::ContractViolation);
                }
                next |= relation == "next";
            }
            next
        }
        Some(_) => return Err(FhirR4SearchError::ContractViolation),
    };
    let entries = match bundle.get("entry") {
        None => &[][..],
        Some(Value::Array(entries)) => entries.as_slice(),
        Some(_) => return Err(FhirR4SearchError::ContractViolation),
    };
    if entries.len() > usize::from(max_entries) {
        return Err(FhirR4SearchError::CardinalityViolation);
    }
    let total = match bundle.get("total") {
        None => None,
        Some(total) => Some(total.as_u64().ok_or(FhirR4SearchError::ContractViolation)?),
    };
    if total.is_some_and(|total| total < entries.len() as u64) {
        return Err(FhirR4SearchError::CardinalityViolation);
    }
    let mut resources = Vec::with_capacity(entries.len());
    for entry in entries {
        let resource = entry
            .get("resource")
            .filter(|resource| resource.is_object())
            .ok_or(FhirR4SearchError::ContractViolation)?;
        let resource = resource
            .as_object()
            .ok_or(FhirR4SearchError::ContractViolation)?;
        let resource_type = resource
            .get("resourceType")
            .and_then(Value::as_str)
            .ok_or(FhirR4SearchError::ContractViolation)?;
        if resource_type == "OperationOutcome" || resource_type != expected_resource_type {
            return Err(FhirR4SearchError::ContractViolation);
        }
        resources.push(resource);
    }
    let ambiguous = next_link || entries.len() > 1 || total.is_some_and(|total| total > 1);
    if ambiguous {
        return Ok(FhirR4SearchsetOutcome::Ambiguous);
    }
    if entries.is_empty() {
        if total == Some(1) {
            return Err(FhirR4SearchError::CardinalityViolation);
        }
        return Ok(FhirR4SearchsetOutcome::NoMatch);
    }
    let mut normalized = Zeroizing::new(Vec::new());
    normalized.push(b'[');
    for (resource_index, resource) in resources.iter().enumerate() {
        if resource_index > 0 {
            normalized.push(b',');
        }
        normalized.push(b'{');
        let mut field_index = 0usize;
        for (name, value) in *resource {
            if name == "resourceType" {
                continue;
            }
            if field_index > 0 {
                normalized.push(b',');
            }
            serde_json::to_writer(&mut *normalized, name)
                .map_err(|_| FhirR4SearchError::ContractViolation)?;
            normalized.push(b':');
            serde_json::to_writer(&mut *normalized, value)
                .map_err(|_| FhirR4SearchError::ContractViolation)?;
            field_index += 1;
        }
        normalized.push(b'}');
    }
    normalized.push(b']');
    Ok(FhirR4SearchsetOutcome::Records(BoundedDestinationBody {
        bytes: normalized,
        slot: PhantomData,
    }))
}

/// Apply the exact production normalizer to caller-owned offline fixture bytes.
#[doc(hidden)]
pub fn normalize_r4_searchset_offline_fixture(
    bytes: &[u8],
    expected_resource_type: &str,
    max_entries: u8,
) -> Result<FhirR4SearchsetOutcome, FhirR4SearchError> {
    normalize_r4_searchset(
        BoundedDestinationBody {
            bytes: Zeroizing::new(bytes.to_vec()),
            slot: PhantomData,
        },
        expected_resource_type,
        max_entries,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn body(value: &str) -> DataDestinationBody {
        DataDestinationBody {
            bytes: Zeroizing::new(value.as_bytes().to_vec()),
            slot: PhantomData,
        }
    }

    #[test]
    fn accepts_only_the_fixed_bounded_searchset_shape() {
        let normalized = normalize_r4_searchset(
            body(
                r#"{"resourceType":"Bundle","type":"searchset","total":1,"link":[{"relation":"self","url":"https://example.invalid/Patient?_count=2"}],"entry":[{"resource":{"resourceType":"Patient","id":"p1"}}]}"#,
            ),
            "Patient",
            2,
        )
        .expect("valid fixed-resource searchset");
        let FhirR4SearchsetOutcome::Records(normalized) = normalized else {
            panic!("one fixed resource must normalize as records")
        };
        assert_eq!(normalized.as_bytes(), br#"[{"id":"p1"}]"#);
        assert!(!normalized
            .as_bytes()
            .windows(b"resourceType".len())
            .any(|window| window == b"resourceType"));
        for invalid in [
            r#"{"resourceType":"OperationOutcome","type":"searchset"}"#,
            r#"{"resourceType":"Bundle","type":"history"}"#,
            r#"{"resourceType":"Bundle","type":"searchset","entry":[{"resource":{"resourceType":"Coverage"}}]}"#,
            r#"{"resourceType":"Bundle","type":"searchset","entry":[{"resource":{"resourceType":"OperationOutcome"}}]}"#,
        ] {
            assert_eq!(
                normalize_r4_searchset(body(invalid), "Patient", 2).map(|_| ()),
                Err(FhirR4SearchError::ContractViolation)
            );
        }
    }

    #[test]
    fn pagination_and_reported_totals_prove_ambiguity_without_following_links() {
        for ambiguous in [
            r#"{"resourceType":"Bundle","type":"searchset","total":3,"entry":[{"resource":{"resourceType":"Patient","id":"p1"}}]}"#,
            r#"{"resourceType":"Bundle","type":"searchset","total":1,"link":[{"relation":"next","url":"https://example.invalid/page/2"}],"entry":[{"resource":{"resourceType":"Patient","id":"p1"}}]}"#,
            r#"{"resourceType":"Bundle","type":"searchset","total":2,"entry":[{"resource":{"resourceType":"Patient","id":"p1"}},{"resource":{"resourceType":"Patient","id":"p2"}}]}"#,
        ] {
            assert!(matches!(
                normalize_r4_searchset(body(ambiguous), "Patient", 2),
                Ok(FhirR4SearchsetOutcome::Ambiguous)
            ));
        }
        assert!(matches!(
            normalize_r4_searchset(
                body(
                    r#"{"resourceType":"Bundle","type":"searchset","entry":[{"resource":{"resourceType":"Patient","id":"p1"}},{"resource":{"resourceType":"Patient","id":"p2"}},{"resource":{"resourceType":"Patient","id":"p3"}}]}"#
                ),
                "Patient",
                2,
            ),
            Err(FhirR4SearchError::CardinalityViolation)
        ));
        assert!(matches!(
            normalize_r4_searchset(
                body(r#"{"resourceType":"Bundle","type":"searchset","total":0}"#),
                "Patient",
                2,
            ),
            Ok(FhirR4SearchsetOutcome::NoMatch)
        ));
    }
}
