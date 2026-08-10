// SPDX-License-Identifier: Apache-2.0
//! Closed parsing for the supported SDMX data-query subset.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use chrono::NaiveDate;

use super::{
    valid_sdmx_code_value, DatasetView, StatisticalTimeGranularity, StatisticalValue,
    StatisticalValueType, MAXIMUM_COMPONENT_VALUE_BYTES,
};
use crate::model::CompiledStatisticalDataset;

const MAXIMUM_QUERY_BYTES: usize = 16 * 1024;
const MAXIMUM_QUERY_PARAMETERS: usize = 64;
const MAXIMUM_VALUES_PER_COMPONENT: usize = 16;

#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct ComponentConstraint {
    pub(crate) exact: Vec<StatisticalValue>,
    pub(crate) lower: Option<String>,
    pub(crate) upper: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DimensionAtObservation {
    TimePeriod,
    AllDimensions,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct DataQuery {
    pub(crate) constraints: BTreeMap<String, ComponentConstraint>,
    pub(crate) offset: u32,
    pub(crate) limit: u32,
    pub(crate) explicit_limit: bool,
    pub(crate) dimension_at_observation: DimensionAtObservation,
}

/// Value-free query failures. HTTP owns the eventual status and problem code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DataQueryError {
    Invalid,
    TooLarge,
}

impl fmt::Display for DataQueryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "the statistical query is invalid",
            Self::TooLarge => "the statistical query exceeds a configured bound",
        })
    }
}

impl std::error::Error for DataQueryError {}

/// Parses either the canonical keyed route or the canonical omitted-key route.
///
/// `key = None` is the omitted-key route. The keyed route must supply at least
/// one positional value or the explicit `*` wildcard.
pub(crate) fn parse_data_query(
    dataset: &CompiledStatisticalDataset,
    key: Option<&str>,
    query: Option<&str>,
) -> Result<DataQuery, DataQueryError> {
    parse_data_query_view(&DatasetView::from_compiled(dataset), key, query)
}

fn parse_data_query_view(
    dataset: &DatasetView,
    key: Option<&str>,
    query: Option<&str>,
) -> Result<DataQuery, DataQueryError> {
    let mut constraints = BTreeMap::new();
    parse_key(dataset, key, &mut constraints)?;

    let mut offset = 0_u32;
    let mut limit = dataset.maximum_observations;
    let mut explicit_limit = false;
    let mut dimension_at_observation = DimensionAtObservation::TimePeriod;
    let mut seen = BTreeSet::new();

    let query = query.unwrap_or_default();
    if query.len() > MAXIMUM_QUERY_BYTES {
        return Err(DataQueryError::TooLarge);
    }
    let pairs = strict_form_pairs(query)?;
    if pairs.len() > MAXIMUM_QUERY_PARAMETERS {
        return Err(DataQueryError::TooLarge);
    }

    for (name, value) in pairs {
        if !seen.insert(name.clone()) {
            return Err(DataQueryError::Invalid);
        }
        match name.as_str() {
            "offset" => {
                offset = value
                    .parse()
                    .ok()
                    .filter(|value| *value <= dataset.maximum_offset)
                    .ok_or(DataQueryError::Invalid)?;
            }
            "limit" => {
                limit = value
                    .parse()
                    .ok()
                    .filter(|value| *value > 0 && *value <= dataset.maximum_observations)
                    .ok_or(DataQueryError::Invalid)?;
                explicit_limit = true;
            }
            "dimensionAtObservation" => {
                dimension_at_observation = if value == dataset.time.id {
                    DimensionAtObservation::TimePeriod
                } else if value == "AllDimensions" {
                    DimensionAtObservation::AllDimensions
                } else {
                    return Err(DataQueryError::Invalid);
                };
            }
            _ if name.starts_with("c[") && name.ends_with(']') => {
                let id = &name[2..name.len() - 1];
                if id.is_empty() || id.len() > MAXIMUM_COMPONENT_VALUE_BYTES {
                    return Err(DataQueryError::Invalid);
                }
                if constraints.contains_key(id) {
                    return Err(DataQueryError::Invalid);
                }
                if let Some(dimension) = dataset
                    .dimensions
                    .iter()
                    .find(|component| component.id == id)
                {
                    merge_component_constraint(
                        constraints.entry(id.to_owned()).or_default(),
                        dimension.value_type,
                        &value,
                    )?;
                } else if id == dataset.time.id {
                    merge_time_constraint(
                        constraints.entry(id.to_owned()).or_default(),
                        dataset.time.granularity,
                        &value,
                    )?;
                } else {
                    return Err(DataQueryError::Invalid);
                }
            }
            _ => return Err(DataQueryError::Invalid),
        }
    }

    if constraints.is_empty() && !dataset.allow_unfiltered {
        return Err(DataQueryError::Invalid);
    }
    if constraints.values().any(|constraint| {
        constraint
            .lower
            .as_ref()
            .zip(constraint.upper.as_ref())
            .is_some_and(|(lower, upper)| lower > upper)
    }) {
        return Err(DataQueryError::Invalid);
    }

    Ok(DataQuery {
        constraints,
        offset,
        limit,
        explicit_limit,
        dimension_at_observation,
    })
}

fn parse_key(
    dataset: &DatasetView,
    key: Option<&str>,
    constraints: &mut BTreeMap<String, ComponentConstraint>,
) -> Result<(), DataQueryError> {
    let Some(key) = key else {
        return Ok(());
    };
    if key.is_empty() {
        return Err(DataQueryError::Invalid);
    }
    if key.len() > MAXIMUM_QUERY_BYTES {
        return Err(DataQueryError::TooLarge);
    }

    let parts = key.split('.').collect::<Vec<_>>();
    if parts.len() > dataset.dimensions.len() {
        return Err(DataQueryError::Invalid);
    }
    for (index, value) in parts.into_iter().enumerate() {
        if value == "*" {
            continue;
        }
        if value.is_empty() {
            return Err(DataQueryError::Invalid);
        }
        let dimension = &dataset.dimensions[index];
        merge_component_constraint(
            constraints.entry(dimension.id.clone()).or_default(),
            dimension.value_type,
            value,
        )?;
    }
    Ok(())
}

fn merge_component_constraint(
    constraint: &mut ComponentConstraint,
    value_type: StatisticalValueType,
    text: &str,
) -> Result<(), DataQueryError> {
    if text.len() > MAXIMUM_COMPONENT_VALUE_BYTES * MAXIMUM_VALUES_PER_COMPONENT {
        return Err(DataQueryError::TooLarge);
    }

    if text.contains('+')
        || text
            .split(',')
            .any(|term| term.starts_with("ge:") || term.starts_with("le:"))
    {
        return Err(DataQueryError::Invalid);
    }
    for term in text.split(',') {
        if term.is_empty() {
            return Err(DataQueryError::Invalid);
        }
        let value = term.strip_prefix("eq:").unwrap_or(term);
        constraint
            .exact
            .push(parse_component_value(value_type, value)?);
    }
    if constraint.exact.len() > MAXIMUM_VALUES_PER_COMPONENT {
        return Err(DataQueryError::TooLarge);
    }
    Ok(())
}

fn merge_time_constraint(
    constraint: &mut ComponentConstraint,
    granularity: StatisticalTimeGranularity,
    text: &str,
) -> Result<(), DataQueryError> {
    if text.len() > MAXIMUM_COMPONENT_VALUE_BYTES * MAXIMUM_VALUES_PER_COMPONENT {
        return Err(DataQueryError::TooLarge);
    }
    let is_range = text
        .split(['+', ','])
        .any(|term| term.starts_with("ge:") || term.starts_with("le:"));
    if (is_range && text.contains(',')) || (!is_range && text.contains('+')) {
        return Err(DataQueryError::Invalid);
    }

    let separator = if is_range { '+' } else { ',' };
    for term in text.split(separator) {
        if term.is_empty() {
            return Err(DataQueryError::Invalid);
        }
        if let Some(value) = term.strip_prefix("ge:") {
            if !valid_time_period(granularity, value) || constraint.lower.is_some() {
                return Err(DataQueryError::Invalid);
            }
            constraint.lower = Some(value.to_owned());
        } else if let Some(value) = term.strip_prefix("le:") {
            if !valid_time_period(granularity, value) || constraint.upper.is_some() {
                return Err(DataQueryError::Invalid);
            }
            constraint.upper = Some(value.to_owned());
        } else {
            let value = term.strip_prefix("eq:").unwrap_or(term);
            if !valid_time_period(granularity, value) {
                return Err(DataQueryError::Invalid);
            }
            constraint
                .exact
                .push(StatisticalValue::String(value.to_owned()));
        }
    }
    if constraint.exact.len() > MAXIMUM_VALUES_PER_COMPONENT {
        return Err(DataQueryError::TooLarge);
    }
    if !constraint.exact.is_empty() && (constraint.lower.is_some() || constraint.upper.is_some()) {
        return Err(DataQueryError::Invalid);
    }
    Ok(())
}

fn parse_component_value(
    value_type: StatisticalValueType,
    value: &str,
) -> Result<StatisticalValue, DataQueryError> {
    if value.is_empty() || value.len() > MAXIMUM_COMPONENT_VALUE_BYTES {
        return Err(DataQueryError::Invalid);
    }
    match value_type {
        StatisticalValueType::Code if valid_sdmx_code_value(value) => {
            Ok(StatisticalValue::String(value.to_owned()))
        }
        StatisticalValueType::Code => Err(DataQueryError::Invalid),
        StatisticalValueType::String => Ok(StatisticalValue::String(value.to_owned())),
        StatisticalValueType::Integer => value
            .parse::<i64>()
            .map(StatisticalValue::Integer)
            .map_err(|_| DataQueryError::Invalid),
        StatisticalValueType::Decimal => value
            .parse::<f64>()
            .ok()
            .filter(|value| value.is_finite())
            .map(StatisticalValue::Decimal)
            .ok_or(DataQueryError::Invalid),
        StatisticalValueType::Boolean => match value {
            "true" => Ok(StatisticalValue::Boolean(true)),
            "false" => Ok(StatisticalValue::Boolean(false)),
            _ => Err(DataQueryError::Invalid),
        },
    }
}

pub(super) fn valid_time_period(granularity: StatisticalTimeGranularity, value: &str) -> bool {
    let bytes = value.as_bytes();
    match granularity {
        StatisticalTimeGranularity::Annual => {
            bytes.len() == 4 && bytes.iter().all(u8::is_ascii_digit)
        }
        StatisticalTimeGranularity::Quarterly => {
            bytes.len() == 7
                && bytes[..4].iter().all(u8::is_ascii_digit)
                && bytes[4] == b'-'
                && bytes[5] == b'Q'
                && matches!(bytes[6], b'1'..=b'4')
        }
        StatisticalTimeGranularity::Monthly => {
            bytes.len() == 7
                && bytes[..4].iter().all(u8::is_ascii_digit)
                && bytes[4] == b'-'
                && bytes[5..].iter().all(u8::is_ascii_digit)
                && value[5..]
                    .parse::<u8>()
                    .is_ok_and(|month| (1..=12).contains(&month))
        }
        StatisticalTimeGranularity::Daily => {
            bytes.len() == 10
                && bytes[..4].iter().all(u8::is_ascii_digit)
                && bytes[4] == b'-'
                && bytes[5..7].iter().all(u8::is_ascii_digit)
                && bytes[7] == b'-'
                && bytes[8..].iter().all(u8::is_ascii_digit)
                && NaiveDate::parse_from_str(value, "%Y-%m-%d").is_ok()
        }
    }
}

fn strict_form_pairs(query: &str) -> Result<Vec<(String, String)>, DataQueryError> {
    if query.is_empty() {
        return Ok(Vec::new());
    }

    query
        .split('&')
        .map(|pair| {
            if pair.is_empty() {
                return Err(DataQueryError::Invalid);
            }
            let (name, value) = pair.split_once('=').ok_or(DataQueryError::Invalid)?;
            if name.is_empty() {
                return Err(DataQueryError::Invalid);
            }
            Ok((strict_percent_decode(name)?, strict_percent_decode(value)?))
        })
        .collect()
}

/// Percent decoding is deliberately not `application/x-www-form-urlencoded`:
/// a literal `+` is the SDMX range separator, not a space.
fn strict_percent_decode(value: &str) -> Result<String, DataQueryError> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return Err(DataQueryError::Invalid);
            }
            let high = hex_value(bytes[index + 1]).ok_or(DataQueryError::Invalid)?;
            let low = hex_value(bytes[index + 2]).ok_or(DataQueryError::Invalid)?;
            decoded.push((high << 4) | low);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).map_err(|_| DataQueryError::Invalid)
}

const fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdmx::test_dataset_view;

    #[test]
    fn keyed_and_omitted_key_routes_share_one_closed_parser() {
        let dataset = test_dataset_view();
        let keyed = parse_data_query_view(
            &dataset,
            Some("TH.*"),
            Some("c[TIME_PERIOD]=ge:2026-Q1+le:2026-Q4&limit=25&offset=2"),
        )
        .expect("supported query parses");
        assert_eq!(keyed.limit, 25);
        assert_eq!(keyed.offset, 2);
        assert_eq!(
            keyed.constraints["REF_AREA"].exact,
            vec![StatisticalValue::String("TH".into())]
        );
        assert_eq!(
            keyed.constraints["TIME_PERIOD"].lower.as_deref(),
            Some("2026-Q1")
        );

        let omitted = parse_data_query_view(&dataset, None, None).expect("key may be omitted");
        assert!(omitted.constraints.is_empty());
        assert_eq!(omitted.limit, dataset.maximum_observations);
        assert_eq!(
            parse_data_query_view(&dataset, Some(""), None),
            Err(DataQueryError::Invalid)
        );
    }

    #[test]
    fn positional_key_requires_an_explicit_wildcard_for_an_omitted_middle_value() {
        let dataset = test_dataset_view();
        let query = parse_data_query_view(&dataset, Some("*.F"), None).unwrap();
        assert!(!query.constraints.contains_key("REF_AREA"));
        assert_eq!(
            query.constraints["SEX"].exact,
            vec![StatisticalValue::String("F".into())]
        );
        assert_eq!(
            parse_data_query_view(&dataset, Some(".F"), None),
            Err(DataQueryError::Invalid)
        );
    }

    #[test]
    fn component_constraints_are_exact_or_time_ranges_only() {
        let dataset = test_dataset_view();
        let exact =
            parse_data_query_view(&dataset, None, Some("c[REF_AREA]=TH,VN&c[SEX]=eq:F")).unwrap();
        assert_eq!(exact.constraints["REF_AREA"].exact.len(), 2);
        assert_eq!(exact.constraints["SEX"].exact.len(), 1);

        assert_eq!(
            parse_data_query_view(&dataset, None, Some("c[REF_AREA]=ge:TH")),
            Err(DataQueryError::Invalid)
        );
        assert_eq!(
            parse_data_query_view(&dataset, Some("TH"), Some("c[REF_AREA]=TH")),
            Err(DataQueryError::Invalid)
        );
    }

    #[test]
    fn granularity_rejects_mixed_time_period_shapes_and_invalid_dates() {
        assert!(valid_time_period(
            StatisticalTimeGranularity::Annual,
            "2026"
        ));
        assert!(!valid_time_period(
            StatisticalTimeGranularity::Annual,
            "2026-Q1"
        ));
        assert!(valid_time_period(
            StatisticalTimeGranularity::Quarterly,
            "2026-Q4"
        ));
        assert!(!valid_time_period(
            StatisticalTimeGranularity::Quarterly,
            "2026-Q5"
        ));
        assert!(valid_time_period(
            StatisticalTimeGranularity::Monthly,
            "2026-12"
        ));
        assert!(!valid_time_period(
            StatisticalTimeGranularity::Monthly,
            "2026-13"
        ));
        assert!(valid_time_period(
            StatisticalTimeGranularity::Daily,
            "2024-02-29"
        ));
        assert!(!valid_time_period(
            StatisticalTimeGranularity::Daily,
            "2026-02-29"
        ));
    }

    #[test]
    fn paging_and_dimension_at_observation_are_bounded() {
        let dataset = test_dataset_view();
        let query = parse_data_query_view(
            &dataset,
            None,
            Some("limit=100&offset=1000&dimensionAtObservation=AllDimensions"),
        )
        .unwrap();
        assert!(query.explicit_limit);
        assert_eq!(
            query.dimension_at_observation,
            DimensionAtObservation::AllDimensions
        );

        assert_eq!(
            parse_data_query_view(&dataset, None, Some("limit=101")),
            Err(DataQueryError::Invalid)
        );
        assert_eq!(
            parse_data_query_view(&dataset, None, Some("offset=1001")),
            Err(DataQueryError::Invalid)
        );
        assert_eq!(
            parse_data_query_view(&dataset, None, Some("dimensionAtObservation=SEX")),
            Err(DataQueryError::Invalid)
        );
    }

    #[test]
    fn malformed_encoding_duplicates_and_unknown_parameters_are_closed() {
        let dataset = test_dataset_view();
        assert_eq!(
            parse_data_query_view(&dataset, None, Some("limit=1&limit=2")),
            Err(DataQueryError::Invalid)
        );
        assert_eq!(
            parse_data_query_view(&dataset, None, Some("c%5BREF_AREA%5D=%ZZ")),
            Err(DataQueryError::Invalid)
        );
        assert_eq!(
            parse_data_query_view(&dataset, None, Some("startPeriod=2026-Q1")),
            Err(DataQueryError::Invalid)
        );
        assert_eq!(
            parse_data_query_view(&dataset, None, Some("c[REF_AREA]=not%20an%20sdmx%20code")),
            Err(DataQueryError::Invalid)
        );
    }

    #[test]
    fn literal_and_encoded_plus_are_both_range_separators() {
        let dataset = test_dataset_view();
        for query in [
            "c[TIME_PERIOD]=ge:2026-Q1+le:2026-Q2",
            "c%5BTIME_PERIOD%5D=ge%3A2026-Q1%2Ble%3A2026-Q2",
        ] {
            let parsed = parse_data_query_view(&dataset, None, Some(query)).unwrap();
            assert_eq!(
                parsed.constraints["TIME_PERIOD"].upper.as_deref(),
                Some("2026-Q2")
            );
        }
    }
}
