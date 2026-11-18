// SPDX-License-Identifier: Apache-2.0
//! Pure statistical-dataset periods, aggregation, disclosure, and representations.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{Datelike, Duration, NaiveDate};
use registry_platform_canonical_json::canonicalize_json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::contract::FieldTypeSource;

pub const MAX_CELLS_PER_RESPONSE: usize = 10_000;
pub const MAX_PERIODS_PER_READ: usize = 366;
pub const TOTAL_CODE: &str = "_T";
pub const UNKNOWN_CODE: &str = "_U";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeriodGranularity {
    Day,
    Month,
    Quarter,
    Year,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeriodKind {
    Flow,
    Stock,
}

/// How a release protects the values it states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(
    tag = "method",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum DisclosureMethod {
    MinimumCountAndRounding {
        minimum_count: u64,
        rounding_base: u64,
    },
    ExactPublicValues,
}

impl DisclosureMethod {
    /// The method name a release document states.
    pub fn name(&self) -> &'static str {
        match self {
            Self::MinimumCountAndRounding { .. } => "minimum-count-and-rounding",
            Self::ExactPublicValues => "exact-public-values",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Period {
    pub code: String,
    pub start: NaiveDate,
    pub end: NaiveDate,
    pub reference_date: NaiveDate,
    pub ended: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DimensionDomain {
    pub field: String,
    pub vocabulary: String,
    pub codes: Vec<String>,
    pub include_unknown: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupedCell {
    pub period: String,
    pub codes: Vec<String>,
    /// One value per declared measure, in declaration order.
    pub values: Vec<Option<CellValue>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellStatus {
    Exact,
    Suppressed,
    Rounded,
    /// The measure has no value for this cell, and nothing is withheld: a mean
    /// over no values.
    #[serde(rename = "not-applicable")]
    NotApplicable,
}

/// The value of one cell. A count is a JSON integer; a sum or mean is a decimal
/// string, which keeps every digit the database computed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CellValue {
    Count(u64),
    Decimal(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cell {
    pub period: String,
    pub dimensions: BTreeMap<String, String>,
    /// The id of the declared measure this cell reports.
    pub measure: String,
    pub value: Option<CellValue>,
    pub status: CellStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseStatus {
    Provisional,
    Final,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum WithdrawalReason {
    ComputationError,
    SourceDataError,
    DisclosureRisk,
}

/// One declared measure: its local id and how its value is computed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum Measure {
    /// The number of unit Records in the population.
    Count { id: String },
    /// The sum of a field over the records that have a value for it, with
    /// `scale` fractional digits.
    Sum {
        id: String,
        field: String,
        scale: u8,
    },
    /// The mean of a field over the records that have a value for it, rounded
    /// half away from zero to `scale` fractional digits.
    Mean {
        id: String,
        field: String,
        scale: u8,
    },
    /// The number of distinct values of a `reference` field among the records
    /// that have a value for it.
    DistinctCount { id: String, field: String },
}

impl Measure {
    pub fn id(&self) -> &str {
        match self {
            Self::Count { id }
            | Self::Sum { id, .. }
            | Self::Mean { id, .. }
            | Self::DistinctCount { id, .. } => id,
        }
    }

    /// True when a total of this measure is the total of its cells' values:
    /// a count adds up across the cells, and a sum and a mean are computed from
    /// the cells' sums and counts. A distinct count does not: the owners of two
    /// districts are not the sum of each district's owners, so a dataset that
    /// declares one computes its totals over the records.
    pub fn is_additive(&self) -> bool {
        !matches!(self, Self::DistinctCount { .. })
    }

    /// True for a measure whose value is a whole number of records or values,
    /// which a minimum-count-and-rounding release suppresses and rounds.
    pub fn is_count_like(&self) -> bool {
        matches!(self, Self::Count { .. } | Self::DistinctCount { .. })
    }

    /// The value of a cell no record falls into: a count, a distinct count and
    /// a sum are zero, and a mean has none.
    fn empty_value(&self) -> Option<CellValue> {
        match self {
            Self::Count { .. } | Self::DistinctCount { .. } => Some(CellValue::Count(0)),
            Self::Sum { scale, .. } => Some(CellValue::Decimal(zero_decimal(*scale))),
            Self::Mean { .. } => None,
        }
    }

    /// True when `value` is a value this measure can report.
    fn admits(&self, value: &Option<CellValue>) -> bool {
        match (self, value) {
            (Self::Count { .. } | Self::DistinctCount { .. }, Some(CellValue::Count(_))) => true,
            (Self::Sum { scale, .. }, Some(CellValue::Decimal(text)))
            | (Self::Mean { scale, .. }, Some(CellValue::Decimal(text))) => {
                is_decimal_text(text, *scale)
            }
            (Self::Mean { .. }, None) => true,
            _ => false,
        }
    }
}

fn zero_decimal(scale: u8) -> String {
    if scale == 0 {
        "0".to_owned()
    } else {
        format!("0.{}", "0".repeat(usize::from(scale)))
    }
}

/// True when `text` is a plain decimal, `-?(0|[1-9][0-9]*)(\.[0-9]+)?`, with
/// exactly `scale` fractional digits.
pub fn is_decimal_text(text: &str, scale: u8) -> bool {
    let unsigned = text.strip_prefix('-').unwrap_or(text);
    let (integer, fraction) = match unsigned.split_once('.') {
        Some((integer, fraction)) => (integer, Some(fraction)),
        None => (unsigned, None),
    };
    let digits = |part: &str| part.bytes().all(|byte| byte.is_ascii_digit());
    !integer.is_empty()
        && digits(integer)
        && (integer == "0" || !integer.starts_with('0'))
        && match fraction {
            Some(fraction) => {
                usize::from(scale) > 0 && fraction.len() == usize::from(scale) && digits(fraction)
            }
            None => scale == 0,
        }
}

/// The most characters a sum or mean over a field of `field_type` can take as a
/// decimal string: every digit, the point when there are fractional digits, and
/// the sign. A count, and a field that is not `int64` or `decimal`, has none.
///
/// - A sum adds at most 10^19 values (one per record, bounded by an `int64` row
///   count), so it gains 19 integer digits over the field's `p - s` (19 for
///   `int64`) and keeps the field's `s` fractional digits.
/// - A mean never exceeds the field's largest value in magnitude, so it keeps the
///   field's integer digits, plus one when a scale below the field's rounds
///   99.99 up to 100, and has the measure's `scale` fractional digits.
///
/// The compiler sizes its byte bound with this, and the runtime refuses a value
/// longer than it.
pub fn maximum_decimal_characters(
    measure: &Measure,
    field_type: &FieldTypeSource,
) -> Option<usize> {
    let (integer_digits, field_scale) = match field_type {
        FieldTypeSource::Int64 => (19_usize, 0_usize),
        FieldTypeSource::Decimal {
            precision, scale, ..
        } => (
            usize::from(*precision).saturating_sub(usize::from(*scale)),
            usize::from(*scale),
        ),
        _ => return None,
    };
    let (extra_integer_digits, scale) = match measure {
        Measure::Count { .. } | Measure::DistinctCount { .. } => return None,
        Measure::Sum { scale, .. } => (19, usize::from(*scale)),
        Measure::Mean { scale, .. } => (
            usize::from(usize::from(*scale) < field_scale),
            usize::from(*scale),
        ),
    };
    let point = usize::from(scale > 0);
    Some(integer_digits + extra_integer_digits + scale + point + 1)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatasetDocument {
    pub id: String,
    pub unit: String,
    /// Declared measures in publication order; every cell names one of them.
    pub measures: Vec<Measure>,
    pub period_kind: PeriodKind,
    pub granularity: PeriodGranularity,
    pub population: String,
    pub definition_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeriodVersionHeader {
    pub version: u64,
    pub status: ReleaseStatus,
    pub content_digest: String,
    pub snapshot: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WithdrawalDocument {
    pub withdrawn_at: String,
    pub reason: WithdrawalReason,
}

/// Complete immutable header returned by release listings and mutations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseVersionHeader {
    pub dataset: String,
    pub period: String,
    pub version: u64,
    pub status: ReleaseStatus,
    pub snapshot: Option<String>,
    pub computed_at: String,
    pub package_digest: String,
    pub definition_digest: String,
    /// Names the stored document. A withdrawn header carries none: withdrawal
    /// deletes the document, and a digest of it would let a reader confirm
    /// guessed cell values offline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawal: Option<WithdrawalDocument>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeriodDocument {
    pub code: String,
    pub start: String,
    pub end: String,
    pub reference_date: String,
    pub ended: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<PeriodVersionHeader>,
}

impl From<&Period> for PeriodDocument {
    fn from(period: &Period) -> Self {
        Self {
            code: period.code.clone(),
            start: period.start.to_string(),
            end: period.end.to_string(),
            reference_date: period.reference_date.to_string(),
            ended: period.ended,
            version: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DimensionDocument {
    pub field: String,
    pub vocabulary: String,
    pub codes: Vec<String>,
}

impl DimensionDomain {
    pub fn document(&self) -> DimensionDocument {
        let mut codes = self.codes.clone();
        if self.include_unknown {
            codes.push(UNKNOWN_CODE.to_owned());
        }
        codes.push(TOTAL_CODE.to_owned());
        DimensionDocument {
            field: self.field.clone(),
            vocabulary: self.vocabulary.clone(),
            codes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReleaseDocument {
    pub period: String,
    pub version: u64,
    pub status: ReleaseStatus,
    pub snapshot: Option<String>,
    pub computed_at: String,
    pub package_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LiveDocument {
    pub evaluated_at: String,
    pub access_profile: String,
}

/// Metadata of an exact read: the ended periods' values as they stand when
/// evaluated, for the caller's profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExactDocument {
    pub evaluated_at: String,
    pub access_profile: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "method",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum DisclosureDocument {
    MinimumCountAndRounding {
        minimum_count: u64,
        rounding_base: u64,
        rounding_rule: String,
        totals: String,
    },
    ExactPublicValues,
}

impl From<DisclosureMethod> for DisclosureDocument {
    fn from(method: DisclosureMethod) -> Self {
        match method {
            DisclosureMethod::MinimumCountAndRounding {
                minimum_count,
                rounding_base,
            } => Self::MinimumCountAndRounding {
                minimum_count,
                rounding_base,
                rounding_rule: "nearest-multiple-halves-up".to_owned(),
                totals: "rounded-independently".to_owned(),
            },
            DisclosureMethod::ExactPublicValues => Self::ExactPublicValues,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StatisticsDocument {
    pub dataset: DatasetDocument,
    pub periods: Vec<PeriodDocument>,
    pub dimensions: Vec<DimensionDocument>,
    pub cells: Vec<Cell>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub release: Option<ReleaseDocument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live: Option<LiveDocument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exact: Option<ExactDocument>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disclosure: Option<DisclosureDocument>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalDocument {
    pub bytes: Vec<u8>,
    pub content_digest: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum StatisticsError {
    #[error("invalid {granularity:?} period code `{code}`")]
    InvalidPeriodCode {
        granularity: PeriodGranularity,
        code: String,
    },
    #[error("the period range starts after it ends")]
    ReversedPeriodRange,
    #[error("the period range exceeds the {MAX_PERIODS_PER_READ}-period limit")]
    TooManyPeriods,
    #[error("the statistical response exceeds the {MAX_CELLS_PER_RESPONSE}-cell limit")]
    TooManyCells,
    #[error(
        "the statistical dataset `{dataset}` produced a value outside dimension `{dimension}`"
    )]
    UnknownCode { dataset: String, dimension: String },
    #[error("the statistical dataset `{dataset}` produced a row with an invalid dimension count")]
    DimensionCount { dataset: String },
    #[error("the statistical dataset `{dataset}` produced an unknown period")]
    UnknownPeriod { dataset: String },
    #[error("the statistical dataset `{dataset}` produced the same grouped cell more than once")]
    DuplicateGroupedCell { dataset: String },
    #[error("the statistical dataset `{dataset}` produced a total that differs from its cells")]
    InconsistentTotal { dataset: String },
    #[error("the statistical dataset has an invalid dimension domain for `{dimension}`")]
    InvalidDimensionDomain { dimension: String },
    #[error("the statistical dataset `{dataset}` produced a row with the wrong number of values")]
    MeasureValueCount { dataset: String },
    #[error(
        "the statistical dataset `{dataset}` produced an invalid value for measure `{measure}`"
    )]
    InvalidMeasureValue { dataset: String, measure: String },
    #[error("statistical count arithmetic overflowed")]
    CountOverflow,
    #[error("minimumCount and roundingBase must each be at least 2")]
    InvalidDisclosureParameters,
    #[error("the statistics document is structurally invalid: {0}")]
    InvalidDocument(&'static str),
    #[error("the statistics document could not be canonicalized")]
    Canonicalization,
}

pub fn period_for_code(
    granularity: PeriodGranularity,
    code: &str,
    today: NaiveDate,
) -> Result<Period, StatisticsError> {
    let (canonical, start, end) = parse_period_bounds(granularity, code)?;
    let current = start <= today && today < end;
    let reference_date = if current {
        today
    } else {
        end.checked_sub_signed(Duration::days(1))
            .ok_or_else(|| invalid_period(granularity, code))?
    };
    Ok(Period {
        code: canonical,
        start,
        end,
        reference_date,
        ended: end <= today,
    })
}

pub fn current_period(
    granularity: PeriodGranularity,
    today: NaiveDate,
) -> Result<Period, StatisticsError> {
    let code = match granularity {
        PeriodGranularity::Day => today.format("%Y-%m-%d").to_string(),
        PeriodGranularity::Month => today.format("%Y-%m").to_string(),
        PeriodGranularity::Quarter => format!("{:04}-Q{}", today.year(), today.month0() / 3 + 1),
        PeriodGranularity::Year => format!("{:04}", today.year()),
    };
    period_for_code(granularity, &code, today)
}

pub fn period_range(
    granularity: PeriodGranularity,
    from: &str,
    to: &str,
    today: NaiveDate,
) -> Result<Vec<Period>, StatisticsError> {
    let first = period_for_code(granularity, from, today)?;
    let last = period_for_code(granularity, to, today)?;
    if first.start > last.start {
        return Err(StatisticsError::ReversedPeriodRange);
    }
    let mut periods = Vec::new();
    let mut next = first;
    loop {
        if periods.len() == MAX_PERIODS_PER_READ {
            return Err(StatisticsError::TooManyPeriods);
        }
        let done = next.start == last.start;
        let next_start = next.end;
        periods.push(next);
        if done {
            break;
        }
        next = period_for_code(granularity, &code_for_start(granularity, next_start), today)?;
        if next.start > last.start {
            return Err(StatisticsError::ReversedPeriodRange);
        }
    }
    Ok(periods)
}

pub fn build_exact_cells(
    dataset: &str,
    periods: &[Period],
    dimensions: &[DimensionDomain],
    measures: &[Measure],
    grouped: &[GroupedCell],
) -> Result<Vec<Cell>, StatisticsError> {
    validate_dimensions(dimensions)?;
    validate_measures(measures)?;
    let period_codes: BTreeSet<&str> = periods.iter().map(|period| period.code.as_str()).collect();
    let base_codes: Vec<Vec<String>> = dimensions
        .iter()
        .map(|dimension| {
            let mut codes = dimension.codes.clone();
            if dimension.include_unknown {
                codes.push(UNKNOWN_CODE.to_owned());
            }
            codes
        })
        .collect();
    let output_codes: Vec<Vec<String>> = base_codes
        .iter()
        .map(|codes| {
            let mut codes = codes.clone();
            codes.push(TOTAL_CODE.to_owned());
            codes
        })
        .collect();
    let cells_per_period = checked_product(output_codes.iter().map(Vec::len))?;
    let total_cells = cells_per_period
        .checked_mul(measures.len())
        .and_then(|cells| cells.checked_mul(periods.len()))
        .ok_or(StatisticsError::TooManyCells)?;
    if total_cells > MAX_CELLS_PER_RESPONSE {
        return Err(StatisticsError::TooManyCells);
    }

    // The database returns base cells and total cells alike, each a finished value.
    let mut returned = BTreeMap::<(String, Vec<String>), &[Option<CellValue>]>::new();
    for row in grouped {
        if !period_codes.contains(row.period.as_str()) {
            return Err(StatisticsError::UnknownPeriod {
                dataset: dataset.to_owned(),
            });
        }
        if row.codes.len() != dimensions.len() {
            return Err(StatisticsError::DimensionCount {
                dataset: dataset.to_owned(),
            });
        }
        for (index, code) in row.codes.iter().enumerate() {
            if !output_codes[index].contains(code) {
                return Err(StatisticsError::UnknownCode {
                    dataset: dataset.to_owned(),
                    dimension: dimensions[index].field.clone(),
                });
            }
        }
        if row.values.len() != measures.len() {
            return Err(StatisticsError::MeasureValueCount {
                dataset: dataset.to_owned(),
            });
        }
        if let Some((measure, _)) = measures
            .iter()
            .zip(&row.values)
            .find(|(measure, value)| !measure.admits(value))
        {
            return Err(StatisticsError::InvalidMeasureValue {
                dataset: dataset.to_owned(),
                measure: measure.id().to_owned(),
            });
        }
        if returned
            .insert((row.period.clone(), row.codes.clone()), &row.values)
            .is_some()
        {
            return Err(StatisticsError::DuplicateGroupedCell {
                dataset: dataset.to_owned(),
            });
        }
    }

    // A cell the database returned no row for has no records: its measures take
    // their empty value.
    let mut values = BTreeMap::<(String, Vec<String>), Vec<Option<CellValue>>>::new();
    for period in periods {
        for_each_combination(&output_codes, |codes| {
            let row = match returned.get(&(period.code.clone(), codes.clone())) {
                Some(row) => row.to_vec(),
                None => measures.iter().map(Measure::empty_value).collect(),
            };
            values.insert((period.code.clone(), codes), row);
        });
    }
    // Only counts add up across totals; a sum has its own database total and a
    // mean does not add up at all.
    for (index, measure) in measures.iter().enumerate() {
        if !matches!(measure, Measure::Count { .. }) {
            continue;
        }
        let mut counts = BTreeMap::new();
        for (key, row) in &values {
            let Some(CellValue::Count(count)) = row[index] else {
                return Err(StatisticsError::InvalidMeasureValue {
                    dataset: dataset.to_owned(),
                    measure: measure.id().to_owned(),
                });
            };
            counts.insert(key.clone(), count);
        }
        check_totals(dataset, periods, &base_codes, &output_codes, &counts)?;
    }

    let mut cells = Vec::with_capacity(total_cells);
    for period in periods {
        for_each_combination(&output_codes, |codes| {
            let dimensions_map: BTreeMap<String, String> = dimensions
                .iter()
                .zip(&codes)
                .map(|(dimension, code)| (dimension.field.clone(), code.clone()))
                .collect();
            let row = &values[&(period.code.clone(), codes)];
            for (measure, value) in measures.iter().zip(row) {
                cells.push(Cell {
                    period: period.code.clone(),
                    dimensions: dimensions_map.clone(),
                    measure: measure.id().to_owned(),
                    value: value.clone(),
                    status: if value.is_some() {
                        CellStatus::Exact
                    } else {
                        CellStatus::NotApplicable
                    },
                });
            }
        });
    }
    Ok(cells)
}

pub fn apply_disclosure(
    cells: &mut [Cell],
    method: DisclosureMethod,
) -> Result<(), StatisticsError> {
    let DisclosureMethod::MinimumCountAndRounding {
        minimum_count,
        rounding_base,
    } = method
    else {
        return Ok(());
    };
    if minimum_count < 2 || rounding_base < 2 {
        return Err(StatisticsError::InvalidDisclosureParameters);
    }
    for cell in cells {
        let Some(CellValue::Count(value)) = cell.value else {
            return Err(StatisticsError::InvalidDocument(
                "disclosure control requires exact count cells",
            ));
        };
        if value == 0 {
            cell.status = CellStatus::Exact;
        } else if value < minimum_count {
            cell.value = None;
            cell.status = CellStatus::Suppressed;
        } else {
            cell.value = Some(CellValue::Count(round_halves_up(value, rounding_base)?));
            cell.status = CellStatus::Rounded;
        }
    }
    Ok(())
}

pub fn canonical_document(document: &StatisticsDocument) -> Result<Vec<u8>, StatisticsError> {
    validate_document(document)?;
    let value = serde_json::to_value(document).map_err(|_| StatisticsError::Canonicalization)?;
    canonicalize_json(&value).map_err(|_| StatisticsError::Canonicalization)
}

pub fn canonical_document_and_digest(
    document: &StatisticsDocument,
) -> Result<CanonicalDocument, StatisticsError> {
    let bytes = canonical_document(document)?;
    Ok(CanonicalDocument {
        content_digest: format!("sha256:{}", sha256_hex(&bytes)),
        bytes,
    })
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("String writes cannot fail");
    }
    encoded
}

pub fn document_csv(document: &StatisticsDocument) -> Result<Vec<u8>, StatisticsError> {
    validate_document(document)?;
    let period_by_code: BTreeMap<&str, &PeriodDocument> = document
        .periods
        .iter()
        .map(|period| (period.code.as_str(), period))
        .collect();
    let mut output = Vec::new();
    let mut header = vec![
        "period".to_owned(),
        "periodStart".to_owned(),
        "periodEnd".to_owned(),
    ];
    header.extend(
        document
            .dimensions
            .iter()
            .map(|dimension| dimension.field.clone()),
    );
    header.extend([
        "measure".to_owned(),
        "value".to_owned(),
        "status".to_owned(),
    ]);
    write_csv_row(&mut output, &header);
    for cell in &document.cells {
        let period =
            period_by_code
                .get(cell.period.as_str())
                .ok_or(StatisticsError::InvalidDocument(
                    "a cell names a period outside the document",
                ))?;
        let mut row = vec![
            cell.period.clone(),
            period.start.clone(),
            period.end.clone(),
        ];
        for dimension in &document.dimensions {
            row.push(
                cell.dimensions
                    .get(&dimension.field)
                    .ok_or(StatisticsError::InvalidDocument(
                        "a cell omits a declared dimension",
                    ))?
                    .clone(),
            );
        }
        row.push(cell.measure.clone());
        row.push(match &cell.value {
            Some(CellValue::Count(count)) => count.to_string(),
            Some(CellValue::Decimal(decimal)) => decimal.clone(),
            None => String::new(),
        });
        row.push(
            match cell.status {
                CellStatus::Exact => "exact",
                CellStatus::Suppressed => "suppressed",
                CellStatus::Rounded => "rounded",
                CellStatus::NotApplicable => "not-applicable",
            }
            .to_owned(),
        );
        write_csv_row(&mut output, &row);
    }
    Ok(output)
}

fn parse_period_bounds(
    granularity: PeriodGranularity,
    code: &str,
) -> Result<(String, NaiveDate, NaiveDate), StatisticsError> {
    let invalid = || invalid_period(granularity, code);
    // Query values are untrusted UTF-8. Admit the closed ASCII grammar before
    // slicing, and keep every period and its exclusive end in the wire's
    // four-digit calendar-year domain.
    if code.len() < 4
        || !code
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'-' | b'Q'))
        || parse_year(&code[..4]).is_none()
    {
        return Err(invalid());
    }
    let (start, end) = match granularity {
        PeriodGranularity::Day => {
            if code.len() != 10 || code.as_bytes()[4] != b'-' || code.as_bytes()[7] != b'-' {
                return Err(invalid());
            }
            let start = NaiveDate::parse_from_str(code, "%Y-%m-%d").map_err(|_| invalid())?;
            let end = start
                .checked_add_signed(Duration::days(1))
                .ok_or_else(invalid)?;
            (start, end)
        }
        PeriodGranularity::Month => {
            if code.len() != 7 || code.as_bytes().get(4) != Some(&b'-') {
                return Err(invalid());
            }
            let year = parse_year(&code[..4]).ok_or_else(invalid)?;
            let month = code[5..]
                .parse::<u32>()
                .ok()
                .filter(|month| (1..=12).contains(month))
                .ok_or_else(invalid)?;
            let start = NaiveDate::from_ymd_opt(year, month, 1).ok_or_else(invalid)?;
            let (next_year, next_month) = if month == 12 {
                (year.checked_add(1).ok_or_else(invalid)?, 1)
            } else {
                (year, month + 1)
            };
            let end = NaiveDate::from_ymd_opt(next_year, next_month, 1).ok_or_else(invalid)?;
            (start, end)
        }
        PeriodGranularity::Quarter => {
            if code.len() != 7 || &code[4..6] != "-Q" {
                return Err(invalid());
            }
            let year = parse_year(&code[..4]).ok_or_else(invalid)?;
            let quarter = code[6..]
                .parse::<u32>()
                .ok()
                .filter(|quarter| (1..=4).contains(quarter))
                .ok_or_else(invalid)?;
            let month = (quarter - 1) * 3 + 1;
            let start = NaiveDate::from_ymd_opt(year, month, 1).ok_or_else(invalid)?;
            let (next_year, next_month) = if quarter == 4 {
                (year.checked_add(1).ok_or_else(invalid)?, 1)
            } else {
                (year, month + 3)
            };
            let end = NaiveDate::from_ymd_opt(next_year, next_month, 1).ok_or_else(invalid)?;
            (start, end)
        }
        PeriodGranularity::Year => {
            if code.len() != 4 {
                return Err(invalid());
            }
            let year = parse_year(code).ok_or_else(invalid)?;
            let start = NaiveDate::from_ymd_opt(year, 1, 1).ok_or_else(invalid)?;
            let end = NaiveDate::from_ymd_opt(year.checked_add(1).ok_or_else(invalid)?, 1, 1)
                .ok_or_else(invalid)?;
            (start, end)
        }
    };
    if end.year() > 9999 {
        return Err(invalid());
    }
    Ok((code.to_owned(), start, end))
}

fn parse_year(value: &str) -> Option<i32> {
    (value.len() == 4 && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse::<i32>().ok())
        .flatten()
        .filter(|year| *year >= 1)
}

fn code_for_start(granularity: PeriodGranularity, start: NaiveDate) -> String {
    match granularity {
        PeriodGranularity::Day => start.format("%Y-%m-%d").to_string(),
        PeriodGranularity::Month => start.format("%Y-%m").to_string(),
        PeriodGranularity::Quarter => format!("{:04}-Q{}", start.year(), start.month0() / 3 + 1),
        PeriodGranularity::Year => format!("{:04}", start.year()),
    }
}

fn invalid_period(granularity: PeriodGranularity, code: &str) -> StatisticsError {
    StatisticsError::InvalidPeriodCode {
        granularity,
        code: code.to_owned(),
    }
}

fn validate_dimensions(dimensions: &[DimensionDomain]) -> Result<(), StatisticsError> {
    let mut fields = BTreeSet::new();
    for dimension in dimensions {
        let codes: BTreeSet<&str> = dimension.codes.iter().map(String::as_str).collect();
        if dimension.field.is_empty()
            || !fields.insert(dimension.field.as_str())
            || dimension.codes.is_empty()
            || codes.len() != dimension.codes.len()
            || codes.contains(TOTAL_CODE)
            || codes.contains(UNKNOWN_CODE)
            || dimension.codes.iter().any(|code| code.starts_with('_'))
        {
            return Err(StatisticsError::InvalidDimensionDomain {
                dimension: dimension.field.clone(),
            });
        }
    }
    Ok(())
}

fn validate_measures(measures: &[Measure]) -> Result<(), StatisticsError> {
    let ids: BTreeSet<&str> = measures.iter().map(Measure::id).collect();
    if measures.is_empty() || ids.len() != measures.len() || ids.contains("") {
        return Err(StatisticsError::InvalidDocument(
            "measures must be a non-empty list of unique ids",
        ));
    }
    Ok(())
}

fn checked_product(lengths: impl IntoIterator<Item = usize>) -> Result<usize, StatisticsError> {
    let product = lengths
        .into_iter()
        .try_fold(1_usize, usize::checked_mul)
        .ok_or(StatisticsError::TooManyCells)?;
    if product > MAX_CELLS_PER_RESPONSE {
        Err(StatisticsError::TooManyCells)
    } else {
        Ok(product)
    }
}

fn for_each_combination(domains: &[Vec<String>], mut visit: impl FnMut(Vec<String>)) {
    fn recurse(
        domains: &[Vec<String>],
        index: usize,
        current: &mut Vec<String>,
        visit: &mut dyn FnMut(Vec<String>),
    ) {
        if index == domains.len() {
            visit(current.clone());
            return;
        }
        for code in &domains[index] {
            current.push(code.clone());
            recurse(domains, index + 1, current, visit);
            current.pop();
        }
    }
    recurse(
        domains,
        0,
        &mut Vec::with_capacity(domains.len()),
        &mut visit,
    );
}

/// Every count total must equal the sum of the cells it totals along each total
/// position. The database computes the totals; this guards against a wrong grouping.
fn check_totals(
    dataset: &str,
    periods: &[Period],
    base_codes: &[Vec<String>],
    output_codes: &[Vec<String>],
    values: &BTreeMap<(String, Vec<String>), u64>,
) -> Result<(), StatisticsError> {
    let mut failure = None;
    for period in periods {
        for_each_combination(output_codes, |codes| {
            if failure.is_some() {
                return;
            }
            for (index, code) in codes.iter().enumerate() {
                if code != TOTAL_CODE {
                    continue;
                }
                let mut sum = 0_u64;
                for base in &base_codes[index] {
                    let mut part = codes.clone();
                    part[index].clone_from(base);
                    let value = values
                        .get(&(period.code.clone(), part))
                        .copied()
                        .unwrap_or(0);
                    let Some(next) = sum.checked_add(value) else {
                        failure = Some(StatisticsError::CountOverflow);
                        return;
                    };
                    sum = next;
                }
                let total = values
                    .get(&(period.code.clone(), codes.clone()))
                    .copied()
                    .unwrap_or(0);
                if sum != total {
                    failure = Some(StatisticsError::InconsistentTotal {
                        dataset: dataset.to_owned(),
                    });
                    return;
                }
            }
        });
    }
    failure.map_or(Ok(()), Err)
}

fn round_halves_up(value: u64, base: u64) -> Result<u64, StatisticsError> {
    let quotient = value / base;
    let remainder = value % base;
    let halfway = base / 2 + base % 2;
    let rounded = if remainder >= halfway {
        quotient
            .checked_add(1)
            .ok_or(StatisticsError::CountOverflow)?
    } else {
        quotient
    };
    rounded
        .checked_mul(base)
        .ok_or(StatisticsError::CountOverflow)
}

fn validate_document(document: &StatisticsDocument) -> Result<(), StatisticsError> {
    if document.periods.is_empty() {
        return Err(StatisticsError::InvalidDocument(
            "periods must not be empty",
        ));
    }
    if document.periods.len() > MAX_PERIODS_PER_READ {
        return Err(StatisticsError::TooManyPeriods);
    }
    if document.cells.len() > MAX_CELLS_PER_RESPONSE {
        return Err(StatisticsError::TooManyCells);
    }
    let metadata = [
        document.release.is_some(),
        document.live.is_some(),
        document.exact.is_some(),
    ];
    if metadata.into_iter().filter(|present| *present).count() > 1 {
        return Err(StatisticsError::InvalidDocument(
            "release, live, and exact metadata are mutually exclusive",
        ));
    }
    if document.exact.is_some() && document.disclosure.is_some() {
        return Err(StatisticsError::InvalidDocument(
            "an exact document carries no disclosure method",
        ));
    }
    if let Some(release) = &document.release {
        if release.version == 0 {
            return Err(StatisticsError::InvalidDocument(
                "release.version must be allocated before canonicalization",
            ));
        }
        if document.periods.len() != 1 || document.periods[0].code != release.period {
            return Err(StatisticsError::InvalidDocument(
                "a release document must contain its one release period",
            ));
        }
        if document.disclosure.is_none() {
            return Err(StatisticsError::InvalidDocument(
                "a release document must state its disclosure method",
            ));
        }
    }
    let period_codes: BTreeSet<&str> = document
        .periods
        .iter()
        .map(|period| period.code.as_str())
        .collect();
    let fields: BTreeSet<&str> = document
        .dimensions
        .iter()
        .map(|dimension| dimension.field.as_str())
        .collect();
    if fields.len() != document.dimensions.len() {
        return Err(StatisticsError::InvalidDocument(
            "dimension field ids must be unique",
        ));
    }
    validate_measures(&document.dataset.measures)?;
    let measures: BTreeMap<&str, &Measure> = document
        .dataset
        .measures
        .iter()
        .map(|measure| (measure.id(), measure))
        .collect();
    if matches!(
        document.disclosure,
        Some(DisclosureDocument::MinimumCountAndRounding { .. })
    ) && document
        .dataset
        .measures
        .iter()
        .any(|measure| !measure.is_count_like())
    {
        return Err(StatisticsError::InvalidDocument(
            "a minimum-count-and-rounding release carries counts and distinct counts only",
        ));
    }
    let mut seen_cells = BTreeSet::new();
    for cell in &document.cells {
        if document.exact.is_some()
            && matches!(cell.status, CellStatus::Suppressed | CellStatus::Rounded)
        {
            return Err(StatisticsError::InvalidDocument(
                "an exact document carries no suppressed or rounded cell",
            ));
        }
        match (&document.disclosure, cell.status) {
            (
                Some(DisclosureDocument::ExactPublicValues),
                CellStatus::Suppressed | CellStatus::Rounded,
            ) => {
                return Err(StatisticsError::InvalidDocument(
                    "an exact-public-values release carries no suppressed or rounded cell",
                ))
            }
            (
                Some(DisclosureDocument::MinimumCountAndRounding { .. }),
                CellStatus::NotApplicable,
            ) => {
                return Err(StatisticsError::InvalidDocument(
                    "a minimum-count-and-rounding release carries no not-applicable cell",
                ))
            }
            _ => {}
        }
        if !period_codes.contains(cell.period.as_str()) {
            return Err(StatisticsError::InvalidDocument(
                "a cell names a period outside the document",
            ));
        }
        if cell.dimensions.len() != document.dimensions.len()
            || !cell
                .dimensions
                .keys()
                .all(|field| fields.contains(field.as_str()))
        {
            return Err(StatisticsError::InvalidDocument(
                "each cell must carry exactly the declared dimensions",
            ));
        }
        let Some(measure) = measures.get(cell.measure.as_str()) else {
            return Err(StatisticsError::InvalidDocument(
                "a cell names a measure the dataset does not declare",
            ));
        };
        if !seen_cells.insert((&cell.period, &cell.dimensions, &cell.measure)) {
            return Err(StatisticsError::InvalidDocument(
                "a period, dimension combination, and measure appears more than once",
            ));
        }
        match (cell.status, &cell.value) {
            (CellStatus::Suppressed | CellStatus::NotApplicable, None)
            | (CellStatus::Exact | CellStatus::Rounded, Some(_)) => {}
            _ => {
                return Err(StatisticsError::InvalidDocument(
                    "cell value and status disagree",
                ))
            }
        }
        // A suppressed cell withholds a value its measure would admit; any other
        // cell carries one the measure admits, and only a mean admits none.
        if cell.status != CellStatus::Suppressed && !measure.admits(&cell.value) {
            return Err(StatisticsError::InvalidDocument(
                "a cell value does not fit its measure's type and scale",
            ));
        }
    }
    Ok(())
}

fn write_csv_row(output: &mut Vec<u8>, fields: &[String]) {
    for (index, field) in fields.iter().enumerate() {
        if index != 0 {
            output.push(b',');
        }
        let quote = field
            .as_bytes()
            .iter()
            .any(|byte| matches!(byte, b',' | b'"' | b'\r' | b'\n'));
        if quote {
            output.push(b'"');
            for byte in field.as_bytes() {
                if *byte == b'"' {
                    output.extend_from_slice(b"\"\"");
                } else {
                    output.push(*byte);
                }
            }
            output.push(b'"');
        } else {
            output.extend_from_slice(field.as_bytes());
        }
    }
    output.extend_from_slice(b"\r\n");
}
