// SPDX-License-Identifier: Apache-2.0
//! Pure statistical-dataset periods, aggregation, disclosure, and representations.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{Datelike, Duration, NaiveDate};
use registry_platform_canonical_json::canonicalize_json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisclosureParameters {
    pub minimum_count: u64,
    pub rounding_base: u64,
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
    pub value: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CellStatus {
    Exact,
    Suppressed,
    Rounded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cell {
    pub period: String,
    pub dimensions: BTreeMap<String, String>,
    pub value: Option<u64>,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Measure {
    Count,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatasetDocument {
    pub id: String,
    pub unit: String,
    pub measure: Measure,
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
    pub content_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawal: Option<WithdrawalDocument>,
}

impl From<&ReleaseVersionHeader> for PeriodVersionHeader {
    fn from(header: &ReleaseVersionHeader) -> Self {
        Self {
            version: header.version,
            status: header.status,
            content_digest: header.content_digest.clone(),
            snapshot: header.snapshot.clone(),
        }
    }
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DisclosureDocument {
    pub method: String,
    pub minimum_count: u64,
    pub rounding_base: u64,
    pub rounding_rule: String,
    pub totals: String,
}

impl From<DisclosureParameters> for DisclosureDocument {
    fn from(parameters: DisclosureParameters) -> Self {
        Self {
            method: "minimum-count-and-rounding".to_owned(),
            minimum_count: parameters.minimum_count,
            rounding_base: parameters.rounding_base,
            rounding_rule: "nearest-multiple-halves-up".to_owned(),
            totals: "rounded-independently".to_owned(),
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
    #[error("the statistical dataset has an invalid dimension domain for `{dimension}`")]
    InvalidDimensionDomain { dimension: String },
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
    grouped: &[GroupedCell],
) -> Result<Vec<Cell>, StatisticsError> {
    validate_dimensions(dimensions)?;
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
        .checked_mul(periods.len())
        .ok_or(StatisticsError::TooManyCells)?;
    if total_cells > MAX_CELLS_PER_RESPONSE {
        return Err(StatisticsError::TooManyCells);
    }

    let mut base = BTreeMap::<(String, Vec<String>), u64>::new();
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
            if !base_codes[index].contains(code) {
                return Err(StatisticsError::UnknownCode {
                    dataset: dataset.to_owned(),
                    dimension: dimensions[index].field.clone(),
                });
            }
        }
        if base
            .insert((row.period.clone(), row.codes.clone()), row.value)
            .is_some()
        {
            return Err(StatisticsError::DuplicateGroupedCell {
                dataset: dataset.to_owned(),
            });
        }
    }

    let mut values = BTreeMap::<(String, Vec<String>), u64>::new();
    for period in periods {
        for_each_combination(&base_codes, |codes| {
            let value = base
                .get(&(period.code.clone(), codes.clone()))
                .copied()
                .unwrap_or(0);
            // The closure cannot return an error; retain it and surface immediately below.
            values.insert((period.code.clone(), codes), value);
        });
    }
    let base_values = std::mem::take(&mut values);
    for ((period, codes), value) in base_values {
        add_base_and_margins(&mut values, &period, &codes, value)?;
    }

    let mut cells = Vec::with_capacity(total_cells);
    for period in periods {
        for_each_combination(&output_codes, |codes| {
            let dimensions_map = dimensions
                .iter()
                .zip(&codes)
                .map(|(dimension, code)| (dimension.field.clone(), code.clone()))
                .collect();
            cells.push(Cell {
                period: period.code.clone(),
                dimensions: dimensions_map,
                value: Some(
                    values
                        .get(&(period.code.clone(), codes))
                        .copied()
                        .unwrap_or(0),
                ),
                status: CellStatus::Exact,
            });
        });
    }
    Ok(cells)
}

pub fn apply_disclosure(
    cells: &mut [Cell],
    parameters: DisclosureParameters,
) -> Result<(), StatisticsError> {
    if parameters.minimum_count < 2 || parameters.rounding_base < 2 {
        return Err(StatisticsError::InvalidDisclosureParameters);
    }
    for cell in cells {
        let value = cell.value.ok_or(StatisticsError::InvalidDocument(
            "disclosure control requires exact input cells",
        ))?;
        if value == 0 {
            cell.status = CellStatus::Exact;
        } else if value < parameters.minimum_count {
            cell.value = None;
            cell.status = CellStatus::Suppressed;
        } else {
            cell.value = Some(round_halves_up(value, parameters.rounding_base)?);
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
    header.extend(["value".to_owned(), "status".to_owned()]);
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
        row.push(
            cell.value
                .map(|value| value.to_string())
                .unwrap_or_default(),
        );
        row.push(
            match cell.status {
                CellStatus::Exact => "exact",
                CellStatus::Suppressed => "suppressed",
                CellStatus::Rounded => "rounded",
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

fn add_base_and_margins(
    values: &mut BTreeMap<(String, Vec<String>), u64>,
    period: &str,
    codes: &[String],
    value: u64,
) -> Result<(), StatisticsError> {
    let shift = u32::try_from(codes.len()).map_err(|_| StatisticsError::TooManyCells)?;
    let variants = 1_usize
        .checked_shl(shift)
        .ok_or(StatisticsError::TooManyCells)?;
    for mask in 0..variants {
        let output_codes = codes
            .iter()
            .enumerate()
            .map(|(index, code)| {
                if mask & (1 << index) == 0 {
                    code.clone()
                } else {
                    TOTAL_CODE.to_owned()
                }
            })
            .collect::<Vec<_>>();
        let entry = values.entry((period.to_owned(), output_codes)).or_default();
        *entry = entry
            .checked_add(value)
            .ok_or(StatisticsError::CountOverflow)?;
    }
    Ok(())
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
    if document.release.is_some() && document.live.is_some() {
        return Err(StatisticsError::InvalidDocument(
            "release and live metadata are mutually exclusive",
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
    for cell in &document.cells {
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
        match (cell.status, cell.value) {
            (CellStatus::Suppressed, None) | (CellStatus::Exact | CellStatus::Rounded, Some(_)) => {
            }
            _ => {
                return Err(StatisticsError::InvalidDocument(
                    "cell value and status disagree",
                ))
            }
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
