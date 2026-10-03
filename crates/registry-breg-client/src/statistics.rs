// SPDX-License-Identifier: Apache-2.0
//! Bounded statistical-dataset exchanges.

use reqwest::StatusCode;
use serde::Serialize;
use time::{Date, Month};

use crate::client::{access_profile_query, validate_breg_identifier};
use crate::{
    BRegComplete, BRegIdempotencyKey, BRegRawDocument, BaseRegistryClient, BaseRegistryClientError,
};

pub const STATISTICS_JSON_MEDIA_TYPE: &str = "application/json";
pub const STATISTICS_CSV_MEDIA_TYPE: &str = "text/csv";
const MAX_PERIOD_CODE_BYTES: usize = 10;
// CursorCodec emits base64url without padding over one version byte, a 24-byte
// nonce, at most 8 KiB of plaintext, and a 16-byte authentication tag.
const MAX_SKIP_TOKEN_BYTES: usize = ((1_usize + 24 + 8 * 1024 + 16) * 4).div_ceil(3);
const MAX_RELEASE_PAGE_SIZE: u16 = 100;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum BRegStatisticsFormat {
    #[default]
    Json,
    Csv,
}

impl BRegStatisticsFormat {
    #[must_use]
    pub const fn media_type(self) -> &'static str {
        match self {
            Self::Json => STATISTICS_JSON_MEDIA_TYPE,
            Self::Csv => STATISTICS_CSV_MEDIA_TYPE,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BRegReleaseStatus {
    Provisional,
    Final,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BRegReleaseSelection {
    Any,
    Final,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum BRegWithdrawalReason {
    ComputationError,
    SourceDataError,
    DisclosureRisk,
}

#[derive(Serialize)]
struct PublishBody {
    status: BRegReleaseStatus,
}

#[derive(Serialize)]
struct WithdrawalBody {
    reason: BRegWithdrawalReason,
}

impl BaseRegistryClient {
    /// Read one bounded live statistical document as JSON or CSV.
    pub async fn statistics_live(
        &self,
        dataset: &str,
        from: Option<&str>,
        to: Option<&str>,
        access_profile: Option<&str>,
        format: BRegStatisticsFormat,
    ) -> Result<BRegComplete<BRegRawDocument>, BaseRegistryClientError> {
        validate_dataset(dataset)?;
        let mut pairs = range_query(from, to)?;
        pairs.extend(access_profile_query(access_profile)?);
        self.statistics_get_raw(
            &["v1", "statistics", &format!("{dataset}:live")],
            &pairs,
            format.media_type(),
            true,
        )
        .await
    }

    /// List one caller-chosen page of release version headers.
    pub async fn statistics_releases(
        &self,
        dataset: &str,
        top: Option<u16>,
        skip_token: Option<&str>,
        access_profile: Option<&str>,
    ) -> Result<BRegComplete<BRegRawDocument>, BaseRegistryClientError> {
        validate_dataset(dataset)?;
        let mut pairs = Vec::new();
        if let Some(top) = top {
            if top == 0 || top > MAX_RELEASE_PAGE_SIZE {
                return Err(invalid("the statistics release page size is invalid"));
            }
            pairs.push(("$top".to_owned(), top.to_string()));
        }
        if let Some(token) = skip_token {
            validate_skip_token(token)?;
            pairs.push(("$skiptoken".to_owned(), token.to_owned()));
        }
        pairs.extend(access_profile_query(access_profile)?);
        self.statistics_get_raw(
            &["v1", "statistics", dataset, "releases"],
            &pairs,
            STATISTICS_JSON_MEDIA_TYPE,
            false,
        )
        .await
    }

    /// Read the latest release, or latest final release, for one period.
    pub async fn statistics_latest_release(
        &self,
        dataset: &str,
        period: &str,
        selection: BRegReleaseSelection,
        access_profile: Option<&str>,
        format: BRegStatisticsFormat,
    ) -> Result<BRegComplete<BRegRawDocument>, BaseRegistryClientError> {
        validate_dataset(dataset)?;
        validate_period(period)?;
        let mut pairs = Vec::new();
        if selection == BRegReleaseSelection::Final {
            pairs.push(("status".to_owned(), "final".to_owned()));
        }
        pairs.extend(access_profile_query(access_profile)?);
        self.statistics_get_raw(
            &["v1", "statistics", dataset, "releases", period],
            &pairs,
            format.media_type(),
            true,
        )
        .await
    }

    /// Read one exact immutable release version.
    pub async fn statistics_release_version(
        &self,
        dataset: &str,
        period: &str,
        version: u64,
        access_profile: Option<&str>,
        format: BRegStatisticsFormat,
    ) -> Result<BRegComplete<BRegRawDocument>, BaseRegistryClientError> {
        validate_dataset(dataset)?;
        validate_period(period)?;
        if version == 0 || version > i64::MAX as u64 {
            return Err(invalid("the statistics release version is invalid"));
        }
        let pairs = access_profile_query(access_profile)?;
        self.statistics_get_raw(
            &[
                "v1",
                "statistics",
                dataset,
                "releases",
                period,
                "versions",
                &version.to_string(),
            ],
            &pairs,
            format.media_type(),
            true,
        )
        .await
    }

    /// Read the latest selected release for each period in a bounded range.
    pub async fn statistics_release_series(
        &self,
        dataset: &str,
        from: &str,
        to: &str,
        selection: BRegReleaseSelection,
        access_profile: Option<&str>,
        format: BRegStatisticsFormat,
    ) -> Result<BRegComplete<BRegRawDocument>, BaseRegistryClientError> {
        validate_dataset(dataset)?;
        let mut pairs = range_query(Some(from), Some(to))?;
        if selection == BRegReleaseSelection::Final {
            pairs.push(("status".to_owned(), "final".to_owned()));
        }
        pairs.extend(access_profile_query(access_profile)?);
        self.statistics_get_raw(
            &["v1", "statistics", dataset, "releases:series"],
            &pairs,
            format.media_type(),
            true,
        )
        .await
    }

    /// Explicitly compute and persist one release version. The client never retries.
    pub async fn statistics_publish(
        &self,
        dataset: &str,
        period: &str,
        status: BRegReleaseStatus,
        access_profile: &str,
        idempotency_key: &BRegIdempotencyKey,
    ) -> Result<BRegComplete<BRegRawDocument>, BaseRegistryClientError> {
        validate_dataset(dataset)?;
        validate_period(period)?;
        let pairs = access_profile_query(Some(access_profile))?;
        let body = serde_json::to_vec(&PublishBody { status })
            .map_err(|_| invalid("the statistics publish request is invalid"))?;
        self.statistics_post_json(
            &["v1", "statistics", dataset, "releases", period, "versions"],
            &pairs,
            body,
            idempotency_key,
            StatusCode::CREATED,
        )
        .await
    }

    /// Withdraw one version with a closed reason code. The client never retries.
    pub async fn statistics_withdraw(
        &self,
        dataset: &str,
        period: &str,
        version: u64,
        reason: BRegWithdrawalReason,
        access_profile: &str,
        idempotency_key: &BRegIdempotencyKey,
    ) -> Result<BRegComplete<BRegRawDocument>, BaseRegistryClientError> {
        validate_dataset(dataset)?;
        validate_period(period)?;
        if version == 0 || version > i64::MAX as u64 {
            return Err(invalid("the statistics release version is invalid"));
        }
        let pairs = access_profile_query(Some(access_profile))?;
        let body = serde_json::to_vec(&WithdrawalBody { reason })
            .map_err(|_| invalid("the statistics withdrawal request is invalid"))?;
        self.statistics_post_json(
            &[
                "v1",
                "statistics",
                dataset,
                "releases",
                period,
                "versions",
                &version.to_string(),
                "withdrawal",
            ],
            &pairs,
            body,
            idempotency_key,
            StatusCode::OK,
        )
        .await
    }
}

fn range_query(
    from: Option<&str>,
    to: Option<&str>,
) -> Result<Vec<(String, String)>, BaseRegistryClientError> {
    let mut pairs = Vec::with_capacity(2);
    if let Some(from) = from {
        validate_period(from)?;
        pairs.push(("from".to_owned(), from.to_owned()));
    }
    if let Some(to) = to {
        validate_period(to)?;
        pairs.push(("to".to_owned(), to.to_owned()));
    }
    Ok(pairs)
}

fn validate_dataset(dataset: &str) -> Result<(), BaseRegistryClientError> {
    validate_breg_identifier(dataset, "the statistical dataset identifier is invalid")
}

fn validate_period(period: &str) -> Result<(), BaseRegistryClientError> {
    let bytes = period.as_bytes();
    let valid = bytes.len() <= MAX_PERIOD_CODE_BYTES
        && parse_ascii_decimal(bytes.get(..4).unwrap_or_default())
            .filter(|year| (1..=9999).contains(year))
            .is_some_and(|year| match bytes.len() {
                4 => year < 9999,
                7 if bytes[4] == b'-' && bytes[5] == b'Q' => parse_ascii_decimal(&bytes[6..])
                    .filter(|quarter| (1..=4).contains(quarter))
                    .is_some_and(|quarter| year < 9999 || quarter < 4),
                7 if bytes[4] == b'-' => parse_ascii_decimal(&bytes[5..])
                    .filter(|month| (1..=12).contains(month))
                    .is_some_and(|month| year < 9999 || month < 12),
                10 if bytes[4] == b'-' && bytes[7] == b'-' => {
                    let month = parse_ascii_decimal(&bytes[5..7])
                        .and_then(|month| u8::try_from(month).ok())
                        .and_then(|month| Month::try_from(month).ok());
                    let day =
                        parse_ascii_decimal(&bytes[8..]).and_then(|day| u8::try_from(day).ok());
                    match (month, day) {
                        (Some(month), Some(day)) => {
                            Date::from_calendar_date(year as i32, month, day).is_ok()
                                && !(year == 9999 && month == Month::December && day == 31)
                        }
                        _ => false,
                    }
                }
                _ => false,
            });
    if !valid {
        return Err(invalid("the statistics period code is invalid"));
    }
    Ok(())
}

fn parse_ascii_decimal(bytes: &[u8]) -> Option<u32> {
    (!bytes.is_empty() && bytes.iter().all(u8::is_ascii_digit)).then(|| {
        bytes
            .iter()
            .fold(0_u32, |value, byte| value * 10 + u32::from(byte - b'0'))
    })
}

fn validate_skip_token(token: &str) -> Result<(), BaseRegistryClientError> {
    if token.is_empty() || token.len() > MAX_SKIP_TOKEN_BYTES || token.chars().any(char::is_control)
    {
        return Err(invalid("the statistics release continuation is invalid"));
    }
    Ok(())
}

fn invalid(reason: &'static str) -> BaseRegistryClientError {
    BaseRegistryClientError::invalid_request(reason)
}
