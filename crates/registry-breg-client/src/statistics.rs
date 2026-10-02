// SPDX-License-Identifier: Apache-2.0
//! Bounded statistical-dataset exchanges.

use reqwest::StatusCode;
use serde::Serialize;

use crate::client::{access_profile_query, validate_breg_identifier};
use crate::{
    BRegComplete, BRegIdempotencyKey, BRegRawDocument, BaseRegistryClient, BaseRegistryClientError,
};

pub const STATISTICS_JSON_MEDIA_TYPE: &str = "application/json";
pub const STATISTICS_CSV_MEDIA_TYPE: &str = "text/csv";
const MAX_PERIOD_CODE_BYTES: usize = 10;
const MAX_SKIP_TOKEN_BYTES: usize = 2_048;
const MAX_RELEASE_PAGE_SIZE: u16 = 1_000;

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

impl BRegReleaseSelection {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::Final => "final",
        }
    }
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
        if version == 0 {
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
        pairs.push(("status".to_owned(), selection.as_str().to_owned()));
        pairs.extend(access_profile_query(access_profile)?);
        self.statistics_get_raw(
            &["v1", "statistics", dataset, "releases:series"],
            &pairs,
            format.media_type(),
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
        if version == 0 {
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
    match (from, to) {
        (None, None) => Ok(Vec::new()),
        (Some(from), Some(to)) => {
            validate_period(from)?;
            validate_period(to)?;
            Ok(vec![
                ("from".to_owned(), from.to_owned()),
                ("to".to_owned(), to.to_owned()),
            ])
        }
        _ => Err(invalid("statistics period ranges require both from and to")),
    }
}

fn validate_dataset(dataset: &str) -> Result<(), BaseRegistryClientError> {
    validate_breg_identifier(dataset, "the statistical dataset identifier is invalid")
}

fn validate_period(period: &str) -> Result<(), BaseRegistryClientError> {
    let bytes = period.as_bytes();
    if bytes.len() < 4
        || bytes.len() > MAX_PERIOD_CODE_BYTES
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'-' | b'Q'))
    {
        return Err(invalid("the statistics period code is invalid"));
    }
    Ok(())
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
