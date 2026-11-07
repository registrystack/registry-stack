// SPDX-License-Identifier: Apache-2.0

use std::fmt;

/// Why a metric could not be declared, recorded, or written.
///
/// Variants name code-defined metric and label names, never label values, so
/// a refusal can be logged without leaking what a caller supplied.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetricsError {
    /// A metric name outside `[a-zA-Z_:][a-zA-Z0-9_:]*`.
    InvalidMetricName(String),
    /// A label name outside `[a-zA-Z_][a-zA-Z0-9_]*`.
    InvalidLabelName(String),
    /// A label name the exposition format reserves (`__` prefix, or `le` on a
    /// histogram).
    ReservedLabelName(String),
    /// The same label name twice in one label set.
    DuplicateLabelName(String),
    /// Histogram bounds that are empty, non-finite, or not strictly
    /// increasing, or a snapshot that does not match its bounds.
    InvalidHistogram,
    /// A series limit of zero or above [`MAX_SERIES_LIMIT`](crate::MAX_SERIES_LIMIT).
    InvalidSeriesLimit,
    /// A closed label space that declares the same series twice.
    DuplicateSeries,
    /// A number of label values that differs from the declared label names.
    LabelCount { expected: usize, actual: usize },
    /// A label value longer than [`MAX_LABEL_VALUE_BYTES`](crate::MAX_LABEL_VALUE_BYTES).
    LabelValueTooLong { max: usize },
    /// A series outside a closed label space.
    UnknownSeries,
    /// A new series past a bounded label space's limit.
    SeriesLimit { max: usize },
    /// A histogram observation that is NaN or infinite.
    NonFiniteObservation,
}

impl fmt::Display for MetricsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidMetricName(name) => write!(f, "invalid metric name {name:?}"),
            Self::InvalidLabelName(name) => write!(f, "invalid label name {name:?}"),
            Self::ReservedLabelName(name) => write!(f, "reserved label name {name:?}"),
            Self::DuplicateLabelName(name) => write!(f, "duplicate label name {name:?}"),
            Self::InvalidHistogram => f.write_str("invalid histogram bounds or snapshot"),
            Self::InvalidSeriesLimit => f.write_str("series limit out of range"),
            Self::DuplicateSeries => f.write_str("duplicate declared series"),
            Self::LabelCount { expected, actual } => {
                write!(f, "expected {expected} label values, got {actual}")
            }
            Self::LabelValueTooLong { max } => {
                write!(f, "label value longer than {max} bytes")
            }
            Self::UnknownSeries => f.write_str("series is outside the closed label space"),
            Self::SeriesLimit { max } => write!(f, "series limit of {max} reached"),
            Self::NonFiniteObservation => f.write_str("histogram observation is not finite"),
        }
    }
}

impl std::error::Error for MetricsError {}
