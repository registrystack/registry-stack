// SPDX-License-Identifier: Apache-2.0
//! Prometheus text exposition (format 0.0.4) with bounded label cardinality.
//!
//! [`Exposition`] writes headers, samples, and histograms with validated names
//! and escaped label values. [`CounterVec`] and [`HistogramVec`] hold the
//! recorded state over a [`LabelSpace`] that refuses a series it does not
//! admit. Label values are caller-supplied closed vocabularies; nothing here
//! derives a label from a request, and refusals never repeat a label value.

mod error;
mod exposition;
mod sampling;
mod series;

pub use error::MetricsError;
pub use exposition::{Exposition, HistogramSnapshot, MetricKind, SumCountOrder, Value};
pub use sampling::{
    sample_error_class, ScrapeDeadline, CLASS_NO_TIME_LEFT, CLASS_POOL, CLASS_TIMEOUT,
    SCRAPE_BUDGET,
};
pub use series::{CounterVec, HistogramVec, LabelSpace, MAX_LABEL_VALUE_BYTES, MAX_SERIES_LIMIT};

/// The `Content-Type` of a text exposition scrape response.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4";
