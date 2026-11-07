// SPDX-License-Identifier: Apache-2.0

use std::fmt::Write as _;

use crate::error::MetricsError;

/// The `# TYPE` of a metric family.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetricKind {
    Counter,
    Gauge,
    Histogram,
}

impl MetricKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Counter => "counter",
            Self::Gauge => "gauge",
            Self::Histogram => "histogram",
        }
    }
}

/// A sample value. Integers print as integers; floats print in Rust's
/// shortest round-trip decimal form with no exponent, and the non-finite
/// values print as `NaN`, `+Inf`, and `-Inf`.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Value {
    Unsigned(u64),
    Signed(i64),
    Float(f64),
}

macro_rules! value_from {
    ($variant:ident, $wide:ty, $($narrow:ty),+) => {
        $(impl From<$narrow> for Value {
            fn from(value: $narrow) -> Self {
                Self::$variant(<$wide>::from(value))
            }
        })+
    };
}
value_from!(Unsigned, u64, u8, u16, u32, u64);
value_from!(Signed, i64, i8, i16, i32, i64);

impl From<usize> for Value {
    fn from(value: usize) -> Self {
        Self::Unsigned(u64::try_from(value).unwrap_or(u64::MAX))
    }
}

impl From<f64> for Value {
    fn from(value: f64) -> Self {
        Self::Float(value)
    }
}

fn write_float(out: &mut String, value: f64) {
    if value.is_nan() {
        out.push_str("NaN");
    } else if value == f64::INFINITY {
        out.push_str("+Inf");
    } else if value == f64::NEG_INFINITY {
        out.push_str("-Inf");
    } else {
        // Display never uses an exponent for f64 and prints the shortest
        // decimal that round-trips, which is the form the exposition accepts.
        let _ = write!(out, "{value}");
    }
}

impl Value {
    fn write(self, out: &mut String) {
        match self {
            Self::Unsigned(value) => {
                let _ = write!(out, "{value}");
            }
            Self::Signed(value) => {
                let _ = write!(out, "{value}");
            }
            Self::Float(value) => write_float(out, value),
        }
    }
}

/// The order a histogram writes its `_sum` and `_count` lines. The format
/// accepts either; the choice exists so an adopting product keeps its scrape
/// bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SumCountOrder {
    SumThenCount,
    CountThenSum,
}

/// One histogram series' state: cumulative bucket counts aligned with the
/// bounds, the total observation count, and the sum of observations.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct HistogramSnapshot {
    pub cumulative: Vec<u64>,
    pub count: u64,
    pub sum: f64,
}

fn valid_metric_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_' || first == b':')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b':')
}

pub(crate) fn check_label_name(name: &str) -> Result<(), MetricsError> {
    let mut bytes = name.bytes();
    let valid = bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if !valid {
        return Err(MetricsError::InvalidLabelName(name.to_owned()));
    }
    if name.starts_with("__") {
        return Err(MetricsError::ReservedLabelName(name.to_owned()));
    }
    Ok(())
}

fn check_metric_name(name: &str) -> Result<(), MetricsError> {
    if valid_metric_name(name) {
        Ok(())
    } else {
        Err(MetricsError::InvalidMetricName(name.to_owned()))
    }
}

fn check_labels(labels: &[(&str, &str)]) -> Result<(), MetricsError> {
    for (index, (name, _)) in labels.iter().enumerate() {
        check_label_name(name)?;
        if labels[..index].iter().any(|(earlier, _)| earlier == name) {
            return Err(MetricsError::DuplicateLabelName((*name).to_owned()));
        }
    }
    Ok(())
}

fn escape_into(out: &mut String, text: &str, quote: bool) {
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '"' if quote => out.push_str("\\\""),
            other => out.push(other),
        }
    }
}

/// Write `{name="value",...}` into `out`, with `extra` appended as a final
/// unescaped-value label (the histogram `le`). Writes nothing for an empty
/// label set.
fn write_labels(out: &mut String, labels: &[(&str, &str)], le: Option<&str>) {
    if labels.is_empty() && le.is_none() {
        return;
    }
    out.push('{');
    let mut first = true;
    for (name, value) in labels {
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str(name);
        out.push_str("=\"");
        escape_into(out, value, true);
        out.push('"');
    }
    if let Some(le) = le {
        if !first {
            out.push(',');
        }
        out.push_str("le=\"");
        out.push_str(le);
        out.push('"');
    }
    out.push('}');
}

/// An in-progress Prometheus text exposition (format 0.0.4).
///
/// The writer validates names and escapes label values, then writes exactly
/// what it is told, in the order it is told. It does not regroup samples by
/// family, so a caller can keep a scrape byte-stable; call [`Exposition::header`]
/// before the family's samples to produce the grouped form the format
/// recommends. A refused call writes nothing.
#[derive(Debug, Default)]
pub struct Exposition {
    out: String,
}

impl Exposition {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The text written so far.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.out
    }

    /// The finished exposition. Every line, including the last, ends in a
    /// newline.
    #[must_use]
    pub fn finish(self) -> String {
        self.out
    }

    /// Write a family's `# HELP` (when given) and `# TYPE` lines. HELP text
    /// escapes backslash and newline.
    pub fn header(
        &mut self,
        name: &str,
        help: Option<&str>,
        kind: MetricKind,
    ) -> Result<(), MetricsError> {
        check_metric_name(name)?;
        if let Some(help) = help {
            self.out.push_str("# HELP ");
            self.out.push_str(name);
            self.out.push(' ');
            escape_into(&mut self.out, help, false);
            self.out.push('\n');
        }
        let _ = writeln!(self.out, "# TYPE {name} {}", kind.as_str());
        Ok(())
    }

    /// Write one sample line.
    pub fn sample(
        &mut self,
        name: &str,
        labels: &[(&str, &str)],
        value: impl Into<Value>,
    ) -> Result<(), MetricsError> {
        check_metric_name(name)?;
        check_labels(labels)?;
        self.out.push_str(name);
        write_labels(&mut self.out, labels, None);
        self.out.push(' ');
        value.into().write(&mut self.out);
        self.out.push('\n');
        Ok(())
    }

    /// Write one histogram series: a `_bucket` line per bound with the
    /// snapshot's cumulative count, the `+Inf` bucket (the total count), and
    /// the `_sum` and `_count` lines in `order`. Bounds print with the same
    /// float form as sample values (`1`, not `1.0`).
    pub fn histogram(
        &mut self,
        family: &str,
        labels: &[(&str, &str)],
        bounds: &[f64],
        snapshot: &HistogramSnapshot,
        order: SumCountOrder,
    ) -> Result<(), MetricsError> {
        check_metric_name(family)?;
        check_labels(labels)?;
        if labels.iter().any(|(name, _)| *name == "le") {
            return Err(MetricsError::ReservedLabelName("le".to_owned()));
        }
        check_bounds(bounds)?;
        if snapshot.cumulative.len() != bounds.len() {
            return Err(MetricsError::InvalidHistogram);
        }
        let mut bound_text = String::new();
        for (bound, count) in bounds.iter().zip(&snapshot.cumulative) {
            bound_text.clear();
            write_float(&mut bound_text, *bound);
            self.out.push_str(family);
            self.out.push_str("_bucket");
            write_labels(&mut self.out, labels, Some(&bound_text));
            let _ = writeln!(self.out, " {count}");
        }
        self.out.push_str(family);
        self.out.push_str("_bucket");
        write_labels(&mut self.out, labels, Some("+Inf"));
        let _ = writeln!(self.out, " {}", snapshot.count);
        let write_sum = |out: &mut String| {
            out.push_str(family);
            out.push_str("_sum");
            write_labels(out, labels, None);
            out.push(' ');
            write_float(out, snapshot.sum);
            out.push('\n');
        };
        let write_count = |out: &mut String| {
            out.push_str(family);
            out.push_str("_count");
            write_labels(out, labels, None);
            let _ = writeln!(out, " {}", snapshot.count);
        };
        match order {
            SumCountOrder::SumThenCount => {
                write_sum(&mut self.out);
                write_count(&mut self.out);
            }
            SumCountOrder::CountThenSum => {
                write_count(&mut self.out);
                write_sum(&mut self.out);
            }
        }
        Ok(())
    }
}

pub(crate) fn check_bounds(bounds: &[f64]) -> Result<(), MetricsError> {
    let ordered = bounds.windows(2).all(|pair| pair[0] < pair[1]);
    if bounds.is_empty() || !ordered || bounds.iter().any(|bound| !bound.is_finite()) {
        return Err(MetricsError::InvalidHistogram);
    }
    Ok(())
}
