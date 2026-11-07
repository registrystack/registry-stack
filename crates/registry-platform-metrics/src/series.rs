// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use crate::error::MetricsError;
use crate::exposition::{
    check_bounds, check_label_name, Exposition, HistogramSnapshot, MetricKind, SumCountOrder,
};

/// The most series a bounded label space may be configured to hold.
pub const MAX_SERIES_LIMIT: usize = 10_000;

/// The longest label value, in bytes, a recording call accepts.
pub const MAX_LABEL_VALUE_BYTES: usize = 256;

enum Shape {
    /// Every series is declared up front, in the order they render.
    Closed {
        declared: Vec<Vec<String>>,
        zero_filled: bool,
    },
    /// Series appear on first use, up to `max_series`, and render in sorted
    /// label-value order.
    Bounded { max_series: usize },
}

/// The fixed label names of a metric and the set of label-value combinations
/// it may hold. A combination outside the space is refused, never added, so
/// request-derived text cannot grow a registry.
pub struct LabelSpace {
    names: Vec<&'static str>,
    shape: Shape,
}

impl LabelSpace {
    fn names(names: &[&'static str]) -> Result<Vec<&'static str>, MetricsError> {
        for (index, name) in names.iter().enumerate() {
            check_label_name(name)?;
            if names[..index].contains(name) {
                return Err(MetricsError::DuplicateLabelName((*name).to_owned()));
            }
        }
        Ok(names.to_vec())
    }

    fn declare(
        names: &[&'static str],
        declared: &[&[&str]],
        zero_filled: bool,
    ) -> Result<Self, MetricsError> {
        let names = Self::names(names)?;
        let mut checked: Vec<Vec<String>> = Vec::with_capacity(declared.len());
        for values in declared {
            check_values(values, names.len())?;
            let values: Vec<String> = values.iter().map(|value| (*value).to_owned()).collect();
            if checked.contains(&values) {
                return Err(MetricsError::DuplicateSeries);
            }
            checked.push(values);
        }
        if checked.len() > MAX_SERIES_LIMIT {
            return Err(MetricsError::InvalidSeriesLimit);
        }
        Ok(Self {
            names,
            shape: Shape::Closed {
                declared: checked,
                zero_filled,
            },
        })
    }

    /// A closed space whose declared series render in the order given, and
    /// only once they have been recorded.
    pub fn closed(names: &[&'static str], declared: &[&[&str]]) -> Result<Self, MetricsError> {
        Self::declare(names, declared, false)
    }

    /// A closed space whose declared series all render from the first
    /// scrape, at zero, in the order given.
    pub fn closed_zero_filled(
        names: &[&'static str],
        declared: &[&[&str]],
    ) -> Result<Self, MetricsError> {
        Self::declare(names, declared, true)
    }

    /// A space that admits up to `max_series` combinations (1 through
    /// [`MAX_SERIES_LIMIT`]) and renders them in sorted label-value order.
    /// Use it only where the caller already maps request input onto a closed
    /// vocabulary, such as a route-template table; the limit is the backstop.
    pub fn bounded(names: &[&'static str], max_series: usize) -> Result<Self, MetricsError> {
        let names = Self::names(names)?;
        if max_series == 0 || max_series > MAX_SERIES_LIMIT {
            return Err(MetricsError::InvalidSeriesLimit);
        }
        Ok(Self {
            names,
            shape: Shape::Bounded { max_series },
        })
    }
}

fn check_values(values: &[&str], expected: usize) -> Result<(), MetricsError> {
    if values.len() != expected {
        return Err(MetricsError::LabelCount {
            expected,
            actual: values.len(),
        });
    }
    if values
        .iter()
        .any(|value| value.len() > MAX_LABEL_VALUE_BYTES)
    {
        return Err(MetricsError::LabelValueTooLong {
            max: MAX_LABEL_VALUE_BYTES,
        });
    }
    Ok(())
}

/// Series storage shared by the counter and histogram vectors.
struct Table<V> {
    names: Vec<&'static str>,
    shape: Shape,
    index: BTreeMap<Vec<String>, usize>,
    slots: Vec<V>,
    refused: u64,
}

impl<V: Default> Table<V> {
    fn new(space: LabelSpace) -> Self {
        let mut table = Self {
            names: space.names,
            shape: space.shape,
            index: BTreeMap::new(),
            slots: Vec::new(),
            refused: 0,
        };
        let preseed = match &table.shape {
            Shape::Closed {
                declared,
                zero_filled: true,
            } => declared.clone(),
            _ => Vec::new(),
        };
        for values in preseed {
            table.index.insert(values, table.slots.len());
            table.slots.push(V::default());
        }
        table
    }

    fn slot(&mut self, values: &[&str]) -> Result<&mut V, MetricsError> {
        let result = self.find_or_admit(values);
        match result {
            Ok(slot) => Ok(&mut self.slots[slot]),
            Err(error) => {
                self.refused = self.refused.saturating_add(1);
                Err(error)
            }
        }
    }

    fn find_or_admit(&mut self, values: &[&str]) -> Result<usize, MetricsError> {
        check_values(values, self.names.len())?;
        let key: Vec<String> = values.iter().map(|value| (*value).to_owned()).collect();
        if let Some(slot) = self.index.get(&key) {
            return Ok(*slot);
        }
        match &self.shape {
            Shape::Closed { declared, .. } => {
                if !declared.contains(&key) {
                    return Err(MetricsError::UnknownSeries);
                }
            }
            Shape::Bounded { max_series } => {
                if self.slots.len() >= *max_series {
                    return Err(MetricsError::SeriesLimit { max: *max_series });
                }
            }
        }
        let slot = self.slots.len();
        self.slots.push(V::default());
        self.index.insert(key, slot);
        Ok(slot)
    }

    fn find(&self, values: &[&str]) -> Option<&V> {
        let key: Vec<String> = values.iter().map(|value| (*value).to_owned()).collect();
        self.index.get(&key).map(|slot| &self.slots[*slot])
    }

    /// The recorded series in render order.
    fn ordered(&self) -> Vec<(&Vec<String>, &V)> {
        match &self.shape {
            Shape::Closed { declared, .. } => declared
                .iter()
                .filter_map(|key| self.index.get(key).map(|slot| (key, &self.slots[*slot])))
                .collect(),
            Shape::Bounded { .. } => self
                .index
                .iter()
                .map(|(key, slot)| (key, &self.slots[*slot]))
                .collect(),
        }
    }

    fn label_pairs<'a>(&self, values: &'a [String]) -> Vec<(&'static str, &'a str)> {
        self.names
            .iter()
            .copied()
            .zip(values.iter().map(String::as_str))
            .collect()
    }
}

/// The registry state is plain counters that a panic cannot leave
/// inconsistent, so a poisoned lock is recovered rather than propagated into
/// a scrape.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A counter family with a fixed label set, safe to share across threads.
pub struct CounterVec {
    name: String,
    help: String,
    table: Mutex<Table<u64>>,
}

impl CounterVec {
    pub fn new(
        name: impl Into<String>,
        help: impl Into<String>,
        space: LabelSpace,
    ) -> Result<Self, MetricsError> {
        let name = name.into();
        // Validate the name once, by writing its header.
        Exposition::new().header(&name, None, MetricKind::Counter)?;
        Ok(Self {
            name,
            help: help.into(),
            table: Mutex::new(Table::new(space)),
        })
    }

    /// Count one event.
    pub fn inc(&self, values: &[&str]) -> Result<(), MetricsError> {
        self.add(values, 1)
    }

    /// Count `amount` events, saturating at `u64::MAX`.
    pub fn add(&self, values: &[&str], amount: u64) -> Result<(), MetricsError> {
        let mut table = lock(&self.table);
        let count = table.slot(values)?;
        *count = count.saturating_add(amount);
        Ok(())
    }

    /// The count for one series, or `None` if it has not been recorded.
    #[must_use]
    pub fn get(&self, values: &[&str]) -> Option<u64> {
        lock(&self.table).find(values).copied()
    }

    /// How many recordings were refused (unknown series, series limit, wrong
    /// label count, or oversize value). Expose it if refusals matter to the
    /// operator; the primitive never adds a series for them.
    #[must_use]
    pub fn refused(&self) -> u64 {
        lock(&self.table).refused
    }

    /// Write the family's `# HELP` and `# TYPE` lines.
    pub fn write_header(&self, out: &mut Exposition) -> Result<(), MetricsError> {
        out.header(&self.name, Some(&self.help), MetricKind::Counter)
    }

    /// Write the family's samples, without a header.
    pub fn write_samples(&self, out: &mut Exposition) -> Result<(), MetricsError> {
        let table = lock(&self.table);
        for (values, count) in table.ordered() {
            out.sample(&self.name, &table.label_pairs(values), *count)?;
        }
        Ok(())
    }

    /// Write the header and the samples.
    pub fn write(&self, out: &mut Exposition) -> Result<(), MetricsError> {
        self.write_header(out)?;
        self.write_samples(out)
    }
}

/// A histogram family with fixed bucket bounds and a fixed label set, safe to
/// share across threads. Observations are cumulative per bound and inclusive
/// of the bound.
pub struct HistogramVec {
    name: String,
    help: String,
    bounds: Vec<f64>,
    table: Mutex<Table<HistogramSnapshot>>,
}

impl HistogramVec {
    /// `bounds` must be non-empty, finite, and strictly increasing. The
    /// `+Inf` bucket is implicit.
    pub fn new(
        name: impl Into<String>,
        help: impl Into<String>,
        bounds: &[f64],
        space: LabelSpace,
    ) -> Result<Self, MetricsError> {
        let name = name.into();
        Exposition::new().header(&name, None, MetricKind::Histogram)?;
        check_bounds(bounds)?;
        Ok(Self {
            name,
            help: help.into(),
            bounds: bounds.to_vec(),
            table: Mutex::new(Table::new(space)),
        })
    }

    /// The bucket upper bounds.
    #[must_use]
    pub fn bounds(&self) -> &[f64] {
        &self.bounds
    }

    /// Record one observation. NaN and infinite values are refused.
    pub fn observe(&self, values: &[&str], observation: f64) -> Result<(), MetricsError> {
        if !observation.is_finite() {
            return Err(MetricsError::NonFiniteObservation);
        }
        let mut table = lock(&self.table);
        let series = table.slot(values)?;
        if series.cumulative.is_empty() {
            series.cumulative = vec![0; self.bounds.len()];
        }
        series.count = series.count.saturating_add(1);
        series.sum += observation;
        for (count, bound) in series.cumulative.iter_mut().zip(&self.bounds) {
            if observation <= *bound {
                *count = count.saturating_add(1);
            }
        }
        Ok(())
    }

    /// How many recordings were refused; see [`CounterVec::refused`].
    #[must_use]
    pub fn refused(&self) -> u64 {
        lock(&self.table).refused
    }

    /// Every recorded series' label values and state, in render order.
    #[must_use]
    pub fn snapshots(&self) -> Vec<(Vec<String>, HistogramSnapshot)> {
        let table = lock(&self.table);
        table
            .ordered()
            .into_iter()
            .map(|(values, series)| (values.clone(), self.complete(series)))
            .collect()
    }

    fn complete(&self, series: &HistogramSnapshot) -> HistogramSnapshot {
        let mut snapshot = series.clone();
        if snapshot.cumulative.is_empty() {
            snapshot.cumulative = vec![0; self.bounds.len()];
        }
        snapshot
    }

    /// Write the family's `# HELP` and `# TYPE` lines.
    pub fn write_header(&self, out: &mut Exposition) -> Result<(), MetricsError> {
        out.header(&self.name, Some(&self.help), MetricKind::Histogram)
    }

    /// Write the family's series, without a header.
    pub fn write_samples(
        &self,
        out: &mut Exposition,
        order: SumCountOrder,
    ) -> Result<(), MetricsError> {
        let table = lock(&self.table);
        for (values, series) in table.ordered() {
            out.histogram(
                &self.name,
                &table.label_pairs(values),
                &self.bounds,
                &self.complete(series),
                order,
            )?;
        }
        Ok(())
    }

    /// Write the header and the series.
    pub fn write(&self, out: &mut Exposition, order: SumCountOrder) -> Result<(), MetricsError> {
        self.write_header(out)?;
        self.write_samples(out, order)
    }
}
