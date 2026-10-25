// SPDX-License-Identifier: Apache-2.0

//! Dated supply facts for one resource. Instants are normalized to UTC when
//! read; callers resolving local calendars retain responsibility for their
//! timezone and daylight-saving rules. Intervals are half-open.

use chrono::{DateTime, Utc};
use registry_platform_calendar::CalendarInterval;
use serde::{Deserialize, Serialize};

use crate::{covers_span, MAXIMUM_HORIZON_DAYS};

/// One concrete opening or closure. It carries no personnel information.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceInterval {
    pub start: DateTime<Utc>,
    pub end: DateTime<Utc>,
}

impl ResourceInterval {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.start < self.end
            && self.end - self.start <= chrono::Duration::days(i64::from(MAXIMUM_HORIZON_DAYS))
    }
}

/// Dated constraints intersect the resource's static availability and the
/// offering's location openings. Omitted openings impose no additional opening
/// constraint; an explicitly empty list publishes no supply. Closures win.
#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceAvailability {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "schema", schemars(length(max = 256)))]
    pub openings: Option<Vec<ResourceInterval>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[cfg_attr(feature = "schema", schemars(length(max = 256)))]
    pub closures: Vec<ResourceInterval>,
}

impl ResourceAvailability {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.closures.len() <= 256
            && self.closures.iter().all(ResourceInterval::is_valid)
            && self.openings.as_ref().is_none_or(|intervals| {
                intervals.len() <= 256 && intervals.iter().all(ResourceInterval::is_valid)
            })
    }

    /// Check the entire occupied interval, including setup and cleanup. Even
    /// a programmatically constructed invalid fact fails closed.
    #[must_use]
    pub fn covers(&self, start: DateTime<Utc>, end: DateTime<Utc>) -> bool {
        if start >= end || !self.is_valid() {
            return false;
        }
        if self
            .closures
            .iter()
            .any(|closed| start < closed.end && closed.start < end)
        {
            return false;
        }
        self.openings.as_ref().is_none_or(|openings| {
            let intervals: Vec<_> = openings
                .iter()
                .map(|interval| CalendarInterval {
                    start: interval.start,
                    end: interval.end,
                })
                .collect();
            covers_span(&intervals, start, end)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn instant(hour: u32) -> DateTime<Utc> {
        format!("2026-10-10T{hour:02}:00:00Z").parse().unwrap()
    }

    fn interval(start: u32, end: u32) -> ResourceInterval {
        ResourceInterval {
            start: instant(start),
            end: instant(end),
        }
    }

    #[test]
    fn dated_supply_distinguishes_omitted_empty_continuous_and_closed_intervals() {
        let mut facts = ResourceAvailability::default();
        assert!(facts.covers(instant(1), instant(5)));
        facts.openings = Some(vec![]);
        assert!(!facts.covers(instant(1), instant(5)));
        facts.openings = Some(vec![interval(3, 5), interval(1, 3), interval(2, 4)]);
        assert!(facts.covers(instant(1), instant(5)));
        assert!(!facts.covers(instant(0), instant(5)));
        facts.closures = vec![interval(3, 4)];
        assert!(facts.covers(instant(1), instant(3)));
        assert!(facts.covers(instant(4), instant(5)));
        assert!(!facts.covers(instant(2), instant(5)));
        assert!(!facts.covers(instant(3), instant(3)));
    }

    #[test]
    fn invalid_or_excessive_resource_facts_never_publish_supply() {
        for closure in [
            interval(3, 3),
            interval(4, 3),
            ResourceInterval {
                start: instant(1),
                end: instant(1) + chrono::Duration::days(3651),
            },
        ] {
            let facts = ResourceAvailability {
                closures: vec![closure],
                ..Default::default()
            };
            assert!(!facts.is_valid());
            assert!(!facts.covers(instant(1), instant(2)));
        }
        let facts = ResourceAvailability {
            openings: Some(vec![interval(1, 5); 257]),
            ..Default::default()
        };
        assert!(!facts.is_valid());
        assert!(!facts.covers(instant(1), instant(2)));
    }
}
