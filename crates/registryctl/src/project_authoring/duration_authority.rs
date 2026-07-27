// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Result};

const INTEGRATION_DEADLINE_MAX_MS: u32 = 20_000;
const FIXTURE_TIMEOUT_MAX_MS: u32 = 20_000;
const ENVIRONMENT_SOURCE_TIMEOUT_MAX_MS: u32 = 20_000;
const OAUTH_REFRESH_SKEW_MAX_MS: u32 = 59_999;
const SNAPSHOT_FRESHNESS_MAX_MS: u32 = 31 * 24 * 60 * 60 * 1_000;
const MATERIALIZATION_REFRESH_MAX_MS: u32 = 30 * 24 * 60 * 60 * 1_000;

#[derive(Clone, Copy)]
enum DurationUnits {
    MillisecondsOrSeconds,
    Extended,
}

impl DurationUnits {
    const fn description(self) -> &'static str {
        match self {
            Self::MillisecondsOrSeconds => "milliseconds or seconds",
            Self::Extended => "milliseconds, seconds, minutes, hours, or days",
        }
    }
}

struct DurationPolicy {
    label: &'static str,
    maximum_ms: u32,
    units: DurationUnits,
}

pub(super) fn parse_integration_deadline_ms(value: &str) -> Result<u32> {
    parse_bounded_duration_ms(
        value,
        DurationPolicy {
            label: "integration limits.deadline",
            maximum_ms: INTEGRATION_DEADLINE_MAX_MS,
            units: DurationUnits::MillisecondsOrSeconds,
        },
    )
}

pub(super) fn parse_fixture_timeout_ms(value: &str) -> Result<u32> {
    parse_bounded_duration_ms(
        value,
        DurationPolicy {
            label: "fixture response.timeout",
            maximum_ms: FIXTURE_TIMEOUT_MAX_MS,
            units: DurationUnits::MillisecondsOrSeconds,
        },
    )
}

pub(super) fn parse_environment_source_timeout_ms(value: &str) -> Result<u32> {
    parse_bounded_duration_ms(
        value,
        DurationPolicy {
            label: "environment source.timeout",
            maximum_ms: ENVIRONMENT_SOURCE_TIMEOUT_MAX_MS,
            units: DurationUnits::MillisecondsOrSeconds,
        },
    )
}

pub(super) fn parse_oauth_refresh_skew_ms(value: &str) -> Result<u32> {
    parse_bounded_duration_ms(
        value,
        DurationPolicy {
            label: "OAuth refresh_skew",
            maximum_ms: OAUTH_REFRESH_SKEW_MAX_MS,
            units: DurationUnits::MillisecondsOrSeconds,
        },
    )
}

pub(super) fn parse_snapshot_freshness_ms(value: &str) -> Result<u32> {
    parse_bounded_duration_ms(
        value,
        DurationPolicy {
            label: "snapshot freshness",
            maximum_ms: SNAPSHOT_FRESHNESS_MAX_MS,
            units: DurationUnits::Extended,
        },
    )
}

pub(super) fn parse_materialization_refresh_ms(value: &str) -> Result<u32> {
    parse_bounded_duration_ms(
        value,
        DurationPolicy {
            label: "entity materialization refresh",
            maximum_ms: MATERIALIZATION_REFRESH_MAX_MS,
            units: DurationUnits::Extended,
        },
    )
}

fn parse_bounded_duration_ms(value: &str, policy: DurationPolicy) -> Result<u32> {
    let milliseconds = if let Some(milliseconds) = value.strip_suffix("ms") {
        Some(parse_positive_decimal(milliseconds, policy.label)?)
    } else if let Some(seconds) = value.strip_suffix('s') {
        parse_positive_decimal(seconds, policy.label)?.checked_mul(1_000)
    } else if matches!(policy.units, DurationUnits::Extended) {
        if let Some(minutes) = value.strip_suffix('m') {
            parse_positive_decimal(minutes, policy.label)?.checked_mul(60_000)
        } else if let Some(hours) = value.strip_suffix('h') {
            parse_positive_decimal(hours, policy.label)?.checked_mul(60 * 60 * 1_000)
        } else if let Some(days) = value.strip_suffix('d') {
            parse_positive_decimal(days, policy.label)?.checked_mul(24 * 60 * 60 * 1_000)
        } else {
            None
        }
    } else {
        None
    }
    .ok_or_else(|| {
        anyhow!(
            "{} must be a positive duration in {}",
            policy.label,
            policy.units.description()
        )
    })?;
    if milliseconds == 0 || milliseconds > policy.maximum_ms {
        bail!("{} is outside its reviewed bound", policy.label);
    }
    Ok(milliseconds)
}

fn parse_positive_decimal(value: &str, label: &str) -> Result<u32> {
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("{label} must use canonical positive decimal digits");
    }
    value
        .parse()
        .map_err(|_| anyhow!("{label} exceeds its numeric representation"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    type Parser = fn(&str) -> Result<u32>;

    struct ExtendedDurationProbe {
        parser: Parser,
        schema: &'static str,
        pointer: &'static str,
        maximum_ms: u32,
    }

    fn positive_decimal_schema_fragment(maximum: u32) -> String {
        let maximum = maximum.to_string();
        let digits = maximum.as_bytes();
        let mut alternatives = Vec::new();
        if digits.len() > 1 {
            alternatives.push(format!("[1-9][0-9]{{0,{}}}", digits.len() - 2));
        }
        for (index, digit) in digits.iter().enumerate() {
            let digit = digit - b'0';
            let lower = u8::from(index == 0);
            if digit <= lower {
                continue;
            }
            let prefix = &maximum[..index];
            let upper = digit - 1;
            let range = if lower == upper {
                char::from(b'0' + lower).to_string()
            } else {
                format!("[{lower}-{upper}]")
            };
            let remaining = digits.len() - index - 1;
            let suffix = if remaining == 0 {
                String::new()
            } else {
                format!("[0-9]{{{remaining}}}")
            };
            alternatives.push(format!("{prefix}{range}{suffix}"));
        }
        alternatives.push(maximum);
        format!("(?:{})", alternatives.join("|"))
    }

    fn extended_duration_schema_pattern(maximum_ms: u32) -> String {
        let alternatives = [
            ("ms", 1_u32),
            ("s", 1_000),
            ("m", 60_000),
            ("h", 60 * 60 * 1_000),
            ("d", 24 * 60 * 60 * 1_000),
        ]
        .map(|(suffix, multiplier)| {
            format!(
                "{}{suffix}",
                positive_decimal_schema_fragment(maximum_ms / multiplier)
            )
        });
        format!("^(?:{})$", alternatives.join("|"))
    }

    fn schema_node(probe: &ExtendedDurationProbe) -> Value {
        let document: Value =
            serde_json::from_str(probe.schema).expect("committed duration schema parses");
        document
            .pointer(probe.pointer)
            .unwrap_or_else(|| panic!("duration schema contains {}", probe.pointer))
            .clone()
    }

    fn assert_duration(probe: &ExtendedDurationProbe, value: &str, accepted: bool) {
        let node = schema_node(probe);
        let schema = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&node)
            .unwrap_or_else(|error| panic!("{} compiles: {error}", probe.pointer));
        assert_eq!(
            schema.is_valid(&json!(value)),
            accepted,
            "{} schema probe {value}",
            probe.pointer
        );
        assert_eq!(
            (probe.parser)(value).is_ok(),
            accepted,
            "{} parser probe {value}",
            probe.pointer
        );
    }

    #[test]
    fn field_policies_keep_distinct_units_and_bounds() {
        for parser in [
            parse_integration_deadline_ms,
            parse_fixture_timeout_ms,
            parse_environment_source_timeout_ms,
        ] {
            assert_eq!(parser("1ms").expect("minimum is valid"), 1);
            assert_eq!(parser("20s").expect("maximum is valid"), 20_000);
            assert!(parser("0ms").is_err());
            assert!(parser("20001ms").is_err());
            assert!(parser("1m").is_err());
            assert!(parser("01s").is_err());
            assert!(parser("0001ms").is_err());
            assert!(parser("+1s").is_err());
        }

        assert_eq!(
            parse_oauth_refresh_skew_ms("30s").expect("explicit default is valid"),
            30_000
        );
        assert_eq!(
            parse_oauth_refresh_skew_ms("59999ms").expect("OAuth maximum is valid"),
            OAUTH_REFRESH_SKEW_MAX_MS
        );
        assert!(parse_oauth_refresh_skew_ms("60s").is_err());
        assert!(parse_oauth_refresh_skew_ms("1m").is_err());

        assert_eq!(
            parse_snapshot_freshness_ms("31d").expect("snapshot maximum is valid"),
            SNAPSHOT_FRESHNESS_MAX_MS
        );
        assert!(parse_snapshot_freshness_ms("32d").is_err());
        assert!(parse_snapshot_freshness_ms("01d").is_err());
        assert_eq!(
            parse_materialization_refresh_ms("30d").expect("materialization maximum is valid"),
            MATERIALIZATION_REFRESH_MAX_MS
        );
        assert!(parse_materialization_refresh_ms("31d").is_err());
    }

    #[test]
    fn extended_field_policies_keep_exact_schema_and_parser_bounds() {
        let integration_schema =
            include_str!("../../schemas/project-authoring/integration.schema.json");
        let entity_schema = include_str!("../../schemas/project-authoring/entity.schema.json");
        let probes = [
            ExtendedDurationProbe {
                parser: parse_snapshot_freshness_ms,
                schema: integration_schema,
                pointer: "/$defs/capability/oneOf/2/properties/snapshot/properties/freshness",
                maximum_ms: SNAPSHOT_FRESHNESS_MAX_MS,
            },
            ExtendedDurationProbe {
                parser: parse_materialization_refresh_ms,
                schema: entity_schema,
                pointer: "/properties/materialization/properties/refresh/oneOf/1",
                maximum_ms: MATERIALIZATION_REFRESH_MAX_MS,
            },
        ];

        for probe in &probes {
            let node = schema_node(probe);
            assert_eq!(
                node["pattern"],
                extended_duration_schema_pattern(probe.maximum_ms),
                "{} must derive the published unit ceilings from the product-owned millisecond authority",
                probe.pointer
            );

            for (suffix, multiplier) in [
                ("ms", 1_u32),
                ("s", 1_000),
                ("m", 60_000),
                ("h", 60 * 60 * 1_000),
                ("d", 24 * 60 * 60 * 1_000),
            ] {
                let maximum = probe.maximum_ms / multiplier;
                assert_duration(probe, &format!("1{suffix}"), true);
                assert_duration(probe, &format!("{maximum}{suffix}"), true);
                assert_duration(probe, &format!("{}{suffix}", maximum + 1), false);
            }
            for value in [
                "0ms",
                "01d",
                "+1s",
                "1w",
                "4294967296ms",
                "18446744073709551616d",
            ] {
                assert_duration(probe, value, false);
            }
        }

        assert_duration(&probes[0], "32d", false);
        assert_duration(&probes[1], "31d", false);
    }
}
