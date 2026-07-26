// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Result};

use super::AuthoredByteSize;

pub(super) const DEFAULT_INTEGRATION_RESPONSE_BYTES: u64 = 512 * 1024;
pub(super) const DEFAULT_INTEGRATION_REQUEST_BYTES: u64 = 64 * 1024;
pub(super) const DEFAULT_INTEGRATION_SOURCE_BYTES: u64 = 2 * 1024 * 1024;

const INTEGRATION_RESPONSE_MAX_BYTES: u64 = 8 * 1024 * 1024;
const INTEGRATION_REQUEST_MAX_BYTES: u64 = 1024 * 1024;
const INTEGRATION_SOURCE_MAX_BYTES: u64 = 16 * 1024 * 1024;
const ENTITY_GENERATION_MAX_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Clone, Copy)]
struct ByteSizePolicy {
    label: &'static str,
    maximum_bytes: u64,
}

pub(super) fn parse_integration_response_bytes(value: &AuthoredByteSize) -> Result<u64> {
    parse_bounded_byte_size(
        value,
        ByteSizePolicy {
            label: "source.response.max_bytes",
            maximum_bytes: INTEGRATION_RESPONSE_MAX_BYTES,
        },
    )
}

pub(super) fn parse_integration_request_bytes(value: &AuthoredByteSize) -> Result<u64> {
    parse_bounded_byte_size(
        value,
        ByteSizePolicy {
            label: "limits.request_bytes",
            maximum_bytes: INTEGRATION_REQUEST_MAX_BYTES,
        },
    )
}

pub(super) fn parse_integration_source_bytes(value: &AuthoredByteSize) -> Result<u64> {
    parse_bounded_byte_size(
        value,
        ByteSizePolicy {
            label: "limits.source_bytes",
            maximum_bytes: INTEGRATION_SOURCE_MAX_BYTES,
        },
    )
}

pub(super) fn parse_entity_generation_bytes(value: &AuthoredByteSize) -> Result<u64> {
    parse_bounded_byte_size(
        value,
        ByteSizePolicy {
            label: "entity.materialization.max_bytes",
            maximum_bytes: ENTITY_GENERATION_MAX_BYTES,
        },
    )
}

fn parse_bounded_byte_size(value: &AuthoredByteSize, policy: ByteSizePolicy) -> Result<u64> {
    let bytes = match value {
        AuthoredByteSize::Bytes(bytes) => *bytes,
        AuthoredByteSize::Human(value) => {
            let (digits, multiplier) = if let Some(digits) = value.strip_suffix("KiB") {
                (digits, 1024_u64)
            } else if let Some(digits) = value.strip_suffix("MiB") {
                (digits, 1024_u64 * 1024)
            } else {
                bail!(
                    "{} must be a positive byte integer or canonical KiB/MiB value",
                    policy.label
                );
            };
            let amount = parse_positive_decimal(digits, policy.label)?;
            amount
                .checked_mul(multiplier)
                .ok_or_else(|| anyhow!("{} exceeds the platform integer range", policy.label))?
        }
    };
    if bytes == 0 || bytes > policy.maximum_bytes {
        bail!("{} is outside its reviewed byte bound", policy.label);
    }
    Ok(bytes)
}

fn parse_positive_decimal(value: &str, label: &str) -> Result<u64> {
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

    type Parser = fn(&AuthoredByteSize) -> Result<u64>;

    struct PolicyProbe {
        parser: Parser,
        schema: &'static str,
        pointer: &'static str,
        maximum_bytes: u64,
        maximum_kib: u64,
        maximum_mib: u64,
    }

    fn compiled_schema(probe: &PolicyProbe) -> jsonschema::JSONSchema {
        let document: Value =
            serde_json::from_str(probe.schema).expect("committed byte-size schema parses");
        let node = document
            .pointer(probe.pointer)
            .unwrap_or_else(|| panic!("byte-size schema contains {}", probe.pointer));
        jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(node)
            .unwrap_or_else(|error| panic!("{} compiles: {error}", probe.pointer))
    }

    fn assert_integer(probe: &PolicyProbe, value: u64, accepted: bool) {
        let schema = compiled_schema(probe);
        assert_eq!(
            schema.is_valid(&json!(value)),
            accepted,
            "{} schema integer probe {value}",
            probe.pointer
        );
        assert_eq!(
            (probe.parser)(&AuthoredByteSize::Bytes(value)).is_ok(),
            accepted,
            "{} parser integer probe {value}",
            probe.pointer
        );
    }

    fn assert_human(probe: &PolicyProbe, value: &str, accepted: bool) {
        let schema = compiled_schema(probe);
        assert_eq!(
            schema.is_valid(&json!(value)),
            accepted,
            "{} schema human probe {value}",
            probe.pointer
        );
        assert_eq!(
            (probe.parser)(&AuthoredByteSize::Human(value.to_owned())).is_ok(),
            accepted,
            "{} parser human probe {value}",
            probe.pointer
        );
    }

    #[test]
    fn field_policies_keep_exact_schema_and_parser_bounds() {
        let integration_schema =
            include_str!("../../schemas/project-authoring/integration.schema.json");
        let entity_schema = include_str!("../../schemas/project-authoring/entity.schema.json");
        let probes = [
            PolicyProbe {
                parser: parse_integration_response_bytes,
                schema: integration_schema,
                pointer: "/$defs/integrationResponseByteSize",
                maximum_bytes: INTEGRATION_RESPONSE_MAX_BYTES,
                maximum_kib: 8 * 1024,
                maximum_mib: 8,
            },
            PolicyProbe {
                parser: parse_integration_request_bytes,
                schema: integration_schema,
                pointer: "/$defs/integrationRequestByteSize",
                maximum_bytes: INTEGRATION_REQUEST_MAX_BYTES,
                maximum_kib: 1024,
                maximum_mib: 1,
            },
            PolicyProbe {
                parser: parse_integration_source_bytes,
                schema: integration_schema,
                pointer: "/$defs/integrationSourceByteSize",
                maximum_bytes: INTEGRATION_SOURCE_MAX_BYTES,
                maximum_kib: 16 * 1024,
                maximum_mib: 16,
            },
            PolicyProbe {
                parser: parse_entity_generation_bytes,
                schema: entity_schema,
                pointer: "/properties/materialization/properties/max_bytes",
                maximum_bytes: ENTITY_GENERATION_MAX_BYTES,
                maximum_kib: 1024 * 1024,
                maximum_mib: 1024,
            },
        ];

        for probe in probes {
            assert_integer(&probe, 0, false);
            assert_integer(&probe, 1, true);
            assert_integer(&probe, probe.maximum_bytes, true);
            assert_integer(&probe, probe.maximum_bytes + 1, false);

            for (value, accepted) in [
                ("0KiB".to_owned(), false),
                ("1KiB".to_owned(), true),
                (format!("{}KiB", probe.maximum_kib), true),
                (format!("{}KiB", probe.maximum_kib + 1), false),
                ("0MiB".to_owned(), false),
                ("1MiB".to_owned(), true),
                (format!("{}MiB", probe.maximum_mib), true),
                (format!("{}MiB", probe.maximum_mib + 1), false),
                ("01KiB".to_owned(), false),
                ("+1KiB".to_owned(), false),
                ("18446744073709551616KiB".to_owned(), false),
                ("1GiB".to_owned(), false),
            ] {
                assert_human(&probe, &value, accepted);
            }
        }
    }
}
