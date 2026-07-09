// SPDX-License-Identifier: Apache-2.0

use std::ffi::CStr;
use std::mem::MaybeUninit;

use unsafe_libyaml::{
    yaml_event_delete, yaml_event_t, yaml_parser_delete, yaml_parser_initialize, yaml_parser_parse,
    yaml_parser_set_input_string, yaml_parser_t, YAML_ALIAS_EVENT, YAML_MAPPING_START_EVENT,
    YAML_SCALAR_EVENT, YAML_SEQUENCE_START_EVENT, YAML_STREAM_END_EVENT,
};

pub const YAML_MAX_BYTES: u64 = 64 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum YamlPrepassError {
    AliasesUnsupported,
    Parse(String),
}

pub fn reject_yaml_anchors_and_aliases(raw: &str) -> Result<(), YamlPrepassError> {
    if contains_obvious_yaml_anchor_or_alias(raw) {
        return Err(YamlPrepassError::AliasesUnsupported);
    }

    // SAFETY: The libyaml parser receives a pointer into `raw`, which remains
    // alive until `yaml_parser_delete` runs through `ParserGuard`.
    unsafe {
        let mut parser = MaybeUninit::<yaml_parser_t>::uninit();
        let parser = parser.as_mut_ptr();
        if yaml_parser_initialize(parser).fail {
            return Err(YamlPrepassError::Parse(
                "could not initialize YAML parser".to_string(),
            ));
        }
        let _guard = ParserGuard(parser);
        yaml_parser_set_input_string(parser, raw.as_ptr(), raw.len() as u64);

        let mut event = MaybeUninit::<yaml_event_t>::uninit();
        let event = event.as_mut_ptr();
        loop {
            if yaml_parser_parse(parser, event).fail {
                return Err(YamlPrepassError::Parse(parser_problem(parser)));
            }
            let event_type = (*event).type_;
            let unsupported = match event_type {
                YAML_ALIAS_EVENT => true,
                YAML_SCALAR_EVENT => !(*event).data.scalar.anchor.is_null(),
                YAML_SEQUENCE_START_EVENT => !(*event).data.sequence_start.anchor.is_null(),
                YAML_MAPPING_START_EVENT => !(*event).data.mapping_start.anchor.is_null(),
                _ => false,
            };
            yaml_event_delete(event);

            if unsupported {
                return Err(YamlPrepassError::AliasesUnsupported);
            }
            if event_type == YAML_STREAM_END_EVENT {
                return Ok(());
            }
        }
    }
}

fn contains_obvious_yaml_anchor_or_alias(raw: &str) -> bool {
    raw.lines()
        .map(str::trim_start)
        .filter(|line| !line.starts_with('#'))
        .any(line_contains_obvious_yaml_anchor_or_alias)
}

fn line_contains_obvious_yaml_anchor_or_alias(line: &str) -> bool {
    starts_anchor_or_alias(line)
        || line
            .strip_prefix("- ")
            .is_some_and(|rest| starts_anchor_or_alias(rest.trim_start()))
}

fn starts_anchor_or_alias(value: &str) -> bool {
    let bytes = value.as_bytes();
    matches!(bytes.first(), Some(b'&' | b'*'))
        && bytes
            .get(1)
            .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_' || *byte == b'-')
}

struct ParserGuard(*mut yaml_parser_t);

impl Drop for ParserGuard {
    fn drop(&mut self) {
        // SAFETY: `ParserGuard` is constructed only after successful
        // `yaml_parser_initialize` and owns parser teardown.
        unsafe {
            yaml_parser_delete(self.0);
        }
    }
}

unsafe fn parser_problem(parser: *mut yaml_parser_t) -> String {
    let problem = (&*parser).problem;
    if problem.is_null() {
        "unknown YAML parse error".to_string()
    } else {
        CStr::from_ptr(problem).to_string_lossy().into_owned()
    }
}

#[cfg(test)]
mod tests {
    use super::{reject_yaml_anchors_and_aliases, YamlPrepassError};

    #[test]
    fn yaml_prepass_rejects_scaled_alias_amplification_shape() {
        let raw = r#"
amplified_seed: &seed lol
amplified_1: [*seed, *seed, *seed, *seed, *seed, *seed, *seed, *seed]
amplified_2: [*seed, *seed, *seed, *seed, *seed, *seed, *seed, *seed]
schema_version: registry-manifest/v1
catalog:
  id: demo
  base_url: https://metadata.example.test
  title: Demo
  publisher:
    name: Publisher
datasets:
  - id: demo
    title: Demo
    entities: []
codelists: []
"#;

        assert!(matches!(
            reject_yaml_anchors_and_aliases(raw),
            Err(YamlPrepassError::AliasesUnsupported)
        ));
    }

    #[test]
    fn yaml_prepass_rejects_nested_anchored_mapping_without_hanging() {
        let raw = r#"
schema_version: registry-manifest/v1
catalog:
  id: demo
  base_url: https://metadata.example.test
  title: Demo
  publisher:
    name: Publisher
datasets:
  - id: demo
    title: Demo
    entities:
      - name: amplified
        fields:
          - &field
            name: a
            type: string
          - *field
codelists: []
"#;

        assert!(matches!(
            reject_yaml_anchors_and_aliases(raw),
            Err(YamlPrepassError::AliasesUnsupported)
        ));
    }
}
