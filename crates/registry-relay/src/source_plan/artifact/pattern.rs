//! Bounded input-pattern automata and shared stable-text validation.

use super::*;
pub(in super::super) use registry_platform_httputil::destination::input_pattern::BoundedInputPattern;
use registry_platform_httputil::destination::input_pattern::BoundedInputPatternError;

pub(super) fn validate_input_pattern(pattern: &str) -> Result<(), SourcePlanArtifactError> {
    parse_input_pattern(pattern).map(|_| ())
}

pub(in super::super) fn parse_input_pattern(
    pattern: &str,
) -> Result<BoundedInputPattern, SourcePlanArtifactError> {
    BoundedInputPattern::compile(pattern).map_err(|error| match error {
        BoundedInputPatternError::InvalidExpression => SourcePlanArtifactError::InvalidExpression,
        BoundedInputPatternError::LimitExceeded => SourcePlanArtifactError::InvalidLimits,
    })
}

pub(super) fn validate_stable_text(value: &str) -> Result<(), SourcePlanArtifactError> {
    let mut bytes = value.bytes();
    let valid = matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= 96
        && bytes.all(|byte| {
            matches!(
                byte,
                b'a'..=b'z' | b'0'..=b'9' | b'.' | b'_' | b':' | b'-'
            )
        });
    valid
        .then_some(())
        .ok_or(SourcePlanArtifactError::InvalidText)
}

pub(super) fn validate_query_name(value: &str) -> Result<(), SourcePlanArtifactError> {
    let mut bytes = value.bytes();
    let valid = matches!(bytes.next(), Some(b'a'..=b'z' | b'A'..=b'Z'))
        && value.len() <= 96
        && bytes.all(|byte| {
            matches!(
                byte,
                b'a'..=b'z'
                    | b'A'..=b'Z'
                    | b'0'..=b'9'
                    | b'.'
                    | b'_'
                    | b':'
                    | b'~'
                    | b'-'
            )
        });
    valid
        .then_some(())
        .ok_or(SourcePlanArtifactError::InvalidText)
}

pub(super) fn validate_bounded_text(
    value: &str,
    max_bytes: usize,
) -> Result<(), SourcePlanArtifactError> {
    let valid =
        !value.is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control);
    valid
        .then_some(())
        .ok_or(SourcePlanArtifactError::InvalidText)
}

pub(super) fn validate_token(value: &str, max_bytes: usize) -> Result<(), SourcePlanArtifactError> {
    let valid = !value.is_empty()
        && value.len() <= max_bytes
        && !value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace());
    valid
        .then_some(())
        .ok_or(SourcePlanArtifactError::InvalidText)
}

pub(super) fn is_sensitive_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    [
        "secret",
        "password",
        "token",
        "credential",
        "private_key",
        "api_key",
        "authorization",
    ]
    .iter()
    .any(|sensitive| name.contains(sensitive))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_name_grammar_preserves_colons_and_accepts_product_camel_case() {
        for valid in [
            "orgUnitMode",
            "pageSize",
            "trackedEntity",
            "selector:subject",
            "XTrace",
        ] {
            assert_eq!(validate_query_name(valid), Ok(()), "rejected {valid:?}");
        }
        assert_eq!(validate_query_name(&"a".repeat(96)), Ok(()));
    }

    #[test]
    fn query_name_grammar_rejects_delimiters_controls_and_oversized_names() {
        for invalid in ["", "a&b", "a=b", "a%b", "a\n", "a\0"] {
            assert_eq!(
                validate_query_name(invalid),
                Err(SourcePlanArtifactError::InvalidText),
                "accepted {invalid:?}"
            );
        }
        assert_eq!(
            validate_query_name(&"a".repeat(97)),
            Err(SourcePlanArtifactError::InvalidText)
        );
    }
}
