//! Shared runtime configuration for Registry Stack runtimes.
//!
//! [`RuntimeConfigLoader`] reads an operator `runtime.yaml` under one set of
//! file, parsing and environment-substitution rules; the [`blocks`] types are
//! the configuration sections every runtime spells the same way; and
//! [`SecretResolver`] resolves the `secret:env/NAME` and `secret:file/name`
//! references those sections carry. Each product still owns and validates the
//! rest of its configuration contract.

pub mod blocks;
mod loader;
#[cfg(feature = "schema")]
pub mod schema;
mod secrets;

use sha2::{Digest, Sha256};

pub use blocks::{
    describe_secret_failure, is_sha256_label, AuditKeyConfig, ConfigBlockError,
    ConfigBlockErrorKind, DatabaseConfig, EnvironmentSecretProviderConfig,
    FileSecretProviderConfig, JwksSource, ListenerBind, ListenerConfig, ListenerNetworkExposure,
    OidcIssuerConfig, PackageConfig, PackageDigestMismatch, PrivateListenerConfig,
    SecretProvidersConfig, TlsTermination, MAX_LISTENER_BIND_CHARACTERS,
    MAX_OIDC_AUDIENCE_CHARACTERS,
};
pub use loader::{
    contains_environment_expression, reject_environment_expressions_in_authored_yaml,
    LoadedRuntimeConfig, RemovedKey, RuntimeConfigError, RuntimeConfigErrorKind,
    RuntimeConfigLoader, RuntimeEnvelope, DEFAULT_MAX_RUNTIME_CONFIG_BYTES,
    MAX_RUNTIME_CONFIG_PATH_BYTES,
};
pub use secrets::{
    ProtectedSecret, SecretError, SecretProvider, SecretReference, SecretResolver, MAX_SECRET_BYTES,
};

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct ConfigEnvExpansionError(String);

/// Expand `${VAR}` expressions in configuration text before it is parsed.
///
/// Runtimes read `runtime.yaml` through [`RuntimeConfigLoader`], which
/// substitutes after parsing instead; this text-level form remains only for
/// runtimes that have not moved to the loader yet.
pub fn expand_config_env_vars(raw: &str) -> Result<String, ConfigEnvExpansionError> {
    expand_config_env_vars_with(raw, |name| std::env::var(name).ok())
}

pub fn expand_config_env_vars_with(
    raw: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<String, ConfigEnvExpansionError> {
    let mut expanded = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(start) = rest.find("${") {
        expanded.push_str(&rest[..start]);
        let after_start = &rest[start + 2..];
        let Some(end) = after_start.find('}') else {
            return Err(ConfigEnvExpansionError(
                "unterminated ${...} expression in config".to_string(),
            ));
        };
        let expression = &after_start[..end];
        let after_expression = &after_start[end + 1..];
        let (name, value) = resolve_config_env_expression(expression, &lookup)?;
        if config_env_expression_is_whole_yaml_scalar(&expanded, after_expression) {
            reject_config_env_nul(name, &value)?;
            expanded.push_str(&yaml_double_quoted_scalar(&value));
        } else {
            reject_unsafe_embedded_config_env_value(name, &value)?;
            expanded.push_str(&value);
        }
        rest = after_expression;
    }
    expanded.push_str(rest);
    Ok(expanded)
}

fn resolve_config_env_expression(
    expression: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<(&str, String), ConfigEnvExpansionError> {
    let (name, operator, fallback) = if let Some((name, fallback)) = expression.split_once(":-") {
        (name, ":-", fallback)
    } else if let Some((name, fallback)) = expression.split_once(":?") {
        (name, ":?", fallback)
    } else {
        (expression, "", "")
    };
    // Neither an invalid name nor a `:?` message is repeated: both are
    // configured text, and a refusal reaches the operator's log.
    if !valid_env_key(name) {
        return Err(ConfigEnvExpansionError(
            "a config expression names an invalid environment variable".to_string(),
        ));
    }

    match lookup(name) {
        Some(value) if !value.is_empty() => Ok((name, value)),
        _ if operator == ":-" => Ok((name, fallback.to_string())),
        _ if operator == ":?" => {
            if fallback.trim().is_empty() {
                Err(ConfigEnvExpansionError(format!(
                    "required env var {name} is unset or empty"
                )))
            } else {
                Err(ConfigEnvExpansionError(format!(
                    "required env var {name} is unset or empty; its configured message is withheld"
                )))
            }
        }
        _ => Err(ConfigEnvExpansionError(format!(
            "required env var {name} is unset or empty"
        ))),
    }
}

fn config_env_expression_is_whole_yaml_scalar(before: &str, after: &str) -> bool {
    let line_prefix = before.rsplit_once('\n').map_or(before, |(_, line)| line);
    let trimmed_prefix = line_prefix.trim_start();
    let prefix_is_scalar = trimmed_prefix.is_empty()
        || trimmed_prefix.trim_end() == "-"
        || trimmed_prefix.trim_end().ends_with(':');
    if !prefix_is_scalar {
        return false;
    }

    let line_suffix = after.split_once('\n').map_or(after, |(line, _)| line);
    let trimmed_suffix = line_suffix.trim_start();
    trimmed_suffix.is_empty() || trimmed_suffix.starts_with('#')
}

fn yaml_double_quoted_scalar(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for ch in value.chars() {
        match ch {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            '\0' => quoted.push_str("\\0"),
            ch if ch.is_control() => {
                use std::fmt::Write;
                let _ = write!(quoted, "\\x{:02X}", ch as u32);
            }
            ch => quoted.push(ch),
        }
    }
    quoted.push('"');
    quoted
}

fn reject_config_env_nul(name: &str, value: &str) -> Result<(), ConfigEnvExpansionError> {
    if value.contains('\0') {
        return Err(ConfigEnvExpansionError(format!(
            "env var {name} contains characters that cannot be used in config expansion"
        )));
    }
    Ok(())
}

fn reject_unsafe_embedded_config_env_value(
    name: &str,
    value: &str,
) -> Result<(), ConfigEnvExpansionError> {
    reject_config_env_nul(name, value)?;
    if value.contains('\n')
        || value.contains('\r')
        // unsafe-libyaml treats NEL, LS, and PS as line breaks too.
        || value.contains('\u{0085}')
        || value.contains('\u{2028}')
        || value.contains('\u{2029}')
        || value.contains('"')
        || value.contains('\'')
        || value.contains('{')
        || value.contains('}')
        || value.contains('[')
        || value.contains(']')
        || value.contains(',')
        || value.contains('|')
        || value.contains('>')
        || value.contains('`')
        || value.contains(": ")
        || value.contains(" #")
    {
        return Err(ConfigEnvExpansionError(format!(
            "env var {name} contains characters that are unsafe in embedded config expansion"
        )));
    }
    let trimmed = value.trim_start();
    if trimmed.starts_with('#')
        || trimmed.starts_with('&')
        || trimmed.starts_with('*')
        || trimmed.starts_with('!')
        || trimmed.starts_with('%')
        || trimmed.starts_with('@')
        || trimmed.starts_with("---")
        || trimmed.starts_with("...")
    {
        return Err(ConfigEnvExpansionError(format!(
            "env var {name} contains characters that are unsafe in embedded config expansion"
        )));
    }
    Ok(())
}

fn valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    matches!(chars.next(), Some(c) if c == '_' || c.is_ascii_alphabetic())
        && chars.all(|c| c == '_' || c.is_ascii_alphanumeric())
}

/// The `sha256:` label of `bytes`: `sha256:` followed by 64 lowercase hex
/// digits.
#[must_use]
pub fn sha256_uri(bytes: &[u8]) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(bytes)))
}

/// Keep the parts of a serde refusal an operator acts on, the member, the
/// reason and the location, while the refused value stays out of the message.
///
/// serde reports the offending value inside an `invalid type:`, an
/// `invalid value:` or an `unknown variant` clause. Only the shape word that
/// opens such a clause survives, so the message still says a string arrived where a number was
/// required without repeating the string. A runtime configuration names
/// secret references, database URLs and destinations, and a startup refusal
/// is written to the operator's log.
#[must_use]
pub fn redact_refused_values(message: &str) -> String {
    const CLAUSES: [&str; 3] = ["invalid type: ", "invalid value: ", "unknown variant"];
    let mut redacted = String::with_capacity(message.len());
    let mut rest = message;
    loop {
        let Some((start, len)) = CLAUSES
            .iter()
            .filter_map(|clause| rest.find(clause).map(|start| (start, clause.len())))
            .min_by_key(|(start, _)| *start)
        else {
            redacted.push_str(rest);
            return redacted;
        };
        let opened = start + len;
        redacted.push_str(&rest[..opened]);
        let (shape, tail) = split_refused_value(&rest[opened..]);
        redacted.push_str(shape);
        rest = tail;
    }
}

/// Split the text after a clause marker into the shape word serde names and
/// the remainder that follows the refused value.
///
/// serde renders the value with `Debug`, so it opens with a quote or a
/// backtick and may hold the comma that would otherwise end the clause.
fn split_refused_value(clause: &str) -> (&str, &str) {
    let bytes = clause.as_bytes();
    let mut index = 0;
    let mut shape_end = None;
    while index < bytes.len() {
        match bytes[index] {
            delimiter @ (b'"' | b'`') => {
                shape_end.get_or_insert(index);
                index = skip_delimited(bytes, index, delimiter);
            }
            b',' => break,
            _ => index += 1,
        }
    }
    let shape_end = shape_end.unwrap_or(index);
    (clause[..shape_end].trim_end(), &clause[index..])
}

/// Return the offset just past the delimited run that opens at `open`.
///
/// A delimiter inside a `Debug` rendering arrives escaped, so it does not end
/// the run.
fn skip_delimited(bytes: &[u8], open: usize, delimiter: u8) -> usize {
    let mut index = open + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            byte if byte == delimiter => return index + 1,
            _ => index += 1,
        }
    }
    bytes.len()
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_env_expansion_distinguishes_unset_empty_and_whitespace_values() {
        struct Case {
            name: &'static str,
            expression: &'static str,
            value: Option<&'static str>,
            expected: Result<&'static str, &'static str>,
        }

        for case in [
            Case {
                name: "plain expression rejects an unset value",
                expression: "${VALUE}",
                value: None,
                expected: Err("required env var VALUE is unset or empty"),
            },
            Case {
                name: "plain expression rejects an empty value",
                expression: "${VALUE}",
                value: Some(""),
                expected: Err("required env var VALUE is unset or empty"),
            },
            Case {
                name: "plain expression preserves whitespace-only value",
                expression: "${VALUE}",
                value: Some("   "),
                expected: Ok("\"   \""),
            },
            Case {
                name: "fallback applies to an unset value",
                expression: "${VALUE:-fallback}",
                value: None,
                expected: Ok("\"fallback\""),
            },
            Case {
                name: "fallback applies to an empty value",
                expression: "${VALUE:-fallback}",
                value: Some(""),
                expected: Ok("\"fallback\""),
            },
            Case {
                name: "non-empty value wins over fallback",
                expression: "${VALUE:-fallback}",
                value: Some("configured"),
                expected: Ok("\"configured\""),
            },
            Case {
                name: "explicit empty fallback applies to an unset value",
                expression: "${VALUE:-}",
                value: None,
                expected: Ok("\"\""),
            },
            Case {
                name: "explicit empty fallback applies to an empty value",
                expression: "${VALUE:-}",
                value: Some(""),
                expected: Ok("\"\""),
            },
            Case {
                name: "required message applies to an unset value",
                expression: "${VALUE:?configure VALUE}",
                value: None,
                expected: Err(
                    "required env var VALUE is unset or empty; its configured message is withheld",
                ),
            },
            Case {
                name: "required message applies to an empty value",
                expression: "${VALUE:?configure VALUE}",
                value: Some(""),
                expected: Err(
                    "required env var VALUE is unset or empty; its configured message is withheld",
                ),
            },
            Case {
                name: "blank required message identifies an unset value",
                expression: "${VALUE:?}",
                value: None,
                expected: Err("required env var VALUE is unset or empty"),
            },
            Case {
                name: "blank required message identifies an empty value",
                expression: "${VALUE:?}",
                value: Some(""),
                expected: Err("required env var VALUE is unset or empty"),
            },
            Case {
                name: "unsupported syntax remains invalid",
                expression: "${VALUE-fallback}",
                value: Some("configured"),
                expected: Err("a config expression names an invalid environment variable"),
            },
        ] {
            let actual = expand_config_env_vars_with(case.expression, |_| {
                case.value.map(ToString::to_string)
            })
            .map_err(|error| error.to_string());

            let actual = actual
                .as_ref()
                .map(|value| value.as_str())
                .map_err(|error| error.as_str());
            assert_eq!(actual, case.expected, "{}", case.name);
        }
    }

    #[test]
    fn config_env_expansion_scalarizes_whole_yaml_values() {
        let expanded =
            expand_config_env_vars_with("base: ${BASE_URL}\nflow: ${FLOW}\n", |name| match name {
                "BASE_URL" => Some("https://registry.example\nadmin: false".to_string()),
                "FLOW" => Some("{admin: false}".to_string()),
                _ => None,
            })
            .expect("whole-scalar config env vars are quoted");

        assert!(expanded.contains("base: \"https://registry.example\\nadmin: false\""));
        assert!(expanded.contains("flow: \"{admin: false}\""));
        assert!(!expanded.contains("\nadmin: false"));
    }

    #[test]
    fn config_env_expansion_quotes_whole_scalar_yaml_syntax_values() {
        let expanded = expand_config_env_vars_with(
            "anchor: ${ANCHOR}\nalias: ${ALIAS}\ntag: ${TAG}\ncomment: ${COMMENT}\nblock: ${BLOCK}\nflow: ${FLOW}\n",
            |name| match name {
                "ANCHOR" => Some("&admin".to_string()),
                "ALIAS" => Some("*admin".to_string()),
                "TAG" => Some("!vault secret".to_string()),
                "COMMENT" => Some("value # hidden".to_string()),
                "BLOCK" => Some("line1\nline2".to_string()),
                "FLOW" => Some("[admin, true]".to_string()),
                _ => None,
            },
        )
        .expect("whole-scalar config env vars are quoted");

        assert!(expanded.contains("anchor: \"&admin\""));
        assert!(expanded.contains("alias: \"*admin\""));
        assert!(expanded.contains("tag: \"!vault secret\""));
        assert!(expanded.contains("comment: \"value # hidden\""));
        assert!(expanded.contains("block: \"line1\\nline2\""));
        assert!(expanded.contains("flow: \"[admin, true]\""));
        assert!(!expanded.contains("\nline2"));
    }

    #[test]
    fn config_env_expansion_rejects_unsafe_embedded_values() {
        let err = expand_config_env_vars_with("base: https://${HOST}\n", |name| match name {
            "HOST" => Some("registry.example\nadmin: false".to_string()),
            _ => None,
        })
        .expect_err("embedded newline cannot be expanded into YAML structure");

        assert!(err.to_string().contains("HOST"));
        assert!(!err.to_string().contains("admin"));

        let err = expand_config_env_vars_with("allowed: [${VALUE}]\n", |name| match name {
            "VALUE" => Some("trusted, attacker".to_string()),
            _ => None,
        })
        .expect_err("embedded comma cannot expand into a YAML flow sequence");
        assert!(err.to_string().contains("VALUE"));
        assert!(!err.to_string().contains("trusted"));
    }

    #[test]
    fn config_env_expansion_rejects_embedded_yaml_syntax_classes() {
        for value in [
            "registry.example # hidden",
            "admin: false",
            "[admin]",
            "trusted, attacker",
            "line1\nline2",
            "line1\u{0085}line2",
            "evil.example\u{2028}admin:",
            "evil.example\u{2028}---\u{2028}x:",
            "line1\u{2029}line2",
            "| block",
            "> folded",
            "&anchor",
            "*alias",
            "!tagged",
            "%YAML 1.2",
            "---",
            "...",
        ] {
            let err = expand_config_env_vars_with("base: https://${VALUE}\n", |name| match name {
                "VALUE" => Some(value.to_string()),
                _ => None,
            })
            .expect_err("embedded YAML syntax value must be rejected")
            .to_string();

            assert!(err.contains("VALUE"));
            assert!(!err.contains(value));
        }
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::redact_refused_values;

    #[test]
    fn refused_values_are_reduced_to_their_shape() {
        assert_eq!(
            redact_refused_values(
                "invalid type: string \"DO_NOT_DISCLOSE, still\", expected u16 at line 1"
            ),
            "invalid type: string, expected u16 at line 1"
        );
        assert_eq!(
            redact_refused_values("invalid value: integer `70000`, expected u16"),
            "invalid value: integer, expected u16"
        );
        assert_eq!(
            redact_refused_values(
                "mode: unknown variant `DO_NOT_DISCLOSE`, expected one of `a`, `b` at line 3"
            ),
            "mode: unknown variant, expected one of `a`, `b` at line 3"
        );
    }
}
