//! Governed runtime configuration verification contracts.

mod config_bundle;

use serde_json::Value;
use sha2::{Digest, Sha256};

pub use config_bundle::{
    load_break_glass_override, load_trust_anchor, read_config_file_limited, verify_config_bundle,
    ConfigBreakGlassMode, ConfigBreakGlassOverride, ConfigBundleError, ConfigBundleFile,
    ConfigBundleManifest, ConfigBundleSignature, ConfigBundleSignatureEnvelope, ConfigTrustAnchor,
    ConfigTrustAnchorSigner, VerifiedConfigBundle, MAX_BUNDLE_FILE_BYTES,
    MAX_CONFIG_BUNDLE_SEQUENCE, MAX_MANIFEST_BYTES, MAX_SIGNATURE_ENVELOPE_BYTES,
    MAX_TRUST_ANCHOR_BYTES,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct DeprecatedConfigField {
    path: Vec<String>,
    replacement: Option<String>,
    message: Option<String>,
}

impl DeprecatedConfigField {
    pub fn renamed(path: impl Into<String>, replacement: impl Into<String>) -> Self {
        Self {
            path: split_config_path(path),
            replacement: Some(replacement.into()),
            message: None,
        }
    }

    pub fn removed(path: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            path: split_config_path(path),
            replacement: None,
            message: Some(message.into()),
        }
    }

    pub fn path(&self) -> String {
        self.path.join(".")
    }
}

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
#[error("{message}")]
pub struct DeprecatedConfigFieldError {
    field: String,
    message: String,
}

impl DeprecatedConfigFieldError {
    pub fn field(&self) -> &str {
        &self.field
    }
}

pub fn reject_deprecated_config_fields(
    root: &Value,
    fields: &[DeprecatedConfigField],
) -> Result<(), DeprecatedConfigFieldError> {
    for field in fields {
        if config_value_at_path(root, &field.path).is_some() {
            let field_path = field.path();
            let message = if let Some(replacement) = &field.replacement {
                format!("{field_path} has been renamed; use {replacement}")
            } else if let Some(message) = &field.message {
                format!("{field_path} has been removed; {message}")
            } else {
                format!("{field_path} has been removed")
            };
            return Err(DeprecatedConfigFieldError {
                field: field_path,
                message,
            });
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Eq, PartialEq, thiserror::Error)]
#[error("{0}")]
pub struct ConfigEnvExpansionError(String);

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

fn split_config_path(path: impl Into<String>) -> Vec<String> {
    path.into()
        .split('.')
        .filter(|segment| !segment.is_empty())
        .map(ToString::to_string)
        .collect()
}

fn config_value_at_path<'a>(root: &'a Value, path: &[String]) -> Option<&'a Value> {
    let mut current = root;
    for segment in path {
        current = current.get(segment)?;
    }
    Some(current)
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
    if !valid_env_key(name) {
        return Err(ConfigEnvExpansionError(format!(
            "invalid env var name in config expression: {name}"
        )));
    }

    match lookup(name) {
        Some(value) if !value.is_empty() => Ok((name, value)),
        Some(value) if operator.is_empty() => Ok((name, value)),
        _ if operator == ":-" => Ok((name, fallback.to_string())),
        _ if operator == ":?" => {
            if fallback.trim().is_empty() {
                Err(ConfigEnvExpansionError(format!(
                    "missing required env var {name}"
                )))
            } else {
                Err(ConfigEnvExpansionError(fallback.to_string()))
            }
        }
        _ => Err(ConfigEnvExpansionError(format!(
            "missing required env var {name}"
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

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ConfigVerificationError {
    #[error("{0} must not be empty")]
    EmptyField(&'static str),
    #[error("{field} must be a sha256: URI")]
    InvalidSha256Uri { field: &'static str },
}

pub fn sha256_uri(bytes: &[u8]) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(bytes)))
}

fn validate_non_empty(field: &'static str, value: &str) -> Result<(), ConfigVerificationError> {
    if value.trim().is_empty() {
        return Err(ConfigVerificationError::EmptyField(field));
    }
    Ok(())
}

fn validate_sha256_uri(field: &'static str, value: &str) -> Result<(), ConfigVerificationError> {
    validate_non_empty(field, value)?;
    let Some(digest) = value.strip_prefix("sha256:") else {
        return Err(ConfigVerificationError::InvalidSha256Uri { field });
    };
    if digest.len() != 64 || !digest.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(ConfigVerificationError::InvalidSha256Uri { field });
    }
    Ok(())
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
    use serde_json::json;

    #[test]
    fn deprecated_config_field_detector_names_replacement() {
        let root = json!({
            "auth": {
                "oidc": {
                    "audience": ["registry-relay"]
                }
            }
        });

        let err = reject_deprecated_config_fields(
            &root,
            &[DeprecatedConfigField::renamed(
                "auth.oidc.audience",
                "auth.oidc.audiences",
            )],
        )
        .expect_err("deprecated field is rejected");

        assert_eq!(err.field(), "auth.oidc.audience");
        assert!(err.to_string().contains("auth.oidc.audiences"));
    }

    #[test]
    fn deprecated_config_field_detector_names_removal_rationale() {
        let root = json!({
            "server": {
                "cors": {
                    "allow_credentials": true
                }
            }
        });

        let err = reject_deprecated_config_fields(
            &root,
            &[DeprecatedConfigField::removed(
                "server.cors.allow_credentials",
                "credentials are always disabled",
            )],
        )
        .expect_err("removed field is rejected");

        assert_eq!(err.field(), "server.cors.allow_credentials");
        assert!(err.to_string().contains("credentials are always disabled"));
    }

    #[test]
    fn config_env_expansion_supports_required_and_default_values() {
        let expanded = expand_config_env_vars_with(
            "base: ${BASE_URL:?missing base}\noptional: ${OPTIONAL_URL:-https://fallback.example}\n",
            |name| match name {
                "BASE_URL" => Some("https://registry.example".to_string()),
                _ => None,
            },
        )
        .expect("config expands");

        assert!(expanded.contains("base: \"https://registry.example\""));
        assert!(expanded.contains("optional: \"https://fallback.example\""));
    }

    #[test]
    fn config_env_expansion_rejects_missing_required_value() {
        let err = expand_config_env_vars_with("${BASE_URL:?missing base}", |_| None)
            .expect_err("missing required env var is rejected");

        assert_eq!(err.to_string(), "missing base");
    }

    #[test]
    fn config_env_expansion_allows_empty_plain_value() {
        let expanded = expand_config_env_vars_with("${BASE_URL}", |_| Some(String::new()))
            .expect("empty env var is allowed for plain expressions");

        assert_eq!(expanded, "\"\"");
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
