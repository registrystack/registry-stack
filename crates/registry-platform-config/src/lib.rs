//! Shared runtime configuration for Registry Stack runtimes.
//!
//! [`RuntimeConfigLoader`] reads an operator `runtime.yaml` under one set of
//! file, parsing and environment-substitution rules; the [`blocks`] types are
//! the configuration sections every runtime spells the same way; and
//! [`SecretResolver`] resolves the `secret:env/NAME` and `secret:file/name`
//! references those sections carry. [`package`] writes and verifies the
//! package directory `package.root` names. Each product still owns and
//! validates the rest of its configuration contract.

pub mod blocks;
mod loader;
mod offline;
pub mod package;
#[cfg(feature = "schema")]
pub mod schema;
mod secrets;

use sha2::{Digest, Sha256};

pub use blocks::{
    describe_secret_failure, is_sha256_label, AuditKeyConfig, ConfigBlockError,
    ConfigBlockErrorKind, DatabaseConfig, EnvironmentSecretProviderConfig,
    FileSecretProviderConfig, JwksSource, ListenerBind, ListenerConfig, ListenerNetworkExposure,
    OidcClientsConfig, OidcIssuerConfig, PackageConfig, PackageDigestMismatch,
    PrivateListenerConfig, SecretProvidersConfig, TlsTermination, MAX_ASSERTION_ISSUERS_PER_CLIENT,
    MAX_ASSERTION_ISSUER_BYTES, MAX_ASSERTION_ISSUER_CLIENTS, MAX_ASSERTION_ISSUER_CLIENT_BYTES,
    MAX_LISTENER_BIND_CHARACTERS, MAX_OIDC_AUDIENCE_CHARACTERS,
};
pub use loader::{
    contains_environment_expression, reject_environment_expressions_in_authored_yaml,
    AuthoredExpressions, LoadedRuntimeConfig, RemovedKey, RuntimeConfigError, RuntimeConfigLoader,
    RuntimeEnvelope, DEFAULT_MAX_RUNTIME_CONFIG_BYTES, MAX_RUNTIME_CONFIG_PATH_BYTES,
    REMOVED_OIDC_JWKS_URI, UNAVAILABLE_CODE,
};
pub use offline::{RuntimeFileCheck, DEFAULT_STAND_IN, INCOMPLETE_CODE};
pub use package::{
    plan_package, verify_package, write_package, write_sum_file, PackageError, PackageErrorKind,
    PackageLimits, VerifiedPackage, REVISION_FILE, SUM_FILE,
};
pub use secrets::{
    ProtectedSecret, SecretError, SecretProvider, SecretReference, SecretResolver, MAX_SECRET_BYTES,
};

fn resolve_config_env_expression(
    expression: &str,
    lookup: impl Fn(&str) -> Option<String>,
) -> Result<(&str, String), String> {
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
        return Err("a config expression names an invalid environment variable".to_string());
    }

    match lookup(name) {
        Some(value) if !value.is_empty() => Ok((name, value)),
        _ if operator == ":-" => Ok((name, fallback.to_string())),
        _ if operator == ":?" => {
            if fallback.trim().is_empty() {
                Err(format!("required env var {name} is unset or empty"))
            } else {
                Err(format!(
                    "required env var {name} is unset or empty; its configured message is withheld"
                ))
            }
        }
        _ => Err(format!("required env var {name} is unset or empty")),
    }
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
    fn config_env_expressions_distinguish_unset_empty_and_whitespace_values() {
        struct Case {
            name: &'static str,
            expression: &'static str,
            value: Option<&'static str>,
            expected: Result<&'static str, &'static str>,
        }

        for case in [
            Case {
                name: "plain expression rejects an unset value",
                expression: "VALUE",
                value: None,
                expected: Err("required env var VALUE is unset or empty"),
            },
            Case {
                name: "plain expression rejects an empty value",
                expression: "VALUE",
                value: Some(""),
                expected: Err("required env var VALUE is unset or empty"),
            },
            Case {
                name: "plain expression preserves whitespace-only value",
                expression: "VALUE",
                value: Some("   "),
                expected: Ok("   "),
            },
            Case {
                name: "fallback applies to an unset value",
                expression: "VALUE:-fallback",
                value: None,
                expected: Ok("fallback"),
            },
            Case {
                name: "fallback applies to an empty value",
                expression: "VALUE:-fallback",
                value: Some(""),
                expected: Ok("fallback"),
            },
            Case {
                name: "non-empty value wins over fallback",
                expression: "VALUE:-fallback",
                value: Some("configured"),
                expected: Ok("configured"),
            },
            Case {
                name: "explicit empty fallback applies to an unset value",
                expression: "VALUE:-",
                value: None,
                expected: Ok(""),
            },
            Case {
                name: "explicit empty fallback applies to an empty value",
                expression: "VALUE:-",
                value: Some(""),
                expected: Ok(""),
            },
            Case {
                name: "required message applies to an unset value",
                expression: "VALUE:?configure VALUE",
                value: None,
                expected: Err(
                    "required env var VALUE is unset or empty; its configured message is withheld",
                ),
            },
            Case {
                name: "required message applies to an empty value",
                expression: "VALUE:?configure VALUE",
                value: Some(""),
                expected: Err(
                    "required env var VALUE is unset or empty; its configured message is withheld",
                ),
            },
            Case {
                name: "blank required message identifies an unset value",
                expression: "VALUE:?",
                value: None,
                expected: Err("required env var VALUE is unset or empty"),
            },
            Case {
                name: "blank required message identifies an empty value",
                expression: "VALUE:?",
                value: Some(""),
                expected: Err("required env var VALUE is unset or empty"),
            },
            Case {
                name: "unsupported syntax remains invalid",
                expression: "VALUE-fallback",
                value: Some("configured"),
                expected: Err("a config expression names an invalid environment variable"),
            },
        ] {
            let actual = resolve_config_env_expression(case.expression, |_| {
                case.value.map(ToString::to_string)
            })
            .map(|(_, value)| value);
            let actual = actual.as_ref().map(String::as_str).map_err(String::as_str);
            assert_eq!(actual, case.expected, "{}", case.name);
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
