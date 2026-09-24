// SPDX-License-Identifier: Apache-2.0

//! Environment values in the runtime configuration.
//!
//! The runtime document may carry `${VAR}`, `${VAR:-default}`, or
//! `${VAR:?message}` inside a string value. Substitution happens after the
//! YAML is parsed, one string scalar at a time, so a substituted value is
//! always text and can never add a key, a list entry, or a document. It is
//! refused in every member whose name ends in `Ref`: a credential is named by
//! a `secret:` reference the resolver reads, never by text an environment
//! variable spliced in.
//!
//! This follows the rule the config convergence work sets for every runtime.
//! It is local until the shared loader in `registry-platform-config` carries
//! it; the refusals here are the ones that loader must keep.

use serde_norway::Value;

/// The suffix naming a credential member. Every secret reference in the
/// runtime document is spelled this way.
const CREDENTIAL_MEMBER_SUFFIX: &str = "Ref";

/// Why a `${...}` expression was refused. The path names the member; the
/// substituted value never appears, and neither does the default text of a
/// `:-` expression, since either might be a credential typed in the wrong
/// place.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubstitutionError {
    pub path: String,
    pub reason: String,
}

/// Substitute every expression in `document`, reading variables through
/// `lookup`.
pub fn substitute(
    document: &mut Value,
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<(), SubstitutionError> {
    walk(document, "", false, lookup)
}

fn walk(
    value: &mut Value,
    path: &str,
    credential: bool,
    lookup: &impl Fn(&str) -> Option<String>,
) -> Result<(), SubstitutionError> {
    match value {
        Value::String(text) => {
            if !text.contains("${") {
                return Ok(());
            }
            if credential {
                return Err(SubstitutionError {
                    path: display_path(path),
                    reason: "an environment expression is not accepted in a credential \
                             member; name the secret with a secret:env/NAME or \
                             secret:file/name reference instead"
                        .to_owned(),
                });
            }
            *text = expand(text, lookup).map_err(|reason| SubstitutionError {
                path: display_path(path),
                reason,
            })?;
            Ok(())
        }
        Value::Sequence(entries) => {
            for (index, entry) in entries.iter_mut().enumerate() {
                walk(entry, &format!("{path}[{index}]"), credential, lookup)?;
            }
            Ok(())
        }
        Value::Mapping(mapping) => {
            for (key, entry) in mapping.iter_mut() {
                let name = key.as_str().unwrap_or("?");
                let child = if path.is_empty() {
                    name.to_owned()
                } else {
                    format!("{path}.{name}")
                };
                let is_credential = credential || name.ends_with(CREDENTIAL_MEMBER_SUFFIX);
                walk(entry, &child, is_credential, lookup)?;
            }
            Ok(())
        }
        Value::Tagged(tagged) => walk(&mut tagged.value, path, credential, lookup),
        Value::Null | Value::Bool(_) | Value::Number(_) => Ok(()),
    }
}

fn display_path(path: &str) -> String {
    if path.is_empty() {
        "/".to_owned()
    } else {
        path.to_owned()
    }
}

fn expand(text: &str, lookup: &impl Fn(&str) -> Option<String>) -> Result<String, String> {
    let mut expanded = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("${") {
        expanded.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| "an environment expression is not terminated by `}`".to_owned())?;
        expanded.push_str(&resolve(&after[..end], lookup)?);
        rest = &after[end + 1..];
    }
    expanded.push_str(rest);
    Ok(expanded)
}

fn resolve(expression: &str, lookup: &impl Fn(&str) -> Option<String>) -> Result<String, String> {
    let (name, fallback) = if let Some((name, default)) = expression.split_once(":-") {
        (name, Fallback::Default(default))
    } else if let Some((name, message)) = expression.split_once(":?") {
        (name, Fallback::Required(message))
    } else {
        (expression, Fallback::None)
    };
    if !valid_variable_name(name) {
        return Err(
            "an environment expression names an invalid variable; use ASCII letters, digits, \
             and underscores, not starting with a digit"
                .to_owned(),
        );
    }
    let value = match (lookup(name).filter(|value| !value.is_empty()), fallback) {
        (Some(value), _) => value,
        (None, Fallback::Default(default)) => default.to_owned(),
        (None, Fallback::Required(message)) if !message.trim().is_empty() => {
            return Err(format!(
                "environment variable {name} is required: {message}"
            ));
        }
        (None, _) => {
            return Err(format!(
                "environment variable {name} is unset or empty and the expression gives no default"
            ));
        }
    };
    if value.contains('\0') {
        return Err(format!("environment variable {name} contains a NUL byte"));
    }
    Ok(value)
}

enum Fallback<'a> {
    None,
    Default(&'a str),
    Required(&'a str),
}

fn valid_variable_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    bytes
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(text: &str) -> Value {
        serde_norway::from_str(text).unwrap()
    }

    fn lookup(name: &str) -> Option<String> {
        match name {
            "BIND" => Some("127.0.0.1:9000".to_owned()),
            "EMPTY" => Some(String::new()),
            "NUL" => Some("a\0b".to_owned()),
            "SNEAKY" => Some("x\nkind: Other".to_owned()),
            _ => None,
        }
    }

    #[test]
    fn a_string_value_is_substituted_after_parsing() {
        let mut value =
            document("listener:\n  bind: ${BIND}\naudit:\n  path: /var/${UNSET:-log}/a\n");
        substitute(&mut value, &lookup).unwrap();
        assert_eq!(value["listener"]["bind"].as_str(), Some("127.0.0.1:9000"));
        assert_eq!(value["audit"]["path"].as_str(), Some("/var/log/a"));
    }

    #[test]
    fn a_substituted_value_stays_one_string() {
        let mut value = document("apiVersion: v\nkind: ${SNEAKY}\n");
        substitute(&mut value, &lookup).unwrap();
        assert_eq!(value["kind"].as_str(), Some("x\nkind: Other"));
        assert_eq!(value.as_mapping().unwrap().len(), 2);
    }

    #[test]
    fn an_expression_in_a_credential_member_is_refused() {
        for text in [
            "database:\n  runtimeUrlRef: ${DATABASE_URL}\n",
            "database:\n  migrationUrlRef: secret:env/${NAME:-X}\n",
            "audit:\n  hashKeyRef: ${BIND}\n",
            "authentication:\n  oidc:\n    jwksSource:\n      kind: static\n      documentRef: ${BIND}\n",
        ] {
            let mut value = document(text);
            let error = substitute(&mut value, &lookup).unwrap_err();
            assert!(error.path.ends_with("Ref"), "{error:?}");
            assert!(error.reason.contains("credential member"));
        }
    }

    #[test]
    fn an_unset_variable_without_a_default_is_refused() {
        let mut value = document("listener:\n  bind: ${MISSING}\n");
        let error = substitute(&mut value, &lookup).unwrap_err();
        assert_eq!(error.path, "listener.bind");
        assert!(error.reason.contains("MISSING"));

        let mut value = document("listener:\n  bind: ${EMPTY}\n");
        assert!(substitute(&mut value, &lookup).is_err());

        let mut value = document("listener:\n  bind: ${MISSING:?set the listener address}\n");
        let error = substitute(&mut value, &lookup).unwrap_err();
        assert!(error.reason.contains("set the listener address"));
    }

    #[test]
    fn malformed_expressions_and_nul_values_are_refused() {
        for text in ["a: ${BIND\n", "a: ${1BAD}\n", "a: ${}\n", "a: ${NUL}\n"] {
            let mut value = document(text);
            assert!(substitute(&mut value, &lookup).is_err(), "{text}");
        }
    }

    #[test]
    fn a_refusal_never_repeats_the_value_or_the_default() {
        let mut value = document("database:\n  runtimeUrlRef: ${X:-postgres://user:hunter2@db}\n");
        let error = substitute(&mut value, &lookup).unwrap_err();
        assert!(!format!("{error:?}").contains("hunter2"));
        let mut value = document("listener:\n  bind: ${NUL}\n");
        let error = substitute(&mut value, &lookup).unwrap_err();
        assert!(!format!("{error:?}").contains("a\0b"));
    }
}
