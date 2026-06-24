// SPDX-License-Identifier: Apache-2.0
//! Vocabulary prefix registry and URI expansion.
//!
//! Behavior here is intentionally simple: declare URIs, do not resolve
//! or reason about them. No HTTP fetch, no SKOS, no validation against
//! vocabulary contents.
//!
//! The accepted shapes are:
//!
//! - `prefix:suffix` where `prefix` is registered: returns
//!   `<base><suffix>`. The base is taken verbatim from the registry,
//!   including its trailing `/` or `#`.
//! - An absolute URI starting with `http://`, `https://`, or `urn:`:
//!   returned unchanged.
//! - Anything else: `None`.

use std::collections::BTreeMap;

use crate::error::ConfigError;

/// Pattern: lowercase ASCII letter, then zero or more `[a-z0-9_]`.
/// Matches `IdRegex` over in `validate.rs`. Reproduced inline so this
/// module can validate the registry without a circular `mod` dep.
fn is_valid_prefix(prefix: &str) -> bool {
    let mut chars = prefix.chars();
    match chars.next() {
        Some(c) if c.is_ascii_lowercase() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Returns `true` if the input looks like an absolute URI: starts with
/// one of `http://`, `https://`, or `urn:`.
#[must_use]
pub fn is_absolute_uri(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://") || s.starts_with("urn:")
}

/// Expand a possibly prefixed URI against the registry.
///
/// Returns:
/// - `Some(<base><suffix>)` if `input` has the form `<prefix>:<suffix>`
///   and `prefix` is registered.
/// - `Some(input.to_string())` if `input` is an absolute URI.
/// - `None` otherwise.
///
/// Note: an absolute URI takes precedence over prefix lookup. The
/// registry never contains a base URI for `http`, so this is purely a
/// formality, but it keeps the precedence explicit.
#[must_use]
pub fn expand(input: &str, registry: &BTreeMap<String, String>) -> Option<String> {
    if is_absolute_uri(input) {
        return Some(input.to_string());
    }
    let (prefix, suffix) = input.split_once(':')?;
    let base = registry.get(prefix)?;
    Some(format!("{base}{suffix}"))
}

/// Validate a prefix registry: every prefix matches the identifier
/// pattern, every base URI ends with `/` or `#`. Failure returns
/// [`ConfigError::ValidationError`]; the offending prefix is logged via
/// `tracing` at error level by the caller.
///
/// # Errors
///
/// Returns [`ConfigError::ValidationError`] if any prefix or base URI
/// is malformed.
pub fn validate_registry(registry: &BTreeMap<String, String>) -> Result<(), ConfigError> {
    for (prefix, base) in registry {
        if !is_valid_prefix(prefix) {
            tracing::error!(
                code = "config.validation_error",
                prefix = %prefix,
                "vocabulary prefix does not match ^[a-z][a-z0-9_]*$"
            );
            return Err(ConfigError::ValidationError);
        }
        if !(base.ends_with('/') || base.ends_with('#')) {
            tracing::error!(
                code = "config.validation_error",
                prefix = %prefix,
                "vocabulary base URI must end with '/' or '#'"
            );
            return Err(ConfigError::ValidationError);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> BTreeMap<String, String> {
        let mut r = BTreeMap::new();
        r.insert("psc".into(), "https://publicschema.org/".into());
        r.insert(
            "sdmx".into(),
            "http://purl.org/linked-data/sdmx/2009/concept#".into(),
        );
        r
    }

    #[test]
    fn expands_prefixed_with_slash_base() {
        let r = registry();
        assert_eq!(
            expand("psc:concepts/Person", &r).as_deref(),
            Some("https://publicschema.org/concepts/Person")
        );
    }

    #[test]
    fn expands_prefixed_with_hash_base() {
        let r = registry();
        assert_eq!(
            expand("sdmx:OBS_VALUE", &r).as_deref(),
            Some("http://purl.org/linked-data/sdmx/2009/concept#OBS_VALUE")
        );
    }

    #[test]
    fn passes_through_absolute_uris() {
        let r = registry();
        assert_eq!(
            expand("https://schema.org/Person", &r).as_deref(),
            Some("https://schema.org/Person")
        );
        assert_eq!(
            expand("http://example/x", &r).as_deref(),
            Some("http://example/x")
        );
        assert_eq!(
            expand("urn:isbn:0451450523", &r).as_deref(),
            Some("urn:isbn:0451450523")
        );
    }

    #[test]
    fn rejects_unknown_prefix() {
        let r = registry();
        assert!(expand("nope:Foo", &r).is_none());
    }

    #[test]
    fn rejects_unprefixed_non_uri() {
        let r = registry();
        assert!(expand("BareString", &r).is_none());
    }

    #[test]
    fn validate_registry_accepts_canonical() {
        validate_registry(&registry()).expect("canonical registry is valid");
    }

    #[test]
    fn validate_registry_rejects_bad_prefix() {
        let mut r = BTreeMap::new();
        r.insert("BadCase".into(), "https://example/".into());
        assert!(validate_registry(&r).is_err());
    }

    #[test]
    fn validate_registry_rejects_missing_terminator() {
        let mut r = BTreeMap::new();
        r.insert("ok".into(), "https://example".into());
        assert!(validate_registry(&r).is_err());
    }
}
