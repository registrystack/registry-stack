// SPDX-License-Identifier: Apache-2.0
//! Pure, value-free parsing of closed secret references.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::Invalid;

/// The schema pattern of an exact secret reference.
pub const SECRET_REFERENCE_PATTERN: &str =
    "^(?:secret:env/[A-Z][A-Z0-9_]{0,127}|secret:file/[a-z][a-z0-9._-]{0,127})$";

/// Closed set of providers an exact secret reference may name.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SecretProvider {
    /// An exact process environment variable.
    Environment,
    /// One named secret under a configured file root.
    File,
}

/// Parsed `secret:...` reference whose debug form never exposes the name.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SecretReference {
    reference: String,
    provider: SecretProvider,
    name_start: usize,
}

impl SecretReference {
    /// Build one exact `secret:env/NAME` or `secret:file/name` reference.
    pub fn new(reference: impl Into<String>) -> Result<Self, Invalid> {
        let reference = reference.into();
        if let Some(name) = reference.strip_prefix("secret:env/") {
            if valid_environment_name(name) {
                return Ok(Self {
                    reference,
                    provider: SecretProvider::Environment,
                    name_start: "secret:env/".len(),
                });
            }
        } else if let Some(name) = reference.strip_prefix("secret:file/") {
            if valid_file_name(name) {
                return Ok(Self {
                    reference,
                    provider: SecretProvider::File,
                    name_start: "secret:file/".len(),
                });
            }
        }
        Err(invalid_reference())
    }

    /// Parse one exact `secret:env/NAME` or `secret:file/name` reference.
    pub fn parse(reference: impl Into<String>) -> Result<Self, Invalid> {
        Self::new(reference)
    }

    /// The provider the reference names.
    #[must_use]
    pub fn provider(&self) -> SecretProvider {
        self.provider
    }

    /// The provider-local name, kept exactly as written.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.reference[self.name_start..]
    }

    /// The complete reference, kept exactly as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.reference
    }
}

impl Serialize for SecretReference {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.reference)
    }
}

impl<'de> Deserialize<'de> for SecretReference {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for SecretReference {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecretReference")
            .field("provider", &self.provider)
            .field("name", &"[REDACTED]")
            .finish()
    }
}

fn invalid_reference() -> Invalid {
    Invalid::expected(
        "an exact secret:env/NAME or secret:file/name reference",
        "Write the reference as secret:env/NAME or secret:file/name.",
    )
}

fn valid_environment_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    matches!(bytes.first(), Some(b'A'..=b'Z'))
        && bytes.len() <= 128
        && bytes[1..]
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
}

fn valid_file_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes.len() <= 128
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for SecretReference {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "SecretReference".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "An exact secret reference: secret:file/name, resolved under secretProviders.file.root, or secret:env/NAME, resolved only when secretProviders.environment is declared.",
            "type": "string",
            "pattern": SECRET_REFERENCE_PATTERN
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_references_use_only_the_two_exact_grammars() {
        for (valid, provider, name) in [
            ("secret:env/A", SecretProvider::Environment, "A"),
            (
                "secret:env/SOURCE_2_PASSWORD",
                SecretProvider::Environment,
                "SOURCE_2_PASSWORD",
            ),
            ("secret:file/a", SecretProvider::File, "a"),
            (
                "secret:file/source-token_v2.json",
                SecretProvider::File,
                "source-token_v2.json",
            ),
        ] {
            let reference = SecretReference::new(valid).expect("valid reference parses");
            assert_eq!(reference.provider(), provider);
            assert_eq!(reference.name(), name);
            assert_eq!(reference.as_str(), valid);
        }
        for invalid in [
            "secret:env/",
            "secret:env/lower",
            "secret:env/A-B",
            "secret:environment/A",
            "secret:file/Upper",
            "secret:file/../token",
            "secret:file/nested/token",
            "secret:file/.token",
            "secret:file/token\0suffix",
            "plain-value",
        ] {
            assert!(SecretReference::new(invalid).is_err(), "{invalid:?}");
        }
        assert!(SecretReference::new(format!("secret:env/A{}", "B".repeat(127))).is_ok());
        assert!(SecretReference::new(format!("secret:env/A{}", "B".repeat(128))).is_err());
        assert!(SecretReference::new(format!("secret:file/a{}", "b".repeat(127))).is_ok());
        assert!(SecretReference::new(format!("secret:file/a{}", "b".repeat(128))).is_err());
    }

    #[test]
    fn parse_and_serde_keep_the_exact_reference() {
        let parsed = SecretReference::parse("secret:file/source-token_v2.json")
            .expect("valid reference parses");
        assert_eq!(
            serde_json::to_value(&parsed).unwrap(),
            "secret:file/source-token_v2.json"
        );
        let decoded: SecretReference =
            serde_json::from_str("\"secret:env/SOURCE_2_PASSWORD\"").unwrap();
        assert_eq!(decoded.as_str(), "secret:env/SOURCE_2_PASSWORD");
    }

    #[test]
    fn invalid_and_debug_output_never_render_the_reference_name() {
        let invalid = SecretReference::new("reference-name-canary")
            .expect_err("a literal is not a secret reference")
            .to_string();
        assert!(!invalid.contains("reference-name-canary"), "{invalid:?}");

        let reference =
            SecretReference::new("secret:file/reference-name-canary").expect("reference parses");
        let rendered = format!("{reference:?}");
        assert!(rendered.contains("File"));
        assert!(!rendered.contains("reference-name-canary"));
        assert!(!rendered.contains(reference.as_str()));
    }

    #[cfg(feature = "schema")]
    #[test]
    fn schema_preserves_the_runtime_contract() {
        use schemars::JsonSchema as _;

        assert_eq!(SecretReference::schema_name(), "SecretReference");
        let schema = SecretReference::json_schema(&mut schemars::SchemaGenerator::default());
        assert_eq!(
            serde_json::to_value(schema).unwrap(),
            serde_json::json!({
                "description": "An exact secret reference: secret:file/name, resolved under secretProviders.file.root, or secret:env/NAME, resolved only when secretProviders.environment is declared.",
                "type": "string",
                "pattern": "^(?:secret:env/[A-Z][A-Z0-9_]{0,127}|secret:file/[a-z][a-z0-9._-]{0,127})$"
            })
        );
    }
}
