//! Pure scalar contracts in target bindings that are not network URLs.

use registry_platform_yaml::{ExternalId, Invalid};
use serde::{Deserialize, Deserializer, Serialize};

/// The Evidence issuer identifier, including URNs. It names the signer; it is
/// never fetched as a network endpoint. The governed bundle revalidates it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TargetIssuerId(ExternalId);

impl<'de> Deserialize<'de> for TargetIssuerId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = ExternalId::deserialize(deserializer)?;
        if value.chars().any(char::is_whitespace) || url::Url::parse(&value).is_err() {
            return Err(Invalid::expected(
                "an absolute Evidence issuer URI identifier within 512 characters without whitespace or control characters",
                "Write an absolute URI such as a URN or HTTPS identifier; this member does not name a network endpoint.",
            ).into_error());
        }
        Ok(Self(value))
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for TargetIssuerId {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "TargetIssuerId".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string", "format": "uri", "minLength": 1, "maxLength": 512,
            "pattern": r"^[A-Za-z][A-Za-z0-9+.-]*:[^\u0000-\u0020\u007F-\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]*$",
            "description": "An absolute Evidence issuer URI identifier, including URNs, within 512 Unicode characters and without whitespace or control characters. It names the signer and is never fetched; it is not an OIDC issuer or a network origin."
        })
    }
}

/// A direct JWT claim name. Dots remain literal characters, never paths.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct TargetClaimName(ExternalId);

impl<'de> Deserialize<'de> for TargetClaimName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = ExternalId::deserialize(deserializer)?;
        let bytes = value.as_bytes();
        if bytes.len() > 128
            || !matches!(bytes.first(), Some(b'A'..=b'Z' | b'a'..=b'z' | b'_'))
            || !bytes[1..]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
        {
            return Err(Invalid::expected(
                "a direct JWT claim name matching [A-Za-z_][A-Za-z0-9_.-]{0,127}",
                "Write one direct claim name within 128 ASCII bytes; a dot is a literal character, not a nested path.",
            ).into_error());
        }
        Ok(Self(value))
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for TargetClaimName {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "TargetClaimName".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string", "minLength": 1, "maxLength": 128,
            "pattern": "^[A-Za-z_][A-Za-z0-9_.-]{0,127}$",
            "description": "The name of one direct JWT claim, within 128 ASCII bytes. Dots are literal characters. Omit to retain the governed runtime's default claim name; claim-role uniqueness and reserved names are revalidated with the complete authentication configuration."
        })
    }
}
