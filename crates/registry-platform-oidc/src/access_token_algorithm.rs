//! The asymmetric access-token signature algorithms a resource server may
//! admit, spelled as configuration spells them.

use serde::{Deserialize, Serialize};

/// An asymmetric access-token signature algorithm.
///
/// The configuration spelling is the JWA name (`EdDSA`, `ES256`, `ES384`,
/// `RS256`, `RS384`), one spelling per value and no aliases. Symmetric
/// (`HS*`) and any other algorithm are not members, so a configuration
/// naming one is refused while it loads as an unknown variant.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum AccessTokenAlgorithm {
    EdDSA,
    ES256,
    ES384,
    RS256,
    RS384,
}

impl AccessTokenAlgorithm {
    /// Every member, in configuration order.
    pub const ALL: [Self; 5] = [
        Self::EdDSA,
        Self::ES256,
        Self::ES384,
        Self::RS256,
        Self::RS384,
    ];

    /// The `jsonwebtoken` algorithm this member names.
    #[must_use]
    pub const fn to_jsonwebtoken(self) -> jsonwebtoken::Algorithm {
        match self {
            Self::EdDSA => jsonwebtoken::Algorithm::EdDSA,
            Self::ES256 => jsonwebtoken::Algorithm::ES256,
            Self::ES384 => jsonwebtoken::Algorithm::ES384,
            Self::RS256 => jsonwebtoken::Algorithm::RS256,
            Self::RS384 => jsonwebtoken::Algorithm::RS384,
        }
    }

    /// The JWS `alg` value, which is also the configuration spelling.
    #[must_use]
    pub const fn jwa_name(self) -> &'static str {
        match self {
            Self::EdDSA => "EdDSA",
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
        }
    }

    /// A closed string enum schema naming exactly `allowed`, in the order
    /// given. A product whose configuration admits fewer members than the
    /// roster publishes the schema of the members it admits.
    #[cfg(feature = "schema")]
    #[must_use]
    pub fn subset_schema(allowed: &[Self]) -> schemars::Schema {
        let names: Vec<&str> = allowed.iter().map(|member| member.jwa_name()).collect();
        schemars::json_schema!({ "type": "string", "enum": names })
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for AccessTokenAlgorithm {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "AccessTokenAlgorithm".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        Self::subset_schema(&Self::ALL)
    }
}

#[cfg(test)]
mod tests {
    use super::AccessTokenAlgorithm;
    use registry_platform_yaml::{ApiVersion, EnvelopeRule, Expect, FormatSpec, Reader};
    use serde::Deserialize;

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    #[allow(dead_code)]
    struct Holder {
        algorithms: Vec<AccessTokenAlgorithm>,
    }

    const API_VERSION: &str = "id.registrystack.org/formats/example/runtime/v1alpha1";
    const FORMAT: FormatSpec = FormatSpec {
        kind: "ExampleRuntimeConfig",
        envelope: EnvelopeRule::ApiVersionKind {
            api_versions: &[ApiVersion::current(API_VERSION)],
            retired_api_versions: &[],
        },
        removed_keys: &[],
    };

    fn decode(value: &str) -> Result<Holder, registry_platform_yaml::Report> {
        let text = format!(
            "apiVersion: {API_VERSION}\nkind: ExampleRuntimeConfig\nalgorithms: [{value}]\n"
        );
        let expect = Expect::one(&FORMAT);
        Reader::new("runtime.yaml")
            .decode::<Holder>(text.as_bytes(), &expect)
            .map(|decoded| decoded.value)
    }

    #[test]
    fn every_roster_value_decodes_and_maps() {
        let expected = [
            ("EdDSA", jsonwebtoken::Algorithm::EdDSA),
            ("ES256", jsonwebtoken::Algorithm::ES256),
            ("ES384", jsonwebtoken::Algorithm::ES384),
            ("RS256", jsonwebtoken::Algorithm::RS256),
            ("RS384", jsonwebtoken::Algorithm::RS384),
        ];
        assert_eq!(AccessTokenAlgorithm::ALL.len(), expected.len());
        for (name, mapped) in expected {
            let holder = decode(name).unwrap_or_else(|report| panic!("{name}: {report}"));
            let [algorithm] = holder.algorithms[..] else {
                panic!("one algorithm expected");
            };
            assert_eq!(algorithm.to_jsonwebtoken(), mapped, "{name}");
            assert_eq!(algorithm.jwa_name(), name);
            assert!(AccessTokenAlgorithm::ALL.contains(&algorithm));
        }
    }

    #[test]
    fn symmetric_unknown_and_respelled_values_are_refused_as_unknown_variants() {
        for value in [
            "HS256", "HS384", "HS512", "PS256", "PS384", "ES512", "RS512", "none", "eddsa",
            "es256", "Rs256", "ed25519", "EdDSA ", "",
        ] {
            let report =
                decode(&format!("\"{value}\"")).expect_err(&format!("{value:?} must be refused"));
            let diagnostics = report.diagnostics();
            assert_eq!(diagnostics.len(), 1, "{value:?}: {report}");
            assert_eq!(diagnostics[0].code, "config.unknown-variant", "{value:?}");
            assert!(
                diagnostics[0]
                    .message
                    .contains("`EdDSA`, `ES256`, `ES384`, `RS256`, `RS384`"),
                "{value:?}: {}",
                diagnostics[0].message
            );
        }
    }

    #[test]
    fn serialization_uses_the_configuration_spelling() {
        for algorithm in AccessTokenAlgorithm::ALL {
            let json = serde_json::to_string(&algorithm).unwrap();
            assert_eq!(json, format!("\"{}\"", algorithm.jwa_name()));
            let back: AccessTokenAlgorithm = serde_json::from_str(&json).unwrap();
            assert_eq!(back, algorithm);
        }
    }

    #[cfg(feature = "schema")]
    #[test]
    fn the_schema_is_a_closed_string_enum_of_the_roster() {
        let schema = schemars::schema_for!(AccessTokenAlgorithm);
        let value = serde_json::to_value(&schema).unwrap();
        assert_eq!(value["type"], "string");
        assert_eq!(
            value["enum"],
            serde_json::json!(["EdDSA", "ES256", "ES384", "RS256", "RS384"])
        );
        let subset = AccessTokenAlgorithm::subset_schema(&[
            AccessTokenAlgorithm::RS256,
            AccessTokenAlgorithm::ES256,
        ]);
        let value = serde_json::to_value(&subset).unwrap();
        assert_eq!(value["enum"], serde_json::json!(["RS256", "ES256"]));
        assert_eq!(value["type"], "string");
    }
}
