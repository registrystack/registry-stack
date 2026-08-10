// SPDX-License-Identifier: Apache-2.0
//! One derived account of the response wire formats a compiled access profile permits.
//!
//! Format availability is presentation-only. It is derived from the immutable
//! compiled resource and access profile and never adds a second authorization
//! or disclosure plane.

use serde::{Deserialize, Serialize};

use crate::model::{CompiledAccessProfile, CompiledResource, FormatProfile};

pub const CRS84_URI: &str = "http://www.opengis.net/def/crs/OGC/0/CRS84";
pub const RFC7946_PROFILE_URI: &str = "http://www.opengis.net/def/profile/OGC/0/rfc7946";
pub const JSON_FG_PROFILE_URI: &str = "http://www.opengis.net/def/profile/OGC/0/jsonfg";
pub const JSON_FG_CORE_CONFORMANCE: &str = "http://www.opengis.net/spec/json-fg-1/1.0/conf/core";
pub const JSON_FG_TYPES_CONFORMANCE: &str =
    "http://www.opengis.net/spec/json-fg-1/1.0/conf/types-schemas";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireFormatCapability {
    pub id: WireFormatIdentifier,
    pub media_type: String,
    pub format_profiles: Vec<FormatProfileCapability>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WireFormatIdentifier {
    Json,
    JsonLd,
    Geojson,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct FormatProfileCapability {
    pub id: FormatProfileIdentifier,
    pub uri: String,
    pub crs: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conforms_to: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FormatProfileIdentifier {
    Rfc7946,
    Jsonfg,
}

#[must_use]
pub fn supports_geojson(
    resource: &CompiledResource,
    access_profile: &CompiledAccessProfile,
) -> bool {
    resource.primary_geometry.as_ref().is_some_and(|geometry| {
        access_profile
            .selectable_properties
            .iter()
            .any(|property| property == &geometry.name)
    })
}

#[must_use]
pub fn response_format_capabilities(
    resource: &CompiledResource,
    access_profile: &CompiledAccessProfile,
) -> Vec<WireFormatCapability> {
    let mut formats = vec![
        WireFormatCapability {
            id: WireFormatIdentifier::Json,
            media_type: "application/json".into(),
            format_profiles: Vec::new(),
        },
        WireFormatCapability {
            id: WireFormatIdentifier::JsonLd,
            media_type: "application/ld+json".into(),
            format_profiles: Vec::new(),
        },
    ];
    if supports_geojson(resource, access_profile) {
        formats.push(WireFormatCapability {
            id: WireFormatIdentifier::Geojson,
            media_type: "application/geo+json".into(),
            format_profiles: vec![
                format_profile_capability(FormatProfile::Rfc7946),
                format_profile_capability(FormatProfile::JsonFg),
            ],
        });
    }
    formats
}

#[must_use]
pub fn format_profile_capability(profile: FormatProfile) -> FormatProfileCapability {
    match profile {
        FormatProfile::Rfc7946 => FormatProfileCapability {
            id: FormatProfileIdentifier::Rfc7946,
            uri: RFC7946_PROFILE_URI.into(),
            crs: CRS84_URI.into(),
            conforms_to: Vec::new(),
        },
        FormatProfile::JsonFg => FormatProfileCapability {
            id: FormatProfileIdentifier::Jsonfg,
            uri: JSON_FG_PROFILE_URI.into(),
            crs: CRS84_URI.into(),
            conforms_to: vec![
                JSON_FG_CORE_CONFORMANCE.into(),
                JSON_FG_TYPES_CONFORMANCE.into(),
            ],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compiler::{compile_contract_with_governed_files, tests as compiler_tests};
    use crate::model::CompileProfile;

    #[test]
    fn geometry_disclosure_is_the_only_geojson_availability_gate() {
        let contract = compiler_tests::spatial_contract(true);
        let registry = compile_contract_with_governed_files(
            &contract,
            &[compiler_tests::spatial_observed_schema()],
            CompileProfile::Production,
            &compiler_tests::governed_files_for(&contract),
        )
        .expect("spatial contract compiles");
        let resource = &registry.resources[0];
        let access_profile = &resource.operations[0].access_profiles[0];
        assert_eq!(
            response_format_capabilities(resource, access_profile).len(),
            3
        );

        let mut hidden_geometry = access_profile.clone();
        let geometry = resource.primary_geometry.as_ref().expect("geometry");
        hidden_geometry
            .selectable_properties
            .retain(|property| property != &geometry.name);
        let formats = response_format_capabilities(resource, &hidden_geometry);
        assert_eq!(formats.len(), 2);
        assert!(formats
            .iter()
            .all(|format| format.id != WireFormatIdentifier::Geojson));
    }
}
