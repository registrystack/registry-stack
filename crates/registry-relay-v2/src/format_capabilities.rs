// SPDX-License-Identifier: Apache-2.0
//! Derived response wire formats for one compiled access profile.

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
    resource.primary_geometry.as_ref().is_some_and(|name| {
        resource
            .properties
            .iter()
            .any(|property| property.name == *name && property.point_binding().is_some())
            && access_profile
                .selectable_properties
                .iter()
                .any(|property| property == name)
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
