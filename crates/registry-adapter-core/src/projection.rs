// SPDX-License-Identifier: Apache-2.0

//! Normalized read operations for an independently governed projection host.

use registry_platform_yaml::BoundedU64;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::ScriptReference;

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProjectionOperationKind {
    Exact,
    Batch,
    ByParent,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProjectionRetention {
    LiveOnly,
    Retain,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProjectionAbsence {
    Protected,
    Authoritative,
}

/// Whether the source authorizes disclosure under the host's narrower
/// profiles when acquisition uses a shared service identity.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProjectionLocalDisclosure {
    AcquisitionOnly,
    HostProfiles,
}

/// A reviewed source operation's ceiling. The host still has to establish its
/// own current project grant, connection and eligible selectors before I/O.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectionRouteContract {
    pub operation: ProjectionOperationKind,
    pub operation_version: String,
    pub authority: String,
    pub purpose: String,
    pub scope: String,
    pub selector_scheme: String,
    pub record_key_scheme: String,
    pub retention: ProjectionRetention,
    pub absence: ProjectionAbsence,
    pub local_disclosure: ProjectionLocalDisclosure,
    pub fields_schema: ScriptReference,
    pub maximum_batch_keys: BoundedU64<1, 1000>,
    pub maximum_pages: BoundedU64<1, 100>,
    pub maximum_rows: BoundedU64<1, 10000>,
}

impl ProjectionRouteContract {
    #[must_use]
    pub fn identifiers_valid(&self) -> bool {
        [
            &self.operation_version,
            &self.authority,
            &self.purpose,
            &self.scope,
            &self.selector_scheme,
            &self.record_key_scheme,
        ]
        .into_iter()
        .all(|identifier| projection_token_valid(identifier))
            && (self.operation == ProjectionOperationKind::ByParent
                || self.selector_scheme == self.record_key_scheme)
    }
}

/// Bounds a selector, row key, revision or cursor without normalizing it.
/// The binding reviewed with the source establishes the actual scheme.
#[must_use]
pub fn projection_token_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 512
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProjectionMode {
    Live,
    Indexed,
}

/// The complete root selection already authorized by the host. Collection
/// cursors are internal to the Adapter; callers cannot supply them.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ProjectionRequest {
    Exact { key: String },
    Batch { keys: Vec<String> },
    ByParent { parent_key: String },
}

impl ProjectionRequest {
    #[must_use]
    pub fn kind(&self) -> ProjectionOperationKind {
        match self {
            Self::Exact { .. } => ProjectionOperationKind::Exact,
            Self::Batch { .. } => ProjectionOperationKind::Batch,
            Self::ByParent { .. } => ProjectionOperationKind::ByParent,
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "outcome",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ProjectionRecord {
    Present {
        key: String,
        fields: Map<String, Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_revision: Option<String>,
    },
    AuthoritativeAbsent {
        key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_revision: Option<String>,
    },
    Unavailable {
        key: String,
    },
}

impl ProjectionRecord {
    #[must_use]
    pub fn key(&self) -> &str {
        match self {
            Self::Present { key, .. }
            | Self::AuthoritativeAbsent { key, .. }
            | Self::Unavailable { key } => key,
        }
    }
}

#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProjectionRow {
    pub key: String,
    pub parent_key: String,
    pub fields: Map<String, Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_revision: Option<String>,
}

/// Returned only after structural and scope checks. A ByParent result means
/// every page of one snapshot passed; interruption yields no collection.
#[derive(Clone, PartialEq, Serialize)]
#[serde(
    tag = "type",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase"
)]
pub enum ProjectionResult {
    Exact {
        record: ProjectionRecord,
    },
    Batch {
        records: Vec<ProjectionRecord>,
    },
    ByParent {
        parent_key: String,
        snapshot: String,
        rows: Vec<ProjectionRow>,
    },
}

// Do not make source values visible through diagnostics or tracing fields.
macro_rules! redact_projection_debug {
    ($($name:ident),+) => {$(
        impl std::fmt::Debug for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
    )+};
}
redact_projection_debug!(
    ProjectionRequest,
    ProjectionRecord,
    ProjectionRow,
    ProjectionResult
);
