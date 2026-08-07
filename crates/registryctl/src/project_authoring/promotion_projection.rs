// SPDX-License-Identifier: Apache-2.0
//! Private projection embedded in the current reviewed build state.
//!
//! This is not a public promotion contract. The authoring compiler emits the
//! projection into signed approval state, and review comparison validates it
//! when loading an approved baseline.

use serde::{Deserialize, Serialize};

const MAX_PROMOTION_AUTHORITY_MEMBERS: usize = 8_192;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PromotionDocument {
    Project,
    Environment,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
pub(crate) enum PromotionFieldPath {
    #[serde(rename = "/integrations/*/origin")]
    IntegrationOrigin,
    #[serde(rename = "/integrations/*/credentials")]
    IntegrationCredentials,
    #[serde(rename = "/integrations/*/trust")]
    IntegrationTrust,
    #[serde(rename = "/operations")]
    OperationalSettings,
    #[serde(rename = "/purposes/*")]
    Purpose,
    #[serde(rename = "/service_policy")]
    ServicePolicy,
    #[serde(rename = "/products/*")]
    ProductEnablement,
    #[serde(rename = "/integrations/*/capabilities/*")]
    CapabilityEnablement,
    #[serde(rename = "/integrations/*/limits")]
    IntegrationCeiling,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PromotionFieldAddress {
    pub document: PromotionDocument,
    pub path: PromotionFieldPath,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PromotionChangeKind {
    Origin,
    CredentialBinding,
    Trust,
    Operational,
    Purpose,
    ServicePolicy,
    ProductEnablement,
    CapabilityEnablement,
    IntegrationCeiling,
}

impl PromotionChangeKind {
    pub(crate) const ALL: [Self; 9] = [
        Self::Origin,
        Self::CredentialBinding,
        Self::Trust,
        Self::Operational,
        Self::Purpose,
        Self::ServicePolicy,
        Self::ProductEnablement,
        Self::CapabilityEnablement,
        Self::IntegrationCeiling,
    ];

    pub(crate) const fn address(self) -> PromotionFieldAddress {
        let (document, path) = match self {
            Self::Origin => (
                PromotionDocument::Environment,
                PromotionFieldPath::IntegrationOrigin,
            ),
            Self::CredentialBinding => (
                PromotionDocument::Environment,
                PromotionFieldPath::IntegrationCredentials,
            ),
            Self::Trust => (
                PromotionDocument::Environment,
                PromotionFieldPath::IntegrationTrust,
            ),
            Self::Operational => (
                PromotionDocument::Environment,
                PromotionFieldPath::OperationalSettings,
            ),
            Self::ProductEnablement => (
                PromotionDocument::Environment,
                PromotionFieldPath::ProductEnablement,
            ),
            Self::CapabilityEnablement => (
                PromotionDocument::Environment,
                PromotionFieldPath::CapabilityEnablement,
            ),
            Self::IntegrationCeiling => (
                PromotionDocument::Project,
                PromotionFieldPath::IntegrationCeiling,
            ),
            Self::Purpose => (PromotionDocument::Project, PromotionFieldPath::Purpose),
            Self::ServicePolicy => (
                PromotionDocument::Project,
                PromotionFieldPath::ServicePolicy,
            ),
        };
        PromotionFieldAddress { document, path }
    }

    pub(crate) const fn expected_ownership(self) -> PromotionFieldOwnership {
        if matches!(
            self,
            Self::Origin
                | Self::CredentialBinding
                | Self::Trust
                | Self::Operational
                | Self::ProductEnablement
                | Self::CapabilityEnablement
        ) {
            PromotionFieldOwnership::EnvironmentOwned
        } else {
            PromotionFieldOwnership::ReviewedProjectOwned
        }
    }

    pub(crate) const fn expected_classification(self) -> PromotionFieldClassification {
        match self {
            Self::CredentialBinding => PromotionFieldClassification::SecretReference,
            Self::Origin | Self::Trust => PromotionFieldClassification::Sensitive,
            Self::Operational | Self::Purpose | Self::ServicePolicy => {
                PromotionFieldClassification::Internal
            }
            Self::ProductEnablement | Self::CapabilityEnablement | Self::IntegrationCeiling => {
                PromotionFieldClassification::Structural
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PromotionFieldClassification {
    Internal,
    Sensitive,
    SecretReference,
    Structural,
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PromotionFieldOwnership {
    EnvironmentOwned,
    ReviewedProjectOwned,
    Unclassified,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub(crate) enum ProjectPromotionProjectionSchemaVersion {
    #[serde(rename = "registry.project.promotion-projection.v1")]
    V1,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PromotionProjectedProduct {
    Relay,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum PromotionProjectedCapability {
    Http,
    Script,
    Snapshot,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PromotionAuthoringSchemaVersions {
    pub project: u8,
    pub environment: u8,
    pub integrations: Vec<u8>,
    pub entities: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PromotionProjectedField {
    pub address: PromotionFieldAddress,
    pub kind: PromotionChangeKind,
    pub classification: PromotionFieldClassification,
    pub ownership: PromotionFieldOwnership,
    pub digest: String,
    pub authority_members: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ProjectPromotionProjectionV1 {
    pub schema_version: ProjectPromotionProjectionSchemaVersion,
    pub field_knowledge_revision: String,
    pub authoring_schemas: PromotionAuthoringSchemaVersions,
    pub products: Vec<PromotionProjectedProduct>,
    pub capabilities: Vec<PromotionProjectedCapability>,
    pub fields: Vec<PromotionProjectedField>,
}

pub(crate) fn validate_project_promotion_projection(
    projection: &ProjectPromotionProjectionV1,
    expected_field_knowledge_revision: &str,
) -> Result<(), &'static str> {
    validate_project_promotion_projection_structure(projection)?;
    if projection.field_knowledge_revision != expected_field_knowledge_revision {
        return Err("promotion projection field-knowledge revision is not current");
    }
    Ok(())
}

pub(crate) fn validate_project_promotion_projection_structure(
    projection: &ProjectPromotionProjectionV1,
) -> Result<(), &'static str> {
    if projection.schema_version != ProjectPromotionProjectionSchemaVersion::V1 {
        return Err("promotion projection has an unsupported schema version");
    }
    if !is_sha256_uri(&projection.field_knowledge_revision) {
        return Err("promotion projection field-knowledge revision is invalid");
    }
    if projection.authoring_schemas.project == 0
        || projection.authoring_schemas.environment == 0
        || projection.authoring_schemas.integrations.contains(&0)
        || projection.authoring_schemas.entities.contains(&0)
        || !is_strictly_sorted_unique(&projection.authoring_schemas.integrations)
        || !is_strictly_sorted_unique(&projection.authoring_schemas.entities)
    {
        return Err("promotion projection authoring schema versions are invalid");
    }
    if projection.products.is_empty()
        || !is_strictly_sorted_unique(&projection.products)
        || !is_strictly_sorted_unique(&projection.capabilities)
    {
        return Err("promotion projection product or capability inventory is invalid");
    }
    if projection.fields.len() != PromotionChangeKind::ALL.len() {
        return Err("promotion projection must cover every classified field address exactly once");
    }

    for (expected_kind, field) in PromotionChangeKind::ALL.iter().zip(&projection.fields) {
        if field.kind != *expected_kind
            || field.address != field.kind.address()
            || field.ownership != field.kind.expected_ownership()
            || field.classification != field.kind.expected_classification()
            || !is_sha256_uri(&field.digest)
            || field.authority_members.len() > MAX_PROMOTION_AUTHORITY_MEMBERS
            || field
                .authority_members
                .iter()
                .any(|member| !is_sha256_uri(member))
            || !is_strictly_sorted_unique(&field.authority_members)
        {
            return Err("promotion projection field evidence is incomplete or non-canonical");
        }
    }
    Ok(())
}

fn is_strictly_sorted_unique<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn is_sha256_uri(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use crate::project_authoring::{
        knowledge, load_registry_project, project_promotion_capability_enabled,
        project_promotion_projection, promotion_kind_for_field_path,
        validate_promotion_field_knowledge_mapping, PromotionChangeKind,
        PromotionProjectedCapability, PROMOTION_FIELD_KNOWLEDGE_REVISION,
    };

    #[test]
    fn published_field_paths_require_current_projection_mapping() {
        let revision = validate_promotion_field_knowledge_mapping()
            .expect("field knowledge mapping is current");
        assert_eq!(revision, PROMOTION_FIELD_KNOWLEDGE_REVISION);

        let index = knowledge::published_field_knowledge_index().expect("knowledge indexes");
        assert_eq!(index.by_path().len(), 562);
        let mapped = index
            .by_path()
            .keys()
            .filter_map(promotion_kind_for_field_path)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            mapped,
            PromotionChangeKind::ALL
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
        assert!(index.by_path().keys().all(|path| {
            promotion_kind_for_field_path(path).is_some()
                || path.schema == knowledge::SchemaKind::Fixture
        }));
    }

    #[test]
    fn snapshot_entity_enablement_is_bound_into_the_capability_projection() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/project-authoring/snapshot-exact");
        let loaded = load_registry_project(&root, Some("local")).expect("snapshot project loads");
        let environment = loaded
            .environment
            .as_ref()
            .expect("snapshot project has an environment");
        let projection =
            project_promotion_projection(&loaded, environment).expect("projection builds");

        assert_eq!(
            projection.capabilities,
            vec![PromotionProjectedCapability::Snapshot]
        );
        let capability = projection
            .fields
            .iter()
            .find(|field| field.kind == PromotionChangeKind::CapabilityEnablement)
            .expect("capability field is projected");
        assert_eq!(capability.authority_members.len(), 1);
        let integration = loaded
            .integrations
            .get("person-snapshot")
            .expect("snapshot integration exists");
        assert!(project_promotion_capability_enabled(
            "person-snapshot",
            &integration.document.capability,
            environment,
        ));
    }
}
