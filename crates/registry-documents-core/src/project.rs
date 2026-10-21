// SPDX-License-Identifier: Apache-2.0

//! The authored project document, `documents.yaml`.
//!
//! The model reads the whole project shape through the shared reader, so an
//! adopter's editor, `documentsctl check`, and the runtime refuse the same
//! documents at the same positions. It is configuration only: the decisions
//! the policies imply (who may place a document in custody, issue a grant,
//! or read a released version) are made by the runtime, and the hook
//! declarations are carried for the runtime's delivery path.

use std::collections::BTreeMap;

use registry_platform_yaml::{
    ApiVersion, BoundedU32, BoundedU64, Decoded, DisplayText, EnvelopeRule, Expect, ExternalId,
    FormatSpec, Identified, Invalid, LocalId, ProjectIdentity, Reader, Report, UniqueIdList,
    UniqueList,
};
use serde::Deserialize;

use crate::naming::{DOCUMENTS_PROJECT_API_VERSION, DOCUMENTS_PROJECT_KIND};

/// The format a `documents.yaml` file declares (CFG-ENV-1).
pub const DOCUMENTS_PROJECT_FORMAT: FormatSpec<'static> = FormatSpec {
    kind: DOCUMENTS_PROJECT_KIND,
    envelope: EnvelopeRule::ApiVersionKind {
        api_versions: &[ApiVersion::current(DOCUMENTS_PROJECT_API_VERSION)],
        retired_api_versions: &[],
    },
    removed_keys: &[],
};

/// The largest document a deployment or a policy may admit: one gibibyte.
pub const MAXIMUM_DOCUMENT_BYTES: u64 = 1_073_741_824;

/// The longest any grant or cleanup period may run, in hours: one year.
pub const MAXIMUM_PERIOD_HOURS: u32 = 8_760;

/// The authored project document, `documents.yaml`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentsProject {
    pub api_version: String,
    pub kind: String,
    pub project: ProjectIdentity,
    /// The caller profiles a document policy names, by id.
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "local_id_map_schema::<AccessProfile>")
    )]
    pub access_profiles: BTreeMap<LocalId, AccessProfile>,
    /// The policies a document is held under, by id.
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "local_id_map_schema::<DocumentPolicy>")
    )]
    pub document_policies: BTreeMap<LocalId, DocumentPolicy>,
    /// After-commit observer hooks. A project with none omits the member.
    #[serde(default)]
    pub hooks: UniqueIdList<HookPolicy>,
}

impl DocumentsProject {
    /// Read one `documents.yaml` file through the shared reader. `file` is
    /// the name diagnostics carry. A refusal is the report a check command
    /// prints unchanged. A `${...}` expression is refused: substitution
    /// applies to the runtime configuration only (CFG-SEC-2).
    pub fn decode(file: &str, bytes: &[u8]) -> Result<Decoded<Self>, Report> {
        let mut hook = registry_platform_config::AuthoredExpressions;
        Reader::new(file)
            .with_hook(&mut hook)
            .decode::<Self>(bytes, &Expect::one(&DOCUMENTS_PROJECT_FORMAT))
    }
}

/// One declared caller profile.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccessProfile {
    /// `sub`, or the name of another string claim identifying the principal.
    pub principal_claim: ExternalId,
    /// The scopes a token must carry; at least one.
    pub required_scopes: ListedIds,
    /// The OAuth clients whose tokens resolve to this profile; at least one.
    pub requester_clients: ListedIds,
    /// The actor kind the token must claim.
    pub actor_kind: ActorKind,
    /// What a caller resolved to this profile is to a document.
    pub role: AccessRole,
}

/// A list of at least one distinct external identifier. An empty list is
/// refused, because it reads as both "none" and "any" (CFG-EMPTY-2).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListedIds(Vec<ExternalId>);

impl ListedIds {
    /// The listed identifiers, in authored order.
    pub fn as_slice(&self) -> &[ExternalId] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for ListedIds {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let items = UniqueList::<ExternalId>::deserialize(deserializer)?.into_vec();
        if items.is_empty() {
            return Err(Invalid::expected(
                "a list of at least one entry",
                "List at least one entry; an empty list does not restrict anything.",
            )
            .into_error());
        }
        Ok(Self(items))
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for ListedIds {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ListedIds".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let mut schema = generator.subschema_for::<UniqueList<ExternalId>>();
        schema.insert("minItems".to_owned(), 1.into());
        schema
    }
}

/// The actor kind an access profile admits.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum ActorKind {
    Service,
    Human,
}

/// What a caller resolved to an access profile is to a document.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum AccessRole {
    /// Places documents in custody and issues document grants.
    Custodian,
    /// The person on whose behalf custody is held.
    RepresentedPrincipal,
    /// Reads exactly the document version a document grant names.
    Recipient,
}

/// One document policy: who may hold, grant, and receive a document held
/// under it, and the restrictions every such document carries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DocumentPolicy {
    pub version: String,
    pub label: DisplayText,
    /// Profiles that may place a document in custody under this policy.
    pub custody_profiles: UniqueList<LocalId>,
    /// Profiles that may issue a document grant on a document under this
    /// policy.
    pub granting_profiles: UniqueList<LocalId>,
    /// The profile a represented principal authenticates under.
    pub represented_principal_profile: LocalId,
    /// Whether the represented principal may issue document grants itself.
    pub represented_principal_grants: RepresentedPrincipalGrants,
    /// Profiles a document grant may name as its recipient.
    pub recipient_profiles: UniqueList<LocalId>,
    pub mandatory_restrictions: MandatoryRestrictions,
}

/// Whether a represented principal may issue document grants itself.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum RepresentedPrincipalGrants {
    Refused,
    Permitted,
}

/// The restrictions every document held under a policy carries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MandatoryRestrictions {
    pub maximum_document_bytes: BoundedU64<1, MAXIMUM_DOCUMENT_BYTES>,
    pub allowed_content_types: UniqueList<ExternalId>,
    pub grant_expiry_hours: BoundedU32<1, MAXIMUM_PERIOD_HOURS>,
    pub maximum_grant_expiry_hours: BoundedU32<1, MAXIMUM_PERIOD_HOURS>,
    /// Time between expiry or revocation and erasure of what it released.
    pub cleanup_grace_hours: BoundedU32<0, MAXIMUM_PERIOD_HOURS>,
}

/// One after-commit observer hook.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HookPolicy {
    pub id: LocalId,
    pub phase: HookPhase,
    pub trigger: HookTrigger,
    /// The fields of the trigger's projection the observer receives.
    pub projection: UniqueList<ExternalId>,
    pub handler: HookHandler,
}

impl Identified for HookPolicy {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

/// When an observer hook runs relative to the triggering transaction.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum HookPhase {
    After,
}

/// The committed change an observer hook follows.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub enum HookTrigger {
    #[serde(rename = "document-version.ready")]
    DocumentVersionReady,
    #[serde(rename = "document-version.rejected")]
    DocumentVersionRejected,
    #[serde(rename = "document-grant.changed")]
    DocumentGrantChanged,
}

/// Where an observer hook delivers, chosen by its `type` member: a URL
/// destination the runtime configuration binds under `destinations.hooks`.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
pub enum HookHandler {
    Url { destination_id: LocalId },
}
registry_platform_yaml::tagged_union!(HookHandler);

/// The schema of a map keyed by local identifiers: an object whose property
/// names are `LocalId` and whose values are `V`.
#[cfg(feature = "schema")]
pub fn local_id_map_schema<V: schemars::JsonSchema>(
    generator: &mut schemars::SchemaGenerator,
) -> schemars::Schema {
    let names = generator.subschema_for::<LocalId>();
    schemars::json_schema!({
        "type": "object",
        "propertyNames": names,
        "additionalProperties": generator.subschema_for::<V>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const STARTER: &str =
        include_str!("../../../products/documents/examples/starter/documents.yaml");

    #[test]
    fn the_starter_project_reads_as_written() {
        let decoded = DocumentsProject::decode("documents.yaml", STARTER.as_bytes())
            .unwrap_or_else(|report| panic!("the starter project is refused: {report:?}"));
        let project = decoded.value;
        assert_eq!(project.project.id.as_str(), "civil-registry-documents");
        assert_eq!(project.access_profiles.len(), 4);
        assert_eq!(project.document_policies.len(), 3);
        assert_eq!(project.hooks.len(), 3);
        assert_eq!(
            project.hooks[0].handler,
            HookHandler::Url {
                destination_id: LocalId::new("custodian-events").unwrap()
            }
        );
    }

    fn refusal_codes(text: &str) -> Vec<String> {
        let report = DocumentsProject::decode("documents.yaml", text.as_bytes())
            .expect_err("the document is refused");
        report
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.clone())
            .collect()
    }

    #[test]
    fn an_unknown_member_is_refused() {
        let text = STARTER.replace(
            "    role: custodian\n",
            "    role: custodian\n    admin: true\n",
        );
        assert!(refusal_codes(&text)
            .iter()
            .any(|code| code == "config.unknown-key"));
    }

    #[test]
    fn another_format_is_refused_by_its_envelope() {
        let text = STARTER.replace("kind: DocumentsProject", "kind: MessagingProject");
        assert!(!refusal_codes(&text).is_empty());
    }

    #[test]
    fn an_unknown_trigger_is_refused() {
        let text = STARTER.replace(
            "trigger: document-version.rejected",
            "trigger: document.deleted",
        );
        assert!(!refusal_codes(&text).is_empty());
    }

    #[test]
    fn a_restriction_outside_its_bounds_is_refused() {
        let text = STARTER.replacen(
            "maximumDocumentBytes: 16777216",
            "maximumDocumentBytes: 0",
            1,
        );
        assert!(refusal_codes(&text)
            .iter()
            .any(|code| code == "config.out-of-range"));
    }

    #[test]
    fn a_substitution_expression_is_refused_in_the_authored_file() {
        let text = STARTER.replacen(
            "maximumDocumentBytes: 16777216",
            "maximumDocumentBytes: \"${DOCUMENT_BYTES}\"",
            1,
        );
        assert_ne!(text, STARTER);
        assert_eq!(refusal_codes(&text), ["config.substitution-not-allowed"]);
    }

    #[test]
    fn an_empty_scope_or_client_list_is_refused_at_its_member() {
        for (member, written) in [
            (
                "requiredScopes",
                "    requiredScopes: [documents:custody]\n",
            ),
            (
                "requesterClients",
                "    requesterClients: [civil-registry-app]\n",
            ),
        ] {
            let text = STARTER.replacen(written, &format!("    {member}: []\n"), 1);
            assert_ne!(text, STARTER, "{member}");
            let report = DocumentsProject::decode("documents.yaml", text.as_bytes())
                .expect_err("an empty list is refused");
            let paths: Vec<&str> = report
                .diagnostics()
                .iter()
                .map(|diagnostic| diagnostic.path.as_str())
                .collect();
            assert_eq!(paths, [format!("/accessProfiles/custodian-app/{member}")]);
        }
    }

    #[test]
    fn a_repeated_hook_id_is_refused() {
        let text = STARTER.replace(
            "id: document-version-rejected",
            "id: document-version-ready",
        );
        assert!(refusal_codes(&text)
            .iter()
            .any(|code| code == "config.duplicate-id"));
    }
}
