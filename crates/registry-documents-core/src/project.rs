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
    ApiVersion, BoundedU32, BoundedU64, Decoded, Diagnostic, DisplayText, Document, EnvelopeRule, Expect, ExternalId,
    FormatSpec, Identified, Invalid, LocalId, ProjectIdentity, Reader, Report, Severity,
    UniqueIdList, UniqueList,
};
use serde::{Deserialize, Serialize};

use crate::custody::AllowedContentTypes;
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

/// The largest byte quota one custodian may hold under one policy: one
/// tebibyte.
pub const MAXIMUM_CUSTODIAN_BYTES: u64 = 1_099_511_627_776;

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
    ///
    /// Every reference is resolved here too (CFG-ID-4): a policy that names
    /// an undeclared profile, a profile listed against its role, a
    /// requester client two profiles share, or a default grant expiry above
    /// the policy maximum is refused at the member that carries it, every
    /// finding in one report.
    pub fn decode(file: &str, bytes: &[u8]) -> Result<Decoded<Self>, Report> {
        let mut hook = registry_platform_config::AuthoredExpressions;
        let decoded = Reader::new(file)
            .with_hook(&mut hook)
            .decode::<Self>(bytes, &Expect::one(&DOCUMENTS_PROJECT_FORMAT))?;
        let findings = decoded.value.reference_findings(&decoded.document);
        if findings.is_empty() {
            Ok(decoded)
        } else {
            Err(decoded.document.report_with(findings))
        }
    }

    /// The reference and consistency findings of a decoded project.
    fn reference_findings(&self, document: &Document) -> Vec<Diagnostic> {
        let mut findings = Vec::new();
        let mut clients: BTreeMap<&str, &LocalId> = BTreeMap::new();
        for (id, profile) in &self.access_profiles {
            for (index, client) in profile.requester_clients.as_slice().iter().enumerate() {
                if clients.insert(client.as_str(), id).is_some() {
                    findings.push(document.diagnostic_at_value(
                        Severity::Error,
                        "documents.project.shared-requester-client",
                        &format!("/accessProfiles/{id}/requesterClients/{index}"),
                        "this requester client already resolves to another access profile",
                        "List each OAuth client in exactly one access profile, so a token never resolves to two authorities.",
                    ));
                }
            }
        }
        for (id, policy) in &self.document_policies {
            let base = format!("/documentPolicies/{id}");
            let lists = [
                ("custodyProfiles", &policy.custody_profiles, CUSTODY_ROLES),
                ("grantingProfiles", &policy.granting_profiles, GRANTING_ROLES),
                ("recipientProfiles", &policy.recipient_profiles, RECIPIENT_ROLES),
            ];
            for (member, list, roles) in lists {
                for (index, profile) in list.iter().enumerate() {
                    let pointer = format!("{base}/{member}/{index}");
                    if let Some(finding) = self.profile_finding(document, &pointer, profile, roles)
                    {
                        findings.push(finding);
                    }
                }
            }
            let pointer = format!("{base}/representedPrincipalProfile");
            if let Some(finding) = self.profile_finding(
                document,
                &pointer,
                &policy.represented_principal_profile,
                REPRESENTED_PRINCIPAL_ROLES,
            ) {
                findings.push(finding);
            }
            let restrictions = &policy.mandatory_restrictions;
            if restrictions.grant_expiry_hours.get() > restrictions.maximum_grant_expiry_hours.get()
            {
                findings.push(document.diagnostic_at_value(
                    Severity::Error,
                    "documents.project.grant-expiry-above-maximum",
                    &format!("{base}/mandatoryRestrictions/grantExpiryHours"),
                    "the default grant expiry is above the policy's maximum grant expiry",
                    "Lower grantExpiryHours to at most maximumGrantExpiryHours, or raise the maximum.",
                ));
            }
        }
        findings
    }

    /// The finding for one profile reference, if it names no declared
    /// profile or a profile whose role the member does not admit.
    fn profile_finding(
        &self,
        document: &Document,
        pointer: &str,
        profile: &LocalId,
        roles: &[AccessRole],
    ) -> Option<Diagnostic> {
        match self.access_profiles.get(profile) {
            None => Some(document.diagnostic_at_value(
                Severity::Error,
                "documents.project.unknown-profile",
                pointer,
                "this names an access profile the project does not declare",
                "Name a profile declared under accessProfiles, or declare it.",
            )),
            Some(declared) if !roles.contains(&declared.role) => {
                Some(document.diagnostic_at_value(
                    Severity::Error,
                    "documents.project.profile-role-mismatch",
                    pointer,
                    "this names an access profile whose role this member does not admit",
                    "Custody profiles have the custodian or represented-principal role, granting profiles the custodian role, the represented principal profile the represented-principal role, and recipient profiles the recipient role.",
                ))
            }
            Some(_) => None,
        }
    }
}

/// The roles a policy's custody profiles may have.
const CUSTODY_ROLES: &[AccessRole] = &[AccessRole::Custodian, AccessRole::RepresentedPrincipal];
/// The roles a policy's granting profiles may have.
const GRANTING_ROLES: &[AccessRole] = &[AccessRole::Custodian];
/// The roles a policy's represented principal profile may have.
const REPRESENTED_PRINCIPAL_ROLES: &[AccessRole] = &[AccessRole::RepresentedPrincipal];
/// The roles a policy's recipient profiles may have.
const RECIPIENT_ROLES: &[AccessRole] = &[AccessRole::Recipient];

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
    /// The institution this profile acts for. The Document Store records it
    /// as the issuing institution of every document version a caller under
    /// this profile reserves; a profile that names none records none.
    #[serde(default)]
    pub institution: Option<ExternalId>,
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
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
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
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "kebab-case")]
pub enum RepresentedPrincipalGrants {
    Refused,
    Permitted,
}

/// The restrictions every document held under a policy carries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MandatoryRestrictions {
    /// The largest document a reservation may declare. It may not exceed
    /// the deployment ceiling `storage.maximumDocumentBytes`; the runtime
    /// refuses to start otherwise.
    pub maximum_document_bytes: BoundedU64<1, MAXIMUM_DOCUMENT_BYTES>,
    /// The bytes one custodian may hold under this policy, counted over
    /// every reserved or stored version not yet erased and checked at
    /// reservation.
    pub maximum_custodian_bytes: BoundedU64<1, MAXIMUM_CUSTODIAN_BYTES>,
    /// The media types a document may be declared as, matched exactly.
    pub allowed_content_types: AllowedContentTypes,
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
    fn allowed_content_types_follow_the_exact_match_grammar() {
        let written = "      allowedContentTypes: [application/pdf]\n";
        assert!(STARTER.contains(written));
        let seventeen = (0..17)
            .map(|index| format!("application/x-{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        for refused in [
            "[]".to_owned(),
            "[application/*]".to_owned(),
            "[Application/PDF]".to_owned(),
            "[\"application/pdf; charset=binary\"]".to_owned(),
            "[application/pdf, application/pdf]".to_owned(),
            format!("[{seventeen}]"),
        ] {
            let text = STARTER.replacen(
                written,
                &format!("      allowedContentTypes: {refused}\n"),
                1,
            );
            assert!(!refusal_codes(&text).is_empty(), "{refused}");
        }
    }

    #[test]
    fn every_policy_names_a_custodian_quota() {
        let text = STARTER.replacen("      maximumCustodianBytes: 1073741824\n", "", 1);
        assert_ne!(text, STARTER);
        assert!(!refusal_codes(&text).is_empty());
        let text = STARTER.replacen(
            "maximumCustodianBytes: 1073741824",
            "maximumCustodianBytes: 0",
            1,
        );
        assert!(refusal_codes(&text)
            .iter()
            .any(|code| code == "config.out-of-range"));
    }

    #[test]
    fn a_profile_names_the_institution_it_acts_for() {
        let project = DocumentsProject::decode("documents.yaml", STARTER.as_bytes())
            .unwrap()
            .value;
        let profile = |id: &str| &project.access_profiles[&LocalId::new(id).unwrap()];
        assert_eq!(
            profile("custodian-app")
                .institution
                .as_ref()
                .map(ExternalId::as_str),
            Some("civil-registry")
        );
        assert_eq!(profile("citizen").institution, None);
    }

    fn refusals(text: &str) -> Vec<(String, String)> {
        let report = DocumentsProject::decode("documents.yaml", text.as_bytes())
            .expect_err("the document is refused");
        report
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
            .collect()
    }

    #[test]
    fn a_policy_naming_an_undeclared_profile_is_refused_at_the_reference() {
        for (written, replaced, path) in [
            (
                "    custodyProfiles: [custodian-app]
    # Profiles that may issue",
                "    custodyProfiles: [archive-app]
    # Profiles that may issue",
                "/documentPolicies/citizen-delivery/custodyProfiles/0",
            ),
            (
                "    grantingProfiles: [custodian-app]
    # The profile a represented",
                "    grantingProfiles: [archive-app]
    # The profile a represented",
                "/documentPolicies/citizen-delivery/grantingProfiles/0",
            ),
            (
                "    representedPrincipalProfile: citizen
    # Whether",
                "    representedPrincipalProfile: resident
    # Whether",
                "/documentPolicies/citizen-delivery/representedPrincipalProfile",
            ),
            (
                "    recipientProfiles: [reader, staff]
",
                "    recipientProfiles: [reader, auditor]
",
                "/documentPolicies/named-share/recipientProfiles/1",
            ),
        ] {
            let text = STARTER.replacen(written, replaced, 1);
            assert_ne!(text, STARTER, "{path}");
            assert_eq!(
                refusals(&text),
                [("documents.project.unknown-profile".to_owned(), path.to_owned())]
            );
        }
    }

    #[test]
    fn a_requester_client_shared_by_two_profiles_is_refused() {
        let text = STARTER.replacen(
            "requesterClients: [citizen-portal]",
            "requesterClients: [civil-registry-app]",
            1,
        );
        assert_eq!(
            refusals(&text),
            [(
                "documents.project.shared-requester-client".to_owned(),
                "/accessProfiles/custodian-app/requesterClients/0".to_owned()
            )]
        );
    }

    #[test]
    fn a_profile_listed_against_its_role_is_refused() {
        for (written, replaced, path) in [
            (
                "    recipientProfiles: [reader]
",
                "    recipientProfiles: [custodian-app]
",
                "/documentPolicies/citizen-delivery/recipientProfiles/0",
            ),
            (
                "    custodyProfiles: [custodian-app, citizen]
",
                "    custodyProfiles: [custodian-app, reader]
",
                "/documentPolicies/named-share/custodyProfiles/1",
            ),
            (
                "    grantingProfiles: [custodian-app]
    representedPrincipalProfile: citizen
    representedPrincipalGrants: permitted
",
                "    grantingProfiles: [staff]
    representedPrincipalProfile: citizen
    representedPrincipalGrants: permitted
",
                "/documentPolicies/named-share/grantingProfiles/0",
            ),
            (
                "    representedPrincipalProfile: citizen
    # Whether",
                "    representedPrincipalProfile: reader
    # Whether",
                "/documentPolicies/citizen-delivery/representedPrincipalProfile",
            ),
        ] {
            let text = STARTER.replacen(written, replaced, 1);
            assert_ne!(text, STARTER, "{path}");
            assert_eq!(
                refusals(&text),
                [(
                    "documents.project.profile-role-mismatch".to_owned(),
                    path.to_owned()
                )]
            );
        }
    }

    #[test]
    fn a_default_grant_expiry_above_the_maximum_is_refused() {
        let text = STARTER.replacen(
            "      grantExpiryHours: 24
      maximumGrantExpiryHours: 24
",
            "      grantExpiryHours: 48
      maximumGrantExpiryHours: 24
",
            1,
        );
        assert_ne!(text, STARTER);
        assert_eq!(
            refusals(&text),
            [(
                "documents.project.grant-expiry-above-maximum".to_owned(),
                "/documentPolicies/citizen-delivery/mandatoryRestrictions/grantExpiryHours"
                    .to_owned()
            )]
        );
    }

    #[test]
    fn every_reference_finding_is_reported_in_one_run() {
        let text = STARTER
            .replacen(
                "    recipientProfiles: [reader]
",
                "    recipientProfiles: [auditor]
",
                1,
            )
            .replacen(
                "      grantExpiryHours: 24
      maximumGrantExpiryHours: 24
",
                "      grantExpiryHours: 48
      maximumGrantExpiryHours: 24
",
                1,
            );
        let codes: Vec<String> = refusals(&text).into_iter().map(|(code, _)| code).collect();
        assert!(codes.contains(&"documents.project.unknown-profile".to_owned()));
        assert!(codes.contains(&"documents.project.grant-expiry-above-maximum".to_owned()));
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
