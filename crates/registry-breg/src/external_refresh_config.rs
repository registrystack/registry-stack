// SPDX-License-Identifier: Apache-2.0
//! Deployment bindings for managed external-projection refresh work.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use chrono::{DateTime, Utc};
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_oidc::ActorKind;
use registry_platform_yaml::{ExternalId, LocalId, UniqueList};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::api::{VerifiedClaimValue, VerifiedContextError, VerifiedRequestClaims};
use crate::contract::{external_id_map, local_id_map, Operation, RowBoundarySource};
#[cfg(feature = "schema")]
use crate::contract::{external_id_map_schema, local_id_map_schema};
use crate::external_source::ExternalSourceBinding;
use crate::external_views::ExternalProjectionMode;
use crate::model::CompiledRegistry;

const DEFAULT_PAGE_SIZE: u16 = 50;
const MAXIMUM_PAGE_SIZE: u32 = 100;
const MAXIMUM_INTERVAL_SECONDS: u32 = 31_536_000;

/// The optional `externalRefresh` runtime block. Empty is the omission default.
#[cfg_attr(feature = "schema", derive(Serialize, schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ExternalRefreshConfig {
    /// Refresh plans keyed by plan ID. Each names the indexed link it keeps
    /// current and the worker identity that runs it.
    #[serde(default, deserialize_with = "local_id_map")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "local_id_map_schema::<ExternalRefreshPlan>")
    )]
    plans: BTreeMap<String, ExternalRefreshPlan>,
}

impl ExternalRefreshConfig {
    pub(crate) fn plans(&self) -> &BTreeMap<String, ExternalRefreshPlan> {
        &self.plans
    }

    /// Resolve each plan independently so one bad deployment binding does not
    /// take unrelated views or plans out of service.
    pub(crate) fn resolve(
        &self,
        registry: &CompiledRegistry,
        sources: &[ExternalSourceBinding],
    ) -> ExternalRefreshResolution {
        let mut resolution = ExternalRefreshResolution::default();
        for (id, plan) in &self.plans {
            match self.resolve_plan(id, plan, registry, sources) {
                Ok(plan) => {
                    resolution.available.insert(id.clone(), plan);
                }
                Err(problem) => {
                    resolution.unavailable.insert(id.clone(), problem);
                }
            }
        }
        resolution.report_unplanned_links(registry, sources, &self.plans);
        resolution
    }

    fn resolve_plan(
        &self,
        id: &str,
        plan: &ExternalRefreshPlan,
        registry: &CompiledRegistry,
        sources: &[ExternalSourceBinding],
    ) -> Result<ResolvedExternalRefreshPlan, ExternalRefreshPlanProblem> {
        let plan_path = format!("/externalRefresh/plans/{id}");
        let worker_path = format!("{plan_path}/worker");
        let worker = &plan.worker;
        let views = registry.external_views();
        let view = views.views.get(plan.target.view.as_str()).ok_or_else(|| {
            problem(
                format!("{plan_path}/target/view"),
                "breg.external-refresh.view-missing",
                "the plan target view is not declared by the active project",
                "Select an indexed external view declared by the project.",
            )
        })?;
        let link = view
            .links
            .iter()
            .find(|link| link.id == plan.target.link)
            .ok_or_else(|| {
                problem(
                    format!("{plan_path}/target/link"),
                    "breg.external-refresh.link-missing",
                    "the plan target link is not declared by its view",
                    "Select a link declared by the target view.",
                )
            })?;
        let primary = resolved_projection(link.projection.as_str(), &plan_path, registry, sources)?;
        let profile_id = worker.access_profile.as_str();
        let root = registry
            .entities()
            .get(view.record_type.as_str())
            .ok_or_else(|| {
                problem(
                    format!("{plan_path}/target/view"),
                    "breg.external-refresh.root-missing",
                    "the target view root record type is unavailable",
                    "Rebuild the project so the external view and its root record type agree.",
                )
            })?;
        let profile = root.access_profiles.get(profile_id).ok_or_else(|| {
            problem(
                format!("{worker_path}/accessProfile"),
                "breg.external-refresh.profile-missing",
                "the worker access profile is not declared on the target root record type",
                "Select a service profile that can list the target root and refresh its projection.",
            )
        })?;
        let granted = views.refresh.get(profile_id);
        // The link's label is refreshed when, and only when, the worker
        // profile's grant covers the label's projection.
        let label_projection = link.label.as_ref().filter(|label| {
            granted.is_some_and(|ids| {
                ids.iter()
                    .any(|id| id.as_str() == label.projection.as_str())
            })
        });
        let label = label_projection
            .map(|label| {
                resolved_projection(label.projection.as_str(), &plan_path, registry, sources)
            })
            .transpose()?;
        if !profile.operations.contains(&Operation::List)
            || !granted.is_some_and(|ids| ids.contains(&link.projection))
        {
            return Err(problem(
                format!("{worker_path}/accessProfile"),
                "breg.external-refresh.profile-authority-missing",
                "the worker profile does not grant root List and refreshExternalProjections for the link's projection",
                "Grant List on the target root and refreshExternalProjections for the link's projection; a label projection the grant also covers is refreshed with it.",
            ));
        }
        if !profile.require_consent.is_empty() {
            return Err(problem(
                format!("{worker_path}/accessProfile"),
                "breg.external-refresh.profile-authority-missing",
                "the worker profile declares a consent boundary, which a refresh worker has no recipient to satisfy",
                "Select a service profile on the target root that declares no requireConsent.",
            ));
        }
        if !profile
            .requester_clients
            .contains(worker.requester_client.as_str())
        {
            return Err(problem(
                format!("{worker_path}/requesterClient"),
                "breg.external-refresh.worker-client-mismatch",
                "the worker requester client is not admitted by its access profile",
                "Use a requester client declared by the selected access profile.",
            ));
        }

        let mut expected_claims = worker.row_claims.clone();
        let principal_claim = profile.principal_claim.clone();
        let principal_value = BTreeSet::from([worker.principal.as_str().to_owned()]);
        if expected_claims
            .insert(principal_claim.clone(), principal_value.clone())
            .is_some_and(|values| values != principal_value)
        {
            return Err(problem(
                format!("{worker_path}/rowClaims/{principal_claim}"),
                "breg.external-refresh.principal-claim-conflict",
                "rowClaims conflicts with the principal value for the profile principal claim",
                "Remove this rowClaims entry; principal supplies the expected principal claim value.",
            ));
        }
        let target_claim_names = profile
            .row_boundaries
            .iter()
            .map(|boundary| boundary.claim.clone())
            .collect::<BTreeSet<_>>();
        if let Some(missing) = target_claim_names
            .iter()
            .find(|claim| !expected_claims.contains_key(*claim))
        {
            return Err(problem(
                format!("{worker_path}/rowClaims/{missing}"),
                "breg.external-refresh.row-claim-missing",
                "the worker does not pin a value for a claim used by this plan's root List boundary",
                "Add the expected claim value under the worker's rowClaims map.",
            ));
        }

        let allowed_notifier_projections = std::iter::once(primary.projection.as_str())
            .chain(
                label
                    .as_ref()
                    .map(|projection| projection.projection.as_str()),
            )
            .collect::<BTreeSet<_>>();
        let mut notifiers = BTreeMap::new();
        for (projection, notifier) in &plan.source_changes {
            if !allowed_notifier_projections.contains(projection.as_str()) {
                return Err(problem(
                    format!("{plan_path}/sourceChanges/{projection}"),
                    "breg.external-refresh.notifier-projection-mismatch",
                    "sourceChanges names neither the primary nor an enabled label projection",
                    "Key sourceChanges by the primary projection or by its enabled label projection.",
                ));
            }
            notifiers.insert(
                projection.clone(),
                ResolvedExternalRefreshNotifier {
                    requester_client: notifier.requester_client.as_str().to_owned(),
                    required_scope: notifier.required_scope.as_str().to_owned(),
                },
            );
        }

        let worker = ResolvedExternalRefreshWorker {
            id: id.to_owned(),
            access_profile: profile_id.to_owned(),
            requester_client: worker.requester_client.as_str().to_owned(),
            principal: worker.principal.as_str().to_owned(),
            principal_claim,
            required_scopes: profile.required_scopes.iter().cloned().collect(),
            required_purposes: profile.required_purposes.iter().cloned().collect(),
            row_claims: expected_claims,
        };
        let target = ResolvedExternalRefreshTarget {
            view: plan.target.view.as_str().to_owned(),
            link: plan.target.link.as_str().to_owned(),
            root_record_type: view.record_type.as_str().to_owned(),
            from_field: link.from_field.as_str().to_owned(),
            row_boundaries: profile.row_boundaries.clone(),
            row_boundary_fields: profile
                .row_boundaries
                .iter()
                .map(|boundary| boundary.field.clone())
                .collect(),
            target_claim_names,
            primary_projection: primary,
            label_projection: label,
        };
        let refresh_labels = target.label_projection.is_some();
        let authority_digest = authority_digest(id, &worker, &target, &notifiers, refresh_labels);
        let resolved = ResolvedExternalRefreshPlan {
            id: id.to_owned(),
            worker,
            target,
            notifiers,
            interval: Duration::from_secs(u64::from(plan.interval_seconds)),
            page_size: plan.page_size,
            refresh_labels,
            authority_digest,
        };
        // Each worker step admits these claims through the profile as a
        // request would be admitted, so a plan whose worker the profile
        // refuses stays unavailable instead of failing on every tick.
        let admitted = resolved
            .worker_claims()
            .is_ok_and(|claims| crate::api::authorize_profile_claims(profile, &claims).is_ok());
        if !admitted {
            return Err(problem(
                worker_path,
                "breg.external-refresh.worker-not-admitted",
                "the worker access profile would refuse the worker identity this plan configures",
                "Pin exactly one rowClaims value for each equals boundary and a list of 1 to 64 values for an in boundary, and keep the principal and each value within 512 bytes.",
            ));
        }
        Ok(resolved)
    }
}

#[cfg_attr(feature = "schema", derive(Serialize, schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ExternalRefreshWorker {
    /// The service access profile, on the target root record type, the worker runs under.
    access_profile: LocalId,
    /// The requester client that profile admits.
    requester_client: ExternalId,
    /// The principal the refresh acts as.
    principal: ExternalId,
    /// Values the worker pins for the claims the profile's row boundaries use.
    #[serde(default, deserialize_with = "row_claim_map")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "external_id_map_schema::<RawRowClaimValues>")
    )]
    row_claims: BTreeMap<String, BTreeSet<String>>,
}

#[cfg(test)]
impl ExternalRefreshWorker {
    pub(crate) fn row_claims(&self) -> &BTreeMap<String, BTreeSet<String>> {
        &self.row_claims
    }
}

#[cfg_attr(feature = "schema", derive(Serialize, schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ExternalRefreshPlan {
    /// The external view and link this plan keeps current.
    target: ExternalRefreshTarget,
    /// The service identity BReg refreshes as.
    worker: ExternalRefreshWorker,
    /// Seconds between refresh sweeps.
    #[serde(deserialize_with = "crate::contract::bounded_u32::<_, 1, MAXIMUM_INTERVAL_SECONDS>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MAXIMUM_INTERVAL_SECONDS>")
    )]
    interval_seconds: u32,
    #[serde(default = "default_page_size")]
    #[serde(deserialize_with = "crate::contract::bounded_u16::<_, 1, MAXIMUM_PAGE_SIZE>")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "registry_platform_yaml::BoundedU32<1, MAXIMUM_PAGE_SIZE>")
    )]
    page_size: u16,
    /// Notifiers allowed to report a source change, keyed by projection ID.
    #[serde(default, deserialize_with = "local_id_map")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "local_id_map_schema::<ExternalRefreshNotifier>")
    )]
    source_changes: BTreeMap<String, ExternalRefreshNotifier>,
}

#[cfg(test)]
impl ExternalRefreshPlan {
    pub(crate) const fn page_size(&self) -> u16 {
        self.page_size
    }

    pub(crate) fn source_changes(&self) -> &BTreeMap<String, ExternalRefreshNotifier> {
        &self.source_changes
    }
}

const fn default_page_size() -> u16 {
    DEFAULT_PAGE_SIZE
}

#[cfg_attr(feature = "schema", derive(Serialize, schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExternalRefreshTarget {
    /// The external view, whose root record type the profile lists.
    view: LocalId,
    /// The link of that view whose projection is refreshed.
    link: LocalId,
}

#[cfg_attr(feature = "schema", derive(Serialize, schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ExternalRefreshNotifier {
    /// The requester client of the source-change notifier.
    requester_client: ExternalId,
    /// The scope that client must hold.
    required_scope: ExternalId,
}

#[cfg_attr(feature = "schema", derive(Serialize, schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum RawRowClaimValues {
    One(ExternalId),
    Many(UniqueList<ExternalId>),
}

fn row_claim_map<'de, D>(deserializer: D) -> Result<BTreeMap<String, BTreeSet<String>>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let raw = external_id_map::<D, RawRowClaimValues>(deserializer)?;
    Ok(raw
        .into_iter()
        .map(|(claim, values)| {
            let values = match values {
                RawRowClaimValues::One(value) => BTreeSet::from([value.into_string()]),
                RawRowClaimValues::Many(values) => values
                    .into_vec()
                    .into_iter()
                    .map(ExternalId::into_string)
                    .collect(),
            };
            (claim, values)
        })
        .collect())
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ExternalRefreshResolution {
    pub(crate) available: BTreeMap<String, ResolvedExternalRefreshPlan>,
    pub(crate) unavailable: BTreeMap<String, ExternalRefreshPlanProblem>,
}

impl ExternalRefreshResolution {
    /// An indexed link whose projection is bound but that no plan targets
    /// would never refresh; report it under `<view>/<link>`.
    fn report_unplanned_links(
        &mut self,
        registry: &CompiledRegistry,
        sources: &[ExternalSourceBinding],
        plans: &BTreeMap<String, ExternalRefreshPlan>,
    ) {
        let catalog = registry.external_views();
        for (view_id, view) in &catalog.views {
            for link in &view.links {
                let indexed = catalog
                    .projections
                    .get(link.projection.as_str())
                    .is_some_and(|projection| projection.mode == ExternalProjectionMode::Indexed);
                let bound = sources
                    .iter()
                    .any(|binding| binding.id.as_str() == link.projection.as_str());
                let planned = plans.values().any(|plan| {
                    plan.target.view.as_str() == view_id && plan.target.link == link.id
                });
                if indexed && bound && !planned {
                    self.unavailable.insert(
                        format!("{view_id}/{}", link.id.as_str()),
                        problem(
                            "/externalRefresh/plans".to_owned(),
                            "breg.external-refresh.plan-missing",
                            "an indexed link with a bound source has no refresh plan, so its cache is never refreshed",
                            "Add a plan under externalRefresh.plans that targets the view and link.",
                        ),
                    );
                }
            }
        }
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResolvedExternalRefreshPlan {
    pub(crate) id: String,
    pub(crate) worker: ResolvedExternalRefreshWorker,
    pub(crate) target: ResolvedExternalRefreshTarget,
    pub(crate) notifiers: BTreeMap<String, ResolvedExternalRefreshNotifier>,
    #[serde(skip)]
    pub(crate) interval: Duration,
    pub(crate) page_size: u16,
    pub(crate) refresh_labels: bool,
    pub(crate) authority_digest: String,
}

impl ResolvedExternalRefreshPlan {
    /// The claims the worker presents to its access profile, built from the
    /// runtime file in place of a verified token: the configured principal,
    /// the profile's scopes, the link projection's purpose, the pinned values
    /// of the profile's row-boundary claims, and the requester client, acting
    /// as a service.
    pub(crate) fn worker_claims(&self) -> Result<VerifiedRequestClaims, VerifiedContextError> {
        let worker = &self.worker;
        let row_claims = worker
            .row_claims
            .iter()
            .filter(|(name, _)| self.target.target_claim_names.contains(*name))
            .map(|(name, values)| {
                let value = match values.len() {
                    1 => VerifiedClaimValue::direct_string(
                        values.iter().next().cloned().unwrap_or_default(),
                    ),
                    _ => VerifiedClaimValue::direct_string_set(values.iter().cloned()),
                };
                value.map(|value| (name.clone(), value))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        VerifiedRequestClaims::authenticated_with_actor_kind(
            worker.principal_claim.clone(),
            worker.principal.clone(),
            worker.required_scopes.clone(),
            Some(self.target.primary_projection.purpose.clone()),
            row_claims,
            ActorKind::Service,
        )?
        .with_contextual_authority(
            Some(ActorKind::Service),
            Some(worker.requester_client.clone()),
            None,
            None,
            BTreeMap::new(),
        )
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResolvedExternalRefreshWorker {
    pub(crate) id: String,
    pub(crate) access_profile: String,
    pub(crate) requester_client: String,
    pub(crate) principal: String,
    pub(crate) principal_claim: String,
    pub(crate) required_scopes: BTreeSet<String>,
    pub(crate) required_purposes: BTreeSet<String>,
    pub(crate) row_claims: BTreeMap<String, BTreeSet<String>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResolvedExternalRefreshTarget {
    pub(crate) view: String,
    pub(crate) link: String,
    pub(crate) root_record_type: String,
    pub(crate) from_field: String,
    pub(crate) row_boundaries: Vec<RowBoundarySource>,
    pub(crate) row_boundary_fields: BTreeSet<String>,
    pub(crate) target_claim_names: BTreeSet<String>,
    pub(crate) primary_projection: ResolvedExternalRefreshProjection,
    pub(crate) label_projection: Option<ResolvedExternalRefreshProjection>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResolvedExternalRefreshProjection {
    pub(crate) projection: String,
    pub(crate) operation: String,
    pub(crate) operation_version: String,
    pub(crate) purpose: String,
    pub(crate) scope: String,
    pub(crate) selector_scheme: String,
    pub(crate) effective_cache_ttl_seconds: u32,
    pub(crate) grant_valid_until: DateTime<Utc>,
    pub(crate) binding_digest: String,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResolvedExternalRefreshNotifier {
    pub(crate) requester_client: String,
    pub(crate) required_scope: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ExternalRefreshPlanProblem {
    pub(crate) path: String,
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
    pub(crate) suggested_action: &'static str,
}

fn resolved_projection(
    id: &str,
    plan_path: &str,
    registry: &CompiledRegistry,
    sources: &[ExternalSourceBinding],
) -> Result<ResolvedExternalRefreshProjection, ExternalRefreshPlanProblem> {
    let projection = registry
        .external_views()
        .projections
        .get(id)
        .filter(|projection| projection.mode == ExternalProjectionMode::Indexed)
        .ok_or_else(|| {
            problem(
                format!("{plan_path}/target"),
                "breg.external-refresh.projection-not-indexed",
                "the target does not resolve to an indexed external projection",
                "Select a link backed by an indexed projection.",
            )
        })?;
    let binding = sources
        .iter()
        .find(|binding| binding.id.as_str() == id)
        .ok_or_else(|| {
            problem(
                "/externalSources".to_owned(),
                "breg.external-refresh.source-binding-missing",
                "an external refresh projection has no runtime source binding",
                "Add an externalSources binding keyed by the projection ID.",
            )
        })?;
    // An indexed projection always declares cacheTtlSeconds and a source
    // binding always carries a valid grant cutoff; compile and binding
    // validation refuse the alternatives before a plan resolves.
    let authored = projection
        .cache_ttl_seconds
        .as_ref()
        .map(|ttl| ttl.get())
        .expect("compile requires cacheTtlSeconds on an indexed projection");
    let effective_cache_ttl_seconds = binding
        .cache_ttl_seconds
        .as_ref()
        .map_or(authored, |bound| authored.min(bound.get() as u32));
    let grant_valid_until = DateTime::parse_from_rfc3339(&binding.grant_valid_until)
        .map(|value| value.with_timezone(&Utc))
        .expect("binding validation requires an RFC 3339 grant cutoff");
    Ok(ResolvedExternalRefreshProjection {
        projection: id.to_owned(),
        operation: projection.operation.as_str().to_owned(),
        operation_version: projection.operation_version.as_str().to_owned(),
        purpose: projection.purpose.as_str().to_owned(),
        scope: projection.scope.as_str().to_owned(),
        selector_scheme: projection.selector_scheme.as_str().to_owned(),
        effective_cache_ttl_seconds,
        grant_valid_until,
        // The queue fence follows effective authority, not routine operator
        // rotation. Cutoff renewal, endpoint/credential rotation, cache
        // lifetime tuning and request limits therefore do not discard work.
        binding_digest: digest_serializable(&serde_json::json!({
            "projection": binding.id.as_str(),
            "packDigest": &binding.pack_digest,
            "allowedFields": &binding.allowed_fields,
        })),
    })
}

fn authority_digest(
    id: &str,
    worker: &ResolvedExternalRefreshWorker,
    target: &ResolvedExternalRefreshTarget,
    notifiers: &BTreeMap<String, ResolvedExternalRefreshNotifier>,
    refresh_labels: bool,
) -> String {
    let projection = |projection: &ResolvedExternalRefreshProjection| {
        serde_json::json!({
            "projection": projection.projection.as_str(),
            "operation": projection.operation.as_str(),
            "operationVersion": projection.operation_version.as_str(),
            "purpose": projection.purpose.as_str(),
            "scope": projection.scope.as_str(),
            "selectorScheme": projection.selector_scheme.as_str(),
            "bindingDigest": projection.binding_digest.as_str(),
        })
    };
    digest_serializable(&serde_json::json!({
        "plan": id,
        "worker": worker,
        "target": {
            "view": target.view.as_str(),
            "link": target.link.as_str(),
            "rootRecordType": target.root_record_type.as_str(),
            "fromField": target.from_field.as_str(),
            "rowBoundaries": &target.row_boundaries,
            "rowBoundaryFields": &target.row_boundary_fields,
            "targetClaimNames": &target.target_claim_names,
            "primaryProjection": projection(&target.primary_projection),
            "labelProjection": target.label_projection.as_ref().map(projection),
        },
        "notifiers": notifiers,
        "refreshLabels": refresh_labels,
    }))
}

fn digest_serializable(value: &impl Serialize) -> String {
    let value = serde_json::to_value(value).expect("closed external refresh authority serializes");
    let canonical =
        canonicalize_json(&value).expect("closed external refresh authority canonicalizes");
    format!("sha256:{}", hex::encode(Sha256::digest(canonical)))
}

fn problem(
    path: String,
    code: &'static str,
    message: &'static str,
    suggested_action: &'static str,
) -> ExternalRefreshPlanProblem {
    ExternalRefreshPlanProblem {
        path,
        code,
        message,
        suggested_action,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::compiler::{compile_project, CompileProfile};
    use crate::contract::BoundaryOperator;

    fn empty_registry() -> CompiledRegistry {
        let project = crate::parse_project_json(
            br#"{
                "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
                "kind":"BRegProject",
                "project":{
                    "id":"external-refresh-config",
                    "version":"1",
                    "defaultLanguage":"en",
                    "canonicalBaseIri":"https://refresh.example.test"
                },
                "datasets":[{"id":"registry"}],
                "recordTypes":{"record": {
                    "primaryDataset":"registry",
                    "route":"records",
                    "mutationMode":"mutable",
                    "fields":[{
                        "id":"key",
                        "type":"string",
                        "required":true,
                        "maximumLength":64,
                        "classification":"internal"
                    }]
                }}
            }"#,
        )
        .unwrap();
        compile_project(&project, &[], CompileProfile::Authoring).unwrap()
    }

    const WORKER: &str = r#"{
        "accessProfile": "projection-refresh",
        "requesterClient": "licensing-refresh",
        "principal": "synthetic-licensing-refresh",
        "rowClaims": {"jurisdiction": ["zone-a", "zone-b"], "office": "licensing"}
    }"#;

    fn worker_json() -> serde_json::Value {
        serde_json::from_str(WORKER).unwrap()
    }

    #[test]
    fn strict_shape_accepts_scalar_and_set_claims_and_defaults_plan_settings() {
        let config: ExternalRefreshConfig = serde_json::from_value(serde_json::json!({
            "plans": {
                "licensing-holders": {
                    "target": {"view": "licence-holder-indexed", "link": "holder"},
                    "worker": worker_json(),
                    "intervalSeconds": 900
                }
            }
        }))
        .unwrap();
        let plan = &config.plans()["licensing-holders"];
        assert_eq!(plan.worker.row_claims()["jurisdiction"].len(), 2);
        assert_eq!(plan.page_size(), 50);
        assert!(plan.source_changes().is_empty());
    }

    #[test]
    fn strict_shape_refuses_unknown_and_out_of_range_plan_members() {
        let target = serde_json::json!({"view":"view","link":"link"});
        for plan in [
            serde_json::json!({"target":target,"worker":worker_json(),"intervalSeconds":0}),
            serde_json::json!({"target":target,"worker":worker_json(),"intervalSeconds":1,"pageSize":101}),
            serde_json::json!({"target":target,"worker":worker_json(),"intervalSeconds":1,"surprise":true}),
            serde_json::json!({"target":target,"worker":worker_json(),"intervalSeconds":1,"refreshLabels":true}),
            serde_json::json!({"target":target,"worker":"licensing-zone-a","intervalSeconds":1}),
        ] {
            assert!(serde_json::from_value::<ExternalRefreshPlan>(plan).is_err());
        }
    }

    #[test]
    fn a_workers_map_is_an_unknown_member_of_the_block() {
        assert!(serde_json::from_value::<ExternalRefreshConfig>(
            serde_json::json!({"workers": {}, "plans": {}})
        )
        .is_err());
    }

    #[test]
    fn resolution_reports_a_dangling_view_at_the_operator_setting() {
        let registry = empty_registry();
        let missing_view: ExternalRefreshConfig = serde_json::from_value(serde_json::json!({
            "plans": {
                "holders": {
                    "target": {"view": "missing", "link": "holder"},
                    "worker": worker_json(),
                    "intervalSeconds": 60
                }
            }
        }))
        .unwrap();
        let resolution = missing_view.resolve(&registry, &[]);
        let problem = &resolution.unavailable["holders"];
        assert_eq!(problem.path, "/externalRefresh/plans/holders/target/view");
        assert_eq!(problem.code, "breg.external-refresh.view-missing");
    }

    pub(crate) fn example_registry() -> CompiledRegistry {
        let source = include_str!("../../../products/breg/examples/external-views/registry.yaml");
        let project = crate::parse_project_yaml(source.as_bytes()).unwrap();
        compile_project(&project, &[], CompileProfile::Authoring).unwrap()
    }

    fn binding(projection: &str) -> ExternalSourceBinding {
        ExternalSourceBinding::new(
            registry_platform_yaml::LocalId::new(projection).unwrap(),
            serde_json::from_value(serde_json::json!({
                "packFile": "/deferred/pack.yaml",
                "packDigest": format!("sha256:{}", "0".repeat(64)),
                "connection": {"id": "synthetic", "endpoints": []},
                "endpointPolicies": [],
                "allowedFields": ["given-name"],
                "grantValidUntil": "2030-01-01T00:00:00Z",
                "acquisition": {
                    "maximumDataOperations": 8,
                    "attemptTimeoutMilliseconds": 8000,
                    "maximumResponseBytes": 262144
                }
            }))
            .unwrap(),
        )
    }

    /// A worker the example's `projection-refresh` profile admits: its
    /// `jurisdiction` boundary is `equals`, so the worker pins one value.
    fn admitted_worker_json() -> serde_json::Value {
        let mut worker = worker_json();
        worker["rowClaims"]["jurisdiction"] = "zone-a".into();
        worker
    }

    fn plan_with_worker(
        view: &str,
        link: &str,
        worker: serde_json::Value,
    ) -> ExternalRefreshConfig {
        serde_json::from_value(serde_json::json!({
            "plans": {
                "plan": {
                    "target": {"view": view, "link": link},
                    "worker": worker,
                    "intervalSeconds": 60
                }
            }
        }))
        .unwrap()
    }

    fn holdings_plan(view: &str, link: &str) -> ExternalRefreshConfig {
        plan_with_worker(view, link, admitted_worker_json())
    }

    /// The example's licence holder plan under a worker its profile admits.
    pub(crate) fn admitted_holder_plan() -> ResolvedExternalRefreshPlan {
        let registry = example_registry();
        let sources = [binding("person-indexed")];
        let mut resolution =
            holdings_plan("licence-holder-indexed", "holder").resolve(&registry, &sources);
        resolution
            .available
            .remove("plan")
            .unwrap_or_else(|| panic!("{:?}", resolution.unavailable))
    }

    fn holder_plan_problem(worker: serde_json::Value) -> ExternalRefreshPlanProblem {
        let registry = example_registry();
        let sources = [binding("person-indexed")];
        let mut resolution = plan_with_worker("licence-holder-indexed", "holder", worker)
            .resolve(&registry, &sources);
        assert!(resolution.available.is_empty());
        resolution.unavailable.remove("plan").unwrap()
    }

    #[test]
    fn resolution_reports_a_requester_client_the_profile_does_not_admit() {
        let mut worker = admitted_worker_json();
        worker["requesterClient"] = "staff-app".into();
        let problem = holder_plan_problem(worker);
        assert_eq!(problem.code, "breg.external-refresh.worker-client-mismatch");
        assert_eq!(
            problem.path,
            "/externalRefresh/plans/plan/worker/requesterClient"
        );
    }

    #[test]
    fn resolution_reports_a_row_boundary_claim_the_worker_does_not_pin() {
        let mut worker = admitted_worker_json();
        worker["rowClaims"] = serde_json::json!({"office": "licensing"});
        let problem = holder_plan_problem(worker);
        assert_eq!(problem.code, "breg.external-refresh.row-claim-missing");
        assert_eq!(
            problem.path,
            "/externalRefresh/plans/plan/worker/rowClaims/jurisdiction"
        );
    }

    /// The runtime admits the worker exactly as it would a request, so a
    /// worker identity its profile would refuse never reaches the worker tick.
    #[test]
    fn a_plan_whose_worker_identity_its_profile_refuses_is_unavailable() {
        // 300 characters fit the runtime file's identifier bound, but their
        // 600 bytes exceed a verified claim value's bound.
        let oversized = "é".repeat(300);
        let cases = [
            (
                "two values for an equals boundary",
                serde_json::json!({"jurisdiction": ["zone-a", "zone-b"]}),
                None,
            ),
            (
                "an empty list",
                serde_json::json!({"jurisdiction": []}),
                None,
            ),
            (
                "an oversized row claim value",
                serde_json::json!({"jurisdiction": oversized}),
                None,
            ),
            (
                "an oversized principal",
                serde_json::json!({"jurisdiction": "zone-a"}),
                Some(oversized.as_str()),
            ),
        ];
        for (case, row_claims, principal) in cases {
            let mut worker = admitted_worker_json();
            worker["rowClaims"] = row_claims;
            if let Some(principal) = principal {
                worker["principal"] = principal.into();
            }
            let problem = holder_plan_problem(worker);
            assert_eq!(
                problem.code, "breg.external-refresh.worker-not-admitted",
                "{case}"
            );
            assert_eq!(problem.path, "/externalRefresh/plans/plan/worker", "{case}");
        }
    }

    #[test]
    fn a_plan_refreshes_the_labels_its_worker_profile_is_granted() {
        let registry = example_registry();
        let sources = [binding("holdings-indexed"), binding("person-indexed")];
        let granted =
            holdings_plan("business-holdings-indexed", "holdings").resolve(&registry, &sources);
        let plan = granted
            .available
            .get("plan")
            .unwrap_or_else(|| panic!("{:?}", granted.unavailable));
        assert!(plan.refresh_labels);
    }

    #[test]
    fn a_link_without_a_label_refreshes_no_labels() {
        let registry = example_registry();
        let sources = [binding("person-indexed")];
        let resolution =
            holdings_plan("licence-holder-indexed", "holder").resolve(&registry, &sources);
        let plan = resolution
            .available
            .get("plan")
            .unwrap_or_else(|| panic!("{:?}", resolution.unavailable));
        assert!(!plan.refresh_labels);
    }

    #[test]
    fn a_bound_indexed_link_without_a_plan_is_reported() {
        let registry = example_registry();
        let sources = [binding("person-indexed")];
        let resolution = ExternalRefreshConfig::default().resolve(&registry, &sources);
        let problem = &resolution.unavailable["licence-holder-indexed/holder"];
        assert_eq!(problem.code, "breg.external-refresh.plan-missing");
        assert_eq!(problem.path, "/externalRefresh/plans");
        assert!(!resolution
            .unavailable
            .contains_key("business-holdings-indexed/holdings"));
    }

    #[test]
    fn authority_digest_omits_schedule_and_page_size() {
        let worker = ResolvedExternalRefreshWorker {
            id: "worker".to_owned(),
            access_profile: "profile".to_owned(),
            requester_client: "client".to_owned(),
            principal: "principal".to_owned(),
            principal_claim: "sub".to_owned(),
            required_scopes: BTreeSet::from(["refresh".to_owned()]),
            required_purposes: BTreeSet::from(["purpose".to_owned()]),
            row_claims: BTreeMap::from([(
                "sub".to_owned(),
                BTreeSet::from(["principal".to_owned()]),
            )]),
        };
        let projection = ResolvedExternalRefreshProjection {
            projection: "people".to_owned(),
            operation: "fetch-people".to_owned(),
            operation_version: "urn:operation:version:1".to_owned(),
            purpose: "urn:purpose:licensing".to_owned(),
            scope: "urn:scope:people".to_owned(),
            selector_scheme: "urn:person".to_owned(),
            effective_cache_ttl_seconds: 1800,
            grant_valid_until: "2030-01-01T00:00:00Z".parse().unwrap(),
            binding_digest: format!("sha256:{}", "a".repeat(64)),
        };
        let target = ResolvedExternalRefreshTarget {
            view: "people-view".to_owned(),
            link: "holder".to_owned(),
            root_record_type: "licence".to_owned(),
            from_field: "holder-id".to_owned(),
            row_boundaries: vec![RowBoundarySource {
                field: "zone".to_owned(),
                claim: "zone".to_owned(),
                operator: BoundaryOperator::Equals,
            }],
            row_boundary_fields: BTreeSet::from(["zone".to_owned()]),
            target_claim_names: BTreeSet::from(["zone".to_owned()]),
            primary_projection: projection,
            label_projection: None,
        };
        let digest = authority_digest("plan", &worker, &target, &BTreeMap::new(), false);
        let mut routine_edit = target.clone();
        routine_edit.primary_projection.effective_cache_ttl_seconds = 900;
        routine_edit.primary_projection.grant_valid_until = "2031-01-01T00:00:00Z".parse().unwrap();
        assert_eq!(
            digest,
            authority_digest("plan", &worker, &routine_edit, &BTreeMap::new(), false)
        );
        let mut authority_edit = target.clone();
        authority_edit.primary_projection.scope = "urn:scope:other".to_owned();
        assert_ne!(
            digest,
            authority_digest("plan", &worker, &authority_edit, &BTreeMap::new(), false)
        );
        assert!(digest.starts_with("sha256:"));
    }
}
