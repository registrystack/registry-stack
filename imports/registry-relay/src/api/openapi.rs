// SPDX-License-Identifier: Apache-2.0
//! Best-effort OpenAPI route.

use std::collections::BTreeSet;
use std::sync::Arc;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Json, Response};
use axum::routing::get;
use axum::{Extension, Router};
use serde_json::{json, Map, Value};

use crate::audit::ErrorCodeExt;
use crate::auth::Principal;
use crate::config::{AuthMode, Config, DatasetConfig, EntityConfig, FilterOp};
use crate::entity::EntityRegistry;
use crate::error::{AuthError, Error};
// Reads the local `CatalogDocument`, not `registry-manifest-core`'s
// `CompiledMetadata`, because the OpenAPI synthesizer below depends on
// Relay-specific wire vocabulary (`has_many` cardinality, the local
// `field_property_uri` shape, `FieldMetadata`'s type strings) that is part
// of the published OpenAPI contract.
use crate::metadata::catalog::{
    catalog_document_for_entity_ids, entity_class_uri, field_property_uri, CatalogDocument,
    DatasetMetadata, EntityMetadata, FieldMetadata, RelationshipMetadata,
};

const PROBLEM_JSON: HeaderValue = HeaderValue::from_static("application/problem+json");
const OPENAPI_UNAVAILABLE_CODE: &str = "openapi.generation_unavailable";

const TAG_SERVICE: &str = "Service";
const TAG_CATALOG: &str = "Catalog";
const TAG_PROVENANCE: &str = "Provenance";
#[cfg(feature = "ogcapi-features")]
const TAG_OGC: &str = "OGC API Features";
#[cfg(feature = "ogcapi-records")]
const TAG_OGC_RECORDS: &str = "OGC API Records";
#[cfg(feature = "ogcapi-edr")]
const TAG_OGC_EDR: &str = "OGC API EDR";
#[cfg(feature = "spdci-api-standards")]
const TAG_SPD_CI: &str = "SP DCI";
const VC_JWT_MEDIA_TYPE: &str = "application/vc+jwt";

const INFO_SUMMARY: &str = "Read-only data gateway exposing entity records, \
    catalog metadata, and SHACL/DCAT-AP shapes for governed datasets.";

/// Sub-router for the best-effort OpenAPI document.
pub fn router<S>() -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new().route("/openapi.json", get(openapi))
}

async fn openapi(
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
    principal: Option<Extension<Principal>>,
) -> Response {
    let Some((config, registry)) = openapi_state(config, registry) else {
        return openapi_unavailable("OpenAPI route matched, but metadata state is not installed");
    };
    let visible_entity_ids = match visible_metadata_entity_ids(&config, principal) {
        Ok(entity_ids) => entity_ids,
        Err(error) => return error.into_response(),
    };
    let catalog = catalog_document_for_entity_ids(&config, &registry, &visible_entity_ids);

    Json(openapi_document(&catalog, &config)).into_response()
}

fn openapi_state(
    config: Option<Extension<Arc<Config>>>,
    registry: Option<Extension<Arc<EntityRegistry>>>,
) -> Option<(Arc<Config>, Arc<EntityRegistry>)> {
    Some((config?.0, registry?.0))
}

fn visible_metadata_entity_ids(
    config: &Config,
    principal: Option<Extension<Principal>>,
) -> Result<BTreeSet<(String, String)>, Error> {
    let Some(Extension(principal)) = principal else {
        return Err(AuthError::MissingCredential.into());
    };
    let entity_ids = config
        .datasets
        .iter()
        .flat_map(|dataset| {
            dataset
                .entities
                .iter()
                .filter(|entity| principal.scopes.contains(&entity.access.metadata_scope))
                .map(|entity| (dataset.id.to_string(), entity.name.clone()))
        })
        .collect::<BTreeSet<_>>();
    if entity_ids.is_empty() {
        Err(AuthError::ScopeDenied {
            required: "metadata scope on at least one entity".to_string(),
        }
        .into())
    } else {
        Ok(entity_ids)
    }
}

fn openapi_document(catalog: &CatalogDocument, config: &Config) -> Value {
    let mut paths = Map::new();

    // ---- Service ----
    insert_json_path(
        &mut paths,
        "/healthz",
        "get",
        "Liveness probe",
        "HealthResponse",
    );
    set_op_id(&mut paths, "/healthz", "get", "get_health");
    set_description(
        &mut paths,
        "/healthz",
        "get",
        "Returns 200 once the gateway process has started. Unauthenticated.",
    );
    mark_public(&mut paths, "/healthz", "get");
    tag(&mut paths, "/healthz", "get", TAG_SERVICE);

    insert_json_path(
        &mut paths,
        "/ready",
        "get",
        "Readiness probe",
        "ReadinessResponse",
    );
    set_op_id(&mut paths, "/ready", "get", "get_ready");
    set_description(
        &mut paths,
        "/ready",
        "get",
        "Returns 200 once dependent state (entity registry, audit sink) is initialised. \
         Unauthenticated.",
    );
    mark_public(&mut paths, "/ready", "get");
    tag(&mut paths, "/ready", "get", TAG_SERVICE);

    // ---- Portable metadata ----
    insert_json_path(
        &mut paths,
        "/metadata",
        "get",
        "Metadata landing page",
        "MetadataLanding",
    );
    set_op_id(&mut paths, "/metadata", "get", "get_metadata_landing");
    set_description(
        &mut paths,
        "/metadata",
        "get",
        "Lists canonical metadata publication links and embeds the scoped metadata catalog.",
    );
    set_json_response_example(
        &mut paths,
        "/metadata",
        "get",
        "200",
        "metadata_landing",
        "Metadata landing page with scoped catalog links.",
        metadata_landing_example(catalog),
    );
    tag(&mut paths, "/metadata", "get", TAG_CATALOG);

    insert_json_path(
        &mut paths,
        "/metadata/catalog",
        "get",
        "Portable metadata catalog",
        "MetadataCatalogDocument",
    );
    set_op_id(
        &mut paths,
        "/metadata/catalog",
        "get",
        "get_metadata_catalog",
    );
    set_description(
        &mut paths,
        "/metadata/catalog",
        "get",
        "Returns the canonical route-neutral metadata catalog for datasets and entities visible \
         to the calling principal.",
    );
    set_json_response_example(
        &mut paths,
        "/metadata/catalog",
        "get",
        "200",
        "metadata_catalog",
        "Scoped portable metadata catalog.",
        portable_catalog_example(catalog),
    );
    tag(&mut paths, "/metadata/catalog", "get", TAG_CATALOG);

    insert_json_path(
        &mut paths,
        "/metadata/evidence-offerings",
        "get",
        "List visible evidence offerings",
        "EvidenceOfferingList",
    );
    set_op_id(
        &mut paths,
        "/metadata/evidence-offerings",
        "get",
        "list_metadata_evidence_offerings",
    );
    set_description(
        &mut paths,
        "/metadata/evidence-offerings",
        "get",
        "Returns evidence offerings visible to the caller. Evidence offerings describe the requirement, evidence type, issuing authority, dataset/entity binding, and access route.",
    );
    set_json_response_example(
        &mut paths,
        "/metadata/evidence-offerings",
        "get",
        "200",
        "evidence_offerings",
        "Evidence offering discovery list.",
        evidence_offering_list_example(),
    );
    tag(
        &mut paths,
        "/metadata/evidence-offerings",
        "get",
        TAG_CATALOG,
    );

    paths.insert(
        "/metadata/evidence-offerings/{offering_id}".to_string(),
        path_item_with_params(
            "get",
            "Evidence offering metadata",
            "EvidenceOffering",
            vec![path_parameter(
                "offering_id",
                "Evidence offering identifier",
            )],
        ),
    );
    set_op_id(
        &mut paths,
        "/metadata/evidence-offerings/{offering_id}",
        "get",
        "get_metadata_evidence_offering",
    );
    set_description(
        &mut paths,
        "/metadata/evidence-offerings/{offering_id}",
        "get",
        "Returns one visible evidence offering. Unknown, hidden, and unauthorized offerings return `offering.not_found`.",
    );
    set_json_response_example(
        &mut paths,
        "/metadata/evidence-offerings/{offering_id}",
        "get",
        "200",
        "evidence_offering",
        "Evidence offering discovery record.",
        evidence_offering_example(),
    );
    tag(
        &mut paths,
        "/metadata/evidence-offerings/{offering_id}",
        "get",
        TAG_CATALOG,
    );

    paths.insert(
        "/metadata/dcat".to_string(),
        jsonld_path_item(
            "get_metadata_dcat",
            "Base DCAT catalog (JSON-LD)",
            "Returns the visible metadata catalog as a base DCAT JSON-LD document.",
            "Base DCAT JSON-LD catalog",
        ),
    );
    set_response_example(
        &mut paths,
        "/metadata/dcat",
        "get",
        ResponseExampleContent::new("200", "application/ld+json"),
        "base_dcat",
        "Base DCAT JSON-LD catalog.",
        base_dcat_example(catalog),
    );
    tag(&mut paths, "/metadata/dcat", "get", TAG_CATALOG);

    paths.insert(
        "/metadata/dcat/bregdcat-ap".to_string(),
        jsonld_path_item(
            "get_metadata_dcat_bregdcat_ap",
            "BRegDCAT-AP catalog (JSON-LD)",
            "Returns the visible metadata catalog as a BRegDCAT-AP JSON-LD document.",
            "BRegDCAT-AP JSON-LD catalog",
        ),
    );
    set_response_example(
        &mut paths,
        "/metadata/dcat/bregdcat-ap",
        "get",
        ResponseExampleContent::new("200", "application/ld+json"),
        "bregdcat_ap",
        "BRegDCAT-AP JSON-LD catalog with embedded SHACL shape.",
        breg_dcat_example(catalog),
    );
    tag(&mut paths, "/metadata/dcat/bregdcat-ap", "get", TAG_CATALOG);

    paths.insert(
        "/metadata/policies".to_string(),
        jsonld_path_item(
            "get_metadata_policies",
            "Visible dataset policies (ODRL JSON-LD)",
            "Returns the ODRL access-policy documents for datasets visible to the calling principal.",
            "ODRL JSON-LD policy collection",
        ),
    );
    set_response_example(
        &mut paths,
        "/metadata/policies",
        "get",
        ResponseExampleContent::new("200", "application/ld+json"),
        "policy_collection",
        "Dataset ODRL policy collection.",
        policy_collection_example(catalog),
    );
    tag(&mut paths, "/metadata/policies", "get", TAG_CATALOG);

    insert_json_path(
        &mut paths,
        "/metadata/datasets",
        "get",
        "List metadata datasets",
        "MetadataDatasetList",
    );
    set_op_id(
        &mut paths,
        "/metadata/datasets",
        "get",
        "list_metadata_datasets",
    );
    set_description(
        &mut paths,
        "/metadata/datasets",
        "get",
        "Lists portable metadata datasets visible to the calling principal.",
    );
    set_json_response_example(
        &mut paths,
        "/metadata/datasets",
        "get",
        "200",
        "metadata_datasets",
        "Portable metadata dataset list.",
        metadata_dataset_list_example(catalog),
    );
    tag(&mut paths, "/metadata/datasets", "get", TAG_CATALOG);

    paths.insert(
        "/metadata/datasets/{dataset_id}".to_string(),
        path_item_with_params(
            "get",
            "Metadata dataset",
            "MetadataDataset",
            vec![path_parameter("dataset_id", "Dataset identifier")],
        ),
    );
    set_op_id(
        &mut paths,
        "/metadata/datasets/{dataset_id}",
        "get",
        "get_metadata_dataset",
    );
    set_description(
        &mut paths,
        "/metadata/datasets/{dataset_id}",
        "get",
        "Returns one visible portable metadata dataset with entity field metadata.",
    );
    set_json_response_example(
        &mut paths,
        "/metadata/datasets/{dataset_id}",
        "get",
        "200",
        "metadata_dataset",
        "Portable metadata dataset record.",
        first_dataset(catalog)
            .map(|dataset| metadata_dataset_example(catalog, dataset))
            .unwrap_or_else(|| json!({})),
    );
    add_response_404(
        &mut paths,
        "/metadata/datasets/{dataset_id}",
        "get",
        "Dataset not found or not visible to the caller.",
    );
    tag(
        &mut paths,
        "/metadata/datasets/{dataset_id}",
        "get",
        TAG_CATALOG,
    );

    paths.insert(
        "/metadata/datasets/{dataset_id}/policy".to_string(),
        jsonld_path_item_with_params(
            "get_metadata_dataset_policy",
            "Dataset policy (ODRL JSON-LD)",
            "Returns the ODRL access-policy document for one visible dataset.",
            "ODRL JSON-LD dataset policy",
            vec![path_parameter("dataset_id", "Dataset identifier")],
        ),
    );
    set_response_example(
        &mut paths,
        "/metadata/datasets/{dataset_id}/policy",
        "get",
        ResponseExampleContent::new("200", "application/ld+json"),
        "dataset_policy",
        "One dataset ODRL policy document.",
        first_dataset(catalog)
            .map(|dataset| dataset_policy_example(catalog, dataset))
            .unwrap_or_else(|| json!({})),
    );
    tag(
        &mut paths,
        "/metadata/datasets/{dataset_id}/policy",
        "get",
        TAG_CATALOG,
    );

    #[cfg(feature = "ogcapi-features")]
    insert_ogc_paths(&mut paths);
    #[cfg(feature = "ogcapi-records")]
    insert_ogc_records_paths(&mut paths);
    #[cfg(feature = "ogcapi-edr")]
    insert_ogc_edr_paths(&mut paths);
    if provenance_enabled(config) {
        insert_provenance_paths(&mut paths);
    }
    #[cfg(feature = "spdci-api-standards")]
    if spdci_configured(config) {
        insert_spdci_paths(&mut paths);
    }

    insert_json_path(
        &mut paths,
        "/v1/datasets",
        "get",
        "List datasets",
        "DatasetList",
    );
    set_op_id(&mut paths, "/v1/datasets", "get", "list_datasets");
    set_description(
        &mut paths,
        "/v1/datasets",
        "get",
        "Lists every dataset visible to the calling principal.",
    );
    set_json_response_example(
        &mut paths,
        "/v1/datasets",
        "get",
        "200",
        "datasets",
        "Dataset list for the visible Relay catalog.",
        relay_dataset_list_example(catalog),
    );
    tag(&mut paths, "/v1/datasets", "get", TAG_CATALOG);

    for dataset in &catalog.datasets {
        let dataset_slug = op_id_slug(&dataset.dataset_id);

        let dataset_path = format!("/v1/datasets/{}", dataset.dataset_id);
        paths.insert(
            dataset_path.clone(),
            json_path_item("get", "Dataset metadata", "DatasetSummary"),
        );
        set_op_id(
            &mut paths,
            &dataset_path,
            "get",
            &format!("get_{dataset_slug}_metadata"),
        );
        set_description(
            &mut paths,
            &dataset_path,
            "get",
            &format!(
                "Returns metadata for the `{}` dataset: entities, publishers, sensitivity, \
                 update frequency, and links to JSON, JSON-LD, and SHACL artifacts.\n\n{}",
                dataset.dataset_id, dataset.description
            ),
        );
        add_response_404(
            &mut paths,
            &dataset_path,
            "get",
            "Dataset not found or not visible to the caller.",
        );
        set_json_response_example(
            &mut paths,
            &dataset_path,
            "get",
            "200",
            "dataset",
            "Dataset summary.",
            relay_dataset_summary_example(dataset),
        );
        tag(&mut paths, &dataset_path, "get", TAG_CATALOG);

        for entity in &dataset.entities {
            let Some(entity_config) = entity_config(config, &dataset.dataset_id, &entity.name)
            else {
                continue;
            };
            let component = entity_component_name(&dataset.dataset_id, &entity.name);
            let collection_component = entity_collection_component_name(&component);
            let entity_tag = entity_tag_name(&dataset.dataset_id, &entity.name);
            let entity_slug = op_id_slug(&entity.name);
            let stem = format!("{dataset_slug}_{entity_slug}");
            let entity_desc = entity.description.as_deref().unwrap_or("");

            // List records
            let collection_path = format!(
                "/v1/datasets/{}/entities/{}/records",
                dataset.dataset_id, entity.name
            );
            paths.insert(
                collection_path.clone(),
                entity_collection_path_item("List records", &collection_component, entity_config),
            );
            set_op_id(
                &mut paths,
                &collection_path,
                "get",
                &format!("list_{stem}_records"),
            );
            set_description(
                &mut paths,
                &collection_path,
                "get",
                &format!(
                    "List `{}` records from dataset `{}`.{}\n\n\
                     Supports pagination via `limit`+`cursor`, projection via `fields`, \
                     relationship expansion via `expand`, and configured filters.",
                    entity.name,
                    dataset.dataset_id,
                    if entity_desc.is_empty() {
                        String::new()
                    } else {
                        format!(" {entity_desc}")
                    },
                ),
            );
            set_code_samples(
                &mut paths,
                &collection_path,
                "get",
                code_samples_for_collection(&dataset.dataset_id, &entity.name),
            );
            if entity_config.api.require_purpose_header {
                add_purpose_header_parameter(&mut paths, &collection_path, "get");
            }
            tag(&mut paths, &collection_path, "get", &entity_tag);

            // Get record by id
            let record_path = format!(
                "/v1/datasets/{}/entities/{}/records/{{id}}",
                dataset.dataset_id, entity.name
            );
            paths.insert(
                record_path.clone(),
                entity_record_path_item("Get record by id", &component, entity_config),
            );
            set_op_id(
                &mut paths,
                &record_path,
                "get",
                &format!("get_{stem}_record"),
            );
            set_description(
                &mut paths,
                &record_path,
                "get",
                &format!(
                    "Return a single `{}` record from `{}` by primary key.{}",
                    entity.name,
                    dataset.dataset_id,
                    if entity_desc.is_empty() {
                        String::new()
                    } else {
                        format!(" {entity_desc}")
                    },
                ),
            );
            add_response_404(
                &mut paths,
                &record_path,
                "get",
                &format!(
                    "`{}` record with the given primary key not found.",
                    entity.name
                ),
            );
            set_code_samples(
                &mut paths,
                &record_path,
                "get",
                code_samples_for_record(&dataset.dataset_id, &entity.name),
            );
            if entity_config.api.require_purpose_header {
                add_purpose_header_parameter(&mut paths, &record_path, "get");
            }
            add_signed_vc_variant(
                &mut paths,
                &record_path,
                "get",
                config,
                "Signed entity-record Verifiable Credential.",
            );
            tag(&mut paths, &record_path, "get", &entity_tag);

            // Field schema (JSON Schema view)
            let field_schema_path = format!(
                "/v1/datasets/{}/entities/{}/schema",
                dataset.dataset_id, entity.name
            );
            paths.insert(
                field_schema_path.clone(),
                json_path_item("get", "Field schema", &format!("{component}Schema")),
            );
            set_op_id(
                &mut paths,
                &field_schema_path,
                "get",
                &format!("get_{stem}_field_schema"),
            );
            set_description(
                &mut paths,
                &field_schema_path,
                "get",
                &format!(
                    "Returns the `{}` field schema in a JSON-friendly form: field names, \
                     types, concept URIs, codelists, units, and language tags. Useful for \
                     codegen and validation.",
                    entity.name,
                ),
            );
            tag(&mut paths, &field_schema_path, "get", &entity_tag);

            // Relationships
            for relationship in &entity.relationships {
                let relationship_path = format!(
                    "/v1/datasets/{}/entities/{}/records/{{id}}/relationships/{}",
                    dataset.dataset_id, entity.name, relationship.name
                );
                paths.insert(
                    relationship_path.clone(),
                    entity_relationship_path_item(dataset, relationship),
                );
                let rel_slug = op_id_slug(&relationship.name);
                set_op_id(
                    &mut paths,
                    &relationship_path,
                    "get",
                    &format!("get_{stem}_{rel_slug}"),
                );
                set_description(
                    &mut paths,
                    &relationship_path,
                    "get",
                    &format!(
                        "Returns the `{}` ({}) target(s) for one `{}` record. Foreign key: `{}`.",
                        relationship.name, relationship.kind, entity.name, relationship.foreign_key,
                    ),
                );
                add_response_404(
                    &mut paths,
                    &relationship_path,
                    "get",
                    "Parent record not found, or relationship target unavailable.",
                );
                let target_requires_purpose = config
                    .datasets
                    .iter()
                    .find(|d| d.id.as_str() == dataset.dataset_id)
                    .and_then(|d| d.entities.iter().find(|e| e.name == relationship.target))
                    .is_some_and(|target| target.api.require_purpose_header);
                if entity_config.api.require_purpose_header || target_requires_purpose {
                    add_purpose_header_parameter(&mut paths, &relationship_path, "get");
                }
                tag(&mut paths, &relationship_path, "get", &entity_tag);
            }
        }
        if let Some(dataset_config) = dataset_config(config, &dataset.dataset_id) {
            if !dataset_config.aggregates.is_empty() {
                let aggregate_tag = aggregate_tag_name(&dataset.dataset_id);
                let aggregates_path = format!("/v1/datasets/{}/aggregates", dataset.dataset_id);
                paths.insert(
                    aggregates_path.clone(),
                    json_path_item("get", "List dataset aggregates", "AggregateListResponse"),
                );
                set_op_id(
                    &mut paths,
                    &aggregates_path,
                    "get",
                    &format!("list_{dataset_slug}_aggregates"),
                );
                set_description(
                    &mut paths,
                    &aggregates_path,
                    "get",
                    &format!(
                        "Lists dataset-scoped analytical aggregates defined for `{}`.",
                        dataset.dataset_id,
                    ),
                );
                tag(&mut paths, &aggregates_path, "get", &aggregate_tag);

                let aggregate_run_path = format!(
                    "/v1/datasets/{}/aggregates/{{aggregate_id}}",
                    dataset.dataset_id
                );
                paths.insert(
                    aggregate_run_path.clone(),
                    aggregate_run_path_item(&dataset.dataset_id),
                );
                set_op_id(
                    &mut paths,
                    &aggregate_run_path,
                    "get",
                    &format!("run_{dataset_slug}_aggregate"),
                );
                set_op_id(
                    &mut paths,
                    &aggregate_run_path,
                    "post",
                    &format!("query_{dataset_slug}_aggregate"),
                );
                add_response_404(
                    &mut paths,
                    &aggregate_run_path,
                    "get",
                    "Aggregate definition not found for this dataset.",
                );
                add_response_404(
                    &mut paths,
                    &aggregate_run_path,
                    "post",
                    "Aggregate definition not found for this dataset.",
                );
                add_signed_vc_variant(
                    &mut paths,
                    &aggregate_run_path,
                    "get",
                    config,
                    "Signed aggregate-result Verifiable Credential.",
                );
                if dataset_aggregates_require_purpose(dataset_config) {
                    add_purpose_header_parameter(&mut paths, &aggregate_run_path, "get");
                    add_purpose_header_parameter(&mut paths, &aggregate_run_path, "post");
                }
                tag(&mut paths, &aggregate_run_path, "get", &aggregate_tag);
                tag(&mut paths, &aggregate_run_path, "post", &aggregate_tag);

                let aggregate_query_path = format!(
                    "/v1/datasets/{}/aggregates/{{aggregate_id}}/query",
                    dataset.dataset_id
                );
                paths.insert(
                    aggregate_query_path.clone(),
                    aggregate_query_path_item(&dataset.dataset_id),
                );
                set_op_id(
                    &mut paths,
                    &aggregate_query_path,
                    "post",
                    &format!("query_{dataset_slug}_aggregate_explicit"),
                );
                add_response_404(
                    &mut paths,
                    &aggregate_query_path,
                    "post",
                    "Aggregate definition not found for this dataset.",
                );
                if dataset_aggregates_require_purpose(dataset_config) {
                    add_purpose_header_parameter(&mut paths, &aggregate_query_path, "post");
                }
                tag(&mut paths, &aggregate_query_path, "post", &aggregate_tag);

                let aggregate_metadata_path = format!(
                    "/v1/datasets/{}/aggregates/{{aggregate_id}}/metadata",
                    dataset.dataset_id
                );
                paths.insert(
                    aggregate_metadata_path.clone(),
                    path_item_with_params(
                        "get",
                        "Get aggregate metadata",
                        "AggregateMetadata",
                        vec![path_parameter("aggregate_id", "Aggregate identifier")],
                    ),
                );
                set_op_id(
                    &mut paths,
                    &aggregate_metadata_path,
                    "get",
                    &format!("get_{dataset_slug}_aggregate_metadata"),
                );
                add_response_404(
                    &mut paths,
                    &aggregate_metadata_path,
                    "get",
                    "Aggregate definition not found for this dataset.",
                );
                tag(&mut paths, &aggregate_metadata_path, "get", &aggregate_tag);

                let indicators_path = format!("/v1/datasets/{}/indicators", dataset.dataset_id);
                paths.insert(
                    indicators_path.clone(),
                    json_path_item("get", "List dataset indicators", "AggregateIndicatorList"),
                );
                set_op_id(
                    &mut paths,
                    &indicators_path,
                    "get",
                    &format!("list_{dataset_slug}_indicators"),
                );
                set_description(
                    &mut paths,
                    &indicators_path,
                    "get",
                    &format!(
                        "Lists indicator definitions declared by aggregates in `{}`.",
                        dataset.dataset_id,
                    ),
                );
                tag(&mut paths, &indicators_path, "get", &aggregate_tag);

                let indicator_path =
                    format!("/v1/datasets/{}/indicators/{{item_id}}", dataset.dataset_id);
                paths.insert(
                    indicator_path.clone(),
                    path_item_with_params(
                        "get",
                        "Get dataset indicator",
                        "AggregateIndicatorDiscovery",
                        vec![path_parameter("item_id", "Indicator identifier")],
                    ),
                );
                set_op_id(
                    &mut paths,
                    &indicator_path,
                    "get",
                    &format!("get_{dataset_slug}_indicator"),
                );
                add_response_404(
                    &mut paths,
                    &indicator_path,
                    "get",
                    "Indicator definition not found for this dataset.",
                );
                tag(&mut paths, &indicator_path, "get", &aggregate_tag);

                let dimensions_path = format!("/v1/datasets/{}/dimensions", dataset.dataset_id);
                paths.insert(
                    dimensions_path.clone(),
                    json_path_item("get", "List dataset dimensions", "AggregateDimensionList"),
                );
                set_op_id(
                    &mut paths,
                    &dimensions_path,
                    "get",
                    &format!("list_{dataset_slug}_dimensions"),
                );
                set_description(
                    &mut paths,
                    &dimensions_path,
                    "get",
                    &format!(
                        "Lists dimension definitions declared by aggregates in `{}`.",
                        dataset.dataset_id,
                    ),
                );
                tag(&mut paths, &dimensions_path, "get", &aggregate_tag);

                let dimension_path =
                    format!("/v1/datasets/{}/dimensions/{{item_id}}", dataset.dataset_id);
                paths.insert(
                    dimension_path.clone(),
                    path_item_with_params(
                        "get",
                        "Get dataset dimension",
                        "AggregateDimensionDiscovery",
                        vec![path_parameter("item_id", "Dimension identifier")],
                    ),
                );
                set_op_id(
                    &mut paths,
                    &dimension_path,
                    "get",
                    &format!("get_{dataset_slug}_dimension"),
                );
                add_response_404(
                    &mut paths,
                    &dimension_path,
                    "get",
                    "Dimension definition not found for this dataset.",
                );
                tag(&mut paths, &dimension_path, "get", &aggregate_tag);
            }
        }
    }

    let server_url = catalog.base_url.trim_end_matches('/').to_string();

    json!({
        "openapi": "3.1.0",
        "info": {
            "title": catalog.title,
            "summary": INFO_SUMMARY,
            "description": "Best-effort Registry Relay API document generated from visible metadata.",
            "version": env!("CARGO_PKG_VERSION"),
            "contact": { "name": catalog.publisher },
            "license": {
                "name": "Apache-2.0",
                "identifier": "Apache-2.0",
            },
        },
        "servers": [{
            "url": server_url,
            "description": "Configured base URL for this gateway instance.",
        }],
        "security": security_requirements(config),
        "tags": tag_definitions(catalog, config),
        "x-tagGroups": tag_groups(catalog, config),
        "paths": paths,
        "components": {
            "schemas": schemas(catalog, config),
            "securitySchemes": security_schemes(config),
        },
    })
}

fn provenance_enabled(config: &Config) -> bool {
    config
        .provenance
        .as_ref()
        .is_some_and(|provenance| provenance.enabled)
}

#[cfg(feature = "spdci-api-standards")]
fn spdci_configured(config: &Config) -> bool {
    config.standards.spdci.is_some()
}

fn entity_tag_name(dataset_id: &str, entity_name: &str) -> String {
    format!("{dataset_id} / {entity_name}")
}

fn aggregate_tag_name(dataset_id: &str) -> String {
    format!("{dataset_id} / aggregates")
}

/// Build the document-level `tags` array. Tag order drives the sidebar
/// order in Scalar: `Service` and `Catalog` first, then one tag per
/// `(dataset, entity)` pair in catalog iteration order (the catalog
/// document is already sorted). Entity tags carry `x-displayName` so
/// Scalar can render a short label while the tag key (used by every
/// per-operation `tags` reference) stays stable.
fn tag_definitions(catalog: &CatalogDocument, config: &Config) -> Value {
    let mut tags = vec![
        json!({
            "name": TAG_SERVICE,
            "description": "Liveness and readiness probes. Unauthenticated.",
        }),
        json!({
            "name": TAG_CATALOG,
            "description": "Catalog discovery: dataset listing, dataset metadata, DCAT-AP export.",
        }),
    ];
    if provenance_enabled(config) {
        tags.push(json!({
            "name": TAG_PROVENANCE,
            "description": "Public verification artefacts and signed Verifiable Credential support.",
        }));
    }
    #[cfg(feature = "ogcapi-features")]
    tags.push(json!({
        "name": TAG_OGC,
        "description": "OGC API Features discovery and dataset-scoped feature collections.",
    }));
    #[cfg(feature = "ogcapi-records")]
    tags.push(json!({
        "name": TAG_OGC_RECORDS,
        "description": "OGC API Records catalog discovery over visible dataset metadata.",
    }));
    #[cfg(feature = "ogcapi-edr")]
    tags.push(json!({
        "name": TAG_OGC_EDR,
        "description": "OGC API EDR area queries over configured spatial aggregates.",
    }));
    #[cfg(feature = "spdci-api-standards")]
    if spdci_configured(config) {
        tags.push(json!({
            "name": TAG_SPD_CI,
            "description": "Social Protection Digital Convergence Initiative sync adapter routes.",
        }));
    }
    for dataset in &catalog.datasets {
        if dataset_config(config, &dataset.dataset_id)
            .is_some_and(|dataset| !dataset.aggregates.is_empty())
        {
            tags.push(json!({
                "name": aggregate_tag_name(&dataset.dataset_id),
                "x-displayName": "Aggregates",
                "description": format!(
                    "Dataset-scoped aggregate discovery and execution for `{}`.",
                    dataset.dataset_id,
                ),
            }));
        }
        for entity in &dataset.entities {
            let display = entity.title.as_deref().unwrap_or(&entity.name);
            let mut tag_obj = json!({
                "name": entity_tag_name(&dataset.dataset_id, &entity.name),
                "x-displayName": display,
                "description": format!(
                    "Operations on the `{}` entity in dataset `{}`.",
                    entity.name, dataset.dataset_id,
                ),
            });
            if let Some(desc) = entity.description.as_deref() {
                if !desc.is_empty() {
                    tag_obj["description"] = json!(format!(
                        "Operations on the `{}` entity in dataset `{}`. {desc}",
                        entity.name, dataset.dataset_id,
                    ));
                }
            }
            tags.push(tag_obj);
        }
    }
    Value::Array(tags)
}

/// Build the Scalar-specific `x-tagGroups` array. Groups every entity
/// tag under its dataset, with `Service` and `Catalog` as their own
/// groups. Scalar renders each group as a collapsible sidebar section.
fn tag_groups(catalog: &CatalogDocument, config: &Config) -> Value {
    let mut groups = vec![
        json!({ "name": "Service", "tags": [TAG_SERVICE] }),
        json!({ "name": "Catalog", "tags": [TAG_CATALOG] }),
    ];
    if provenance_enabled(config) {
        groups.push(json!({ "name": "Provenance", "tags": [TAG_PROVENANCE] }));
    }
    #[cfg(feature = "ogcapi-features")]
    groups.push(json!({ "name": "OGC", "tags": [TAG_OGC] }));
    #[cfg(feature = "ogcapi-records")]
    groups.push(json!({ "name": "OGC Records", "tags": [TAG_OGC_RECORDS] }));
    #[cfg(feature = "ogcapi-edr")]
    groups.push(json!({ "name": "OGC EDR", "tags": [TAG_OGC_EDR] }));
    #[cfg(feature = "spdci-api-standards")]
    if spdci_configured(config) {
        groups.push(json!({ "name": "SP DCI", "tags": [TAG_SPD_CI] }));
    }
    for dataset in &catalog.datasets {
        let mut entity_tags: Vec<String> = Vec::new();
        if dataset_config(config, &dataset.dataset_id)
            .is_some_and(|dataset| !dataset.aggregates.is_empty())
        {
            entity_tags.push(aggregate_tag_name(&dataset.dataset_id));
        }
        entity_tags.extend(
            dataset
                .entities
                .iter()
                .map(|entity| entity_tag_name(&dataset.dataset_id, &entity.name)),
        );
        if entity_tags.is_empty() {
            continue;
        }
        groups.push(json!({
            "name": dataset.title,
            "tags": entity_tags,
        }));
    }
    Value::Array(groups)
}

fn security_requirements(config: &Config) -> Value {
    match config.auth.mode {
        AuthMode::ApiKey => json!([{ "bearerAuth": [] }, { "apiKeyAuth": [] }]),
        AuthMode::Oidc => json!([{ "bearerAuth": [] }]),
    }
}

fn security_schemes(config: &Config) -> Value {
    let mut schemes = Map::new();
    let bearer_description = match config.auth.mode {
        AuthMode::ApiKey => {
            "API key carried as `Authorization: Bearer <key>`. The gateway hashes the bearer with SHA-256 and matches the fingerprint against `config.auth.api_keys[*].hash_env`."
        }
        AuthMode::Oidc => {
            "OIDC/OAuth2 bearer JWT validated against the configured issuer, audience, JWKS, token type, and scope claim."
        }
    };
    schemes.insert(
        "bearerAuth".to_string(),
        json!({
            "type": "http",
            "scheme": "bearer",
            "description": bearer_description,
        }),
    );
    if config.auth.mode == AuthMode::ApiKey {
        schemes.insert(
            "apiKeyAuth".to_string(),
            json!({
                "type": "apiKey",
                "in": "header",
                "name": "X-Api-Key",
                "description": "Compatibility API-key header accepted by API-key deployments. `Authorization: Bearer` takes precedence when both headers are present.",
            }),
        );
    }
    Value::Object(schemes)
}

// --- post-construction mutators ------------------------------------
// All mutators follow the same shape as `tag()`/`mark_public()`:
// resolve `(path, method)` to an operation object, then mutate. Each
// is a no-op if the operation is absent, which keeps the openapi_document
// body declarative.

fn op_at<'a>(
    paths: &'a mut Map<String, Value>,
    path: &str,
    method: &str,
) -> Option<&'a mut Map<String, Value>> {
    paths
        .get_mut(path)?
        .get_mut(method)
        .and_then(Value::as_object_mut)
}

fn set_op_id(paths: &mut Map<String, Value>, path: &str, method: &str, op_id: &str) {
    if let Some(op) = op_at(paths, path, method) {
        op.insert("operationId".to_string(), json!(op_id));
    }
}

fn set_description(paths: &mut Map<String, Value>, path: &str, method: &str, description: &str) {
    if let Some(op) = op_at(paths, path, method) {
        op.insert("description".to_string(), json!(description));
    }
}

fn set_code_samples(paths: &mut Map<String, Value>, path: &str, method: &str, samples: Vec<Value>) {
    if samples.is_empty() {
        return;
    }
    if let Some(op) = op_at(paths, path, method) {
        op.insert("x-codeSamples".to_string(), Value::Array(samples));
    }
}

fn set_json_response_example(
    paths: &mut Map<String, Value>,
    path: &str,
    method: &str,
    status: &str,
    name: &str,
    summary: &str,
    value: Value,
) {
    set_response_example(
        paths,
        path,
        method,
        ResponseExampleContent::new(status, "application/json"),
        name,
        summary,
        value,
    );
}

#[derive(Clone, Copy)]
struct ResponseExampleContent<'a> {
    status: &'a str,
    media_type: &'a str,
}

impl<'a> ResponseExampleContent<'a> {
    fn new(status: &'a str, media_type: &'a str) -> Self {
        Self { status, media_type }
    }
}

fn set_response_example(
    paths: &mut Map<String, Value>,
    path: &str,
    method: &str,
    response_content: ResponseExampleContent<'_>,
    name: &str,
    summary: &str,
    value: Value,
) {
    let Some(content) = paths
        .get_mut(path)
        .and_then(|path_item| path_item.get_mut(method))
        .and_then(|op| op.get_mut("responses"))
        .and_then(Value::as_object_mut)
        .and_then(|responses| responses.get_mut(response_content.status))
        .and_then(Value::as_object_mut)
        .and_then(|ok| ok.get_mut("content"))
        .and_then(Value::as_object_mut)
        .and_then(|content| content.get_mut(response_content.media_type))
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    let Some(examples) = content
        .entry("examples".to_string())
        .or_insert_with(|| Value::Object(Map::new()))
        .as_object_mut()
    else {
        return;
    };
    examples.entry(name.to_string()).or_insert_with(|| {
        json!({
            "summary": summary,
            "value": value,
        })
    });
}

/// Append the `Data-Purpose` header parameter to the operation at
/// `(path, method)`. No-op if the operation does not exist or already
/// declares the header. The parameter is required by the gateway when
/// the entity has `api.require_purpose_header: true`.
fn add_purpose_header_parameter(paths: &mut Map<String, Value>, path: &str, method: &str) {
    let Some(op) = op_at(paths, path, method) else {
        return;
    };
    let parameters = op
        .entry("parameters".to_string())
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut();
    let Some(parameters) = parameters else {
        return;
    };
    let already_declared = parameters.iter().any(|p| {
        p.get("name")
            .and_then(Value::as_str)
            .is_some_and(|n| n.eq_ignore_ascii_case("Data-Purpose"))
            && p.get("in").and_then(Value::as_str) == Some("header")
    });
    if !already_declared {
        parameters.push(purpose_header_parameter());
    }
}

fn add_signed_vc_variant(
    paths: &mut Map<String, Value>,
    path: &str,
    method: &str,
    config: &Config,
    description: &str,
) {
    let Some(provenance) = config
        .provenance
        .as_ref()
        .filter(|provenance| provenance.enabled)
    else {
        return;
    };
    let Some(op) = op_at(paths, path, method) else {
        return;
    };
    add_accept_parameter(op, &provenance.accepted_media_types);
    let Some(content) = op
        .get_mut("responses")
        .and_then(Value::as_object_mut)
        .and_then(|responses| responses.get_mut("200"))
        .and_then(Value::as_object_mut)
        .and_then(|ok| ok.get_mut("content"))
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    content.insert(
        VC_JWT_MEDIA_TYPE.to_string(),
        json!({
            "schema": {
                "type": "string",
                "description": description,
                "examples": ["eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9..."],
            }
        }),
    );
}

fn add_accept_parameter(op: &mut Map<String, Value>, accepted_media_types: &[String]) {
    let parameters = op
        .entry("parameters".to_string())
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut();
    let Some(parameters) = parameters else {
        return;
    };
    let already_declared = parameters.iter().any(|p| {
        p.get("name")
            .and_then(Value::as_str)
            .is_some_and(|n| n.eq_ignore_ascii_case("Accept"))
            && p.get("in").and_then(Value::as_str) == Some("header")
    });
    if already_declared {
        return;
    }
    let mut values = vec!["application/json".to_string()];
    for media_type in accepted_media_types {
        if !values
            .iter()
            .any(|value| value.eq_ignore_ascii_case(media_type))
        {
            values.push(media_type.clone());
        }
    }
    parameters.push(json!({
        "name": "Accept",
        "in": "header",
        "required": false,
        "description": "Use `application/json` or omit for the default JSON response. Use an enabled provenance media type to request a signed Verifiable Credential response.",
        "schema": { "type": "string", "enum": values },
    }));
}

fn add_response_404(paths: &mut Map<String, Value>, path: &str, method: &str, description: &str) {
    if let Some(op) = op_at(paths, path, method) {
        if let Some(responses) = op.get_mut("responses").and_then(Value::as_object_mut) {
            responses.insert("404".to_string(), problem_response(description));
        }
    }
}

/// Single tag on the operation at `(path, method)`. No-op if the
/// operation does not exist.
fn tag(paths: &mut Map<String, Value>, path: &str, method: &str, tag: &str) {
    if let Some(op) = op_at(paths, path, method) {
        op.insert("tags".to_string(), json!([tag]));
    }
}

/// Override the document-level security requirement on a single
/// operation so it advertises as unauthenticated. Used for `/healthz`
/// and `/ready`, which are merged onto the public sub-router in
/// `crate::server::build_app_with_provenance`.
fn mark_public(paths: &mut Map<String, Value>, path: &str, method: &str) {
    if let Some(op) = op_at(paths, path, method) {
        op.insert("security".to_string(), json!([]));
    }
}

// --- Scalar code samples -------------------------------------------

fn code_samples_for_collection(dataset_id: &str, entity_name: &str) -> Vec<Value> {
    let curl = format!(
        "curl -sS \\\n  -H 'Authorization: Bearer $REGISTRY_RELAY_TOKEN' \\\n  'http://localhost:4242/v1/datasets/{dataset_id}/entities/{entity_name}/records?limit=10'"
    );
    let python = format!(
        "import os, httpx\n\n\
         token = os.environ['REGISTRY_RELAY_TOKEN']\n\
         resp = httpx.get(\n    \
         'http://localhost:4242/v1/datasets/{dataset_id}/entities/{entity_name}/records',\n    \
         params={{'limit': 10}},\n    \
         headers={{'Authorization': f'Bearer {{token}}'}}\n\
         )\n\
         resp.raise_for_status()\n\
         page = resp.json()\n\
         for row in page['data']:\n    \
         print(row)\n\
         next_cursor = page['pagination'].get('next_cursor')"
    );
    vec![
        json!({ "lang": "Shell", "label": "curl", "source": curl }),
        json!({ "lang": "Python", "label": "httpx", "source": python }),
    ]
}

fn code_samples_for_record(dataset_id: &str, entity_name: &str) -> Vec<Value> {
    let curl = format!(
        "curl -sS \\\n  -H 'Authorization: Bearer $REGISTRY_RELAY_TOKEN' \\\n  'http://localhost:4242/v1/datasets/{dataset_id}/entities/{entity_name}/records/$ID'"
    );
    let python = format!(
        "import os, httpx\n\n\
         token = os.environ['REGISTRY_RELAY_TOKEN']\n\
         record_id = '...'\n\
         resp = httpx.get(\n    \
         f'http://localhost:4242/v1/datasets/{dataset_id}/entities/{entity_name}/records/{{record_id}}',\n    \
         headers={{'Authorization': f'Bearer {{token}}'}}\n\
         )\n\
         resp.raise_for_status()\n\
         print(resp.json())"
    );
    vec![
        json!({ "lang": "Shell", "label": "curl", "source": curl }),
        json!({ "lang": "Python", "label": "httpx", "source": python }),
    ]
}

// --- response examples ---------------------------------------------

fn first_dataset(catalog: &CatalogDocument) -> Option<&DatasetMetadata> {
    catalog.datasets.first()
}

fn metadata_landing_example(catalog: &CatalogDocument) -> Value {
    json!({
        "links": [
            { "rel": "self", "href": "/metadata" },
            { "rel": "describedby", "href": "/metadata/catalog", "type": "application/json" },
            { "rel": "alternate", "href": "/metadata/dcat", "type": "application/ld+json" },
            { "rel": "alternate", "href": "/metadata/dcat/bregdcat-ap", "type": "application/ld+json" },
            { "rel": "describedby", "href": "/metadata/shacl", "type": "application/ld+json" },
            { "rel": "describedby", "href": "/metadata/policies", "type": "application/ld+json" },
        ],
        "catalog": portable_catalog_example(catalog),
    })
}

fn portable_catalog_example(catalog: &CatalogDocument) -> Value {
    json!({
        "id": "registry-relay",
        "title": catalog.title,
        "description": "",
        "publisher": catalog.publisher,
        "base_url": catalog.base_url,
        "participant_id": catalog.participant_id,
        "conforms_to": [],
        "application_profiles": [],
        "datasets": catalog
            .datasets
            .iter()
            .map(|dataset| metadata_dataset_example(catalog, dataset))
            .collect::<Vec<_>>(),
        "profiles": [],
    })
}

fn relay_dataset_list_example(catalog: &CatalogDocument) -> Value {
    json!({
        "data": catalog
            .datasets
            .iter()
            .map(relay_dataset_summary_example)
            .collect::<Vec<_>>()
    })
}

fn relay_dataset_summary_example(dataset: &DatasetMetadata) -> Value {
    let mut value = json!({
        "dataset_id": dataset.dataset_id,
        "title": dataset.title,
        "description": dataset.description,
        "owner": dataset.owner,
        "sensitivity": dataset.sensitivity,
        "access_rights": dataset.access_rights,
        "update_frequency": dataset.update_frequency,
        "conforms_to": dataset.conforms_to,
        "links": {
            "self": format!("/v1/datasets/{}", dataset.dataset_id),
        },
        "entities": dataset
            .entities
            .iter()
            .map(|entity| entity.name.clone())
            .collect::<Vec<_>>(),
    });
    if let Some(ogc_collections) = dataset.links.ogc_collections.as_deref() {
        value["links"]["ogc_collections"] = json!(ogc_collections);
    }
    if let Ok(standards) = serde_json::to_value(&dataset.standards) {
        if standards.as_object().is_some_and(|obj| !obj.is_empty()) {
            value["standards"] = standards;
        }
    }
    value
}

fn metadata_dataset_list_example(catalog: &CatalogDocument) -> Value {
    json!({
        "datasets": catalog
            .datasets
            .iter()
            .map(|dataset| metadata_dataset_example(catalog, dataset))
            .collect::<Vec<_>>()
    })
}

fn metadata_dataset_example(catalog: &CatalogDocument, dataset: &DatasetMetadata) -> Value {
    let entities = dataset
        .entities
        .iter()
        .map(|entity| (entity.name.clone(), metadata_entity_example(entity)))
        .collect::<Map<_, _>>();
    let mut value = json!({
        "dataset_id": dataset.dataset_id,
        "title": dataset.title,
        "description": dataset.description,
        "owner": dataset.owner,
        "sensitivity": dataset.sensitivity,
        "access_rights": dataset.access_rights,
        "update_frequency": dataset.update_frequency,
        "conforms_to": dataset.conforms_to,
        "applicable_legislation": dataset.applicable_legislation,
        "adms_status": dataset.adms_status,
        "policy": metadata_policy_example(catalog, dataset),
        "evidence_offerings": {},
        "entities": entities,
    });
    if let Some(spatial_coverage) = dataset.spatial_coverage.as_deref() {
        value["spatial_coverage"] = json!(spatial_coverage);
    }
    value
}

fn metadata_entity_example(entity: &EntityMetadata) -> Value {
    let fields = entity
        .fields
        .iter()
        .map(|field| (field.name.clone(), metadata_field_example(field)))
        .collect::<Map<_, _>>();
    json!({
        "name": entity.name,
        "title": entity.title.as_deref().unwrap_or(&entity.name),
        "description": entity.description.as_deref().unwrap_or(""),
        "concept_uri": entity.concept_uri,
        "primary_key": entity.primary_key,
        "identifiers": [],
        "fields": fields,
        "relationships": entity.relationships,
    })
}

fn metadata_field_example(field: &FieldMetadata) -> Value {
    let mut value = json!({
        "name": field.name,
        "field_type": field.r#type,
        "required": !field.nullable,
        "constraints": {},
        "concepts": field
            .concept_uri
            .as_ref()
            .map(|concept| vec![concept.clone()])
            .unwrap_or_default(),
    });
    if let Some(codelist) = field.codelist.as_deref() {
        value["codelist_scheme_iri"] = json!(codelist);
    }
    if let Some(unit) = field.unit.as_deref() {
        value["unit"] = json!(unit);
    }
    if let Some(language) = field.language.as_deref() {
        value["language"] = json!(language);
    }
    value
}

fn metadata_policy_example(catalog: &CatalogDocument, dataset: &DatasetMetadata) -> Value {
    let policy = dataset.compiled_policy.as_ref();
    json!({
        "uid": policy
            .map(|policy| policy.uid.clone())
            .unwrap_or_else(|| format!("#policy-{}-offer", dataset.dataset_id)),
        "assigner": policy
            .map(|policy| policy.assigner.clone())
            .unwrap_or_else(|| catalog.participant_id.clone()),
        "profile": policy
            .map(|policy| policy.profile.clone())
            .unwrap_or_default(),
        "permissions": policy
            .map(|policy| {
                policy
                    .permissions
                    .iter()
                    .map(|rule| {
                        json!({
                            "action": rule.action,
                            "target": rule.target,
                            "constraints": rule.constraints,
                            "duties": rule.duties,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| {
                vec![json!({
                    "action": "odrl:use",
                    "target": format!("#dataset-{}", dataset.dataset_id),
                    "constraints": [],
                    "duties": [],
                })]
            }),
        "prohibitions": policy
            .map(|policy| {
                policy
                    .prohibitions
                    .iter()
                    .map(|rule| {
                        json!({
                            "action": rule.action,
                            "target": rule.target,
                            "constraints": rule.constraints,
                            "duties": rule.duties,
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
    })
}

fn policy_collection_example(catalog: &CatalogDocument) -> Value {
    json!({
        "@context": policy_context_example(),
        "@id": format!("{}/metadata/policies", catalog.base_url),
        "dcterms:title": "Dataset access policies",
        "dcterms:isPartOf": format!("{}/metadata/dcat.jsonld", catalog.base_url),
        "@graph": catalog
            .datasets
            .iter()
            .map(|dataset| dataset_policy_example(catalog, dataset))
            .collect::<Vec<_>>(),
    })
}

fn dataset_policy_example(catalog: &CatalogDocument, dataset: &DatasetMetadata) -> Value {
    let policy = dataset.compiled_policy.as_ref();
    let uid = policy
        .map(|policy| policy.uid.clone())
        .unwrap_or_else(|| format!("#policy-{}-offer", dataset.dataset_id));
    let assigner = policy
        .map(|policy| policy.assigner.clone())
        .unwrap_or_else(|| catalog.participant_id.clone());
    let permissions = policy
        .map(|policy| {
            policy
                .permissions
                .iter()
                .map(|rule| {
                    json!({
                        "odrl:target": { "@id": rule.target },
                        "odrl:assigner": { "@id": assigner },
                        "odrl:action": { "@id": rule.action },
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_else(|| {
            vec![json!({
                "odrl:target": { "@id": format!("#dataset-{}", dataset.dataset_id) },
                "odrl:assigner": { "@id": assigner },
                "odrl:action": { "@id": "odrl:use" },
            })]
        });
    let mut value = json!({
        "@context": policy_context_example(),
        "@id": uid,
        "@type": "odrl:Offer",
        "odrl:uid": uid,
        "odrl:assigner": { "@id": assigner },
        "odrl:permission": permissions,
    });
    if let Some(policy) = policy {
        if !policy.profile.is_empty() {
            value["odrl:profile"] = json!(policy
                .profile
                .iter()
                .map(|profile| json!({ "@id": profile }))
                .collect::<Vec<_>>());
        }
    }
    value
}

fn policy_context_example() -> Value {
    json!({
        "dcterms": "http://purl.org/dc/terms/",
        "odrl": "http://www.w3.org/ns/odrl/2/",
        "odrl:action": { "@type": "@id" },
        "odrl:assigner": { "@type": "@id" },
        "odrl:target": { "@type": "@id" },
        "odrl:uid": { "@type": "@id" },
    })
}

fn base_dcat_example(catalog: &CatalogDocument) -> Value {
    json!({
        "@context": dcat_context_example(false),
        "@id": format!("{}/metadata/dcat.jsonld", catalog.base_url),
        "@type": "dcat:Catalog",
        "dcterms:identifier": "registry-relay",
        "dcterms:title": catalog.title,
        "dcterms:publisher": {
            "@type": "foaf:Agent",
            "foaf:name": catalog.publisher,
        },
        "dcat:landingPage": catalog.base_url,
        "dcat:dataset": catalog
            .datasets
            .iter()
            .map(|dataset| {
                json!({
                    "@id": format!("#dataset-{}", dataset.dataset_id),
                    "@type": "dcat:Dataset",
                    "dcterms:identifier": dataset.dataset_id,
                    "dcterms:title": dataset.title,
                    "dcterms:description": dataset.description,
                    "dcat:landingPage": dataset.links.self_url,
                    "odrl:hasPolicy": {
                        "@id": dataset
                            .compiled_policy
                            .as_ref()
                            .map(|policy| policy.uid.clone())
                            .unwrap_or_else(|| format!("#policy-{}-offer", dataset.dataset_id)),
                    },
                })
            })
            .collect::<Vec<_>>(),
    })
}

fn breg_dcat_example(catalog: &CatalogDocument) -> Value {
    let mut example = base_dcat_example(catalog);
    example["@context"] = dcat_context_example(true);
    example["@id"] = json!(format!(
        "{}/metadata/dcat.bregdcat-ap.jsonld",
        catalog.base_url
    ));
    example["dcat:dataset"] = json!(catalog
        .datasets
        .iter()
        .map(|dataset| {
            json!({
                "@id": format!("#dataset-{}", dataset.dataset_id),
                "@type": "dcat:Dataset",
                "dcterms:identifier": dataset.dataset_id,
                "dcterms:title": dataset.title,
                "dcterms:description": dataset.description,
                "dcterms:publisher": {
                    "@type": "foaf:Agent",
                    "foaf:name": catalog.publisher,
                },
                "dcterms:rightsHolder": dataset.owner,
                "dcterms:accessRights": dataset.access_rights,
                "dcterms:accrualPeriodicity": dataset.update_frequency,
                "adms:status": dataset.adms_status,
                "dcat:landingPage": dataset.links.self_url,
                "odrl:hasPolicy": dataset_policy_example(catalog, dataset),
            })
        })
        .collect::<Vec<_>>());
    example["sh:shapesGraph"] = json!(catalog
        .datasets
        .iter()
        .flat_map(|dataset| {
            dataset.entities.iter().map(move |entity| {
                json!({
                    "@id": format!("#shape-{}-{}", dataset.dataset_id, entity.name),
                    "@type": "sh:NodeShape",
                    "sh:targetClass": entity
                        .concept_uri
                        .as_deref()
                        .unwrap_or("https://publicschema.org/concepts/Record"),
                    "sh:nodeKind": "sh:IRI",
                    "sh:property": entity
                        .fields
                        .iter()
                        .map(|field| {
                            json!({
                                "@type": "sh:PropertyShape",
                                "sh:path": field.concept_uri.as_deref().unwrap_or(&field.name),
                                "sh:name": field.name,
                            })
                        })
                        .collect::<Vec<_>>(),
                })
            })
        })
        .collect::<Vec<_>>());
    example
}

fn dcat_context_example(include_breg_terms: bool) -> Value {
    let mut context = json!({
        "dcat": "http://www.w3.org/ns/dcat#",
        "dcterms": "http://purl.org/dc/terms/",
        "foaf": "http://xmlns.com/foaf/0.1/",
        "odrl": "http://www.w3.org/ns/odrl/2/",
        "dcat:dataset": { "@type": "@id" },
        "dcat:landingPage": { "@type": "@id" },
        "odrl:hasPolicy": { "@type": "@id" },
    });
    if include_breg_terms {
        context["adms"] = json!("http://www.w3.org/ns/adms#");
        context["dcatap"] = json!("http://data.europa.eu/r5r/");
        context["sh"] = json!("http://www.w3.org/ns/shacl#");
    }
    context
}

fn evidence_offering_list_example() -> Value {
    json!({
        "evidence_offerings": [evidence_offering_example()]
    })
}

fn evidence_offering_example() -> Value {
    json!({
        "access": {
            "conforms_to": "https://demo.example.gov/standards/registry-notary/evidence-v1",
            "discovery_url": "https://notary.demo.example.gov/.well-known/registry-notary",
            "endpoint_url": "https://notary.demo.example.gov/evidence-offerings/benefits-person/verifications",
            "kind": "registry-notary",
            "ruleset": "benefits-person-v1",
        },
        "dataset_id": "benefits_casework",
        "description": "Registry Notary verification for submitted benefits person eligibility status and role facts.",
        "entity": "person",
        "evidence_type": {
            "id": "benefits_person_record_evidence",
            "iri": "https://demo.example.gov/evidence-types/benefits-person-record",
            "name": "Benefits person record evidence"
        },
        "evidence_type_iri": "https://demo.example.gov/evidence-types/benefits-person-record",
        "id": "benefits_person_evidence",
        "information_concepts": [],
        "iri": "https://demo.example.gov/evidence-offerings/benefits-person",
        "issuing_authority": {
            "country": "ZZ",
            "id": "ministry_of_social_affairs",
            "iri": "did:web:social-affairs.demo.example.gov",
            "name": "Ministry of Social Affairs",
        },
        "jurisdiction": { "country": "ZZ", "region": null },
        "level_of_assurance": "substantial",
        "lookup_keys": ["id"],
        "policy": {
            "purpose": ["https://demo.example.gov/purpose/social-protection-eligibility"],
        },
        "procedure_contexts": [],
        "requirement_iris": ["https://demo.example.gov/requirements/benefits-person"],
        "title": "Benefits person status evidence",
        "verification_request_schema_url": "http://127.0.0.1:4242/metadata/schema/benefits_casework/person/schema.json",
    })
}

// --- schemas --------------------------------------------------------

fn schemas(catalog: &CatalogDocument, config: &Config) -> Value {
    let mut schemas = Map::new();
    schemas.insert("HealthResponse".to_string(), health_schema());
    schemas.insert("ReadinessResponse".to_string(), readiness_schema());
    schemas.insert("MetadataLanding".to_string(), metadata_landing_schema());
    schemas.insert(
        "MetadataCatalogDocument".to_string(),
        catalog_document_schema(),
    );
    schemas.insert(
        "MetadataDatasetList".to_string(),
        metadata_dataset_list_schema(),
    );
    schemas.insert("MetadataDataset".to_string(), metadata_dataset_schema());
    schemas.insert("DatasetList".to_string(), dataset_list_schema());
    schemas.insert("DatasetSummary".to_string(), dataset_summary_schema());
    schemas.insert("Pagination".to_string(), pagination_schema());
    schemas.insert("ProblemDetails".to_string(), problem_details_schema());
    schemas.insert(
        "EvidenceOfferingList".to_string(),
        evidence_offering_list_schema(),
    );
    schemas.insert("EvidenceOffering".to_string(), evidence_offering_schema());
    if provenance_enabled(config) {
        schemas.insert(
            "DidDocument".to_string(),
            generic_object_schema("DID Document."),
        );
        schemas.insert(
            "JsonSchemaDocument".to_string(),
            generic_object_schema("Published JSON Schema document."),
        );
        schemas.insert(
            "JsonLdContext".to_string(),
            generic_object_schema("Published JSON-LD context document."),
        );
    }
    schemas.insert("AggregateListResponse".to_string(), aggregate_list_schema());
    schemas.insert("AggregateResult".to_string(), aggregate_result_schema());
    schemas.insert("AggregateMetadata".to_string(), aggregate_metadata_schema());
    schemas.insert(
        "AggregateIndicatorList".to_string(),
        aggregate_indicator_list_schema(),
    );
    schemas.insert(
        "AggregateIndicatorDiscovery".to_string(),
        aggregate_indicator_discovery_schema(),
    );
    schemas.insert(
        "AggregateDimensionList".to_string(),
        aggregate_dimension_list_schema(),
    );
    schemas.insert(
        "AggregateDimensionDiscovery".to_string(),
        aggregate_dimension_discovery_schema(),
    );
    schemas.insert(
        "AggregateQueryRequest".to_string(),
        aggregate_query_request_schema(),
    );
    #[cfg(feature = "spdci-api-standards")]
    if spdci_configured(config) {
        schemas.insert(
            "SpdciSyncRequest".to_string(),
            generic_object_schema("SP DCI sync request envelope."),
        );
        schemas.insert(
            "SpdciSyncResponse".to_string(),
            generic_object_schema("SP DCI sync response envelope."),
        );
    }
    #[cfg(feature = "ogcapi-features")]
    insert_ogc_schemas(&mut schemas);
    #[cfg(feature = "ogcapi-records")]
    insert_ogc_records_schemas(&mut schemas);
    #[cfg(feature = "ogcapi-edr")]
    insert_ogc_edr_schemas(&mut schemas);

    for dataset in &catalog.datasets {
        for entity in &dataset.entities {
            let component = entity_component_name(&dataset.dataset_id, &entity.name);
            schemas.insert(
                component.clone(),
                entity_response_schema(catalog, dataset, entity),
            );
            schemas.insert(
                entity_collection_component_name(&component),
                entity_collection_schema(&component, catalog, dataset, entity),
            );
            schemas.insert(
                format!("{component}Schema"),
                entity_metadata_schema(dataset, entity),
            );
        }
    }

    Value::Object(schemas)
}

fn generic_object_schema(description: &str) -> Value {
    json!({
        "type": "object",
        "description": description,
        "additionalProperties": true,
    })
}

fn health_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "status": { "type": "string", "examples": ["ok"] }
        },
        "examples": [{ "status": "ok" }],
    })
}

fn readiness_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "status": { "type": "string", "examples": ["ready"] }
        },
        "examples": [{ "status": "ready" }],
    })
}

fn catalog_document_schema() -> Value {
    json!({
        "type": "object",
        "description": "Portable metadata catalog. See `/metadata/catalog` for the live document.",
    })
}

fn metadata_landing_schema() -> Value {
    json!({
        "type": "object",
        "description": "Portable metadata landing document with links and an embedded scoped catalog.",
        "additionalProperties": true,
    })
}

fn dataset_list_schema() -> Value {
    json!({
        "type": "object",
        "description": "Listing of datasets visible to the calling principal.",
    })
}

fn metadata_dataset_list_schema() -> Value {
    json!({
        "type": "object",
        "description": "Portable metadata dataset listing. See `/metadata/datasets` for the live document.",
        "required": ["datasets"],
        "properties": {
            "datasets": {
                "type": "array",
                "items": { "$ref": "#/components/schemas/MetadataDataset" },
            },
        },
        "additionalProperties": true,
    })
}

fn metadata_dataset_schema() -> Value {
    let entity_schema = metadata_entity_schema();
    json!({
        "type": "object",
        "description": "Portable metadata dataset record. See `/metadata/datasets/{dataset_id}` for the live document.",
        "required": [
            "dataset_id",
            "title",
            "description",
            "owner",
            "sensitivity",
            "access_rights",
            "update_frequency",
            "entities"
        ],
        "properties": {
            "dataset_id": { "type": "string" },
            "title": { "type": "string" },
            "description": { "type": "string" },
            "owner": { "type": "string" },
            "sensitivity": { "type": "string" },
            "access_rights": { "type": "string" },
            "update_frequency": { "type": "string" },
            "conforms_to": {
                "type": "array",
                "items": { "type": "string", "format": "uri" },
            },
            "applicable_legislation": {
                "type": "array",
                "items": { "type": "string", "format": "uri" },
            },
            "adms_status": { "type": "string" },
            "spatial_coverage": { "type": "string", "format": "uri" },
            "policy": { "type": "object", "additionalProperties": true },
            "evidence_offerings": { "type": "object", "additionalProperties": true },
            "entities": {
                "type": "object",
                "description": "Entity metadata keyed by entity name.",
                "additionalProperties": entity_schema,
            },
        },
        "additionalProperties": true,
    })
}

fn metadata_entity_schema() -> Value {
    json!({
        "type": "object",
        "required": ["name", "primary_key", "fields"],
        "properties": {
            "name": { "type": "string" },
            "title": { "type": "string" },
            "description": { "type": "string" },
            "concept_uri": { "type": ["string", "null"], "format": "uri" },
            "primary_key": { "type": "string" },
            "identifiers": {
                "type": "array",
                "items": { "type": "object", "additionalProperties": true },
            },
            "fields": {
                "type": "object",
                "description": "Field metadata keyed by field name.",
                "additionalProperties": metadata_field_metadata_schema(),
            },
            "relationships": {
                "type": "array",
                "items": metadata_relationship_metadata_schema(),
            },
        },
        "additionalProperties": true,
    })
}

fn metadata_field_metadata_schema() -> Value {
    json!({
        "type": "object",
        "required": ["name", "field_type", "required"],
        "properties": {
            "name": { "type": "string" },
            "field_type": { "type": "string" },
            "required": { "type": "boolean" },
            "constraints": { "type": "object", "additionalProperties": true },
            "concepts": {
                "type": "array",
                "items": { "type": "string", "format": "uri" },
            },
            "codelist_scheme_iri": { "type": "string", "format": "uri" },
            "unit": { "type": "string" },
            "language": { "type": "string" },
        },
        "additionalProperties": true,
    })
}

fn metadata_relationship_metadata_schema() -> Value {
    json!({
        "type": "object",
        "required": ["name", "kind", "target", "foreign_key"],
        "properties": {
            "name": { "type": "string" },
            "kind": { "type": "string", "enum": ["belongs_to", "has_many"] },
            "target": { "type": "string" },
            "foreign_key": { "type": "string" },
            "concept_uri": { "type": ["string", "null"], "format": "uri" },
            "links": { "type": "object", "additionalProperties": true },
        },
        "additionalProperties": true,
    })
}

fn dataset_summary_schema() -> Value {
    json!({
        "type": "object",
        "description": "Per-dataset metadata. See `/datasets/{id}` for the live shape.",
    })
}

fn pagination_schema() -> Value {
    json!({
        "type": "object",
        "required": ["has_more"],
        "properties": {
            "has_more": { "type": "boolean", "description": "True when more pages remain after this one." },
            "next_cursor": {
                "type": ["string", "null"],
                "description": "Opaque cursor for the next page; null when `has_more` is false.",
            },
        },
        "examples": [{ "has_more": true, "next_cursor": "eyJvIjoyMH0=" }],
    })
}

fn problem_details_schema() -> Value {
    json!({
        "type": "object",
        "description": "RFC 7807 Problem Details, returned for every non-2xx response.",
        "required": ["type", "title", "status", "detail", "code"],
        "properties": {
            "type": { "type": "string", "format": "uri" },
            "title": { "type": "string" },
            "status": { "type": "integer", "format": "int32" },
            "detail": { "type": "string" },
            "code": { "type": "string" },
        },
        "additionalProperties": true,
        "examples": [{
            "type": format!("{}auth/missing_credential", crate::error::PROBLEM_TYPE_BASE),
            "title": "Missing credential",
            "status": 401,
            "detail": "no credential provided in Authorization or X-Api-Key header",
            "code": "auth.missing_credential",
        }],
    })
}

#[cfg(any(
    feature = "ogcapi-features",
    feature = "ogcapi-records",
    feature = "ogcapi-edr"
))]
fn insert_ogc_common_schemas(schemas: &mut Map<String, Value>) {
    schemas.insert("OgcLink".to_string(), ogc_link_schema());
    schemas.insert("OgcLandingPage".to_string(), ogc_landing_page_schema());
    schemas.insert("OgcConformance".to_string(), ogc_conformance_schema());
    schemas.insert("OgcCollections".to_string(), ogc_collections_schema());
    schemas.insert("OgcCollection".to_string(), ogc_collection_schema());
}

#[cfg(feature = "ogcapi-features")]
fn insert_ogc_schemas(schemas: &mut Map<String, Value>) {
    insert_ogc_common_schemas(schemas);
    schemas.insert(
        "GeoJsonFeatureCollection".to_string(),
        geojson_feature_collection_schema(),
    );
    schemas.insert("GeoJsonFeature".to_string(), geojson_feature_schema());
}

#[cfg(feature = "ogcapi-records")]
fn insert_ogc_records_schemas(schemas: &mut Map<String, Value>) {
    insert_ogc_common_schemas(schemas);
    schemas.insert(
        "OgcRecordCollection".to_string(),
        ogc_record_collection_schema(),
    );
    schemas.insert("OgcRecord".to_string(), ogc_record_schema());
}

#[cfg(feature = "ogcapi-edr")]
fn insert_ogc_edr_schemas(schemas: &mut Map<String, Value>) {
    insert_ogc_common_schemas(schemas);
    schemas.insert(
        "EdrAreaFeatureCollection".to_string(),
        generic_object_schema("GeoJSON FeatureCollection returned by an OGC EDR area query."),
    );
}

#[cfg(any(
    feature = "ogcapi-features",
    feature = "ogcapi-records",
    feature = "ogcapi-edr"
))]
fn ogc_link_schema() -> Value {
    json!({
        "type": "object",
        "required": ["href", "rel"],
        "properties": {
            "href": { "type": "string" },
            "rel": { "type": "string" },
            "type": { "type": "string" },
            "title": { "type": "string" },
        },
        "additionalProperties": true,
    })
}

#[cfg(any(
    feature = "ogcapi-features",
    feature = "ogcapi-records",
    feature = "ogcapi-edr"
))]
fn ogc_landing_page_schema() -> Value {
    json!({
        "type": "object",
        "required": ["title", "links"],
        "properties": {
            "title": { "type": "string" },
            "description": { "type": "string" },
            "links": { "type": "array", "items": { "$ref": "#/components/schemas/OgcLink" } },
        },
    })
}

#[cfg(any(
    feature = "ogcapi-features",
    feature = "ogcapi-records",
    feature = "ogcapi-edr"
))]
fn ogc_conformance_schema() -> Value {
    json!({
        "type": "object",
        "required": ["conformsTo"],
        "properties": {
            "conformsTo": { "type": "array", "items": { "type": "string", "format": "uri" } },
        },
    })
}

#[cfg(any(
    feature = "ogcapi-features",
    feature = "ogcapi-records",
    feature = "ogcapi-edr"
))]
fn ogc_collections_schema() -> Value {
    json!({
        "type": "object",
        "required": ["links", "collections"],
        "properties": {
            "links": { "type": "array", "items": { "$ref": "#/components/schemas/OgcLink" } },
            "collections": { "type": "array", "items": { "$ref": "#/components/schemas/OgcCollection" } },
        },
    })
}

#[cfg(any(
    feature = "ogcapi-features",
    feature = "ogcapi-records",
    feature = "ogcapi-edr"
))]
fn ogc_collection_schema() -> Value {
    json!({
        "type": "object",
        "required": ["id", "itemType", "links"],
        "properties": {
            "id": { "type": "string" },
            "title": { "type": "string" },
            "description": { "type": "string" },
            "itemType": { "type": "string", "enum": ["feature", "record"] },
            "crs": { "type": "array", "items": { "type": "string", "format": "uri" } },
            "storageCrs": { "type": "string", "format": "uri" },
            "extent": { "type": "object", "additionalProperties": true },
            "properties": { "type": "object", "additionalProperties": true },
            "links": { "type": "array", "items": { "$ref": "#/components/schemas/OgcLink" } },
        },
    })
}

#[cfg(feature = "ogcapi-records")]
fn ogc_record_collection_schema() -> Value {
    json!({
        "type": "object",
        "required": ["type", "numberMatched", "numberReturned", "features"],
        "properties": {
            "type": { "type": "string", "enum": ["FeatureCollection"] },
            "numberMatched": { "type": "integer", "minimum": 0 },
            "numberReturned": { "type": "integer", "minimum": 0 },
            "links": { "type": "array", "items": { "$ref": "#/components/schemas/OgcLink" } },
            "features": { "type": "array", "items": { "$ref": "#/components/schemas/OgcRecord" } },
        },
    })
}

#[cfg(feature = "ogcapi-records")]
fn ogc_record_schema() -> Value {
    json!({
        "type": "object",
        "required": ["id", "type", "geometry", "properties"],
        "properties": {
            "id": { "type": "string" },
            "type": { "type": "string", "enum": ["Feature"] },
            "geometry": { "type": ["object", "null"], "additionalProperties": true },
            "properties": { "type": "object", "additionalProperties": true },
            "links": { "type": "array", "items": { "$ref": "#/components/schemas/OgcLink" } },
        },
    })
}

#[cfg(feature = "ogcapi-features")]
fn geojson_feature_collection_schema() -> Value {
    json!({
        "type": "object",
        "required": ["type", "features"],
        "properties": {
            "type": { "type": "string", "enum": ["FeatureCollection"] },
            "timeStamp": { "type": "string", "format": "date-time" },
            "numberReturned": { "type": "integer", "minimum": 0 },
            "links": { "type": "array", "items": { "$ref": "#/components/schemas/OgcLink" } },
            "features": { "type": "array", "items": { "$ref": "#/components/schemas/GeoJsonFeature" } },
        },
    })
}

#[cfg(feature = "ogcapi-features")]
fn geojson_feature_schema() -> Value {
    json!({
        "type": "object",
        "required": ["type", "id", "geometry", "properties"],
        "properties": {
            "type": { "type": "string", "enum": ["Feature"] },
            "id": { "type": "string" },
            "geometry": { "type": ["object", "null"], "additionalProperties": true },
            "properties": { "type": "object", "additionalProperties": true },
            "links": { "type": "array", "items": { "$ref": "#/components/schemas/OgcLink" } },
        },
    })
}

fn evidence_offering_list_schema() -> Value {
    json!({
        "type": "object",
        "required": ["evidence_offerings"],
        "properties": {
            "evidence_offerings": {
                "type": "array",
                "items": { "$ref": "#/components/schemas/EvidenceOffering" },
            },
        },
    })
}

fn evidence_offering_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "id",
            "title",
            "verification_request_schema_url",
            "evidence_type",
            "issuing_authority",
            "dataset_id",
            "entity",
            "lookup_keys",
            "access"
        ],
        "properties": {
            "id": { "type": "string" },
            "iri": { "type": ["string", "null"], "format": "uri" },
            "title": { "type": "string" },
            "description": { "type": ["string", "null"] },
            "verification_request_schema_url": { "type": "string", "format": "uri" },
            "evidence_type": { "type": "object", "additionalProperties": true },
            "requirement": { "type": ["object", "null"], "additionalProperties": true },
            "issuing_authority": { "type": "object", "additionalProperties": true },
            "jurisdiction": { "type": ["object", "null"], "additionalProperties": true },
            "level_of_assurance": { "type": ["string", "null"] },
            "dataset_id": { "type": "string" },
            "entity": { "type": "string" },
            "lookup_keys": { "type": "array", "items": { "type": "string" } },
            "procedure_contexts": { "type": "array", "items": { "type": "string", "format": "uri" } },
            "access": {
                "type": "object",
                "required": ["kind", "ruleset"],
                "properties": {
                    "kind": { "type": "string", "enum": ["registry-notary"] },
                    "conforms_to": { "type": ["string", "null"], "format": "uri" },
                    "endpoint_url": { "type": ["string", "null"], "format": "uri" },
                    "discovery_url": { "type": ["string", "null"], "format": "uri" },
                    "ruleset": { "type": "string" },
                    "href": { "type": "string" },
                },
                "additionalProperties": true,
            },
            "policy": { "type": ["object", "null"], "additionalProperties": true },
        },
        "additionalProperties": true,
    })
}

fn aggregate_list_schema() -> Value {
    json!({
        "type": "object",
        "required": ["data", "links"],
        "properties": {
            "data": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["dataset_id", "aggregate_id", "title", "description", "source_entity", "dimensions", "indicators"],
                    "properties": {
                        "dataset_id": { "type": "string" },
                        "aggregate_id": { "type": "string" },
                        "title": { "type": "string" },
                        "description": { "type": "string" },
                        "source_entity": { "type": "string" },
                        "default_group_by": { "type": "array", "items": { "type": "string" } },
                        "temporal_field": { "type": ["string", "null"] },
                        "dimensions": aggregate_schema_dimension_array(),
                        "indicators": aggregate_schema_indicator_array(),
                        "disclosure_control": aggregate_disclosure_schema(),
                        "links": link_array_schema(),
                    },
                },
            },
            "links": link_array_schema(),
        },
        "examples": [{
            "data": [{
                "dataset_id": "social_registry",
                "aggregate_id": "households_by_region",
                "title": "Households by region",
                "description": "Household count by region",
                "source_entity": "household",
                "default_group_by": ["region"],
                "temporal_field": null,
                "dimensions": [{ "id": "region", "label": "Region", "field": "region" }],
                "indicators": [{ "id": "household_count", "label": "Households", "function": "count", "column": "id", "unit_measure": "households" }],
                "disclosure_control": { "method": ["k-anonymity"], "min_cell_size": 2, "suppression": "omit", "suppressed_rows": null, "query_budget": { "tracked": false, "scope": "none" } },
                "links": [],
            }],
            "links": [],
        }],
    })
}

fn aggregate_result_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "dataset_id",
            "aggregate_id",
            "data",
            "schema",
            "disclosure_control",
            "freshness",
            "links"
        ],
        "properties": {
            "dataset_id": { "type": "string" },
            "aggregate_id": { "type": "string" },
            "data": { "type": "array", "items": { "type": "object", "additionalProperties": true } },
            "schema": {
                "type": "object",
                "required": ["dimensions", "indicators"],
                "properties": {
                    "dimensions": aggregate_schema_dimension_array(),
                    "indicators": aggregate_schema_indicator_array(),
                },
                "additionalProperties": false,
            },
            "disclosure_control": aggregate_disclosure_schema(),
            "freshness": aggregate_freshness_schema(),
            "links": link_array_schema(),
        },
        "examples": [{
            "dataset_id": "social_registry",
            "aggregate_id": "households_by_region",
            "data": [{ "region": "north", "household_count": 42 }],
            "schema": {
                "dimensions": [{ "id": "region", "label": "Region", "field": "region" }],
                "indicators": [{ "id": "household_count", "label": "Households", "function": "count", "column": "id", "unit_measure": "households" }]
            },
            "disclosure_control": { "method": ["k-anonymity"], "min_cell_size": 2, "suppression": "omit", "suppressed_rows": 1, "query_budget": { "tracked": false, "scope": "none" } },
            "freshness": { "computed_at": "2026-05-16T08:00:00Z", "as_of": "2026-05-16T07:55:00Z" },
            "links": [],
        }],
    })
}

fn aggregate_metadata_schema() -> Value {
    aggregate_list_schema()["properties"]["data"]["items"].clone()
}

fn aggregate_indicator_list_schema() -> Value {
    json!({
        "type": "object",
        "required": ["data", "links"],
        "properties": {
            "data": {
                "type": "array",
                "items": { "$ref": "#/components/schemas/AggregateIndicatorDiscovery" },
            },
            "links": link_array_schema(),
        },
        "additionalProperties": false,
    })
}

fn aggregate_indicator_discovery_schema() -> Value {
    json!({
        "type": "object",
        "required": ["id", "label", "aggregation_method", "unit_measure", "valid_dimensions", "queryable_via", "aggregates", "links"],
        "properties": {
            "id": { "type": "string" },
            "label": { "type": "string" },
            "aggregation_method": { "type": "string" },
            "column": { "type": "string" },
            "unit_measure": { "type": "string" },
            "unit_mult": { "type": ["number", "null"] },
            "decimals": { "type": ["integer", "null"] },
            "frequency": { "type": ["string", "null"] },
            "definition_uri": { "type": ["string", "null"], "format": "uri" },
            "valid_dimensions": { "type": "array", "items": { "type": "string" } },
            "queryable_via": { "type": "array", "items": { "type": "string" } },
            "aggregates": { "type": "array", "items": aggregate_discovery_ref_schema() },
            "links": link_array_schema(),
        },
        "additionalProperties": false,
    })
}

fn aggregate_dimension_list_schema() -> Value {
    json!({
        "type": "object",
        "required": ["data", "links"],
        "properties": {
            "data": {
                "type": "array",
                "items": { "$ref": "#/components/schemas/AggregateDimensionDiscovery" },
            },
            "links": link_array_schema(),
        },
        "additionalProperties": false,
    })
}

fn aggregate_dimension_discovery_schema() -> Value {
    json!({
        "type": "object",
        "required": ["id", "label", "field", "queryable_via", "aggregates", "links"],
        "properties": {
            "id": { "type": "string" },
            "label": { "type": "string" },
            "field": { "type": "string" },
            "codelist": { "type": ["string", "null"], "format": "uri" },
            "queryable_via": { "type": "array", "items": { "type": "string" } },
            "aggregates": { "type": "array", "items": aggregate_discovery_ref_schema() },
            "links": link_array_schema(),
        },
        "additionalProperties": false,
    })
}

fn aggregate_discovery_ref_schema() -> Value {
    json!({
        "type": "object",
        "required": ["aggregate_id", "href"],
        "properties": {
            "aggregate_id": { "type": "string" },
            "href": { "type": "string" },
            "edr_collection_id": { "type": "string" },
            "edr_area_href": { "type": "string" },
        },
        "additionalProperties": false,
    })
}

fn aggregate_query_request_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "indicators": { "type": "array", "items": { "type": "string" }, "maxItems": 20 },
            "group_by": { "type": "array", "items": { "type": "string" }, "maxItems": 5 },
            "filters": { "type": "object", "additionalProperties": true, "maxProperties": 20 },
            "temporal": {
                "type": "object",
                "description": "Date bounds applied to the aggregate temporal_field when configured.",
                "properties": {
                    "from": { "type": "string", "format": "date" },
                    "to": { "type": "string", "format": "date" },
                },
                "additionalProperties": false,
            },
            "format": { "type": "string", "enum": ["json", "csv"] },
        },
        "additionalProperties": false,
        "examples": [{
            "indicators": ["household_count"],
            "group_by": ["region"],
            "filters": { "region": ["north", "south"] },
            "format": "json",
        }],
    })
}

fn aggregate_schema_dimension_array() -> Value {
    json!({
        "type": "array",
        "items": {
            "type": "object",
            "required": ["id", "label", "field"],
            "properties": {
                "id": { "type": "string" },
                "label": { "type": "string" },
                "field": { "type": "string" },
                "codelist": { "type": ["string", "null"], "format": "uri" },
            },
            "additionalProperties": false,
        },
    })
}

fn aggregate_schema_indicator_array() -> Value {
    json!({
        "type": "array",
        "items": {
            "type": "object",
            "required": ["id", "label", "function", "column", "unit_measure"],
            "properties": {
                "id": { "type": "string" },
                "label": { "type": "string" },
                "function": { "type": "string" },
                "column": { "type": "string" },
                "unit_measure": { "type": "string" },
                "unit_mult": { "type": ["number", "null"] },
                "decimals": { "type": ["integer", "null"] },
                "frequency": { "type": ["string", "null"] },
                "definition_uri": { "type": ["string", "null"], "format": "uri" },
            },
            "additionalProperties": false,
        },
    })
}

fn aggregate_disclosure_schema() -> Value {
    json!({
        "type": "object",
        "required": ["method", "min_cell_size", "suppression", "suppressed_rows", "query_budget"],
        "properties": {
            "method": { "type": "array", "items": { "type": "string" } },
            "min_cell_size": { "type": "integer", "minimum": 1 },
            "suppression": { "type": "string", "enum": ["omit", "mask", "null"] },
            "suppressed_rows": { "type": ["integer", "null"], "minimum": 0 },
            "query_budget": {
                "type": "object",
                "required": ["tracked", "scope"],
                "properties": {
                    "tracked": { "type": "boolean" },
                    "scope": { "type": "string" },
                },
                "additionalProperties": true,
            },
        },
        "additionalProperties": true,
    })
}

fn aggregate_freshness_schema() -> Value {
    json!({
        "type": "object",
        "required": ["computed_at"],
        "properties": {
            "computed_at": { "type": "string", "format": "date-time" },
            "as_of": { "type": "string", "format": "date-time" },
        },
        "additionalProperties": false,
    })
}

fn link_array_schema() -> Value {
    json!({
        "type": "array",
        "items": {
            "type": "object",
            "required": ["rel", "href"],
            "properties": {
                "rel": { "type": "string" },
                "href": { "type": "string" },
                "type": { "type": "string" },
            },
            "additionalProperties": true,
        },
    })
}

fn entity_collection_schema(
    component: &str,
    catalog: &CatalogDocument,
    dataset: &DatasetMetadata,
    entity: &EntityMetadata,
) -> Value {
    let item_example = entity_example(catalog, dataset, entity);
    json!({
        "type": "object",
        "required": ["data", "pagination"],
        "properties": {
            "data": {
                "type": "array",
                "items": { "$ref": format!("#/components/schemas/{component}") },
            },
            "pagination": { "$ref": "#/components/schemas/Pagination" },
        },
        "examples": [{
            "data": [item_example],
            "pagination": { "has_more": false, "next_cursor": null },
        }],
    })
}

fn entity_response_schema(
    catalog: &CatalogDocument,
    dataset: &DatasetMetadata,
    entity: &EntityMetadata,
) -> Value {
    let mut properties = Map::new();
    let mut required = Vec::new();
    for field in &entity.fields {
        if !field.nullable {
            required.push(Value::String(field.name.clone()));
        }
        properties.insert(
            field.name.clone(),
            field_response_schema(&catalog.base_url, &dataset.dataset_id, &entity.name, field),
        );
    }
    for relationship in &entity.relationships {
        properties.insert(
            relationship.name.clone(),
            relationship_response_schema(dataset, relationship),
        );
    }

    let mut schema = Map::new();
    schema.insert("type".to_string(), json!("object"));
    if let Some(desc) = entity.description.as_deref() {
        if !desc.is_empty() {
            schema.insert("description".to_string(), json!(desc));
        }
    }
    schema.insert(
        "x-concept-uri".to_string(),
        json!(entity_class_uri(
            &catalog.base_url,
            &dataset.dataset_id,
            entity
        )),
    );
    schema.insert("x-dataset-id".to_string(), json!(dataset.dataset_id));
    schema.insert("x-entity-name".to_string(), json!(entity.name));
    schema.insert("properties".to_string(), Value::Object(properties));
    if !required.is_empty() {
        schema.insert("required".to_string(), Value::Array(required));
    }
    schema.insert(
        "examples".to_string(),
        Value::Array(vec![entity_example(catalog, dataset, entity)]),
    );
    Value::Object(schema)
}

/// Build a representative JSON example for an entity using each field's
/// declared type. Relationship properties are omitted from the example.
fn entity_example(
    _catalog: &CatalogDocument,
    _dataset: &DatasetMetadata,
    entity: &EntityMetadata,
) -> Value {
    let mut obj = Map::new();
    for field in &entity.fields {
        obj.insert(field.name.clone(), field_example_value(field));
    }
    Value::Object(obj)
}

fn field_example_value(field: &FieldMetadata) -> Value {
    match field.r#type {
        "integer" => json!(42),
        "number" => json!(12.34),
        "boolean" => json!(true),
        "date" => json!("2026-01-15"),
        "timestamp" => json!("2026-01-15T08:30:00Z"),
        _ => json!(example_string_for(field)),
    }
}

fn example_string_for(field: &FieldMetadata) -> String {
    // Conservative defaults that read naturally in Scalar's preview.
    let name = field.name.as_str();
    if name.ends_with("_id") || name == "id" {
        return "01HZX9...".to_string();
    }
    if name.contains("code") {
        return "REG-001".to_string();
    }
    if name.contains("region") || name.contains("country") {
        return "north".to_string();
    }
    if name.contains("email") {
        return "alex@example.test".to_string();
    }
    if name.contains("name") {
        return "Alex Example".to_string();
    }
    format!("<{}>", name)
}

fn field_response_schema(
    base_url: &str,
    dataset_id: &str,
    entity_name: &str,
    field: &FieldMetadata,
) -> Value {
    let (type_value, format) = match field.r#type {
        "integer" => (json!("integer"), Some("int64")),
        "number" => (json!("number"), Some("double")),
        "boolean" => (json!("boolean"), None),
        "date" => (json!("string"), Some("date")),
        "timestamp" => (json!("string"), Some("date-time")),
        _ => (json!("string"), None),
    };

    let mut schema = Map::new();
    // OAS 3.1 nullability is expressed via a type array; the `nullable`
    // keyword from 3.0 is silently ignored by 3.1 tooling.
    let type_field = if field.nullable {
        let base = type_value.as_str().expect("scalar type tag");
        Value::Array(vec![json!(base), json!("null")])
    } else {
        type_value
    };
    schema.insert("type".to_string(), type_field);
    if let Some(fmt) = format {
        schema.insert("format".to_string(), json!(fmt));
    }
    schema.insert(
        "description".to_string(),
        json!(synth_field_description(field)),
    );
    schema.insert(
        "x-concept-uri".to_string(),
        json!(field_property_uri(base_url, dataset_id, entity_name, field)),
    );
    if let Some(codelist) = &field.codelist {
        schema.insert("x-codelist".to_string(), json!(codelist));
    }
    if let Some(unit) = &field.unit {
        schema.insert("x-unit".to_string(), json!(unit));
    }
    if let Some(language) = &field.language {
        schema.insert("x-language".to_string(), json!(language));
    }
    schema.insert(
        "examples".to_string(),
        Value::Array(vec![field_example_value(field)]),
    );
    Value::Object(schema)
}

/// Build a short markdown description from field metadata. There is no
/// human-authored description in the catalog, so we surface what we do
/// know: nullability, codelist URI, unit, language tag.
fn synth_field_description(field: &FieldMetadata) -> String {
    let nullability = if field.nullable {
        "Optional"
    } else {
        "Required"
    };
    let mut parts = vec![format!("{nullability} `{}` field.", field.r#type)];
    if let Some(codelist) = &field.codelist {
        parts.push(format!("Codelist: `{codelist}`."));
    }
    if let Some(unit) = &field.unit {
        parts.push(format!("Unit: `{unit}`."));
    }
    if let Some(language) = &field.language {
        parts.push(format!("Language: `{language}`."));
    }
    parts.join(" ")
}

fn relationship_response_schema(
    dataset: &DatasetMetadata,
    relationship: &RelationshipMetadata,
) -> Value {
    let target_ref = dataset
        .entities
        .iter()
        .find(|entity| entity.name == relationship.target)
        .map(|entity| {
            json!({
                "$ref": format!(
                    "#/components/schemas/{}",
                    entity_component_name(&dataset.dataset_id, &entity.name)
                )
            })
        })
        .unwrap_or_else(|| json!({ "type": "object" }));
    let mut schema = if relationship.kind == "has_many" {
        json!({ "type": "array", "items": target_ref })
    } else {
        target_ref
    };
    if let Some(concept_uri) = &relationship.concept_uri {
        schema["x-concept-uri"] = json!(concept_uri);
    }
    schema["x-relationship-kind"] = json!(relationship.kind);
    schema["x-target-entity"] = json!(relationship.target);
    schema["x-foreign-key"] = json!(relationship.foreign_key);
    schema["x-target-schema"] = json!(relationship.links.target_schema);
    schema
}

fn entity_metadata_schema(dataset: &DatasetMetadata, entity: &EntityMetadata) -> Value {
    json!({
        "type": "object",
        "x-concept-uri": entity.concept_uri,
        "x-dataset-id": dataset.dataset_id,
        "x-entity-name": entity.name,
        "properties": {
            "dataset_id": { "type": "string" },
            "entity": { "type": "string" },
            "primary_key": { "type": "string" },
            "fields": { "type": "array", "items": { "type": "object" } },
            "relationships": { "type": "array", "items": { "type": "object" } },
        },
    })
}

fn entity_config<'a>(
    config: &'a Config,
    dataset_id: &str,
    entity_name: &str,
) -> Option<&'a EntityConfig> {
    dataset_config(config, dataset_id)?
        .entities
        .iter()
        .find(|entity| entity.name == entity_name)
}

fn dataset_config<'a>(config: &'a Config, dataset_id: &str) -> Option<&'a DatasetConfig> {
    config
        .datasets
        .iter()
        .find(|dataset| dataset.id.as_str() == dataset_id)
}

fn dataset_aggregates_require_purpose(dataset: &DatasetConfig) -> bool {
    dataset.aggregates.iter().any(|aggregate| {
        aggregate
            .source_entity
            .as_deref()
            .and_then(|source| dataset.entities.iter().find(|entity| entity.name == source))
            .is_some_and(|entity| entity.api.require_purpose_header)
    })
}

// --- path-item builders --------------------------------------------

fn insert_provenance_paths(paths: &mut Map<String, Value>) {
    paths.insert(
        "/schemas/{claim_type}/{version}".to_string(),
        public_resource_path_item(
            "get_provenance_schema",
            "Get provenance JSON Schema",
            "Returns a published JSON Schema for a supported provenance claim type. Schema bytes are stable for a given version and cacheable.",
            "application/schema+json",
            "JsonSchemaDocument",
            vec![
                path_parameter("claim_type", "Provenance claim type, for example `aggregate-result`."),
                path_parameter("version", "Schema version filename, for example `v1.json`."),
            ],
        ),
    );
    mark_public(paths, "/schemas/{claim_type}/{version}", "get");
    tag(
        paths,
        "/schemas/{claim_type}/{version}",
        "get",
        TAG_PROVENANCE,
    );

    paths.insert(
        "/contexts/{vocab}/{version}".to_string(),
        public_resource_path_item(
            "get_provenance_context",
            "Get provenance JSON-LD context",
            "Returns a published JSON-LD context used by signed Verifiable Credential responses.",
            "application/ld+json",
            "JsonLdContext",
            vec![
                path_parameter("vocab", "Context vocabulary, for example `provenance`."),
                path_parameter(
                    "version",
                    "Context version filename, for example `v1.jsonld`.",
                ),
            ],
        ),
    );
    mark_public(paths, "/contexts/{vocab}/{version}", "get");
    tag(paths, "/contexts/{vocab}/{version}", "get", TAG_PROVENANCE);

    paths.insert(
        "/.well-known/did.json".to_string(),
        public_resource_path_item(
            "get_gateway_did_document",
            "Get gateway DID Document",
            "Returns the gateway-hosted DID Document in gateway issuer mode. Delegated issuer deployments mount the route but return `provenance.did_document_unavailable`.",
            "application/did+json",
            "DidDocument",
            Vec::new(),
        ),
    );
    mark_public(paths, "/.well-known/did.json", "get");
    tag(paths, "/.well-known/did.json", "get", TAG_PROVENANCE);
}

#[cfg(feature = "spdci-api-standards")]
fn insert_spdci_paths(paths: &mut Map<String, Value>) {
    for (path, op_id, summary, description) in [
        (
            "/dci/{registry}/registry/sync/search",
            "spdci_sync_search",
            "SP DCI sync search",
            "Runs the configured SP DCI registry sync search adapter for a named registry.",
        ),
        (
            "/dci/{registry}/registry/sync/disabled",
            "spdci_disabled_status",
            "SP DCI disabled status",
            "Returns disability status using the configured SP DCI disability registry binding.",
        ),
        (
            "/dci/{registry}/registry/sync/get-disability-details",
            "spdci_get_disability_details",
            "SP DCI disability details",
            "Returns disability details using the configured SP DCI registry binding.",
        ),
        (
            "/dci/{registry}/registry/sync/get-disability-support",
            "spdci_get_disability_support",
            "SP DCI disability support",
            "Returns disability support using the configured SP DCI registry binding.",
        ),
    ] {
        paths.insert(
            path.to_string(),
            spdci_path_item(op_id, summary, description),
        );
        tag(paths, path, "post", TAG_SPD_CI);
    }
}

#[cfg(feature = "ogcapi-features")]
fn insert_ogc_paths(paths: &mut Map<String, Value>) {
    paths.insert(
        "/ogc/v1".to_string(),
        ogc_json_path_item("get_ogc_landing_page", "OGC landing page", "OgcLandingPage"),
    );
    tag(paths, "/ogc/v1", "get", TAG_OGC);

    paths.insert(
        "/ogc/v1/conformance".to_string(),
        ogc_json_path_item("get_ogc_conformance", "OGC conformance", "OgcConformance"),
    );
    tag(paths, "/ogc/v1/conformance", "get", TAG_OGC);

    paths.insert(
        "/ogc/v1/collections".to_string(),
        ogc_json_path_item(
            "list_ogc_collections",
            "List OGC collections",
            "OgcCollections",
        ),
    );
    tag(paths, "/ogc/v1/collections", "get", TAG_OGC);

    paths.insert(
        "/ogc/v1/datasets/{dataset_id}/collections".to_string(),
        ogc_path_item_with_params(
            "get",
            "List dataset OGC collections",
            "OgcCollections",
            "application/json",
            vec![path_parameter("dataset_id", "Dataset identifier")],
        ),
    );
    tag(
        paths,
        "/ogc/v1/datasets/{dataset_id}/collections",
        "get",
        TAG_OGC,
    );
    set_op_id(
        paths,
        "/ogc/v1/datasets/{dataset_id}/collections",
        "get",
        "list_dataset_ogc_collections",
    );

    paths.insert(
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}".to_string(),
        ogc_path_item_with_params(
            "get",
            "Get OGC collection",
            "OgcCollection",
            "application/json",
            vec![
                path_parameter("dataset_id", "Dataset identifier"),
                path_parameter("collection_id", "OGC collection identifier"),
            ],
        ),
    );
    tag(
        paths,
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}",
        "get",
        TAG_OGC,
    );
    set_op_id(
        paths,
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}",
        "get",
        "get_dataset_ogc_collection",
    );

    let item_query_parameters = vec![
        path_parameter("dataset_id", "Dataset identifier"),
        path_parameter("collection_id", "OGC collection identifier"),
        query_parameter("limit", "Maximum features to return."),
        query_parameter("after", "Opaque signed pagination cursor."),
        query_parameter("bbox", "CRS84 bbox in minx,miny,maxx,maxy order."),
        query_parameter("bbox-crs", "Bbox CRS. Phase 1 accepts CRS84 only."),
        query_parameter("datetime", "Instant or closed/half-open datetime interval."),
    ];
    paths.insert(
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items".to_string(),
        ogc_path_item_with_params(
            "get",
            "List OGC features",
            "GeoJsonFeatureCollection",
            "application/geo+json",
            item_query_parameters,
        ),
    );
    tag(
        paths,
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items",
        "get",
        TAG_OGC,
    );
    set_op_id(
        paths,
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items",
        "get",
        "list_dataset_ogc_features",
    );

    paths.insert(
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items/{feature_id}".to_string(),
        ogc_path_item_with_params(
            "get",
            "Get OGC feature",
            "GeoJsonFeature",
            "application/geo+json",
            vec![
                path_parameter("dataset_id", "Dataset identifier"),
                path_parameter("collection_id", "OGC collection identifier"),
                path_parameter("feature_id", "Feature identifier"),
            ],
        ),
    );
    tag(
        paths,
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items/{feature_id}",
        "get",
        TAG_OGC,
    );
    set_op_id(
        paths,
        "/ogc/v1/datasets/{dataset_id}/collections/{collection_id}/items/{feature_id}",
        "get",
        "get_dataset_ogc_feature",
    );
}

#[cfg(feature = "ogcapi-records")]
fn insert_ogc_records_paths(paths: &mut Map<String, Value>) {
    paths.insert(
        "/ogc/v1/records".to_string(),
        ogc_json_path_item(
            "get_ogc_records_landing_page",
            "OGC API Records landing page",
            "OgcLandingPage",
        ),
    );
    tag(paths, "/ogc/v1/records", "get", TAG_OGC_RECORDS);

    paths.insert(
        "/ogc/v1/records/conformance".to_string(),
        ogc_json_path_item(
            "get_ogc_records_conformance",
            "OGC API Records conformance",
            "OgcConformance",
        ),
    );
    tag(paths, "/ogc/v1/records/conformance", "get", TAG_OGC_RECORDS);

    paths.insert(
        "/ogc/v1/records/collections".to_string(),
        ogc_json_path_item(
            "list_ogc_record_collections",
            "List OGC API Records collections",
            "OgcCollections",
        ),
    );
    tag(paths, "/ogc/v1/records/collections", "get", TAG_OGC_RECORDS);

    paths.insert(
        "/ogc/v1/records/collections/{collection_id}".to_string(),
        ogc_path_item_with_params(
            "get",
            "Get OGC API Records collection",
            "OgcCollection",
            "application/json",
            vec![path_parameter(
                "collection_id",
                "Records collection identifier",
            )],
        ),
    );
    tag(
        paths,
        "/ogc/v1/records/collections/{collection_id}",
        "get",
        TAG_OGC_RECORDS,
    );
    set_op_id(
        paths,
        "/ogc/v1/records/collections/{collection_id}",
        "get",
        "get_ogc_record_collection",
    );

    paths.insert(
        "/ogc/v1/records/collections/{collection_id}/items".to_string(),
        ogc_path_item_with_params(
            "get",
            "List OGC API Records",
            "OgcRecordCollection",
            "application/geo+json",
            vec![
                path_parameter("collection_id", "Records collection identifier"),
                query_parameter("limit", "Maximum records to return."),
                query_parameter("after", "Opaque signed pagination cursor."),
                query_parameter(
                    "q",
                    "Case-insensitive text search over visible record metadata.",
                ),
            ],
        ),
    );
    tag(
        paths,
        "/ogc/v1/records/collections/{collection_id}/items",
        "get",
        TAG_OGC_RECORDS,
    );
    set_op_id(
        paths,
        "/ogc/v1/records/collections/{collection_id}/items",
        "get",
        "list_ogc_records",
    );

    paths.insert(
        "/ogc/v1/records/collections/{collection_id}/items/{record_id}".to_string(),
        ogc_path_item_with_params(
            "get",
            "Get OGC API Record",
            "OgcRecord",
            "application/geo+json",
            vec![
                path_parameter("collection_id", "Records collection identifier"),
                path_parameter("record_id", "Record identifier"),
            ],
        ),
    );
    tag(
        paths,
        "/ogc/v1/records/collections/{collection_id}/items/{record_id}",
        "get",
        TAG_OGC_RECORDS,
    );
    set_op_id(
        paths,
        "/ogc/v1/records/collections/{collection_id}/items/{record_id}",
        "get",
        "get_ogc_record",
    );
}

#[cfg(feature = "ogcapi-edr")]
fn insert_ogc_edr_paths(paths: &mut Map<String, Value>) {
    paths.insert(
        "/ogc/edr/v1".to_string(),
        ogc_json_path_item(
            "get_ogc_edr_landing_page",
            "OGC EDR landing page",
            "OgcLandingPage",
        ),
    );
    tag(paths, "/ogc/edr/v1", "get", TAG_OGC_EDR);

    paths.insert(
        "/ogc/edr/v1/conformance".to_string(),
        ogc_json_path_item(
            "get_ogc_edr_conformance",
            "OGC EDR conformance",
            "OgcConformance",
        ),
    );
    tag(paths, "/ogc/edr/v1/conformance", "get", TAG_OGC_EDR);

    paths.insert(
        "/ogc/edr/v1/collections".to_string(),
        ogc_json_path_item(
            "list_ogc_edr_collections",
            "List OGC EDR collections",
            "OgcCollections",
        ),
    );
    tag(paths, "/ogc/edr/v1/collections", "get", TAG_OGC_EDR);

    paths.insert(
        "/ogc/edr/v1/collections/{collection_id}".to_string(),
        ogc_path_item_with_params(
            "get",
            "Get OGC EDR collection",
            "OgcCollection",
            "application/json",
            vec![path_parameter("collection_id", "EDR collection identifier")],
        ),
    );
    set_op_id(
        paths,
        "/ogc/edr/v1/collections/{collection_id}",
        "get",
        "get_ogc_edr_collection",
    );
    tag(
        paths,
        "/ogc/edr/v1/collections/{collection_id}",
        "get",
        TAG_OGC_EDR,
    );

    let area_path = "/ogc/edr/v1/collections/{collection_id}/area";
    paths.insert(
        area_path.to_string(),
        json!({
            "get": {
                "operationId": "query_ogc_edr_area",
                "summary": "Query OGC EDR area",
                "parameters": [
                    path_parameter("collection_id", "EDR collection identifier"),
                    query_parameter("coords", "WKT geometry in CRS84."),
                    query_parameter("parameter-name", "Comma-separated aggregate indicator ids."),
                    query_parameter("group_by", "Optional aggregate dimension id."),
                    query_parameter("f", "Response format. Phase 1 accepts `geojson`.")
                ],
                "responses": ogc_area_responses(),
            },
            "post": {
                "operationId": "post_ogc_edr_area",
                "summary": "Query OGC EDR area with GeoJSON",
                "parameters": [
                    path_parameter("collection_id", "EDR collection identifier"),
                    query_parameter("parameter-name", "Comma-separated aggregate indicator ids."),
                    query_parameter("group_by", "Optional aggregate dimension id."),
                    query_parameter("f", "Response format. Phase 1 accepts `geojson`.")
                ],
                "requestBody": {
                    "required": true,
                    "content": {
                        "application/geo+json": {
                            "schema": { "type": "object", "additionalProperties": true }
                        },
                        "application/json": {
                            "schema": { "type": "object", "additionalProperties": true }
                        }
                    }
                },
                "responses": ogc_area_responses(),
            }
        }),
    );
    tag(paths, area_path, "get", TAG_OGC_EDR);
    tag(paths, area_path, "post", TAG_OGC_EDR);
}

#[cfg(feature = "ogcapi-edr")]
fn ogc_area_responses() -> Value {
    json!({
        "200": {
            "description": "GeoJSON FeatureCollection with aggregate EDR area results.",
            "content": {
                "application/geo+json": {
                    "schema": { "$ref": "#/components/schemas/EdrAreaFeatureCollection" }
                }
            }
        },
        "400": problem_response("Invalid OGC EDR area query."),
        "401": problem_response("Missing or invalid bearer credential."),
        "403": problem_response("Authenticated principal lacks the scope required for this operation."),
        "404": problem_response("EDR collection not found."),
        "default": problem_response("Problem Details error response."),
    })
}

#[cfg(any(
    feature = "ogcapi-features",
    feature = "ogcapi-records",
    feature = "ogcapi-edr"
))]
fn ogc_json_path_item(op_id: &str, summary: &str, schema: &str) -> Value {
    let mut item =
        ogc_path_item_with_params("get", summary, schema, "application/json", Vec::new());
    if let Some(op) = item.get_mut("get").and_then(Value::as_object_mut) {
        op.insert("operationId".to_string(), json!(op_id));
    }
    item
}

#[cfg(any(
    feature = "ogcapi-features",
    feature = "ogcapi-records",
    feature = "ogcapi-edr"
))]
fn ogc_path_item_with_params(
    method: &str,
    summary: &str,
    schema: &str,
    media_type: &str,
    parameters: Vec<Value>,
) -> Value {
    json!({
        method: {
            "summary": summary,
            "parameters": parameters,
            "responses": {
                "200": {
                    "description": "Successful response",
                    "content": {
                        media_type: {
                            "schema": { "$ref": format!("#/components/schemas/{schema}") }
                        }
                    }
                },
                "400": problem_response("Invalid OGC or spatial query parameter."),
                "401": problem_response("Missing or invalid bearer credential."),
                "403": problem_response(
                    "Authenticated principal lacks the scope required for this operation."
                ),
                "404": problem_response("OGC collection or feature not found."),
                "default": problem_response("Problem Details error response."),
            }
        }
    })
}

fn public_resource_path_item(
    op_id: &str,
    summary: &str,
    description: &str,
    media_type: &str,
    schema: &str,
    parameters: Vec<Value>,
) -> Value {
    json!({
        "get": {
            "operationId": op_id,
            "summary": summary,
            "description": description,
            "parameters": parameters,
            "responses": {
                "200": {
                    "description": "Successful response",
                    "content": {
                        media_type: {
                            "schema": { "$ref": format!("#/components/schemas/{schema}") }
                        }
                    }
                },
                "404": problem_response("Requested provenance artefact is not available."),
                "default": problem_response("Problem Details error response."),
            }
        }
    })
}

#[cfg(feature = "spdci-api-standards")]
fn spdci_path_item(op_id: &str, summary: &str, description: &str) -> Value {
    json!({
        "post": {
            "operationId": op_id,
            "summary": summary,
            "description": description,
            "parameters": [
                path_parameter("registry", "Configured SP DCI registry adapter name.")
            ],
            "requestBody": {
                "required": true,
                "content": {
                    "application/json": {
                        "schema": { "$ref": "#/components/schemas/SpdciSyncRequest" }
                    }
                }
            },
            "responses": {
                "200": {
                    "description": "Successful SP DCI response envelope.",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": "#/components/schemas/SpdciSyncResponse" }
                        }
                    }
                },
                "400": problem_response("Invalid SP DCI request header or message envelope."),
                "401": problem_response("Missing or invalid bearer credential."),
                "403": problem_response("Authenticated principal lacks the scope required for this adapter."),
                "404": problem_response("Configured SP DCI registry adapter was not found."),
                "default": problem_response("Problem Details error response."),
            }
        }
    })
}

fn insert_json_path(
    paths: &mut Map<String, Value>,
    path: &str,
    method: &str,
    summary: &str,
    schema: &str,
) {
    paths.insert(path.to_string(), json_path_item(method, summary, schema));
}

fn json_path_item(method: &str, summary: &str, schema: &str) -> Value {
    path_item_with_params(method, summary, schema, Vec::new())
}

fn path_item_with_params(
    method: &str,
    summary: &str,
    schema: &str,
    parameters: Vec<Value>,
) -> Value {
    json!({
        method: {
            "summary": summary,
            "parameters": parameters,
            "responses": {
                "200": {
                    "description": "Successful response",
                    "content": {
                        "application/json": {
                            "schema": { "$ref": format!("#/components/schemas/{schema}") }
                        }
                    }
                },
                "401": problem_response(
                    "Missing or invalid bearer credential."
                ),
                "403": problem_response(
                    "Authenticated principal lacks the scope required for this operation."
                ),
                "default": problem_response("Problem Details error response."),
            }
        }
    })
}

fn aggregate_run_path_item(dataset_id: &str) -> Value {
    let parameters = vec![
        path_parameter("aggregate_id", "Aggregate identifier"),
        query_parameter("f", "Response format. Use `json` or `csv`."),
    ];
    json!({
        "get": {
            "summary": "Run aggregate defaults",
            "description": format!(
                "Runs a dataset-scoped aggregate in `{dataset_id}` with its configured default indicators, default group_by, and no optional filters."
            ),
            "parameters": parameters,
            "responses": aggregate_result_responses(),
        },
        "post": {
            "summary": "Query aggregate",
            "description": format!(
                "Runs a dataset-scoped aggregate in `{dataset_id}` with caller-selected indicators, group_by dimensions, and configured filters."
            ),
            "parameters": [path_parameter("aggregate_id", "Aggregate identifier")],
            "requestBody": aggregate_query_request_body(),
            "responses": aggregate_result_responses(),
        }
    })
}

fn aggregate_query_path_item(dataset_id: &str) -> Value {
    json!({
        "post": {
            "summary": "Query aggregate",
            "description": format!(
                "Runs a dataset-scoped aggregate in `{dataset_id}` with caller-selected indicators, group_by dimensions, and configured filters."
            ),
            "parameters": [path_parameter("aggregate_id", "Aggregate identifier")],
            "requestBody": aggregate_query_request_body(),
            "responses": aggregate_result_responses(),
        }
    })
}

fn aggregate_query_request_body() -> Value {
    json!({
        "required": false,
        "content": {
            "application/json": {
                "schema": { "$ref": "#/components/schemas/AggregateQueryRequest" }
            }
        }
    })
}

fn aggregate_result_responses() -> Value {
    json!({
        "200": {
            "description": "Successful aggregate response.",
            "content": {
                "application/json": {
                    "schema": { "$ref": "#/components/schemas/AggregateResult" }
                },
                "text/csv": {
                    "schema": { "type": "string" }
                }
            }
        },
        "400": problem_response("Invalid aggregate query."),
        "401": problem_response("Missing or invalid bearer credential."),
        "403": problem_response("Authenticated principal lacks the scope required for this operation."),
        "default": problem_response("Problem Details error response."),
    })
}

/// Path item for routes that return JSON-LD (DCAT-AP, SHACL). These
/// share the 401/403/default error envelope but emit an inline object
/// schema for their JSON-LD body rather than a `$ref`.
fn jsonld_path_item(
    op_id: &str,
    summary: &str,
    description: &str,
    response_description: &str,
) -> Value {
    jsonld_path_item_with_params(
        op_id,
        summary,
        description,
        response_description,
        Vec::new(),
    )
}

fn jsonld_path_item_with_params(
    op_id: &str,
    summary: &str,
    description: &str,
    response_description: &str,
    parameters: Vec<Value>,
) -> Value {
    json!({
        "get": {
            "operationId": op_id,
            "summary": summary,
            "description": description,
            "parameters": parameters,
            "responses": {
                "200": {
                    "description": response_description,
                    "content": {
                        "application/ld+json": {
                            "schema": { "type": "object" }
                        }
                    }
                },
                "401": problem_response(
                    "Missing or invalid bearer credential."
                ),
                "403": problem_response(
                    "Authenticated principal lacks the scope required for this operation."
                ),
                "default": problem_response("Problem Details error response."),
            }
        }
    })
}

fn problem_response(description: &str) -> Value {
    json!({
        "description": description,
        "content": {
            "application/problem+json": {
                "schema": { "$ref": "#/components/schemas/ProblemDetails" }
            }
        }
    })
}

fn entity_collection_path_item(summary: &str, schema: &str, entity: &EntityConfig) -> Value {
    let mut parameters = pagination_parameters();
    parameters.push(query_parameter(
        "fields",
        "Comma-separated list of entity fields to project. Unknown fields are rejected.",
    ));
    if !entity.api.allowed_expansions.is_empty() {
        parameters.push(enum_query_parameter(
            "expand",
            "Comma-separated relationships to expand inline. Limited to the entity's \
             configured `allowed_expansions`.",
            entity
                .api
                .allowed_expansions
                .iter()
                .map(String::as_str)
                .collect(),
        ));
    }
    parameters.extend(filter_parameters(entity));
    path_item_with_params("get", summary, schema, parameters)
}

fn entity_record_path_item(summary: &str, schema: &str, entity: &EntityConfig) -> Value {
    let mut parameters = vec![path_parameter("id", "Entity primary key")];
    parameters.push(query_parameter(
        "fields",
        "Comma-separated list of entity fields to project. Unknown fields are rejected.",
    ));
    if !entity.api.allowed_expansions.is_empty() {
        parameters.push(enum_query_parameter(
            "expand",
            "Comma-separated relationships to expand inline. Limited to the entity's \
             configured `allowed_expansions`.",
            entity
                .api
                .allowed_expansions
                .iter()
                .map(String::as_str)
                .collect(),
        ));
    }
    path_item_with_params("get", summary, schema, parameters)
}

fn entity_relationship_path_item(
    dataset: &DatasetMetadata,
    relationship: &RelationshipMetadata,
) -> Value {
    let target_component = dataset
        .entities
        .iter()
        .find(|entity| entity.name == relationship.target)
        .map(|entity| entity_component_name(&dataset.dataset_id, &entity.name));
    let schema = match relationship.kind {
        "has_many" => {
            let items = target_component
                .as_deref()
                .map(|component| json!({ "$ref": format!("#/components/schemas/{component}") }))
                .unwrap_or_else(|| json!({ "type": "object", "additionalProperties": true }));
            json!({
            "type": "object",
            "required": ["data", "pagination"],
            "properties": {
                "data": {
                    "type": "array",
                    "items": items,
                },
                "pagination": { "$ref": "#/components/schemas/Pagination" },
            },
            })
        }
        _ if target_component.is_some() => {
            let component = target_component.expect("checked is_some");
            json!({ "$ref": format!("#/components/schemas/{component}") })
        }
        _ => json!({ "type": "object", "additionalProperties": true }),
    };
    json!({
        "get": {
            "summary": format!("Relationship: {}", relationship.name),
            "parameters": relationship_parameters(relationship.kind),
            "responses": {
                "200": {
                    "description": "Successful response",
                    "content": {
                        "application/json": {
                            "schema": schema
                        }
                    }
                },
                "401": problem_response("Missing or invalid bearer credential."),
                "403": problem_response(
                    "Authenticated principal lacks the scope required for this operation."
                ),
                "default": problem_response("Problem Details error response."),
            }
        }
    })
}

fn pagination_parameters() -> Vec<Value> {
    vec![
        json!({
            "name": "limit",
            "in": "query",
            "required": false,
            "schema": { "type": "integer", "format": "int32", "minimum": 1 },
            "description": "Maximum records to return. Capped by the entity's `api.max_limit`.",
            "examples": { "default": { "value": 10 } },
        }),
        query_parameter(
            "cursor",
            "Opaque pagination cursor returned in a prior response's `pagination.next_cursor`.",
        ),
    ]
}

fn relationship_parameters(kind: &str) -> Vec<Value> {
    let mut parameters = vec![path_parameter("id", "Entity primary key")];
    if kind == "has_many" {
        parameters.extend(pagination_parameters());
    }
    parameters
}

fn filter_parameters(entity: &EntityConfig) -> Vec<Value> {
    entity
        .api
        .allowed_filters
        .iter()
        .flat_map(|filter| {
            filter.ops.iter().map(|op| {
                let name = filter_parameter_name(&filter.field, *op);
                let description = filter_parameter_description(&filter.field, *op);
                query_parameter(&name, &description)
            })
        })
        .collect()
}

fn filter_parameter_name(field: &str, op: FilterOp) -> String {
    match op {
        FilterOp::Eq => field.to_string(),
        FilterOp::In => format!("{field}.in"),
        FilterOp::Gte => format!("{field}.gte"),
        FilterOp::Lte => format!("{field}.lte"),
        FilterOp::Between => format!("{field}.between"),
    }
}

fn filter_parameter_description(field: &str, op: FilterOp) -> String {
    match op {
        FilterOp::Eq => format!("Filter by exact match on `{field}`."),
        FilterOp::In => {
            format!("Filter by inclusion in a comma-separated list of `{field}` values.")
        }
        FilterOp::Gte => format!("Filter where `{field}` is greater than or equal to the value."),
        FilterOp::Lte => format!("Filter where `{field}` is less than or equal to the value."),
        FilterOp::Between => {
            format!("Filter where `{field}` is within an inclusive `min,max` range.")
        }
    }
}

fn path_parameter(name: &str, description: &str) -> Value {
    json!({
        "name": name,
        "in": "path",
        "required": true,
        "description": description,
        "schema": { "type": "string" },
    })
}

fn query_parameter(name: &str, description: &str) -> Value {
    json!({
        "name": name,
        "in": "query",
        "required": false,
        "description": description,
        "schema": { "type": "string" },
    })
}

/// Header parameter declaring the `Data-Purpose` requirement. Entities
/// with `api.require_purpose_header: true` reject row-data requests that
/// omit this header with `auth.purpose_required`. Surfacing it in the
/// OpenAPI document lets Scalar render a fillable field in the Try-it
/// panel and lets generated clients carry it through.
fn purpose_header_parameter() -> Value {
    purpose_header_parameter_with_required(true)
}

fn purpose_header_parameter_with_required(required: bool) -> Value {
    json!({
        "name": "Data-Purpose",
        "in": "header",
        "required": required,
        "description": "Absolute purpose-of-use IRI recorded in the audit trail. \
                        Required by this entity's policy. \
                        Header names are case-insensitive, so `Data-Purpose` and \
                        `data-purpose` are equivalent.",
        "schema": { "type": "string", "format": "uri", "minLength": 1 },
        "example": "https://demo.example.gov/purpose/demo-review",
    })
}

fn enum_query_parameter(name: &str, description: &str, values: Vec<&str>) -> Value {
    json!({
        "name": name,
        "in": "query",
        "required": false,
        "description": description,
        "schema": { "type": "string", "enum": values },
    })
}

fn entity_component_name(dataset_id: &str, entity_name: &str) -> String {
    format!(
        "Entity_{}_{}",
        sanitize_component_part(dataset_id),
        sanitize_component_part(entity_name)
    )
}

fn entity_collection_component_name(entity_component: &str) -> String {
    format!("{entity_component}Collection")
}

fn sanitize_component_part(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
}

fn op_id_slug(value: &str) -> String {
    sanitize_component_part(value).to_lowercase()
}

fn openapi_unavailable(detail: &'static str) -> Response {
    let mut response = (
        StatusCode::NOT_IMPLEMENTED,
        Json(json!({
            "type": format!("{}openapi/generation_unavailable", crate::error::PROBLEM_TYPE_BASE),
            "title": "OpenAPI generation unavailable",
            "status": StatusCode::NOT_IMPLEMENTED.as_u16(),
            "detail": detail,
            "code": OPENAPI_UNAVAILABLE_CODE,
        })),
    )
        .into_response();
    response
        .headers_mut()
        .insert(header::CONTENT_TYPE, PROBLEM_JSON);
    response
        .extensions_mut()
        .insert(ErrorCodeExt(OPENAPI_UNAVAILABLE_CODE.to_string()));
    response
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "spdci-api-standards")]
    use std::collections::BTreeMap;
    use std::env;
    use std::path::PathBuf;
    use std::time::Duration;

    use super::*;
    use crate::config::{
        AdmsStatus, AuthMode, ClaimValidity, GatewayIssuerConfig, IssuerConfig,
        ProvenanceAlgorithm, ProvenanceConfig, SignerConfig, SoftwareSignerConfig,
    };
    use crate::metadata::catalog::{CatalogLinks, DatasetLinks, EntityLinks};

    fn load_example_config() -> Config {
        let fingerprint = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        unsafe {
            env::set_var("STATS_OFFICE_API_KEY_HASH", fingerprint);
            env::set_var("PROGRAM_SYSTEM_API_KEY_HASH", fingerprint);
            env::set_var("VERIFICATION_SERVICE_API_KEY_HASH", fingerprint);
            env::set_var(
                "REGISTRY_RELAY_AUDIT_HASH_SECRET",
                "relay-openapi-audit-secret-32-bytes",
            );
        }
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/example.yaml");
        crate::config::load(&path).expect("example config loads")
    }

    fn enable_provenance(config: &mut Config) {
        config.provenance = Some(ProvenanceConfig {
            enabled: true,
            accepted_media_types: vec![
                "application/vc+jwt".to_string(),
                "application/jwt".to_string(),
            ],
            schema_base_url: "https://data.example.test/schemas".to_string(),
            context_base_url: "https://data.example.test/contexts".to_string(),
            claim_validity: ClaimValidity {
                aggregate_result: Duration::from_secs(3600),
                entity_record: Duration::from_secs(86_400),
            },
            issuer: IssuerConfig::Gateway(GatewayIssuerConfig {
                did: "did:web:data.example.test".to_string(),
                verification_method_id: "did:web:data.example.test#issuance".to_string(),
                signer: SignerConfig::Software(SoftwareSignerConfig {
                    jwk_env: "REGISTRY_RELAY_PROVENANCE_JWK".to_string(),
                    signing_algorithm: ProvenanceAlgorithm::EdDSA,
                }),
                retired_keys: Vec::new(),
            }),
        });
    }

    fn catalog_with_individual() -> CatalogDocument {
        CatalogDocument {
            title: "Test Catalog".to_string(),
            publisher: "Test Publisher".to_string(),
            base_url: "https://data.example.test".to_string(),
            participant_id: "did:web:data.example.test".to_string(),
            authority_type: None,
            links: CatalogLinks {
                self_url: "https://data.example.test/metadata/catalog".to_string(),
                dcat_ap: "https://data.example.test/metadata/dcat/bregdcat-ap".to_string(),
            },
            datasets: vec![DatasetMetadata {
                dataset_id: "social_registry".to_string(),
                title: "Social Registry".to_string(),
                description: "Test dataset".to_string(),
                owner: "Test Owner".to_string(),
                publisher: "Test Publisher".to_string(),
                sensitivity: "personal",
                access_rights: "restricted",
                update_frequency: "monthly",
                conforms_to: Vec::new(),
                applicable_legislation: Vec::new(),
                spatial_coverage: None,
                adms_status: AdmsStatus::Completed,
                public_services: Vec::new(),
                compiled_policy: None,
                links: DatasetLinks {
                    self_url: "https://data.example.test/v1/datasets/social_registry".to_string(),
                    ogc_collections: None,
                    ogc_records: None,
                },
                standards: Default::default(),
                entities: vec![EntityMetadata {
                    name: "individual".to_string(),
                    title: Some("Individual".to_string()),
                    description: Some("A person enrolled in Program X".to_string()),
                    concept_uri: Some("https://publicschema.org/concepts/Person".to_string()),
                    primary_key: "id".to_string(),
                    fields: vec![FieldMetadata {
                        name: "id".to_string(),
                        r#type: "string",
                        nullable: false,
                        concept_uri: None,
                        codelist: None,
                        unit: None,
                        language: None,
                    }],
                    relationships: Vec::new(),
                    links: EntityLinks {
                        collection: "https://data.example.test/v1/datasets/social_registry/entities/individual/records"
                            .to_string(),
                        schema:
                            "https://data.example.test/v1/datasets/social_registry/entities/individual/schema"
                                .to_string(),
                        ogc_collection: None,
                        ogc_items: None,
                    },
                }],
            }],
        }
    }

    #[test]
    fn evidence_verification_components_are_registered() {
        let config = load_example_config();
        let doc = openapi_document(&catalog_with_individual(), &config);
        let schemas = doc["components"]["schemas"]
            .as_object()
            .expect("schemas object");

        assert!(schemas.contains_key("EvidenceOfferingList"));
        assert!(schemas.contains_key("EvidenceOffering"));
        assert!(!schemas.contains_key("EvidenceVerificationRequest"));
        assert!(!schemas.contains_key("EvidenceVerificationResponse"));
        assert!(!schemas.contains_key("ClaimVerificationRequest"));
        assert!(!schemas.contains_key("ClaimVerificationResponse"));

        assert_eq!(
            schemas["EvidenceOffering"]["properties"]["access"]["properties"]["kind"]["enum"],
            json!(["registry-notary"])
        );
    }

    #[test]
    fn response_example_mutator_uses_named_key_status_and_preserves_existing_examples() {
        let mut paths = Map::new();
        paths.insert(
            "/created".to_string(),
            json!({
                "post": {
                    "responses": {
                        "201": {
                            "description": "Created",
                            "content": {
                                "application/json": {
                                    "schema": { "type": "object" },
                                    "examples": {
                                        "existing": {
                                            "summary": "Existing example.",
                                            "value": { "id": "kept" }
                                        },
                                        "created": {
                                            "summary": "Original created example.",
                                            "value": { "id": "original" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }),
        );

        set_json_response_example(
            &mut paths,
            "/created",
            "post",
            "201",
            "created",
            "Replacement should not overwrite.",
            json!({ "id": "replacement" }),
        );
        set_json_response_example(
            &mut paths,
            "/created",
            "post",
            "201",
            "alternate",
            "Alternate created response.",
            json!({ "id": "alternate" }),
        );
        set_json_response_example(
            &mut paths,
            "/created",
            "post",
            "200",
            "wrong_status",
            "Wrong status should not create an example.",
            json!({ "id": "wrong" }),
        );

        let examples = &paths["/created"]["post"]["responses"]["201"]["content"]
            ["application/json"]["examples"];
        assert_eq!(examples["existing"]["value"]["id"], "kept");
        assert_eq!(examples["created"]["value"]["id"], "original");
        assert_eq!(examples["alternate"]["value"]["id"], "alternate");
        assert!(examples["name"].is_null());
        assert!(examples["wrong_status"].is_null());
    }

    #[test]
    fn metadata_dataset_components_describe_nested_catalog_shape() {
        let config = load_example_config();
        let doc = openapi_document(&catalog_with_individual(), &config);
        let schemas = &doc["components"]["schemas"];

        assert_eq!(
            schemas["MetadataDatasetList"]["properties"]["datasets"]["items"]["$ref"],
            "#/components/schemas/MetadataDataset"
        );
        let dataset = &schemas["MetadataDataset"];
        assert_eq!(dataset["properties"]["dataset_id"]["type"], "string");
        assert_eq!(
            dataset["properties"]["entities"]["additionalProperties"]["properties"]["fields"]
                ["additionalProperties"]["properties"]["field_type"]["type"],
            "string"
        );
        assert_eq!(
            dataset["properties"]["entities"]["additionalProperties"]["properties"]
                ["relationships"]["items"]["properties"]["kind"]["enum"],
            json!(["belongs_to", "has_many"])
        );
    }

    #[test]
    fn provenance_openapi_documents_public_artifacts_and_signed_vc_variants_when_enabled() {
        let mut config = load_example_config();
        enable_provenance(&mut config);
        let doc = openapi_document(&catalog_with_individual(), &config);

        for (path, media_type, schema) in [
            (
                "/schemas/{claim_type}/{version}",
                "application/schema+json",
                "#/components/schemas/JsonSchemaDocument",
            ),
            (
                "/contexts/{vocab}/{version}",
                "application/ld+json",
                "#/components/schemas/JsonLdContext",
            ),
            (
                "/.well-known/did.json",
                "application/did+json",
                "#/components/schemas/DidDocument",
            ),
        ] {
            let op = &doc["paths"][path]["get"];
            assert_eq!(op["security"], json!([]), "{path} should be public");
            assert_eq!(op["tags"], json!([TAG_PROVENANCE]));
            assert_eq!(
                op["responses"]["200"]["content"][media_type]["schema"]["$ref"], schema,
                "{path} should document its media type"
            );
        }

        for path in [
            "/v1/datasets/social_registry/entities/individual/records/{id}",
            "/v1/datasets/social_registry/aggregates/{aggregate_id}",
        ] {
            let op = &doc["paths"][path]["get"];
            assert_eq!(
                op["responses"]["200"]["content"][VC_JWT_MEDIA_TYPE]["schema"]["type"], "string",
                "{path} should document signed VC-JWT responses"
            );
            let accept = op["parameters"]
                .as_array()
                .expect("parameters")
                .iter()
                .find(|parameter| parameter["name"] == "Accept")
                .expect("Accept parameter");
            assert_eq!(accept["schema"]["enum"][1], VC_JWT_MEDIA_TYPE);
            assert_eq!(accept["schema"]["enum"][2], "application/jwt");
        }

        assert!(doc["components"]["schemas"]["DidDocument"].is_object());
        assert!(doc["components"]["schemas"]["JsonSchemaDocument"].is_object());
        assert!(doc["components"]["schemas"]["JsonLdContext"].is_object());
    }

    #[test]
    fn security_scheme_description_tracks_auth_mode() {
        let mut config = load_example_config();

        let api_key_doc = openapi_document(&catalog_with_individual(), &config);
        assert_eq!(
            api_key_doc["security"],
            json!([{ "bearerAuth": [] }, { "apiKeyAuth": [] }])
        );
        assert!(
            api_key_doc["components"]["securitySchemes"]["bearerAuth"]["description"]
                .as_str()
                .expect("bearer description")
                .contains("API key")
        );
        assert_eq!(
            api_key_doc["components"]["securitySchemes"]["apiKeyAuth"]["name"],
            "X-Api-Key"
        );

        config.auth.mode = AuthMode::Oidc;
        let oidc_doc = openapi_document(&catalog_with_individual(), &config);
        assert_eq!(oidc_doc["security"], json!([{ "bearerAuth": [] }]));
        assert!(oidc_doc["components"]["securitySchemes"]["apiKeyAuth"].is_null());
        assert!(
            oidc_doc["components"]["securitySchemes"]["bearerAuth"]["description"]
                .as_str()
                .expect("bearer description")
                .contains("OIDC/OAuth2 bearer JWT")
        );
    }

    #[cfg(feature = "spdci-api-standards")]
    #[test]
    fn spdci_openapi_documents_configured_sync_surface() {
        let mut config = load_example_config();
        config.standards.spdci = Some(crate::config::SpdciStandardsConfig {
            disability_registry: None,
            registries: BTreeMap::new(),
        });
        let doc = openapi_document(&catalog_with_individual(), &config);

        for path in [
            "/dci/{registry}/registry/sync/search",
            "/dci/{registry}/registry/sync/disabled",
            "/dci/{registry}/registry/sync/get-disability-details",
            "/dci/{registry}/registry/sync/get-disability-support",
        ] {
            let op = &doc["paths"][path]["post"];
            assert_eq!(op["tags"], json!([TAG_SPD_CI]));
            assert_eq!(
                op["requestBody"]["content"]["application/json"]["schema"]["$ref"],
                "#/components/schemas/SpdciSyncRequest"
            );
            assert_eq!(
                op["responses"]["200"]["content"]["application/json"]["schema"]["$ref"],
                "#/components/schemas/SpdciSyncResponse"
            );
        }
        assert!(doc["components"]["schemas"]["SpdciSyncRequest"].is_object());
        assert!(doc["components"]["schemas"]["SpdciSyncResponse"].is_object());
    }
}
