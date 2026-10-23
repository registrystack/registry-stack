#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]
// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use registry_breg::artifacts::REGISTRY_METADATA_ARTIFACT_PATH;
use registry_breg::compiler::{
    compile_project, compile_project_with_assets, deployment_diagnostics, module_digest,
    module_digest_with_assets, CompileProfile,
};
use registry_breg::contract::{
    parse_module_json, parse_module_yaml, parse_project_json, parse_project_yaml,
    ActionExecutionSource, ActionSource, Classification, ComparisonOperator, ConstraintSource,
    DerivedFieldSource, DerivedSource, DisplaySource, FieldTypeSource, ModuleAssetSource,
    ModuleLockSource, Operation, PackageIdentitySource, ReferenceDelete, RegistryModule,
    ReviewAuthoritySource, UniqueWhenPredicate, MODULE_API_VERSION, MODULE_KIND,
};
use registry_breg::diagnostics::{CompileFailure, DiagnosticSeverity};
use registry_breg::generated_ddl::DdlStatementKind;
use registry_breg::model::{
    CompiledMetadataInventory, CompiledQueryFilterOperator, CompiledQueryKind,
    CompiledQuerySortDirection, CompiledQueryTemporalSemantics, CompiledRevisionKind,
    MAX_REVISION_HISTORY_RECORDS,
};
use registry_manifest_core::{compile_manifest, AccessRights, FieldType, MetadataManifest};
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use serde_json::{json, Value};

#[path = "support/source_bytes.rs"]
mod source_bytes;

/// An edit a test applies to a fixture project before reading it.
type ProjectEdit = Box<dyn Fn(&mut Value)>;

fn asset_project() -> registry_breg::contract::RegistryProject {
    acceptance_project("asset-site-placement")
}

fn asset_modules() -> Vec<RegistryModule> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance/asset-site-placement/modules")
        .join("asset-site-placement-core/module.yaml");
    let bytes = fs::read(path).expect("committed acceptance module is readable");
    vec![parse_module_yaml(&bytes).expect("acceptance module follows the authoring contract")]
}

fn acceptance_project(domain: &str) -> registry_breg::contract::RegistryProject {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance")
        .join(domain)
        .join("registry.yaml");
    let bytes = fs::read(path).expect("committed acceptance fixture is readable");
    parse_project_yaml(&bytes).expect("acceptance fixture follows the authoring contract")
}

fn compile_json(source: &[u8]) -> Result<registry_breg::CompiledRegistry, CompileFailure> {
    let project = parse_project_json(source).expect("source shape parses");
    compile_project(&project, &[], CompileProfile::Authoring)
}

fn compile_json_with_assets(
    source: &[u8],
    assets: Vec<ModuleAssetSource>,
) -> Result<registry_breg::CompiledRegistry, CompileFailure> {
    let project = parse_project_json(source).expect("source shape parses");
    compile_project_with_assets(&project, &[], &assets, CompileProfile::Authoring)
}

const MULTI_DATASET_PROJECT: &[u8] = br#"{"datasets":[{"id": "people"}, {"id": "residences"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"multi-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://registry.example.test/multi"},
          "manifestProjection":{
            "accessProfile":"reader",
            "classificationCeiling":"restricted",
            "catalog":{"baseUrl":"https://registry.example.test/multi","title":"Multi Registry","publisher":{"id":"multi-authority","name":"Registry Authority","iri":"https://registry.example.test/authority"}},
            "publicService":{"id":"multi-service","title":"Registry service"},
            "datasets":[
              {"id":"people","iri":"https://identity.example.test/datasets/people","title":"People","version":"2026.1"},
              {"id":"residences","title":"Residences","accessProfile":"reader","classificationCeiling":"internal"}
            ],
            "dataServices":[{"id":"registry-api","title":"Registry API","endpointUrl":"https://registry.example.test/v1","servesDatasets":["people","residences"]}],
            "distributions":[{"id":"people-json","dataset":"people","accessService":"registry-api","mediaType":"application/json"}]
          },
          "recordTypes":[
            {"id":"person","primaryDataset":"people","route":"people","mutationMode":"mutable","classification":"restricted","fields":[{"id":"name","type":"string","maximumLength":100,"classification":"restricted"}]},
            {"id":"residence","primaryDataset":"residences","route":"residences","mutationMode":"mutable","classification":"internal","fields":[
              {"id":"place","type":"string","maximumLength":100,"classification":"internal"},
              {"id":"resident","type":"reference","target":"person","classification":"internal"}
            ]}
          ],
          "accessProfiles":[{"id":"reader","default":true,"principalClaim":"sub","requiredScopes":["registry.read"],"permissions":{
            "records":[
              {"recordType":"person","operations":["get","list"],"readableFields":["name"], "rowBoundaries": "unrestricted"},
              {"recordType":"residence","operations":["get","list"],"readableFields":["place","resident"], "rowBoundaries": "unrestricted"}
            ]
          }}]
        }"#;

fn multi_dataset_project() -> registry_breg::contract::RegistryProject {
    parse_project_json(MULTI_DATASET_PROJECT).expect("multi-dataset source parses")
}

fn authored_display_project() -> registry_breg::contract::RegistryProject {
    parse_project_yaml(include_bytes!(
        "../../../products/breg/fixtures/authoring-display/registry.yaml"
    ))
    .expect("the authored-display fixture parses")
}

fn presentation_extension_module() -> RegistryModule {
    parse_module_json(
        br#"{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"presentation","version":"1",
          "extendRecordTypes":[
            {"recordType":"entry"},
            {"recordType":"entry",
             "accessProfiles":[{
               "id":"module-reader","principalClaim":"registry_principal","requiredScopes":["directory:read"],
               "operations":["get"],"readableFields":["code"],"rowBoundaries":"unrestricted"
             }],
             "hooks":[{
               "id":"module-entry-created","phase":"after","trigger":"created","projection":["code"],
               "handler":{"type":"url","destinationId":"entry-events"}
             }]}
          ]
        }"#,
    )
    .expect("the presentation extension module parses")
}

fn add_presentation_module(project: &mut registry_breg::contract::RegistryProject) {
    project.modules.push(ModuleLockSource {
        id: "presentation".to_owned(),
        version: "1".to_owned(),
        digest: None,
    });
}

#[test]
fn manifest_projection_text_is_one_string_or_a_language_mapping() {
    let title = "project.manifestProjection.catalog.title";
    let project = |written: Value| {
        let mut value: Value =
            serde_json::from_slice(MULTI_DATASET_PROJECT).expect("fixture is JSON");
        value["manifestProjection"]["catalog"]["title"] = written;
        parse_project_yaml(&serde_json::to_vec(&value).expect("fixture serializes"))
    };
    for accepted in [
        json!("Multi Registry"),
        json!({"en":"Multi Registry","fr":"Registre"}),
    ] {
        project(accepted).expect("each text form is read");
    }
    for (written, code, path) in [
        (
            json!(["Multi Registry"]),
            "config.invalid-type",
            title.to_owned(),
        ),
        (
            json!({"en":["Multi Registry"]}),
            "config.expected-string",
            format!("{title}.en"),
        ),
    ] {
        let failure = project(written).expect_err("a malformed text is refused");
        let refused = failure
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(refused, vec![(code, path.as_str())], "{failure:?}");
    }
}

#[test]
fn manifest_endpoint_description_is_an_http_url() {
    let project = |written: &str| {
        let mut value: Value =
            serde_json::from_slice(MULTI_DATASET_PROJECT).expect("fixture is JSON");
        value["manifestProjection"]["dataServices"][0]["endpointDescription"] = json!(written);
        parse_project_yaml(&serde_json::to_vec(&value).expect("fixture serializes"))
    };
    for accepted in [
        "https://registry.example.test/openapi.json",
        "https://registry.example.test/openapi\u{202e}.json",
    ] {
        let project = project(accepted).expect("the endpoint description is read as source text");
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("an endpoint description URL follows Manifest URL rules");
    }
    let refused = "API description";
    let project = project(refused).expect("the endpoint description is read as source text");
    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("Manifest compilation refuses a non-URL endpoint description");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| {
            diagnostic.path == "project.manifestProjection.data_services[0].endpoint_description"
        })
        .unwrap_or_else(|| panic!("endpoint description refusal is located: {failure:?}"));
    assert_eq!(diagnostic.code, "breg.manifest-projection.invalid");
    assert!(!diagnostic.message.contains(refused));
}

#[test]
fn directly_constructed_display_text_is_validated_across_source_shapes() {
    let unsafe_text = "reordered\u{202e}".to_owned();
    let invalid_label = || DisplaySource {
        label: Some(unsafe_text.clone()),
        ..DisplaySource::default()
    };
    let invalid_description = || DisplaySource {
        description: Some(unsafe_text.clone()),
        ..DisplaySource::default()
    };
    let mut project = multi_dataset_project();
    project.project.display = invalid_label();
    project.datasets[0].display = invalid_description();
    project.review_authorities.push(ReviewAuthoritySource {
        id: "review-main".to_owned(),
        protocol: "id.registrystack.org/protocols/review/v1".to_owned(),
        display: invalid_label(),
    });
    project.entities[0].display = invalid_description();
    project.entities[0].fields[0].display = invalid_label();
    project.entities[0].derived.push(DerivedSource {
        id: "summary".to_owned(),
        sql: "sql/summary.sql".to_owned(),
        key: "id".to_owned(),
        execution: Default::default(),
        fields: vec![DerivedFieldSource {
            id: "score".to_owned(),
            api_name: None,
            field_type: FieldTypeSource::Int64,
            classification: Classification::Internal,
            display: invalid_description(),
        }],
    });
    let mut action: ActionSource = serde_json::from_value(json!({
        "id": "rename-person",
        "execution": {"mode": "immediate"},
        "inputs": [{
            "id": "name",
            "type": "string",
            "maximumLength": 100,
            "classification": "restricted"
        }],
        "plan": {"type": "fixed", "effects": [{
            "id": "person",
            "target": {"recordType": "person"},
            "operation": "create",
            "set": {"name": {"fromInput": "name"}}
        }]}
    }))
    .expect("a fixed action parses before direct display mutation");
    action.display = invalid_label();
    action.inputs[0].display = invalid_description();
    project.actions.push(action);

    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("directly constructed unsafe display text is refused");
    let mut paths = failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "breg.display-text.invalid")
        .map(|diagnostic| diagnostic.path.as_str())
        .collect::<Vec<_>>();
    paths.sort_unstable();
    assert_eq!(
        paths,
        [
            "actions[id=rename-person].display.label",
            "actions[id=rename-person].inputs[id=name].display.description",
            "datasets[id=people].display.description",
            "project.project.display.label",
            "recordTypes[id=person].derived[id=summary].fields[id=score].display.description",
            "recordTypes[id=person].display.description",
            "recordTypes[id=person].fields[id=name].display.label",
            "reviewAuthorities[id=review-main].display.label",
        ]
    );
    assert!(failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "breg.display-text.invalid")
        .all(|diagnostic| !diagnostic.message.contains(&unsafe_text)));
}

#[test]
fn directly_constructed_multilingual_display_and_manifest_text_is_preserved() {
    const DISPLAY: &str = "\u{200f}سجل السكان";
    const ENDPOINT_DESCRIPTION: &str =
        "https://registry.example.test/service-description\u{202e}.json";
    let mut project = multi_dataset_project();
    project.project.display.label = Some(DISPLAY.to_owned());
    project.datasets[0].display.description = Some(DISPLAY.to_owned());
    project.entities[0].display.description = Some(DISPLAY.to_owned());
    project.entities[0].fields[0].display.label = Some(DISPLAY.to_owned());
    let projection = project
        .manifest_projection
        .as_mut()
        .expect("fixture has a Manifest projection");
    projection.catalog.publisher.name = DISPLAY.to_owned();
    projection.datasets[0].owner = Some(DISPLAY.to_owned());
    projection.data_services[0].endpoint_description = Some(ENDPOINT_DESCRIPTION.to_owned());

    let compiled = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("multilingual directly constructed display text compiles");
    assert_eq!(compiled.display().label.as_deref(), Some(DISPLAY));
    assert_eq!(
        compiled.entities()["person"].display.description.as_deref(),
        Some(DISPLAY)
    );
    assert_eq!(
        compiled.entities()["person"].fields["name"]
            .display
            .label
            .as_deref(),
        Some(DISPLAY)
    );
    let projection = compiled
        .manifest_projection()
        .expect("compiled projection exists");
    assert_eq!(projection.primary_authority.name, DISPLAY);
    assert_eq!(
        projection.datasets["people"].source.owner.as_deref(),
        Some(DISPLAY)
    );
    assert_eq!(
        projection.data_services["registry-api"]
            .source
            .endpoint_description
            .as_deref(),
        Some(ENDPOINT_DESCRIPTION)
    );
}

#[test]
fn directly_constructed_presentation_text_is_validated_at_each_authored_owner() {
    let unsafe_text = "reordered\u{202e}".to_owned();
    let mut project = authored_display_project();
    add_presentation_module(&mut project);
    project.access_profiles[0].display.label = Some(unsafe_text.clone());
    project.statistical_datasets[0].display.description = Some(unsafe_text.clone());
    project.entities[0].hooks[0].display.label = Some(unsafe_text.clone());
    let ActionExecutionSource::Proposal { proposal } = &mut project.actions[0].execution else {
        panic!("the authored-display Action is a Proposal")
    };
    proposal.hooks[0].display.description = Some(unsafe_text.clone());

    let mut module = presentation_extension_module();
    module.extend_entities[1].access_profiles[0].display.label = Some(unsafe_text.clone());
    module.extend_entities[1].hooks[0].display.description = Some(unsafe_text.clone());

    let failure = compile_project(&project, &[module], CompileProfile::Authoring)
        .expect_err("unsafe directly constructed presentation text is refused");
    let mut paths = failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "breg.display-text.invalid")
        .map(|diagnostic| diagnostic.path.as_str())
        .collect::<Vec<_>>();
    paths.sort_unstable();
    assert_eq!(
        paths,
        [
            "accessProfiles[id=directory-editor].display.label",
            "actions[id=register-entry].execution.proposal.hooks[id=proposal-submitted].display.description",
            "modules[id=presentation].extendRecordTypes[1].accessProfiles[id=module-reader].display.label",
            "modules[id=presentation].extendRecordTypes[1].hooks[id=module-entry-created].display.description",
            "recordTypes[id=entry].hooks[id=entry-created].display.label",
            "statisticalDatasets[id=entry-counts].display.description",
        ]
    );
    assert!(failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "breg.display-text.invalid")
        .all(|diagnostic| !diagnostic.message.contains(&unsafe_text)));
}

#[test]
fn directly_constructed_multilingual_presentation_text_is_preserved() {
    const DISPLAY: &str = "\u{200f}سجل السكان";
    let mut project = authored_display_project();
    add_presentation_module(&mut project);
    project.access_profiles[0].display.label = Some(DISPLAY.to_owned());
    project.statistical_datasets[0].display.description = Some(DISPLAY.to_owned());
    project.entities[0].hooks[0].display.label = Some(DISPLAY.to_owned());
    let ActionExecutionSource::Proposal { proposal } = &mut project.actions[0].execution else {
        panic!("the authored-display Action is a Proposal")
    };
    proposal.hooks[0].display.description = Some(DISPLAY.to_owned());

    let mut module = presentation_extension_module();
    module.extend_entities[1].access_profiles[0].display.label = Some(DISPLAY.to_owned());
    module.extend_entities[1].hooks[0].display.description = Some(DISPLAY.to_owned());

    let compiled = compile_project(&project, &[module], CompileProfile::Authoring)
        .expect("multilingual directly constructed presentation text compiles");
    assert_eq!(
        compiled.access_profile_displays()[0]
            .display
            .label
            .as_deref(),
        Some(DISPLAY)
    );
    assert_eq!(
        compiled.statistical_datasets()["entry-counts"]
            .display
            .description
            .as_deref(),
        Some(DISPLAY)
    );
    let entry = &compiled.entities()["entry"];
    assert_eq!(
        entry.hooks["entry-created"].display.label.as_deref(),
        Some(DISPLAY)
    );
    assert_eq!(
        entry.access_profiles["module-reader"]
            .display
            .label
            .as_deref(),
        Some(DISPLAY)
    );
    assert_eq!(
        entry.hooks["module-entry-created"]
            .display
            .description
            .as_deref(),
        Some(DISPLAY)
    );
    let action = compiled
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "register-entry")
        .expect("the authored-display Action compiles");
    let registry_breg::model::CompiledActionExecution::Proposal { proposal } = &action.execution
    else {
        panic!("the authored-display Action remains a Proposal")
    };
    assert_eq!(
        proposal.hooks[0].display.description.as_deref(),
        Some(DISPLAY)
    );
}

#[test]
fn directly_constructed_manifest_display_text_is_refused_at_each_string_field() {
    let unsafe_text = "reordered\u{202e}".to_owned();
    let mut project = multi_dataset_project();
    let projection = project
        .manifest_projection
        .as_mut()
        .expect("fixture has a Manifest projection");
    projection.catalog.publisher.name = unsafe_text.clone();
    projection.datasets[0].owner = Some(unsafe_text.clone());

    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("directly constructed unsafe Manifest display text is refused");
    let mut paths = failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "breg.display-text.invalid")
        .map(|diagnostic| diagnostic.path.as_str())
        .collect::<Vec<_>>();
    paths.sort_unstable();
    assert_eq!(
        paths,
        [
            "project.manifestProjection.catalog.publisher.name",
            "project.manifestProjection.datasets[0].owner",
        ]
    );
    assert!(failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "breg.display-text.invalid")
        .all(|diagnostic| !diagnostic.message.contains(&unsafe_text)));
}

#[test]
fn plural_projection_compiles_resolved_membership_and_manifest_resources() {
    let compiled = compile_project(&multi_dataset_project(), &[], CompileProfile::Authoring)
        .expect("plural multi-dataset project compiles");
    let projection = compiled
        .manifest_projection()
        .expect("compiled projection exists");
    assert_eq!(
        projection.canonical_base_iri,
        "https://registry.example.test/multi"
    );
    assert_eq!(projection.primary_authority.id, "multi-authority");
    assert_eq!(
        projection.primary_authority.iri,
        "https://registry.example.test/authority"
    );
    assert_eq!(
        projection.public_service.competent_authority,
        "multi-authority"
    );
    assert_eq!(
        projection.public_service.produces,
        ["people".to_owned(), "residences".to_owned()].into()
    );
    assert_eq!(
        projection.public_service.data_services,
        ["registry-api".to_owned()].into()
    );
    assert_eq!(
        projection.public_service.iri,
        "https://registry.example.test/multi/public-services/multi-service"
    );
    assert_eq!(
        projection.datasets["people"].iri,
        "https://identity.example.test/datasets/people"
    );
    assert_eq!(
        projection.datasets["residences"].iri,
        "https://registry.example.test/multi/datasets/residences"
    );
    assert_eq!(
        projection.data_services["registry-api"].iri,
        "https://registry.example.test/multi/data-services/registry-api"
    );
    assert_eq!(
        projection.distributions["people-json"].iri,
        "https://registry.example.test/multi/distributions/people-json"
    );
    assert_eq!(projection.datasets.len(), 2);
    assert_eq!(projection.entity_datasets["person"], "people");
    assert_eq!(projection.entity_datasets["residence"], "residences");
    assert!(matches!(
        &compiled.entities()["residence"].fields["resident"].field_type,
        FieldTypeSource::Reference { target, .. } if target == "person"
    ));
    assert_eq!(
        projection.datasets["residences"].effective_access_profile,
        "reader"
    );
    assert_eq!(
        projection.datasets["residences"].effective_classification_ceiling,
        Classification::Internal
    );

    let manifest_bytes = &compiled
        .artifacts()
        .get("generated/manifest/registry-manifest.json")
        .expect("Manifest artifact exists")
        .bytes;
    let manifest: MetadataManifest = serde_json::from_slice(manifest_bytes).unwrap();
    assert_eq!(manifest.authorities.len(), 1);
    assert_eq!(manifest.public_services.len(), 1);
    assert_eq!(manifest.datasets.len(), 2);
    assert_eq!(manifest.data_services[0].serves_datasets.len(), 2);
    assert_eq!(manifest.distributions[0].dataset, "people");
    assert_eq!(manifest.datasets[0].version.as_deref(), Some("2026.1"));
    let residence = manifest
        .datasets
        .iter()
        .find(|dataset| dataset.id == "residences")
        .expect("residences remains visible in the portable projection");
    assert!(residence.entities[0]
        .relationships
        .iter()
        .all(|relationship| relationship.name != "resident"));
}

#[test]
fn manifest_projection_excludes_every_protected_resource_from_public_bytes() {
    let mut project = parse_project_json(
        br#"{"datasets":[{"id": "protected-records"}, {"id": "public-records"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"classified-catalog","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://catalog.example.test"},
          "manifestProjection":{
            "accessProfile":"public-reader",
            "classificationCeiling":"public",
            "catalog":{"baseUrl":"https://catalog.example.test","title":"Classified Catalog","publisher":{"id":"catalog-authority","name":"Catalog Authority"}},
            "publicService":{"id":"catalog-service","title":"Catalog service"},
            "datasets":[
              {"id":"public-records","title":"Public records","accessProfile":"public-reader","classificationCeiling":"public"},
              {"id":"protected-records","title":"Protected records title","accessProfile":"protected-reader","classificationCeiling":"restricted"}
            ],
            "dataServices":[
              {"id":"public-api","title":"Public API","endpointUrl":"https://catalog.example.test/public","servesDatasets":["public-records"]},
              {"id":"protected-api","title":"Protected API title","endpointUrl":"https://protected.example.test/private","servesDatasets":["protected-records"]}
            ],
            "distributions":[
              {"id":"public-json","dataset":"public-records","accessService":"public-api","downloadUrl":"https://catalog.example.test/public.ndjson"},
              {"id":"protected-json","dataset":"protected-records","accessService":"protected-api","downloadUrl":"https://protected.example.test/private.ndjson","title":"Protected distribution title"}
            ]
          },
          "recordTypes":[
            {"id":"public-record","primaryDataset":"public-records","route":"public-records","mutationMode":"create-only","classification":"public","fields":[
              {"id":"label","type":"string","maximumLength":64,"classification":"public"},
              {"id":"protected-link","type":"reference","target":"protected-record","classification":"public"}
            ]},
            {"id":"protected-record","primaryDataset":"protected-records","route":"protected-records","mutationMode":"create-only","classification":"restricted","fields":[
              {"id":"protected-title","type":"string","maximumLength":64,"classification":"restricted"}
            ]}
          ],
          "accessProfiles":[
            {"id":"public-reader","principalClaim":"sub","requiredScopes":["public.read"],"permissions":{"records":[{"recordType":"public-record","operations":["get"],"readableFields":["label","protected-link"], "rowBoundaries": "unrestricted"}]}},
            {"id":"protected-reader","principalClaim":"sub","requiredScopes":["protected.read"],"permissions":{"records":[{"recordType":"protected-record","operations":["get"],"readableFields":["protected-title"], "rowBoundaries": "unrestricted"}]}}
          ]
        }"#,
    )
    .expect("classified project parses");

    let public = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("public publication context compiles");
    let operational_link = &public.entities()["public-record"].fields["protected-link"];
    assert!(matches!(
        &operational_link.field_type,
        FieldTypeSource::Reference { target, .. } if target == "protected-record"
    ));

    let manifest_bytes = &public
        .artifacts()
        .get("generated/manifest/registry-manifest.json")
        .expect("public Manifest exists")
        .bytes;
    let dcat_bytes = &public
        .artifacts()
        .get("generated/manifest/dcat.jsonld")
        .expect("public DCAT exists")
        .bytes;
    for bytes in [manifest_bytes, dcat_bytes] {
        let rendered = std::str::from_utf8(bytes).expect("generated metadata is UTF-8");
        for protected in [
            "protected-records",
            "Protected records title",
            "protected-record",
            "protected-link",
            "protected-api",
            "Protected API title",
            "protected.example.test",
            "protected-json",
            "Protected distribution title",
        ] {
            assert!(
                !rendered.contains(protected),
                "public metadata disclosed {protected}: {rendered}"
            );
        }
    }

    let manifest: MetadataManifest =
        serde_json::from_slice(manifest_bytes).expect("public Manifest parses");
    assert_eq!(
        manifest
            .datasets
            .iter()
            .map(|dataset| dataset.id.as_str())
            .collect::<Vec<_>>(),
        ["public-records"]
    );
    assert_eq!(manifest.data_services[0].id, "public-api");
    assert_eq!(
        manifest.data_services[0].serves_datasets,
        ["public-records"]
    );
    assert_eq!(manifest.public_services[0].produces, ["public-records"]);
    assert_eq!(manifest.public_services[0].data_services, ["public-api"]);
    assert!(manifest.datasets[0].entities[0].relationships.is_empty());

    let projection = project
        .manifest_projection
        .as_mut()
        .expect("projection exists");
    projection.access_profile = "protected-reader".to_owned();
    projection.classification_ceiling = Classification::Restricted;
    let protected = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("authorized protected publication context compiles");
    let protected_manifest = protected
        .artifacts()
        .get("generated/manifest/registry-manifest.json")
        .expect("protected Manifest exists");
    let protected_rendered =
        std::str::from_utf8(&protected_manifest.bytes).expect("protected Manifest is UTF-8");
    for expected in [
        "protected-records",
        "Protected records title",
        "protected-record",
        "protected-api",
        "protected-json",
    ] {
        assert!(
            protected_rendered.contains(expected),
            "authorized metadata omitted {expected}: {protected_rendered}"
        );
    }
}

#[test]
fn plural_projection_refuses_duplicate_and_dangling_membership() {
    let mut missing_canonical_iri = multi_dataset_project();
    missing_canonical_iri.project.canonical_base_iri.clear();
    assert_compile_diagnostic(
        missing_canonical_iri,
        "breg.registry.canonical-base-iri-required",
    );

    let mut duplicate = multi_dataset_project();
    let repeated = duplicate.manifest_projection.as_ref().unwrap().datasets[0].clone();
    duplicate
        .manifest_projection
        .as_mut()
        .unwrap()
        .datasets
        .push(repeated);
    let failure = compile_project(&duplicate, &[], CompileProfile::Authoring)
        .expect_err("duplicate dataset fails");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.manifest-projection.dataset-duplicate"));

    let mut dangling = multi_dataset_project();
    dangling.entities[0].primary_dataset = "missing".to_owned();
    let failure = compile_project(&dangling, &[], CompileProfile::Authoring)
        .expect_err("dangling entity dataset fails");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.record-type.dataset-unknown"));

    let mut missing = multi_dataset_project();
    missing.entities[0].primary_dataset.clear();
    assert_compile_diagnostic(
        missing,
        "breg.manifest-projection.entity-primary-dataset-required",
    );

    let mut empty_dataset = multi_dataset_project();
    empty_dataset.entities[1].primary_dataset = "people".to_owned();
    assert_compile_diagnostic(
        empty_dataset,
        "breg.manifest-projection.dataset-entities-empty",
    );

    let mut duplicate_service = multi_dataset_project();
    let service = duplicate_service
        .manifest_projection
        .as_ref()
        .unwrap()
        .data_services[0]
        .clone();
    duplicate_service
        .manifest_projection
        .as_mut()
        .unwrap()
        .data_services
        .push(service);
    assert_compile_diagnostic(
        duplicate_service,
        "breg.manifest-projection.data-service-duplicate",
    );

    let mut dangling_service_dataset = multi_dataset_project();
    dangling_service_dataset
        .manifest_projection
        .as_mut()
        .unwrap()
        .data_services[0]
        .serves_datasets
        .push("missing".to_owned());
    assert_compile_diagnostic(
        dangling_service_dataset,
        "breg.manifest-projection.data-service-dataset-dangling",
    );

    let mut duplicate_distribution = multi_dataset_project();
    let distribution = duplicate_distribution
        .manifest_projection
        .as_ref()
        .unwrap()
        .distributions[0]
        .clone();
    duplicate_distribution
        .manifest_projection
        .as_mut()
        .unwrap()
        .distributions
        .push(distribution);
    assert_compile_diagnostic(
        duplicate_distribution,
        "breg.manifest-projection.distribution-duplicate",
    );

    let mut dangling_distribution_service = multi_dataset_project();
    dangling_distribution_service
        .manifest_projection
        .as_mut()
        .unwrap()
        .distributions[0]
        .access_service = Some("missing".to_owned());
    assert_compile_diagnostic(
        dangling_distribution_service,
        "breg.manifest-projection.distribution-access-service-dangling",
    );

    let mut unknown_effective_profile = multi_dataset_project();
    unknown_effective_profile
        .manifest_projection
        .as_mut()
        .unwrap()
        .datasets[1]
        .access_profile = Some("missing".to_owned());
    assert_compile_diagnostic(
        unknown_effective_profile,
        "breg.manifest-projection.dataset-access-profile-unknown",
    );
}

#[test]
fn deployment_refuses_a_reserved_canonical_base_iri_that_compilation_accepts() {
    for iri in [
        "https://invalid",
        "https://household-registry.example.invalid",
        "https://HOUSEHOLD-REGISTRY.EXAMPLE.INVALID",
        "https://household-registry.example.invalid./registry",
        "https://household-registry.example.invalid.?source=placeholder",
        "http://household-registry.example.invalid/",
    ] {
        let mut project = multi_dataset_project();
        project.project.canonical_base_iri = iri.to_owned();
        let diagnostics = deployment_diagnostics(&project);
        assert_eq!(diagnostics.len(), 1, "{iri}");
        assert_eq!(
            diagnostics[0].code,
            "breg.registry.canonical-base-iri-reserved"
        );
        assert_eq!(diagnostics[0].path, "project.project.canonicalBaseIri");
        // Local development and schema tests compile the placeholder
        // unchanged; only deployment tooling refuses it.
        compile_project(&project, &[], CompileProfile::Authoring)
            .expect("authoring accepts the placeholder IRI");
        let production = compile_project(&project, &[], CompileProfile::Production)
            .expect_err("the shared fixture omits production package identity");
        assert!(production
            .diagnostics()
            .iter()
            .all(|diagnostic| diagnostic.code != "breg.registry.canonical-base-iri-reserved"));
    }

    for iri in [
        "https://household-registry.example.invalid.example.org",
        "https://household-registry.exampleinvalid",
    ] {
        let mut project = multi_dataset_project();
        project.project.canonical_base_iri = iri.to_owned();
        assert!(deployment_diagnostics(&project).is_empty(), "{iri}");
    }
}

#[test]
fn missing_resource_identity_members_have_actionable_authoring_diagnostics() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"missing-identity","version":"1","defaultLanguage":"en"},
          "recordTypes":[{"id":"record","route":"records","mutationMode":"create-only"}]
        }"#,
    )
    .expect("omissions reach the compiler diagnostic domain");
    let project = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("project identity members are required for compilation");
    let project_codes = project
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
        .collect::<BTreeSet<_>>();
    assert!(project_codes.contains(&(
        "breg.registry.canonical-base-iri-required",
        "project.project.canonicalBaseIri"
    )));
    assert!(project_codes.contains(&(
        "breg.manifest-projection.entity-primary-dataset-required",
        "recordTypes[id=record].primaryDataset"
    )));

    let module = parse_module_json(
        br#"{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"missing-membership","version":"1","recordTypes":[{"id":"record","route":"records","mutationMode":"create-only"}]}"#,
    )
    .expect("module omission reaches the compiler diagnostic domain");
    let project = parse_project_json(
        br#"{
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"module-host","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://module-host.example.test"},
          "modules":[{"id":"missing-membership","version":"1"}]
        }"#,
    )
    .expect("module host parses");
    let module = compile_project(&project, &[module], CompileProfile::Authoring)
        .expect_err("module entity membership is required for compilation");
    assert!(module.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "breg.manifest-projection.entity-primary-dataset-required"
            && diagnostic.path == "recordTypes[id=record].primaryDataset"
    }));
}

fn assert_compile_diagnostic(project: registry_breg::contract::RegistryProject, code: &str) {
    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("invalid multi-dataset references fail compilation");
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == code),
        "expected {code}, got {:?}",
        failure.diagnostics()
    );
}

fn derived_sql_asset(path: &str, sql: &str) -> ModuleAssetSource {
    ModuleAssetSource {
        module: None,
        path: path.to_owned(),
        bytes: sql.as_bytes().to_vec(),
    }
}

#[test]
fn constraint_unions_refuse_at_the_member_inside_the_form() {
    let constraint = "project.recordTypes[0].constraints[0]";
    for (written, code, path) in [
        (
            r#"{"type":"compare","left":"left","operator":"less-than","right":"right","field":"left"}"#,
            "config.unknown-key",
            format!("{constraint}.field"),
        ),
        (
            r#"{"type":"compare","left":"left","right":"right"}"#,
            "config.missing-key",
            constraint.to_owned(),
        ),
        (
            r#"{"type":"unique","fields":["left"],"when":[{"type":"active-lifecycle","field":"left"}]}"#,
            "config.unknown-key",
            format!("{constraint}.when[0].field"),
        ),
        (
            r#"{"type":"unique","fields":["left"],"when":[{"type":"field_is_empty","field":"left"}]}"#,
            "config.unknown-variant",
            format!("{constraint}.when[0].type"),
        ),
        (
            r#"{"fields":["left"]}"#,
            "config.missing-key",
            constraint.to_owned(),
        ),
    ] {
        let source = format!(
            r#"{{"datasets":[{{"id": "test-dataset"}}],
              "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
              "kind":"BRegProject",
              "project":{{"id":"constraint-unions","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
              "recordTypes":[{{
                "id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"create-only",
                "fields":[
                  {{"id":"left","type":"int64","classification":"internal"}},
                  {{"id":"right","type":"int64","classification":"internal"}}
                ],
                "constraints":[{written}]
              }}]
            }}"#
        );
        let failure = parse_project_yaml(source.as_bytes())
            .expect_err("a malformed constraint is refused when the project is read");
        let refused = failure
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(refused, vec![(code, path.as_str())], "{failure:?}");
    }
}

#[test]
fn derived_fields_selectors_and_read_paths_compile_to_route_specific_inventories() {
    let project = br#"{"datasets":[{"id": "test-dataset"}],
      "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
      "kind":"BRegProject",
      "project":{"id":"household-demo","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
      "recordTypes":[{
        "id":"household","primaryDataset":"test-dataset","route":"households","mutationMode":"mutable",
        "fields":[
          {"id":"household-code","type":"string","maximumLength":32,"required":true,"classification":"internal"},
          {"id":"administrative-area","type":"string","maximumLength":32,"required":true,"classification":"internal"},
          {"id":"local-household-number","type":"string","maximumLength":32,"required":true,"classification":"internal"}
        ],
        "derived":[{
          "id":"demographics","sql":"sql/household-demographics.sql","key":"id","execution":"live",
          "fields":[
            {"id":"child-count","type":"int64","classification":"restricted","display":{"label":"Child count","description":"Number of linked children."}},
            {"id":"single-headed","type":"boolean","classification":"restricted"},
            {"id":"registry-derived-key-cardinality","type":"int64","classification":"restricted"}
          ]
        }],
        "selectorProfiles":[
          {"id":"by-local-reference","fields":["administrative-area","local-household-number"]}
        ],
        "readPaths":[{"id":"people","through":"group-membership","to":"person","route":"people"}]
      },{
        "id":"person","primaryDataset":"test-dataset","route":"people","mutationMode":"mutable",
        "fields":[
          {"id":"legal-name","type":"string","maximumLength":80,"classification":"internal"},
          {"id":"date-of-birth","type":"date","classification":"internal"}
        ]
      },{
        "id":"group-membership","primaryDataset":"test-dataset","route":"memberships","mutationMode":"mutable",
        "fields":[
          {"id":"household","type":"reference","target":"household","classification":"internal"},
          {"id":"person","type":"reference","target":"person","classification":"internal"}
        ]
      }],
      "accessProfiles":[{
        "id":"operator","default":true,"principalClaim":"sub","requiredScopes":"unrestricted","permissions":{"records":[{
          "recordType":"household","operations":["get","lookup","list"],
          "readableFields":["household-code","child-count","single-headed"],
          "filterableFields":["child-count","single-headed"],
          "sortableFields":["child-count"],
          "allowCount":true,
          "lookups":[{"selector":"by-local-reference","valueOrigin":"request"}],
          "readPaths":[{
            "path":"people",
            "readableFields":["legal-name","date-of-birth"],
            "filterableFields":["date-of-birth"],
            "sortableFields":["date-of-birth"],
            "allowCount":true
          }],
          "rowBoundaries": "unrestricted"
        }]}
      }]
    }"#;
    let sql = "SELECT h.id AS id, count(p.id)::bigint AS child_count, false AS single_headed, 1::bigint AS registry_derived_key_cardinality FROM registry_source.household h LEFT JOIN registry_source.group_membership gm ON gm.household = h.id LEFT JOIN registry_source.person p ON p.id = gm.person GROUP BY h.id";
    let compiled = compile_json_with_assets(
        project,
        vec![derived_sql_asset("sql/household-demographics.sql", sql)],
    )
    .expect("derived fields and relationship reads compile");

    let household = &compiled.entities()["household"];
    assert_eq!(
        household.derived_fields["child-count"]
            .display
            .label
            .as_deref(),
        Some("Child count")
    );
    let model = registry_breg::artifacts::inspect_registry(&compiled);
    let fields = model["recordTypes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["id"] == "household")
        .unwrap()["fields"]
        .as_array()
        .unwrap();
    let derived = fields
        .iter()
        .find(|field| field["id"] == "child-count")
        .unwrap();
    assert_eq!(
        derived["display"],
        serde_json::json!({"label":"Child count","description":"Number of linked children."})
    );
    assert_eq!(
        household
            .stored_fields
            .iter()
            .map(|field| field.logical.id.as_str())
            .collect::<Vec<_>>(),
        vec![
            "household-code",
            "administrative-area",
            "local-household-number"
        ],
        "stored field authoring order is preserved for DDL/query workers"
    );
    assert_eq!(household.canonical_id.id, "id");
    assert!(!household.fields.contains_key("id"));
    let person = &compiled.entities()["person"];
    let path_policy = compiled
        .ddl()
        .tables
        .iter()
        .find(|table| table.entity_id == "person")
        .and_then(|table| table.policies.first())
        .and_then(|policy| policy.using_expression.as_deref())
        .expect("target read-path RLS policy is compiled");
    assert!(path_policy.contains(&format!("\"{}\".\"record_id\"", person.physical_table)));
    let child_count = &household.derived_fields["child-count"].logical;
    assert_eq!(child_count.api_name, "childCount");
    assert_eq!(child_count.sql_name, "child_count");
    assert_eq!(
        household.derived_relations["demographics"].sql_bytes,
        sql.as_bytes()
    );
    let last_source_view = compiled
        .ddl()
        .statements
        .iter()
        .rposition(|statement| statement.id.ends_with(".source-view"))
        .expect("source views are generated");
    let first_derived_view = compiled
        .ddl()
        .statements
        .iter()
        .position(|statement| statement.id.contains(".derived."))
        .expect("derived view is generated");
    assert!(
        last_source_view < first_derived_view,
        "all source views must exist before cross-entity derived SQL is installed"
    );
    let derived_view = &compiled.ddl().statements[first_derived_view].sql;
    assert!(derived_view
        .contains("count(*) OVER (PARTITION BY canonical_derived.\"__registry$derived$key\")"));
    assert!(derived_view.contains("\"__registry$derived$cardinality\""));
    assert!(derived_view
        .contains("CASE WHEN \"registry_derived_key_cardinality\" IS NULL THEN NULL::bigint"));
    assert!(derived_view.contains(
        "derived field household.registry-derived-key-cardinality violates declared type"
    ));
    assert!(compiled
        .routes()
        .routes
        .iter()
        .any(|route| route.id == "records.household.lookup"
            && route.path == "/v1/records/households:lookup"));
    assert!(compiled
        .routes()
        .routes
        .iter()
        .any(|route| route.id == "records.household.path.people"
            && route.path == "/v1/records/households/{record_id}/people"));
    assert!(compiled
        .access()
        .entries
        .iter()
        .any(|entry| entry.route_id == "records.household.path.people"
            && entry.profile_ids.contains("operator")));
    let lookup = compiled
        .queries()
        .operations
        .iter()
        .find(|operation| operation.id == "records.household.operator.lookup")
        .expect("lookup selector operation is compiled");
    assert_eq!(
        lookup.selector_fields,
        vec!["administrative-area", "local-household-number"]
    );
    let path = compiled
        .queries()
        .operations
        .iter()
        .find(|operation| operation.id == "records.household.operator.path.people")
        .expect("read-path operation is compiled");
    assert_eq!(path.read_path.as_deref(), Some("people"));
    assert!(path.allow_count);
    assert!(path.processing_fields.contains(&"household".to_owned()));
    assert!(path.processing_fields.contains(&"person".to_owned()));
}

#[test]
fn read_path_processing_diagnostic_names_the_profile_path_and_field() {
    let failure = compile_json(
        br#"{"datasets":[{"id":"records"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"read-path-disclosure","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://read-paths.example.test"},
          "recordTypes":[
            {"id":"household","primaryDataset":"records","route":"households","mutationMode":"mutable",
             "fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"}],
             "readPaths":[{"id":"people","through":"membership","to":"person","route":"people"}]},
            {"id":"person","primaryDataset":"records","route":"people","mutationMode":"mutable",
             "fields":[
               {"id":"legal-name","type":"string","maximumLength":80,"classification":"internal"},
               {"id":"date-of-birth","type":"date","classification":"internal"}
             ]},
            {"id":"membership","primaryDataset":"records","route":"memberships","mutationMode":"mutable","fields":[]}
          ],
          "accessProfiles":[{
            "id":"reader","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
              "recordType":"household","operations":["get"],"readableFields":["code"],"rowBoundaries":"unrestricted",
              "readPaths":[{"path":"people","readableFields":["legal-name"],"filterableFields":["date-of-birth"]}]
            }]}
          }]
        }"#,
    )
    .expect_err("read-path processing cannot exceed its disclosure projection");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| {
            diagnostic.code == "breg.access-profile.read-path-processing-wider-than-read"
        })
        .expect("read-path processing wider than disclosure is diagnosed");
    assert_eq!(
        diagnostic.path,
        "recordTypes[id=household].accessProfiles[id=reader].readPaths[path=people].filterableFields[field=date-of-birth]"
    );
    for identifier in ["reader", "people", "date-of-birth"] {
        assert!(diagnostic.message.contains(identifier), "{diagnostic:?}");
    }
}

#[test]
fn canonical_id_row_boundary_targets_the_physical_record_id_column() {
    let compiled = compile_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"canonical-id-boundary","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"household","primaryDataset":"test-dataset","route":"households","mutationMode":"mutable",
            "fields":[
              {"id":"household-code","type":"string","maximumLength":32,"classification":"internal"}
            ]
          }],
          "accessProfiles":[{
            "id":"viewer","principalClaim":"sub","requiredScopes":"unrestricted","permissions":{"records":[{
              "recordType":"household","operations":["get"],
              "readableFields":["household-code"],
              "rowBoundaries":[{"field":"id","claim":"household_id","operator":"equals"}]
            }]}
          }]
        }"#,
    )
    .expect("the canonical id is a valid governed row boundary");

    let policy = compiled
        .ddl()
        .tables
        .iter()
        .find(|table| table.entity_id == "household")
        .and_then(|table| {
            table
                .policies
                .iter()
                .find(|policy| policy.access_profile == "viewer")
        })
        .expect("viewer RLS policy is compiled");
    let expression = policy
        .using_expression
        .as_deref()
        .expect("viewer SELECT policy has a USING expression");
    assert!(expression.contains("\"record_id\" ="));
    assert!(
        !expression.contains("\"id\" ="),
        "logical aliases must not cross into physical table policies"
    );
}

#[test]
fn derived_sql_is_asset_backed_value_free_and_validates_output_aliases() {
    let project = br#"{"datasets":[{"id": "test-dataset"}],
      "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
      "kind":"BRegProject",
      "project":{"id":"derived-demo","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
      "recordTypes":[{
        "id":"household","primaryDataset":"test-dataset","route":"households","mutationMode":"mutable",
        "fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"}],
        "derived":[{
          "id":"demographics","sql":"sql/demographics.sql","key":"id",
          "fields":[{"id":"child-count","type":"int64","classification":"internal"}]
        }]
      }]
    }"#;

    let missing = compile_json_with_assets(project, vec![])
        .expect_err("derived SQL must be supplied as an explicit asset");
    assert!(missing
        .diagnostics()
        .iter()
        .any(
            |diagnostic| diagnostic.code == "breg.derived.sql-asset-missing"
                && !diagnostic.message.contains("SELECT")
        ));

    let wrong_alias = compile_json_with_assets(
        project,
        vec![derived_sql_asset(
            "sql/demographics.sql",
            "SELECT h.id AS id, 0::bigint AS childCount FROM registry_source.household h",
        )],
    )
    .expect_err("SQL output aliases must use stable SQL field names");
    assert!(wrong_alias
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.derived.sql-invalid"
            && diagnostic.path == "recordTypes[household].derived[demographics].sql"
            && !diagnostic.message.contains("childCount")));

    let wildcard = compile_json_with_assets(
        project,
        vec![derived_sql_asset(
            "sql/demographics.sql",
            "SELECT * FROM registry_source.household",
        )],
    )
    .expect_err("derived SQL cannot use wildcard projection");
    assert!(wildcard
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.derived.sql-invalid"));

    compile_json_with_assets(
        project,
        vec![derived_sql_asset(
            "sql/demographics.sql",
            "WITH counts AS (SELECT h.id AS id, count(*) AS child_count FROM registry_source.household h GROUP BY h.id) SELECT c.id AS id, c.child_count AS child_count FROM counts c",
        )],
    )
    .expect("a bounded non-recursive CTE over registry_source is accepted");
}

#[test]
fn module_digest_can_bind_explicit_sql_assets() {
    let module = parse_module_json(
        br#"{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"core","version":"1","recordTypes":[{"id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"mutable","fields":[{"id":"code","type":"string","maximumLength":8,"classification":"internal"}]}]}"#,
    )
    .expect("module parses");
    let yaml_only = module_digest(&module);
    let with_asset = module_digest_with_assets(
        &module,
        &[ModuleAssetSource {
            module: Some("core".to_owned()),
            path: "sql/derived.sql".to_owned(),
            bytes: b"SELECT r.id AS id FROM registry_source.record r".to_vec(),
        }],
    );
    assert_ne!(yaml_only, with_asset);
    assert_eq!(yaml_only, module_digest_with_assets(&module, &[]));
    assert_eq!(
        yaml_only,
        module_digest_with_assets(
            &module,
            &[ModuleAssetSource {
                module: Some("another-module".to_owned()),
                path: "sql/derived.sql".to_owned(),
                bytes: b"SELECT 1".to_vec(),
            }],
        ),
        "assets owned by another module do not change this module's lock digest"
    );
}

#[test]
fn derived_field_display_only_changes_module_digest_when_authored() {
    let module = |display: Option<Value>| {
        let mut source = json!({
            "apiVersion": MODULE_API_VERSION,
            "kind": MODULE_KIND,
            "id": "core",
            "version": "1",
            "recordTypes": [{
                "id": "record",
                "primaryDataset": "test-dataset",
                "route": "records",
                "mutationMode": "mutable",
                "fields": [{
                    "id": "code",
                    "type": "string",
                    "maximumLength": 8,
                    "classification": "internal"
                }],
                "derived": [{
                    "id": "summary",
                    "sql": "sql/summary.sql",
                    "key": "id",
                    "fields": [{
                        "id": "score",
                        "type": "int64",
                        "classification": "internal"
                    }]
                }]
            }]
        });
        if let Some(display) = display {
            source["recordTypes"][0]["derived"][0]["fields"][0]["display"] = display;
        }
        parse_module_json(&serde_json::to_vec(&source).expect("module source serializes"))
            .expect("module parses")
    };

    let omitted = module(None);
    let empty = module(Some(json!({})));
    let authored = module(Some(json!({
        "label": "Eligibility score",
        "description": "Calculated eligibility points."
    })));
    let omitted_value = serde_json::to_value(&omitted).expect("module serializes");
    let authored_value = serde_json::to_value(&authored).expect("module serializes");

    assert!(omitted_value["recordTypes"][0]["derived"][0]["fields"][0]
        .get("display")
        .is_none());
    assert_eq!(module_digest(&omitted), module_digest(&empty));
    assert_eq!(
        authored_value["recordTypes"][0]["derived"][0]["fields"][0]["display"],
        json!({
            "label": "Eligibility score",
            "description": "Calculated eligibility points."
        })
    );
    assert_ne!(module_digest(&omitted), module_digest(&authored));
}

#[test]
fn batch_route_requires_explicit_bounds_and_compiles_bounded_openapi() {
    let source = |batch: &str, operations: &str| {
        format!(
            r#"{{"datasets":[{{"id":"test-dataset"}}],
              "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
              "kind":"BRegProject",
              "project":{{"id":"batch-contract","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
              "recordTypes":[{{
                "id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"mutable"{batch},
                "fields":[{{"id":"label","type":"string","maximumLength":32,"required":true,"classification":"internal"}}]
              }}],
              "accessProfiles":[{{
                "id":"writer","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{{"records":[{{
                  "rowBoundaries": "unrestricted", "recordType":"record","operations":{operations},
                  "readableFields":["label"],"writableFields":["label"]
                }}]}}
              }}]
            }}"#
        )
    };

    let missing = compile_json(source("", r#"["create","batch"]"#).as_bytes())
        .expect_err("Batch grants require explicit entity-local bounds");
    assert!(missing
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.record-type.batch-required"));

    for batch in [
        r#", "batch":{"maximumItems":0,"maximumBytes":1}"#,
        r#", "batch":{"maximumItems":101,"maximumBytes":1}"#,
        r#", "batch":{"maximumItems":1,"maximumBytes":0}"#,
        r#", "batch":{"maximumItems":1,"maximumBytes":2097153}"#,
    ] {
        let failure = parse_project_yaml(source(batch, r#"["create","batch"]"#).as_bytes())
            .expect_err("out-of-range Batch bounds are refused when the project is read");
        assert!(failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "config.out-of-range"));
    }

    let configured = compile_json(
        source(
            r#", "tombstone":true, "batch":{"maximumItems":37,"maximumBytes":65536}"#,
            r#"["create","get","patch","tombstone","batch"]"#,
        )
        .as_bytes(),
    )
    .expect("bounded Batch contract compiles");
    let route = configured
        .routes()
        .routes
        .iter()
        .find(|route| route.operation == Operation::Batch)
        .expect("one Batch route is generated");
    assert_eq!(route.id, "records.record.batch");
    assert_eq!(route.path, "/v1/records/records:batch");
    let openapi = parse_json_strict(
        &configured
            .artifacts()
            .get("generated/openapi.json")
            .expect("OpenAPI is generated")
            .bytes,
    )
    .expect("OpenAPI is strict JSON");
    let batch_operation = &openapi["paths"]["/v1/records/records:batch"]["post"];
    assert_eq!(batch_operation["x-registry-maximumItems"], 37);
    assert_eq!(batch_operation["x-registry-maximumBytes"], 65536);
    let batch_request_schema =
        &batch_operation["requestBody"]["content"]["application/json"]["schema"];
    assert_eq!(batch_request_schema["properties"]["items"]["maxItems"], 37);
    let change_context = &batch_request_schema["properties"]["changeContext"];
    assert_eq!(change_context["additionalProperties"], false);
    assert_eq!(change_context["x-registry-maxCanonicalBytes"], 16 * 1024);
    assert_eq!(
        change_context["properties"]["kind"]["enum"],
        json!(["change", "correction"])
    );
    assert_eq!(
        change_context["properties"]["reasonCode"]["x-registry-maxBytes"],
        64
    );
    assert_eq!(change_context["properties"]["reasonCode"]["minLength"], 1);
    assert_eq!(
        change_context["properties"]["reasonText"]["x-registry-maxBytes"],
        4 * 1024
    );
    assert_eq!(
        change_context["properties"]["sourceReferences"]["maxItems"],
        16
    );
    assert_eq!(
        change_context["properties"]["sourceReferences"]["items"]["x-registry-maxBytes"],
        256
    );
    assert_eq!(
        change_context["allOf"][0]["then"]["required"],
        json!(["reasonCode"])
    );
    for item_schema in batch_request_schema["properties"]["items"]["items"]["oneOf"]
        .as_array()
        .expect("batch request item alternatives are rendered")
    {
        assert!(item_schema["properties"]
            .as_object()
            .expect("batch item properties render")
            .get("changeContext")
            .is_none());
    }
    let batch_response_schema =
        &batch_operation["responses"]["200"]["content"]["application/json"]["schema"];
    assert!(batch_response_schema["required"]
        .as_array()
        .expect("batch response required properties render")
        .contains(&json!("snapshot")));
    assert_eq!(
        batch_response_schema["properties"]["results"]["maxItems"],
        37
    );
    assert!(
        batch_response_schema["properties"]["results"]["items"]["properties"]
            .as_object()
            .expect("batch result properties render")
            .get("snapshot")
            .is_none()
    );

    let create_response_schema = &openapi["paths"]["/v1/records/records"]["post"]["responses"]
        ["201"]["content"]["application/json"]["schema"];
    let get_response_schema = &openapi["paths"]["/v1/records/records/{record_id}"]["get"]
        ["responses"]["200"]["content"]["application/json"]["schema"];
    let patch_response_schema = &openapi["paths"]["/v1/records/records/{record_id}"]["patch"]
        ["responses"]["200"]["content"]["application/json"]["schema"];
    let tombstone_response_schema = &openapi["paths"]["/v1/records/records/{record_id}"]["delete"]
        ["responses"]["200"]["content"]["application/json"]["schema"];
    for schema in [
        create_response_schema,
        patch_response_schema,
        tombstone_response_schema,
    ] {
        let record = &schema["properties"]["data"];
        assert!(record["required"]
            .as_array()
            .expect("mutation response record properties render")
            .contains(&json!("snapshot")));
        assert!(record["properties"].get("snapshot").is_some());
    }
    let get_record = &get_response_schema["properties"]["data"];
    assert!(get_record["required"]
        .as_array()
        .expect("read response record properties render")
        .iter()
        .all(|property| property.as_str() != Some("snapshot")));
    assert!(get_record["properties"].get("snapshot").is_none());

    let configured_but_ungranted = compile_json(
        source(
            r#", "batch":{"maximumItems":10,"maximumBytes":4096}"#,
            r#"["create"]"#,
        )
        .as_bytes(),
    )
    .expect("unused valid bounds do not create authority");
    assert!(configured_but_ungranted
        .routes()
        .routes
        .iter()
        .all(|route| route.operation != Operation::Batch));

    let create_only = source(
        r#", "batch":{"maximumItems":10,"maximumBytes":4096}"#,
        r#"["create","batch"]"#,
    )
    .replace(
        r#""mutationMode":"mutable""#,
        r#""mutationMode":"create-only""#,
    );
    let create_only = compile_json(create_only.as_bytes())
        .expect("create-only entities may expose bounded batch create");
    assert!(create_only
        .routes()
        .routes
        .iter()
        .any(|route| route.operation == Operation::Batch));

    let create_only_patch = source(
        r#", "batch":{"maximumItems":10,"maximumBytes":4096}"#,
        r#"["create","patch","batch"]"#,
    )
    .replace(
        r#""mutationMode":"mutable""#,
        r#""mutationMode":"create-only""#,
    );
    let unavailable = compile_json(create_only_patch.as_bytes())
        .expect_err("create-only Batch profiles can never grant patch");
    assert!(unavailable
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.access-profile.operation-unavailable"));
}

#[test]
fn public_asset_fixture_compiles_to_coherent_deterministic_inventories() {
    let project = asset_project();
    let modules = asset_modules();
    let first = compile_project(&project, &modules, CompileProfile::Production)
        .expect("the closed asset fixture compiles in production mode");
    let second = compile_project(&project, &modules, CompileProfile::Production)
        .expect("the same source compiles twice");

    assert_eq!(first, second);
    assert_eq!(first.entities().len(), 4);
    assert!(first.ddl().requires_btree_gist);
    assert!(first.ddl().script().contains("EXCLUDE USING gist"));
    assert!(first.artifacts().get("generated/openapi.json").is_some());
    assert!(first
        .artifacts()
        .get("generated/manifest/registry-manifest.json")
        .is_some());
    assert!(first
        .artifacts()
        .get("generated/schemas/asset-placement.schema.json")
        .is_some());

    let inspection_routes: Vec<_> = first
        .routes()
        .routes
        .iter()
        .filter(|route| route.entity_id == "inspection-event")
        .collect();
    assert!(inspection_routes
        .iter()
        .all(|route| !matches!(route.operation, Operation::Patch | Operation::Tombstone)));
    assert!(first
        .findings()
        .iter()
        .all(|d| d.code == "breg.access.profile-unrestricted-collection"));
}

#[test]
fn production_refuses_incomplete_authoring_closure() {
    let mut incomplete = asset_project();
    incomplete.package = None;
    incomplete.modules[0].digest = None;
    let failure = compile_project(&incomplete, &asset_modules(), CompileProfile::Production)
        .expect_err("the authoring fixture is not a production package");
    let codes: Vec<_> = failure
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect();
    assert!(codes.contains(&"breg.package.identity-required"));
    assert!(codes.contains(&"breg.module.lock-digest-required"));
    assert!(!codes.contains(&"manifest_projection.required"));

    let identity = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.package.identity-required")
        .expect("the missing package identity is reported");
    assert!(identity.message.contains("sourceRevision"), "{identity:?}");
    for retired in ["environment", "instanceId", "sequence"] {
        assert!(!identity.message.contains(retired), "{identity:?}");
    }

    let findings = compile_project(&incomplete, &asset_modules(), CompileProfile::Authoring)
        .expect("the authoring fixture still compiles for authoring")
        .findings()
        .to_vec();
    let missing = findings
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.package.identity-missing")
        .expect("the absent package identity is a finding under authoring");
    assert!(missing.message.contains("sourceRevision"), "{missing:?}");
    for retired in ["environment", "instanceId", "sequence"] {
        assert!(!missing.message.contains(retired), "{missing:?}");
    }
}

#[test]
fn registry_revision_is_a_function_of_the_compiled_model_only() {
    let compile = |project: &registry_breg::contract::RegistryProject| {
        compile_project(project, &asset_modules(), CompileProfile::Authoring)
            .expect("the acceptance project compiles")
    };
    let declared = asset_project();
    let mut relabelled = declared.clone();
    let identity = relabelled
        .package
        .as_mut()
        .expect("the acceptance project declares a package identity");
    identity.source_revision = "another-source-revision".to_owned();
    let mut undeclared = declared.clone();
    undeclared.package = None;

    let baseline = compile(&declared);
    for other in [compile(&relabelled), compile(&undeclared)] {
        assert_eq!(other.revision(), baseline.revision());
        assert_eq!(
            other
                .artifacts()
                .get("compiled/effective-model.json")
                .expect("effective model")
                .bytes,
            baseline
                .artifacts()
                .get("compiled/effective-model.json")
                .expect("effective model")
                .bytes
        );
    }
    let effective: Value = serde_json::from_slice(
        &baseline
            .artifacts()
            .get("compiled/effective-model.json")
            .expect("effective model")
            .bytes,
    )
    .expect("effective model is JSON");
    assert!(effective.get("package").is_none());
}

#[test]
fn deployment_identity_keys_in_the_project_are_refused_as_unknown_fields() {
    // The project is governed model bytes: a deployment-only value such as
    // the environment, the instance, or an activation sequence has no member
    // to land in, so the closed source shape refuses it without echoing it.
    for (key, value) in [
        ("environment", json!("deployment-environment-value")),
        ("instanceId", json!("deployment-instance-value")),
        ("sequence", json!(424242)),
    ] {
        let mut project = json!({
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"neutral","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "package":{"sourceRevision":"source"},
          "recordTypes":[]
        });
        project["package"][key] = value.clone();
        let bytes = serde_json::to_vec(&project).expect("project serializes");
        for (failure, code) in [
            (
                parse_project_json(&bytes).expect_err("a deployment key is refused"),
                "config.unknown-key",
            ),
            (
                parse_project_yaml(&bytes).expect_err("a deployment key is refused in YAML"),
                "config.unknown-key",
            ),
        ] {
            let [diagnostic] = failure.diagnostics() else {
                panic!("{key} is refused by one diagnostic: {failure:?}");
            };
            assert_eq!(diagnostic.code, code, "{diagnostic:?}");
            assert!(
                diagnostic
                    .message
                    .contains(&format!("unknown field `{key}`"))
                    || diagnostic
                        .message
                        .contains(&format!("`{key}` is not a member of this mapping")),
                "{}",
                diagnostic.message
            );
            let echoed = value.to_string();
            assert!(
                !diagnostic.message.contains(echoed.trim_matches('"')),
                "{}",
                diagnostic.message
            );
        }
    }
}

#[test]
fn singular_manifest_projection_keys_are_refused_as_unknown_fields() {
    // The projection publishes `datasets` and `dataServices`. A singular
    // `dataset` or `dataService` has no member to land in, so the closed
    // source shape refuses it like any other unknown key.
    for (key, value) in [
        ("dataset", json!({"title":"Dataset"})),
        (
            "dataService",
            json!({"id":"api","title":"API","endpointUrl":"https://registry.example.test"}),
        ),
    ] {
        let mut project = json!({"datasets":[{"id": "neutral"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"neutral","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "package":{"sourceRevision":"source"},
          "manifestProjection":{
            "accessProfile":"reader",
            "classificationCeiling":"public",
            "catalog":{"baseUrl":"https://registry.example.test","title":"Registry","publisher":{"id":"authority","name":"Authority"}},
            "publicService":{"id":"service","title":"Service"},
            "datasets":[{"id":"neutral","title":"Dataset"}],
            "dataServices":[{"id":"api","title":"API","endpointUrl":"https://registry.example.test","servesDatasets":["neutral"]}]
          },
          "recordTypes":[]
        });
        parse_project_json(&serde_json::to_vec(&project).expect("project serializes"))
            .expect("the projection parses without a singular key");
        project["manifestProjection"][key] = value;
        let bytes = serde_json::to_vec(&project).expect("project serializes");
        for (failure, code) in [
            (
                parse_project_json(&bytes).expect_err("a singular projection key is refused"),
                "config.unknown-key",
            ),
            (
                parse_project_yaml(&bytes)
                    .expect_err("a singular projection key is refused in YAML"),
                "config.unknown-key",
            ),
        ] {
            let [diagnostic] = failure.diagnostics() else {
                panic!("{key} is refused by one diagnostic: {failure:?}");
            };
            assert_eq!(diagnostic.code, code, "{diagnostic:?}");
            assert!(
                diagnostic
                    .message
                    .contains(&format!("unknown field `{key}`"))
                    || diagnostic
                        .message
                        .contains(&format!("`{key}` is not a member of this mapping")),
                "{}",
                diagnostic.message
            );
        }
    }
}

#[test]
fn production_allows_missing_manifest_projection_and_emits_no_manifest_artifacts() {
    let compiled = compile_project(
        &parse_project_json(
            br#"{"datasets":[{"id": "test-dataset"}],
              "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
              "kind":"BRegProject",
              "project":{"id":"neutral","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
              "package":{"sourceRevision":"source"},
              "recordTypes":[{
                "id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"create-only",
                "fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal","required":true}]
              }],
              "accessProfiles":[{
                "id":"reader",
                "principalClaim":"principal",
                "requiredScopes":"unrestricted",
                "permissions":{"records":[{
                  "recordType":"record",
                  "operations":["get"],
                  "readableFields":["code"],
                  "rowBoundaries": "unrestricted"
                }]}
              }]
            }"#,
        )
        .expect("source parses"),
        &[],
        CompileProfile::Production,
    )
    .expect("production compilation does not require a manifest projection");

    assert!(compiled.manifest_projection().is_none());
    assert!(compiled
        .artifacts()
        .entries()
        .keys()
        .all(|path| !path.starts_with("generated/manifest/")));
    assert_eq!(
        compiled
            .findings()
            .iter()
            .map(|d| d.code.as_str())
            .collect::<Vec<_>>(),
        vec!["breg.access.profile-unrestricted-rows"]
    );
}

#[test]
fn project_access_profiles_use_the_entity_access_vocabulary() {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"profile-vocabulary","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"case-file","primaryDataset":"test-dataset","route":"case-files","mutationMode":"mutable",
            "fields":[
              {"id":"case-code","type":"string","maximumLength":32,"classification":"internal"},
              {"id":"status","type":"string","maximumLength":32,"classification":"internal"}
            ]
          }],
          "accessProfiles":[{
            "id":"operator",
            "default":true,
            "principalClaim":"sub",
            "requiredScopes":["records.read"],
            "requiredPurposes":["case-management"],
            "permissions":{"records":[{
              "recordType":"case-file",
              "operations":["get","list"],
              "readableFields":["case-code","status"],
              "filterableFields":["status"],
              "allowCount":true,
              "rowBoundaries": "unrestricted"
            }]}
          }]
        }"#,
    )
    .expect("canonical top-level profile source parses");

    let compiled = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("canonical top-level profile source compiles");
    let profile = compiled
        .entities()
        .get("case-file")
        .and_then(|entity| entity.access_profiles.get("operator"))
        .expect("top-level profile is expanded onto its granted entity");

    assert_eq!(profile.principal_claim, "sub");
    assert_eq!(
        profile.required_scopes,
        ["records.read".to_owned()].into_iter().collect()
    );
    assert_eq!(
        profile.required_purposes,
        ["case-management".to_owned()].into_iter().collect()
    );
    assert_eq!(
        profile.operations,
        [Operation::Get, Operation::List].into_iter().collect()
    );
    assert!(profile.allow_count);
    assert!(compiled.access().entries.iter().any(|entry| {
        entry.entity_id == "case-file"
            && entry.operation == Operation::List
            && entry.profile_ids == ["operator".to_owned()].into_iter().collect()
            && entry.default_profile_id.as_deref() == Some("operator")
    }));
}

#[test]
fn root_project_entity_access_profiles_are_compile_time_errors() {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"profile-vocabulary","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"case-file","primaryDataset":"test-dataset","route":"case-files","mutationMode":"mutable",
            "fields":[{"id":"case-code","type":"string","maximumLength":32,"classification":"internal"}],
            "accessProfiles":[{
              "id":"entity-local-reader",
              "principalClaim":"sub",
              "operations":["get"],
              "readableFields":["case-code"],
              "requiredScopes":"unrestricted",
              "rowBoundaries": "unrestricted"
            }]
          }]
        }"#,
    )
    .expect("the shared parser still accepts the internal/module profile field");

    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("root project entity-local profiles match the public schema refusal");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| {
            diagnostic.code == "breg.access-profile.project-record-type-local-forbidden"
        })
        .expect("root entity-local profile refusal is reported");
    assert_eq!(diagnostic.path, "project.recordTypes[].accessProfiles");
}

#[test]
fn module_entity_access_profiles_remain_supported_for_module_composition() {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"module-profile","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"case-file","primaryDataset":"test-dataset","route":"case-files","mutationMode":"mutable",
            "fields":[{"id":"case-code","type":"string","maximumLength":32,"classification":"internal"}]
          }],
          "modules":[{"id":"core","version":"1"}]
        }"#,
    )
    .expect("project parses");
    let module = parse_module_json(
        br#"{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"core",
          "version":"1",
          "recordTypes":[{
            "id":"module-record","primaryDataset":"test-dataset","route":"module-records","mutationMode":"mutable",
            "fields":[{"id":"case-code","type":"string","maximumLength":32,"classification":"internal"}],
            "accessProfiles":[{
              "id":"module-reader",
              "principalClaim":"sub",
              "operations":["get"],
              "readableFields":["case-code"],
              "requiredScopes":"unrestricted",
              "rowBoundaries": "unrestricted"
            }]
          }],
          "extendRecordTypes":[{
            "recordType":"case-file",
            "accessProfiles":[{
              "id":"extension-reader",
              "principalClaim":"sub",
              "operations":["get"],
              "readableFields":["case-code"],
              "requiredScopes":"unrestricted",
              "rowBoundaries": "unrestricted"
            }]
          }]
        }"#,
    )
    .expect("module parses");

    let compiled = compile_project(&project, &[module], CompileProfile::Authoring)
        .expect("module-local access profiles remain module composition input");
    assert!(compiled.entities()["module-record"]
        .access_profiles
        .contains_key("module-reader"));
    assert!(compiled.entities()["case-file"]
        .access_profiles
        .contains_key("extension-reader"));
}

#[test]
fn hook_projection_diagnostics_name_the_record_hook_field_and_module_extension() {
    let project = parse_project_json(
        br#"{"datasets":[{"id":"records"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"hook-paths","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://hook-paths.example.test"},
          "modules":[{"id":"events","version":"1"}],
          "recordTypes":[{
            "id":"entry","primaryDataset":"records","route":"entries","mutationMode":"mutable",
            "fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"}],
            "hooks":[
              {"id":"root-first","phase":"after","trigger":"created","projection":["code"],"handler":{"type":"url","destinationId":"events"}},
              {"id":"root-second","phase":"after","trigger":"created","projection":["no-such-field"],"handler":{"type":"url","destinationId":"events"}}
            ]
          }]
        }"#,
    )
    .expect("project parses");
    let module = parse_module_json(
        br#"{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"events","version":"1",
          "extendRecordTypes":[{
            "recordType":"entry",
            "hooks":[
              {"id":"module-first","phase":"after","trigger":"created","projection":["code"],"handler":{"type":"url","destinationId":"events"}},
              {"id":"module-second","phase":"after","trigger":"created","projection":["no-such-field"],"handler":{"type":"url","destinationId":"events"}}
            ]
          }]
        }"#,
    )
    .expect("module parses");

    let failure = compile_project(&project, &[module], CompileProfile::Authoring)
        .expect_err("unknown projection fields are refused");
    let paths = failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "breg.event.projection-field-unknown")
        .map(|diagnostic| diagnostic.path.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        paths,
        BTreeSet::from([
            "modules[id=events].extendRecordTypes[recordType=entry].hooks[id=module-second].projection[field=no-such-field]",
            "recordTypes[id=entry].hooks[id=root-second].projection[field=no-such-field]",
        ])
    );
}

#[test]
fn module_extension_hook_diagnostics_keep_the_second_hook_and_member_paths() {
    let project = parse_project_json(
        br#"{"datasets":[{"id":"records"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"hook-member-paths","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://hook-member-paths.example.test"},
          "modules":[{"id":"events","version":"1"}],
          "recordTypes":[{
            "id":"entry","primaryDataset":"records","route":"entries","mutationMode":"create-only",
            "fields":[
              {"id":"code","type":"string","maximumLength":32,"classification":"internal"},
              {"id":"secret","type":"string","maximumLength":32,"classification":"restricted","encrypted":true}
            ]
          }]
        }"#,
    )
    .expect("project parses");
    let module = parse_module_json(
        br#"{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"events","version":"1",
          "extendRecordTypes":[{
            "recordType":"entry",
            "hooks":[
              {"id":"module-first","phase":"after","trigger":"created","projection":["code"],"handler":{"type":"url","destinationId":"events"}},
              {"id":"module-second","phase":"before","trigger":"patched","projection":[],
               "when":{"type":"fields","changed":["no-such-field"]},
               "handler":{"type":"rhai","script":"hooks/second.rhai","abi":"registry.hook-handler/v2"}},
              {"id":"module-third","phase":"after","trigger":"created","projection":["secret"],
               "handler":{"type":"url","destinationId":"Invalid Destination"}}
            ]
          }]
        }"#,
    )
    .expect("module parses");

    let failure = compile_project(&project, &[module], CompileProfile::Authoring)
        .expect_err("invalid module extension hooks are refused");
    let path = |code: &str| {
        failure
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == code)
            .unwrap_or_else(|| panic!("missing {code}: {failure:?}"))
            .path
            .as_str()
    };
    let second = "modules[id=events].extendRecordTypes[recordType=entry].hooks[id=module-second]";
    let third = "modules[id=events].extendRecordTypes[recordType=entry].hooks[id=module-third]";
    assert_eq!(
        path("breg.hook.phase-unsupported"),
        format!("{second}.phase")
    );
    assert_eq!(
        path("breg.event.projection-empty"),
        format!("{second}.projection")
    );
    assert_eq!(
        path("breg.event.trigger-unavailable"),
        format!("{second}.trigger")
    );
    assert_eq!(
        path("breg.event.when-field-unknown"),
        format!("{second}.when.changed[field=no-such-field]")
    );
    assert_eq!(
        path("breg.hook.handler-abi-unsupported"),
        format!("{second}.handler.abi")
    );
    assert_eq!(
        path("breg.event.projection-encrypted"),
        format!("{third}.projection[field=secret]")
    );
    assert_eq!(
        path("breg.event.webhook-destination-invalid"),
        format!("{third}.handler.destinationId")
    );
}

#[test]
fn duplicate_hook_ids_do_not_claim_an_ambiguous_hook_selector() {
    let project = parse_project_json(
        br#"{"datasets":[{"id":"records"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"duplicate-hook-paths","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://duplicate-hook-paths.example.test"},
          "recordTypes":[{
            "id":"entry","primaryDataset":"records","route":"entries","mutationMode":"mutable",
            "fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"}],
            "hooks":[
              {"id":"duplicate","phase":"after","trigger":"created","projection":["code"],"handler":{"type":"url","destinationId":"events"}},
              {"id":"duplicate","phase":"before","trigger":"created","projection":["code"],"handler":{"type":"rhai","script":"hooks/duplicate.rhai"}}
            ]
          }]
        }"#,
    )
    .expect("project parses");

    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("duplicate hook identifiers are refused");
    let path = |code: &str| {
        failure
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == code)
            .unwrap_or_else(|| panic!("missing {code}: {failure:?}"))
            .path
            .as_str()
    };
    assert_eq!(
        path("breg.event.id-duplicate"),
        "recordTypes[id=entry].hooks[].id"
    );
    assert_eq!(
        path("breg.hook.phase-unsupported"),
        "recordTypes[id=entry].hooks[].phase"
    );
}

#[test]
fn directly_constructed_module_extension_display_text_keeps_authored_paths() {
    let project = parse_project_json(
        br#"{"datasets":[{"id":"records"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"extension-display","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "modules":[{"id":"core","version":"1"}],
          "recordTypes":[{
            "id":"entry","primaryDataset":"records","route":"entries","mutationMode":"mutable",
            "fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"}]
          }]
        }"#,
    )
    .expect("project parses");
    let mut module = parse_module_json(
        br#"{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"core","version":"1",
          "recordTypes":[{
            "id":"module-entry","primaryDataset":"records","route":"module-entries","mutationMode":"mutable",
            "fields":[{"id":"module-code","type":"string","maximumLength":32,"classification":"internal"}]
          }],
          "extendRecordTypes":[{
            "recordType":"entry",
            "fields":[{"id":"first-note","type":"text","maximumLength":128,"classification":"internal"}]
          },{
            "recordType":"entry",
            "fields":[{"id":"note","type":"text","maximumLength":128,"classification":"internal"}],
            "derived":[{"id":"summary","sql":"sql/summary.sql","key":"id","fields":[{"id":"score","type":"int64","classification":"internal"}]}]
          }],
          "actions":[{
            "id":"create-module-entry",
            "execution":{"mode":"immediate"},
            "inputs":[{"id":"module-code","type":"string","maximumLength":32,"classification":"internal"}],
            "plan":{"type":"fixed","effects":[{"id":"entry","target":{"recordType":"module-entry"},"operation":"create","set":{"module-code":{"fromInput":"module-code"}}}]}
          }]
        }"#,
    )
    .expect("module parses");
    module.entities[0].display.label = Some("reordered\u{202e}".to_owned());
    module.entities[0].fields[0].display.description = Some("reordered\u{202e}".to_owned());
    module.extend_entities[1].fields[0].display.label = Some("reordered\u{202e}".to_owned());
    module.extend_entities[1].derived[0].fields[0]
        .display
        .description = Some("reordered\u{202e}".to_owned());
    module.actions[0].display.label = Some("reordered\u{202e}".to_owned());
    module.actions[0].inputs[0].display.description = Some("reordered\u{202e}".to_owned());

    let failure = compile_project(&project, &[module], CompileProfile::Authoring)
        .expect_err("unsafe directly constructed extension display text is refused");
    let mut paths = failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "breg.display-text.invalid")
        .map(|diagnostic| diagnostic.path.as_str())
        .collect::<Vec<_>>();
    paths.sort_unstable();
    assert_eq!(
        paths,
        [
            "modules[id=core].actions[id=create-module-entry].display.label",
            "modules[id=core].actions[id=create-module-entry].inputs[id=module-code].display.description",
            "modules[id=core].extendRecordTypes[1].derived[id=summary].fields[id=score].display.description",
            "modules[id=core].extendRecordTypes[1].fields[id=note].display.label",
            "modules[id=core].recordTypes[id=module-entry].display.label",
            "modules[id=core].recordTypes[id=module-entry].fields[id=module-code].display.description",
        ]
    );
}

#[test]
fn project_access_profiles_reject_the_legacy_purpose_vocabulary() {
    let failure = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"profile-vocabulary","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"case-file","primaryDataset":"test-dataset","route":"case-files","mutationMode":"mutable",
            "fields":[{"id":"case-code","type":"string","maximumLength":32,"classification":"internal"}]
          }],
          "accessProfiles":[{
            "id":"operator",
            "principalClaim":"sub",
            "requiredScopes":"unrestricted",
            "purposes":["case-management"],
            "permissions":{"records":[{"recordType":"case-file","operations":["get"],"readableFields":["case-code"], "rowBoundaries": "unrestricted"}]}
          }]
        }"#,
    )
    .expect_err("legacy purposes key is no longer part of the authoring contract");

    let diagnostic = &failure.diagnostics()[0];
    assert_eq!(diagnostic.code, "config.unknown-key");
    assert_eq!(diagnostic.path, "project.accessProfiles[0].purposes");
}

/// The read-time refusals of one project whose only access profile holds the
/// written permissions.
fn permission_refusals(permissions: &str) -> Vec<(String, String)> {
    let source = format!(
        r#"{{"datasets":[{{"id": "test-dataset"}}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{{"id":"profile-vocabulary","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
          "recordTypes":[{{
            "id":"case-file","primaryDataset":"test-dataset","route":"case-files","mutationMode":"mutable",
            "fields":[{{"id":"case-code","type":"string","maximumLength":32,"classification":"internal"}}]
          }}],
          "actions":[{{"execution":{{"mode":"immediate"}},
            "id":"create-case-file",
            "inputs":[{{"id":"case-code","type":"string","maximumLength":32,"classification":"internal"}}],
            "plan":{{"type":"fixed","effects":[{{"id":"case","target":{{"recordType":"case-file"}},"operation":"create","set":{{"case-code":{{"fromInput":"case-code"}}}}}}]}}
          }}],
          "accessProfiles":[{{
            "id":"operator",
            "principalClaim":"sub",
            "requiredScopes":"unrestricted",
            "permissions":{permissions}
          }}]
        }}"#
    );
    parse_project_yaml(source.as_bytes())
        .expect_err("the permissions are refused when the project is read")
        .diagnostics()
        .iter()
        .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
        .collect()
}

fn unknown_keys(group: &str, members: &[&str]) -> Vec<(String, String)> {
    members
        .iter()
        .map(|member| {
            (
                "config.unknown-key".to_owned(),
                format!("project.accessProfiles[0].permissions.{group}[0].{member}"),
            )
        })
        .collect()
}

#[test]
fn project_access_grants_reject_the_legacy_action_vocabulary() {
    let refused = permission_refusals(
        r#"{"records":[{"recordType":"case-file","actions":["get"],"readableFields":["case-code"], "rowBoundaries": "unrestricted"}]}"#,
    );
    assert!(
        refused.contains(&(
            "config.unknown-key".to_owned(),
            "project.accessProfiles[0].permissions.records[0].actions".to_owned()
        )),
        "{refused:?}"
    );
}

#[test]
fn entity_access_grants_reject_action_target_and_result_fields() {
    for (extra, member) in [
        (
            r#","targets":[{"recordType":"case-file","rowBoundaries":"unrestricted"}]"#,
            "targets",
        ),
        (r#","results":["created"]"#, "results"),
    ] {
        let refused = permission_refusals(&format!(
            r#"{{"records":[{{
              "rowBoundaries": "unrestricted", "recordType":"case-file",
              "operations":["get"],
              "readableFields":["case-code"]{extra}
            }}]}}"#
        ));
        assert_eq!(refused, unknown_keys("records", &[member]));
    }
}

#[test]
fn project_access_grants_reject_mixed_entity_and_action_targets() {
    let mixed = r#"{
      "recordType":"case-file",
      "action":"create-case-file",
      "operations":["invoke"],
      "targets":[{"recordType":"case-file","rowBoundaries":"unrestricted"}],
      "rowBoundaries": "unrestricted"
    }"#;
    assert_eq!(
        permission_refusals(&format!(r#"{{"records":[{mixed}]}}"#)),
        unknown_keys("records", &["action", "targets"])
    );
    assert_eq!(
        permission_refusals(&format!(r#"{{"actions":[{mixed}]}}"#)),
        unknown_keys("actions", &["recordType", "rowBoundaries"])
    );
}

#[test]
fn manifest_projection_unknown_nested_keys_are_rejected_without_values() {
    let failure = parse_project_json(
        br#"{"datasets":[{"id": "neutral"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"neutral","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://registry.example.test"},
          "manifestProjection":{
            "accessProfile":"reader",
            "classificationCeiling":"internal",
            "catalog":{
              "baseUrl":"https://registry.example.test",
              "title":"Registry Catalog",
              "publisher":{"id":"publisher","name":"Publisher","privateKey":"do-not-echo"}
            },
            "publicService":{"id":"registry-service","title":"Registry service"},
            "datasets":[{"id":"neutral","title":"Registry Dataset"}],
            "dataServices":[{"id":"registry-api","title":"Registry API","endpointUrl":"https://registry.example.test","servesDatasets":["neutral"]}]
          }
        }"#,
    )
    .expect_err("unknown projection members are refused");

    assert_eq!(failure.diagnostics()[0].code, "config.unknown-key");
    assert_eq!(
        failure.diagnostics()[0].path,
        "project.manifestProjection.catalog.publisher.privateKey"
    );
    assert!(!serde_json::to_string(&failure)
        .expect("diagnostic serializes")
        .contains("do-not-echo"));
}

#[test]
fn manifest_projection_compiles_to_deterministic_valid_manifest_core() {
    let compiled = compile_project(&asset_project(), &[], CompileProfile::Authoring)
        .expect("asset fixture compiles");
    let artifact = compiled
        .artifacts()
        .get("generated/manifest/registry-manifest.json")
        .expect("Manifest projection is generated");
    let value = parse_json_strict(&artifact.bytes).expect("Manifest projection is strict JSON");
    assert_eq!(
        canonicalize_json(&value).expect("Manifest projection canonicalizes"),
        artifact.bytes
    );
    let manifest: MetadataManifest =
        serde_json::from_value(value).expect("generated Manifest source parses");
    let first = compile_manifest(&manifest).expect("generated Manifest compiles");
    let second = compile_manifest(&manifest).expect("generated Manifest compiles twice");
    assert_eq!(first, second);

    let dataset = first
        .dataset("asset-site-placement")
        .expect("stable dataset id is preserved");
    assert_eq!(dataset.access_rights, AccessRights::Restricted);
    assert_eq!(dataset.entities.len(), 4);
    assert!(dataset
        .entities
        .get("asset-placement")
        .expect("placement entity is projected")
        .relationships
        .iter()
        .any(|relationship| relationship.name == "asset" && relationship.target == "asset-item"));
}

/// Every project and module the product ships serializes, with its null
/// members left out, to source the reader reads back to the same value, so a
/// test may write a read project or module back as source.
#[test]
fn a_read_project_or_module_serializes_to_source_the_reader_reads_again() {
    let mut files = Vec::new();
    collect_project_and_module_files(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../products/breg"),
        &mut files,
    );
    for canonical in [
        "examples/minimal/registry.yaml",
        "acceptance/asset-site-placement/modules/asset-site-placement-core/module.yaml",
    ] {
        assert!(
            files.iter().any(|path| path.ends_with(canonical)),
            "the product ships its canonical project and module: {canonical}"
        );
    }
    for path in files {
        let bytes = fs::read(&path).expect("the shipped source file reads");
        let display = path.display();
        if path.ends_with("module.yaml") {
            // A file the reader refuses (a negative fixture) has nothing to
            // round-trip.
            let Ok(module) = parse_module_yaml(&bytes) else {
                continue;
            };
            // The read module does not keep the header its file opens with.
            let mut source: Value = serde_json::from_slice(&source_bytes::source_bytes(&module))
                .expect("the module source is JSON");
            source["apiVersion"] = json!(MODULE_API_VERSION);
            source["kind"] = json!(MODULE_KIND);
            let reread =
                parse_module_yaml(&serde_json::to_vec(&source).expect("the module source encodes"))
                    .unwrap_or_else(|failure| panic!("{display}: {:?}", failure.diagnostics()));
            assert_eq!(reread, module, "{display}");
        } else {
            let Ok(project) = parse_project_yaml(&bytes) else {
                continue;
            };
            let reread = parse_project_yaml(&source_bytes::source_bytes(&project))
                .unwrap_or_else(|failure| panic!("{display}: {:?}", failure.diagnostics()));
            assert_eq!(reread, project, "{display}");
        }
    }
}

fn collect_project_and_module_files(directory: &std::path::Path, files: &mut Vec<PathBuf>) {
    let mut entries = fs::read_dir(directory)
        .expect("the product directory reads")
        .map(|entry| entry.expect("the product entry reads").path())
        .collect::<Vec<_>>();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_project_and_module_files(&path, files);
        } else if path.ends_with("registry.yaml") || path.ends_with("module.yaml") {
            files.push(path);
        }
    }
}

#[test]
fn all_acceptance_fixtures_compile_manifest_projection_under_production() {
    for domain in [
        "asset-site-placement",
        "business-establishments",
        "facility",
        "inspection",
        "business",
    ] {
        let mut project = acceptance_project(domain);
        assert!(
            project.manifest_projection.is_some(),
            "{domain} declares explicit projection metadata"
        );
        project
            .package
            .get_or_insert_with(|| PackageIdentitySource {
                source_revision: "acceptance-fixture-source".to_owned(),
            });
        let mut modules = Vec::new();
        let mut assets = Vec::new();
        for lock in &mut project.modules {
            let module_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/breg/acceptance")
                .join(domain)
                .join("modules")
                .join(&lock.id);
            let module_path = module_root.join("module.yaml");
            let module = if module_path.is_file() {
                let bytes = fs::read(module_path).expect("locked acceptance module is readable");
                let module = parse_module_yaml(&bytes).expect("locked acceptance module parses");
                let mut module_assets = Vec::new();
                for derived in module
                    .entities
                    .iter()
                    .flat_map(|entity| &entity.derived)
                    .chain(
                        module
                            .extend_entities
                            .iter()
                            .flat_map(|extension| &extension.derived),
                    )
                {
                    module_assets.push(ModuleAssetSource {
                        module: Some(module.id.clone()),
                        path: derived.sql.clone(),
                        bytes: fs::read(module_root.join(&derived.sql))
                            .expect("locked derived SQL asset is readable"),
                    });
                }
                lock.digest = Some(module_digest_with_assets(&module, &module_assets));
                assets.extend(module_assets);
                module
            } else {
                let module = RegistryModule {
                    id: lock.id.clone(),
                    version: lock.version.clone(),
                    dependencies: Vec::new(),
                    functions: Vec::new(),
                    value_types: Default::default(),
                    entities: Vec::new(),
                    extend_entities: Vec::new(),
                    actions: Vec::new(),
                };
                lock.digest = Some(module_digest(&module));
                module
            };
            modules.push(module);
        }

        let compiled =
            compile_project_with_assets(&project, &modules, &assets, CompileProfile::Production)
                .unwrap_or_else(|failure| {
                    panic!("{domain} production compile failed: {failure:?}")
                });
        let artifact = compiled
            .artifacts()
            .get("generated/manifest/registry-manifest.json")
            .unwrap_or_else(|| panic!("{domain} Manifest projection is generated"));
        let manifest: MetadataManifest = serde_json::from_slice(&artifact.bytes)
            .unwrap_or_else(|error| panic!("{domain} Manifest projection parses: {error}"));
        let manifest = compile_manifest(&manifest)
            .unwrap_or_else(|error| panic!("{domain} Manifest projection compiles: {error:?}"));
        let dcat = compiled
            .artifacts()
            .get("generated/manifest/dcat.jsonld")
            .unwrap_or_else(|| panic!("{domain} DCAT projection is generated"));
        let dcat = parse_json_strict(&dcat.bytes)
            .unwrap_or_else(|error| panic!("{domain} DCAT projection parses: {error}"));

        if domain == "business-establishments" {
            let dataset = manifest
                .dataset("business-registry")
                .expect("configured dataset id is preserved");
            assert_eq!(
                dataset.entities["establishment"].concept_uri.as_deref(),
                Some("https://business-establishments.example.gov/model/establishment")
            );
            assert!(dataset.entities["operator-assignment"]
                .relationships
                .iter()
                .all(|relationship| relationship.name != "business"));
            assert!(manifest.dataset("registered-businesses").is_some());
            assert_eq!(manifest.data_services().count(), 1);
            assert_eq!(manifest.distributions().count(), 1);
            assert!(manifest
                .codelists()
                .any(|codelist| codelist.id == "establishment-role"));
            assert_eq!(
                dcat["dcat:service"][0]["dcat:endpointURL"],
                "https://business-establishments.example.gov/v1"
            );
        }
    }
}

#[test]
fn manifest_projection_filters_by_selected_profile_and_classification_ceiling() {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "public-slice"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"public-slice","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://public-slice.example.test"},
          "manifestProjection":{
            "accessProfile":"operator",
            "classificationCeiling":"public",
            "catalog":{"baseUrl":"https://public-slice.example.test","title":"Public Slice","publisher":{"id":"publisher","name":"Publisher"}},
            "publicService":{"id":"public-slice-service","title":"Public Slice"},
            "datasets":[{"id":"public-slice","title":"Public Slice Dataset","status":"active"}],
            "dataServices":[{"id":"public-slice-api","title":"Public Slice API","endpointUrl":"https://public-slice.example.test/v1","servesDatasets":["public-slice"]}]
          },
          "recordTypes":[
            {"id":"visible-target","primaryDataset":"public-slice","route":"visible-targets","mutationMode":"create-only","classification":"public",
             "fields":[{"id":"label","type":"string","maximumLength":64,"classification":"public"}]},
            {"id":"hidden-target","primaryDataset":"public-slice","route":"hidden-targets","mutationMode":"create-only","classification":"restricted",
             "fields":[{"id":"label","type":"string","maximumLength":64,"classification":"restricted"}]},
            {"id":"link","primaryDataset":"public-slice","route":"links","mutationMode":"create-only","classification":"public",
             "fields":[
               {"id":"name","type":"string","maximumLength":64,"classification":"public"},
               {"id":"operator-note","type":"string","maximumLength":64,"classification":"internal"},
               {"id":"visible-ref","type":"reference","target":"visible-target","classification":"public"},
               {"id":"hidden-ref","type":"reference","target":"hidden-target","classification":"public"}
             ]}
          ],
          "accessProfiles":[{
            "id":"operator","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{
              "records":[
                {"recordType":"visible-target","operations":["get"],"readableFields":["label"], "rowBoundaries": "unrestricted"},
                {"recordType":"hidden-target","operations":["get"],"readableFields":["label"], "rowBoundaries": "unrestricted"},
                {"recordType":"link","operations":["get"],"readableFields":["name","operator-note","visible-ref","hidden-ref"], "rowBoundaries": "unrestricted"}
              ]
            }
          }]
        }"#,
    )
    .expect("project parses");
    let compiled =
        compile_project(&project, &[], CompileProfile::Authoring).expect("project compiles");
    let artifact = compiled
        .artifacts()
        .get("generated/manifest/registry-manifest.json")
        .expect("Manifest projection is generated");
    let manifest: MetadataManifest =
        serde_json::from_slice(&artifact.bytes).expect("generated Manifest projection parses");
    let projected = compile_manifest(&manifest).expect("generated Manifest projection compiles");
    let dataset = projected
        .dataset("public-slice")
        .expect("dataset id is stable");

    assert_eq!(dataset.access_rights, AccessRights::Restricted);
    assert!(dataset.entities.contains_key("visible-target"));
    assert!(dataset.entities.contains_key("link"));
    assert!(!dataset.entities.contains_key("hidden-target"));
    let link = dataset.entities.get("link").expect("link is visible");
    assert!(link.fields.contains_key("name"));
    assert_eq!(link.fields["name"].field_type, FieldType::String);
    assert!(!link.fields.contains_key("operator-note"));
    assert!(link
        .relationships
        .iter()
        .any(|relationship| relationship.name == "visible-ref"
            && relationship.target == "visible-target"));
    assert!(!link
        .relationships
        .iter()
        .any(|relationship| relationship.name == "hidden-ref"));
}

#[test]
fn manifest_projection_metadata_cannot_describe_hidden_entities_or_fields() {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "public-slice"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"public-slice","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://public-slice.example.test"},
          "manifestProjection":{
            "accessProfile":"reader",
            "classificationCeiling":"restricted",
            "catalog":{"baseUrl":"https://public-slice.example.test","title":"Public Slice","publisher":{"id":"publisher","name":"Publisher"}},
            "publicService":{"id":"public-slice-service","title":"Public Slice"},
            "datasets":[{"id":"public-slice","title":"Public Slice Dataset"}],
            "dataServices":[{"id":"public-slice-api","title":"Public Slice API","endpointUrl":"https://public-slice.example.test/v1","servesDatasets":["public-slice"]}],
            "entities":[
              {"id":"record","fields":[
                {"id":"secret-note","concepts":["https://example.test/secret-note"]},
                {"id":"profile","concepts":["https://example.test/Profile"]}
              ]},
              {"id":"secret-record","conceptUri":"https://example.test/SecretRecord"}
            ]
          },
          "recordTypes":[
            {"id":"record","primaryDataset":"public-slice","route":"records","mutationMode":"create-only","classification":"public",
             "fields":[
               {"id":"name","type":"string","maximumLength":64,"classification":"public"},
               {"id":"secret-note","type":"string","maximumLength":64,"classification":"restricted"},
               {"id":"profile","type":"structured","maximumBytes":1024,"schema":{"type":"object","additionalProperties":false},"classification":"public"}
             ]},
            {"id":"secret-record","primaryDataset":"public-slice","route":"secret-records","mutationMode":"create-only","classification":"restricted",
             "fields":[{"id":"name","type":"string","maximumLength":64,"classification":"restricted"}]}
          ],
          "accessProfiles":[
            {"id":"reader","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{"recordType":"record","operations":["get"],"readableFields":["name","profile"], "rowBoundaries": "unrestricted"}]}},
            {"id":"other-reader","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{"recordType":"secret-record","operations":["get"],"readableFields":["name"], "rowBoundaries": "unrestricted"}]}}
          ]
        }"#,
    )
    .expect("project parses");
    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("metadata outside the projected disclosure slice is refused");
    let codes = failure
        .diagnostics()
        .iter()
        .map(|diagnostic| diagnostic.code.as_str())
        .collect::<BTreeSet<_>>();

    assert!(codes.contains("breg.manifest-projection.field-not-visible"));
    assert!(codes.contains("breg.manifest-projection.field-not-representable"));
    assert!(codes.contains("breg.manifest-projection.entity-not-visible"));
}

#[test]
fn manifest_projection_diagnostics_name_the_profile_and_identifier_rule() {
    let mut source: Value = serde_json::from_slice(MULTI_DATASET_PROJECT).unwrap();
    source["accessProfiles"][0]["permissions"]["records"][0]["readableFields"] = json!([]);
    source["manifestProjection"]["entities"] = json!([
        {
            "id": "person",
            "fields": [{"id": "name"}],
            "identifiers": [
                {"field": "missing", "kind": ""},
                {"field": "missing", "kind": "other"}
            ]
        }
    ]);
    source["manifestProjection"]["vocabularies"] = json!([{
        "id": "missing-vocabulary",
        "schemeIri": "https://registry.example.test/vocab/missing",
        "concepts": []
    }]);
    let failure = compile_json(&serde_json::to_vec(&source).unwrap())
        .expect_err("hidden projection members are refused");

    for (code, identifiers) in [
        (
            "breg.manifest-projection.field-not-visible",
            &["reader", "name", "not readable"][..],
        ),
        (
            "breg.manifest-projection.identifier-duplicate",
            &["person", "missing", "repeats"][..],
        ),
        (
            "breg.manifest-projection.identifier-field-not-visible",
            &["reader", "missing", "not a portable field"][..],
        ),
        (
            "breg.manifest-projection.identifier-kind-missing",
            &["missing", "no kind"][..],
        ),
        (
            "breg.manifest-projection.vocabulary-not-visible",
            &["reader", "missing-vocabulary", "not used"][..],
        ),
    ] {
        let diagnostic = failure
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == code)
            .unwrap_or_else(|| panic!("missing {code}: {failure:?}"));
        for identifier in identifiers {
            assert!(
                diagnostic.message.contains(identifier),
                "{code} does not name {identifier}: {}",
                diagnostic.message
            );
        }
    }
}

#[test]
fn an_early_compile_error_says_which_later_checks_did_not_run() {
    let project = parse_project_json(
        br#"{"datasets":[{"id":"records"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"staged-check","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://staged-check.example.test"},
          "manifestProjection":{
            "accessProfile":"reader",
            "classificationCeiling":"restricted",
            "catalog":{"baseUrl":"https://staged-check.example.test","title":"Staged check","publisher":{"id":"publisher","name":"Publisher"}},
            "publicService":{"id":"staged-check-service","title":"Staged check"},
            "datasets":[{"id":"records","title":"Records"}],
            "dataServices":[{"id":"registry-api","title":"Registry API","endpointUrl":"https://staged-check.example.test/v1","servesDatasets":["records"]}],
            "entities":[{"id":"record","fields":[{"id":"secret-note","concepts":["https://example.test/secret-note"]}]}]
          },
          "recordTypes":[{"id":"record","primaryDataset":"records","route":"records","mutationMode":"create-only","classification":"public",
            "fields":[
              {"id":"name","type":"string","maximumLength":64,"classification":"public"},
              {"id":"secret-note","type":"string","maximumLength":64,"classification":"restricted"}
            ]}],
          "accessProfiles":[{"id":"reader","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
            "recordType":"record","operations":["get","list"],"readableFields":["name"],"filterableFields":["secret-note"],"rowBoundaries":"unrestricted"
          }]}}]
        }"#,
    )
    .expect("project parses");

    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("the access profile stops compilation before the Manifest projection stage");
    let processing = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.access-profile.processing-wider-than-read")
        .expect("processing wider than disclosure is diagnosed");
    assert_eq!(
        processing.path,
        "recordTypes[id=record].accessProfiles[id=reader].filterableFields[field=secret-note]"
    );
    assert!(processing.message.contains("reader"), "{processing:?}");
    assert!(processing.message.contains("secret-note"), "{processing:?}");
    let skipped = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.compile.later-checks-skipped")
        .expect("the failed stage says which later checks did not run");
    assert_eq!(DiagnosticSeverity::Finding, skipped.severity);
    assert!(skipped.message.contains("source validation"));
    assert!(skipped.message.contains("Manifest projection"));
}

/// A project whose `authorization-status` vocabulary is used by
/// `authorization.status` for every code but `revoked`, narrowed to one code
/// by `authorization-request.status`, which the compiler visits last, and used
/// in full only by `authorization.archived-status`, which sits above the
/// projection's classification ceiling.
fn narrowed_vocabulary_project(concepts: Value) -> registry_breg::contract::RegistryProject {
    let project = json!({"datasets":[{"id": "narrowed-codes"}],
      "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
      "kind":"BRegProject",
      "project":{"id":"narrowed-codes","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://narrowed-codes.example.test"},
      "manifestProjection":{
        "accessProfile":"reader",
        "classificationCeiling":"public",
        "catalog":{"baseUrl":"https://narrowed-codes.example.test","title":"Narrowed Codes","publisher":{"id":"publisher","name":"Publisher"}},
        "publicService":{"id":"narrowed-codes-service","title":"Narrowed Codes"},
        "datasets":[{"id":"narrowed-codes","title":"Narrowed Codes Dataset"}],
        "dataServices":[{"id":"narrowed-codes-api","title":"Narrowed Codes API","endpointUrl":"https://narrowed-codes.example.test/v1","servesDatasets":["narrowed-codes"]}],
        "vocabularies":[{"id":"authorization-status","schemeIri":"https://narrowed-codes.example.test/vocab/authorization-status","concepts":concepts}]
      },
      "vocabularies":[{"id":"authorization-status","values":["pending","active","suspended","cancelled","revoked"]}],
      "recordTypes":[
        {"id":"authorization","primaryDataset":"narrowed-codes","route":"authorizations","mutationMode":"create-only","classification":"public",
         "fields":[
           {"id":"status","type":"vocabulary-code","vocabulary":"authorization-status","values":["pending","active","suspended","cancelled"],"classification":"public"},
           {"id":"archived-status","type":"vocabulary-code","vocabulary":"authorization-status","classification":"restricted"}
         ]},
        {"id":"authorization-request","primaryDataset":"narrowed-codes","route":"authorization-requests","mutationMode":"create-only","classification":"public",
         "fields":[{"id":"status","type":"vocabulary-code","vocabulary":"authorization-status","values":["pending"],"classification":"public"}]}
      ],
      "accessProfiles":[{
        "id":"reader","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{
          "records":[
            {"recordType":"authorization","operations":["get"],"readableFields":["status","archived-status"],"rowBoundaries":"unrestricted"},
            {"recordType":"authorization-request","operations":["get"],"readableFields":["status"],"rowBoundaries":"unrestricted"}
          ]
        }
      }]
    });
    parse_project_json(&serde_json::to_vec(&project).expect("project serializes"))
        .expect("project parses")
}

#[test]
fn manifest_projection_labels_every_code_a_visible_field_uses() {
    let compiled = compile_project(
        &narrowed_vocabulary_project(json!([
            {"code":"pending","label":{"en":"Pending"}},
            {"code":"active","label":{"en":"Active"}},
            {"code":"suspended","label":{"en":"Suspended"}},
            {"code":"cancelled","label":{"en":"Cancelled"}}
        ])),
        &[],
        CompileProfile::Authoring,
    )
    .unwrap_or_else(|failure| {
        panic!(
            "a narrowed field does not hide the codes another field uses: {:?}",
            failure.diagnostics()
        )
    });
    let artifact = compiled
        .artifacts()
        .get("generated/manifest/registry-manifest.json")
        .expect("Manifest projection is generated");
    let manifest: MetadataManifest =
        serde_json::from_slice(&artifact.bytes).expect("generated Manifest projection parses");
    let projected = compile_manifest(&manifest).expect("generated Manifest projection compiles");
    let codelist = projected
        .codelist("authorization-status")
        .expect("the labelled vocabulary is projected as a codelist");
    let labelled = codelist
        .concepts
        .iter()
        .map(|concept| {
            (
                concept.code.as_str(),
                concept.label.as_ref().map(|label| label.text()),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        labelled,
        [
            ("pending", Some("Pending".to_owned())),
            ("active", Some("Active".to_owned())),
            ("suspended", Some("Suspended".to_owned())),
            ("cancelled", Some("Cancelled".to_owned())),
        ]
    );
}

#[test]
fn manifest_projection_refuses_a_label_for_a_declared_code_no_visible_field_uses() {
    let failure = compile_project(
        &narrowed_vocabulary_project(json!([
            {"code":"active","label":{"en":"Active"}},
            {"code":"revoked","label":{"en":"Revoked"}}
        ])),
        &[],
        CompileProfile::Authoring,
    )
    .expect_err("a label for a code only a hidden field uses is refused");
    let refused = failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(
        refused,
        [(
            "breg.manifest-projection.vocabulary-concept-invalid",
            "project.manifestProjection.vocabularies[authorization-status].concepts[revoked]",
        )]
    );
}

#[test]
fn manifest_projection_codelists_carry_only_codes_the_publication_admits() {
    let project = json!({"datasets":[{"id": "protected-cases"}, {"id": "public-cases"}],
      "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
      "kind":"BRegProject",
      "project":{"id":"shared-codes","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://shared-codes.example.test"},
      "manifestProjection":{
        "accessProfile":"public-reader",
        "classificationCeiling":"public",
        "catalog":{"baseUrl":"https://shared-codes.example.test","title":"Shared Codes","publisher":{"id":"publisher","name":"Publisher"}},
        "publicService":{"id":"shared-codes-service","title":"Shared Codes"},
        "datasets":[
          {"id":"public-cases","title":"Public cases","accessProfile":"public-reader","classificationCeiling":"public"},
          {"id":"protected-cases","title":"Protected cases","accessProfile":"protected-reader","classificationCeiling":"restricted"}
        ],
        "dataServices":[
          {"id":"public-api","title":"Public API","endpointUrl":"https://shared-codes.example.test/public","servesDatasets":["public-cases"]},
          {"id":"protected-api","title":"Protected API","endpointUrl":"https://shared-codes.example.test/protected","servesDatasets":["protected-cases"]}
        ],
        "vocabularies":[{"id":"case-status","schemeIri":"https://shared-codes.example.test/vocab/case-status","concepts":[
          {"code":"open","label":{"en":"Open"}},
          {"code":"sealed-by-court","label":{"en":"Sealed by court order"}}
        ]}]
      },
      "vocabularies":[{"id":"case-status","values":["open","sealed-by-court"]}],
      "recordTypes":[
        {"id":"public-case","primaryDataset":"public-cases","route":"public-cases","mutationMode":"create-only","classification":"public",
         "fields":[{"id":"status","type":"vocabulary-code","vocabulary":"case-status","values":["open"],"classification":"public"}]},
        {"id":"protected-case","primaryDataset":"protected-cases","route":"protected-cases","mutationMode":"create-only","classification":"restricted",
         "fields":[{"id":"status","type":"vocabulary-code","vocabulary":"case-status","classification":"restricted"}]}
      ],
      "accessProfiles":[
        {"id":"public-reader","principalClaim":"sub","requiredScopes":["public.read"],"permissions":{"records":[{"recordType":"public-case","operations":["get"],"readableFields":["status"],"rowBoundaries":"unrestricted"}]}},
        {"id":"protected-reader","principalClaim":"sub","requiredScopes":["protected.read"],"permissions":{"records":[{"recordType":"protected-case","operations":["get"],"readableFields":["status"],"rowBoundaries":"unrestricted"}]}}
      ]
    });
    let project = parse_project_json(&serde_json::to_vec(&project).expect("project serializes"))
        .expect("project parses");
    let compiled = compile_project(&project, &[], CompileProfile::Authoring)
        .unwrap_or_else(|failure| panic!("project compiles: {:?}", failure.diagnostics()));
    let manifest: MetadataManifest = serde_json::from_slice(
        &compiled
            .artifacts()
            .get("generated/manifest/registry-manifest.json")
            .expect("Manifest projection is generated")
            .bytes,
    )
    .expect("generated Manifest projection parses");
    let projected = compile_manifest(&manifest).expect("generated Manifest projection compiles");
    let codes = projected
        .codelist("case-status")
        .expect("the vocabulary a public field uses is projected as a codelist")
        .concepts
        .iter()
        .map(|concept| concept.code.as_str())
        .collect::<Vec<_>>();
    assert_eq!(codes, ["open"]);
    for path in [
        "generated/manifest/registry-manifest.json",
        "generated/manifest/dcat.jsonld",
    ] {
        let rendered = std::str::from_utf8(
            &compiled
                .artifacts()
                .get(path)
                .unwrap_or_else(|| panic!("{path} is generated"))
                .bytes,
        )
        .expect("generated metadata is UTF-8")
        .to_owned();
        for protected in ["sealed-by-court", "Sealed by court order"] {
            assert!(
                !rendered.contains(protected),
                "{path} disclosed {protected}, a code only a protected dataset admits: {rendered}"
            );
        }
    }
}

#[test]
fn manifest_projection_omits_physical_runtime_and_security_terms() {
    let compiled = compile_project(&asset_project(), &[], CompileProfile::Authoring)
        .expect("asset fixture compiles");
    let artifact = compiled
        .artifacts()
        .get("generated/manifest/registry-manifest.json")
        .expect("Manifest projection is generated");
    let rendered = std::str::from_utf8(&artifact.bytes).expect("Manifest is UTF-8");

    for forbidden in [
        "postgres",
        "physical",
        "runtime",
        "secret",
        "authorization",
        "migration",
        "revision",
        "rls",
    ] {
        assert!(!rendered.to_ascii_lowercase().contains(forbidden));
    }
}

#[test]
fn independent_additive_modules_are_order_independent() {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"neutral-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "modules":[
            {"id":"core","version":"1"},
            {"id":"alpha","version":"1"},
            {"id":"beta","version":"1"}
          ],
          "recordTypes":[{
            "id":"object","primaryDataset":"test-dataset","route":"objects","mutationMode":"mutable",
            "fields":[{"id":"code","type":"string","maximumLength":32,"required":true,"classification":"internal"}]
          }],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"registry_principal","requiredScopes":"unrestricted","permissions":{"records":[{
              "recordType":"object","operations":["create","get","list","patch"],
              "readableFields":["code"],"writableFields":["code"],
              "rowBoundaries": "unrestricted"
            }]}
          }]
        }"#,
    )
    .expect("project parses");
    let alpha = parse_module_json(
        br#"{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"alpha","version":"1","dependencies":["core"],
          "extendRecordTypes":[{"recordType":"object","fields":[
            {"id":"alpha-field","type":"boolean","classification":"internal"}
          ]}]
        }"#,
    )
    .expect("alpha module parses");
    let beta = parse_module_json(
        br#"{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"beta","version":"1","dependencies":["core"],
          "extendRecordTypes":[{"recordType":"object","fields":[
            {"id":"beta-field","type":"int64","classification":"internal"}
          ]}]
        }"#,
    )
    .expect("beta module parses");

    let left = compile_project(
        &project,
        &[alpha.clone(), beta.clone()],
        CompileProfile::Authoring,
    )
    .expect("first order compiles");
    let right = compile_project(&project, &[beta, alpha], CompileProfile::Authoring)
        .expect("reverse order compiles");
    assert_eq!(left, right);
    assert_eq!(left.module_order(), ["core", "alpha", "beta"]);
}

#[test]
fn project_access_profile_required_scopes_compile_into_each_grant() {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"scope-bound-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"mutable",
            "fields":[{"id":"code","type":"string","maximumLength":32,"required":true,"classification":"internal"}]
          }],
          "accessProfiles":[{
            "id":"operator","principalClaim":"registry_principal",
            "requiredScopes":["registry:record:operate"],
            "permissions":{"records":[{
              "recordType":"record","operations":["get"],"readableFields":["code"],
              "rowBoundaries": "unrestricted"
            }]}
          }]
        }"#,
    )
    .expect("scope-bound project parses");

    let compiled = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("scope-bound project compiles");
    let profile = compiled.entities()["record"]
        .access_profiles
        .get("operator")
        .expect("project profile is compiled onto the grant");
    assert_eq!(
        profile.required_scopes,
        ["registry:record:operate".to_owned()].into()
    );
}

#[test]
fn strict_parse_refuses_unknown_and_duplicate_members_without_echoing_values() {
    let unknown = parse_project_json(
        br#"{
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"neutral","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test","secretField":"do-not-echo"}
        }"#,
    )
    .expect_err("unknown member is refused");
    assert_eq!(unknown.diagnostics()[0].code, "config.unknown-key");
    assert!(unknown.diagnostics()[0].path.starts_with("project.project"));
    let rendered = serde_json::to_string(&unknown).expect("diagnostic serializes");
    assert!(!rendered.contains("do-not-echo"));
    assert!(unknown.diagnostics()[0].path.ends_with("secretField"));

    let duplicate = parse_project_json(
        br#"{
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "kind":"Other",
          "project":{"id":"neutral","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}
        }"#,
    )
    .expect_err("duplicate member is refused");
    assert_eq!(duplicate.diagnostics()[0].code, "breg.source.json-invalid");
    assert_eq!(duplicate.diagnostics()[0].path, "project");
}

#[test]
fn deferred_query_features_are_strictly_unknown_key_rejected() {
    for (key, member, canary) in [
        (
            "joins",
            r#""joins":[{"source":"join-source-canary"}]"#,
            "join-source-canary",
        ),
        (
            "transforms",
            r#""transforms":[{"source":"transform-source-canary"}]"#,
            "transform-source-canary",
        ),
        (
            "countSources",
            r#""countSources":[{"source":"count-source-canary"}]"#,
            "count-source-canary",
        ),
        (
            "namedQueries",
            r#""namedQueries":[{"source":"named-query-canary"}]"#,
            "named-query-canary",
        ),
        (
            "spatialPredicates",
            r#""spatialPredicates":[{"source":"spatial-predicate-canary"}]"#,
            "spatial-predicate-canary",
        ),
    ] {
        let source = format!(
            r#"{{"datasets":[{{"id":"test-dataset"}}],
              "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
              "kind":"BRegProject",
              "project":{{"id":"closed-query-grammar","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
              "recordTypes":[{{
                "id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"create-only",
                {member}
              }}]
            }}"#
        );
        let failure = parse_project_json(source.as_bytes())
            .expect_err("deferred query features remain outside the strict authoring grammar");
        assert_eq!(failure.diagnostics()[0].code, "config.unknown-key");
        assert!(failure.diagnostics()[0].path.ends_with(key));
        let rendered = format!(
            "{failure:?}\n{failure}\n{}",
            serde_json::to_string(&failure).expect("diagnostic serializes")
        );
        assert!(!rendered.contains(canary));
    }
}

#[test]
fn strict_yaml_parse_refuses_duplicate_members() {
    let failure = parse_project_yaml(
        br#"
apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
kind: AnotherKind
project:
  id: neutral
  version: "1"
  defaultLanguage: en
"#,
    )
    .expect_err("duplicate YAML member is refused");
    assert_eq!(failure.diagnostics()[0].code, "yaml.duplicate-key");
    assert_eq!(failure.diagnostics()[0].path, "project.kind");
    assert!(failure.diagnostics()[0].message.contains("line 4"));
    assert!(!failure.diagnostics()[0].message.contains("AnotherKind"));
}

#[test]
fn an_authored_project_carrying_an_environment_expression_is_refused() {
    let failure = parse_project_yaml(
        br#"
apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project:
  id: neutral
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: ${AUTHORED_BASE_IRI}
recordTypes:
  - id: case
    title: "Case ${AUTHORED_TITLE:-default}"
"#,
    )
    .expect_err("an environment expression in an authored project is refused");
    // Every expression is refused where it is written, not only the first.
    assert_eq!(failure.diagnostics().len(), 2, "{failure:?}");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.path == "project.project.canonicalBaseIri")
        .expect("the expression in the registry block is refused");
    assert_eq!(diagnostic.code, "config.substitution-not-allowed");
    assert_eq!(diagnostic.path, "project.project.canonicalBaseIri");
    assert!(diagnostic.message.contains("runtime.yaml"));
    assert!(!diagnostic.message.contains("AUTHORED_BASE_IRI"));

    let module = parse_module_yaml(
        br#"
apiVersion: id.registrystack.org/formats/breg/module/v1alpha1
kind: BRegModule
recordTypes:
  - id: case
    fields:
      - id: label
        description: ${AUTHORED_DESCRIPTION}
"#,
    )
    .expect_err("an environment expression in an authored module is refused");
    let diagnostic = &module.diagnostics()[0];
    assert_eq!(diagnostic.code, "config.substitution-not-allowed");
    assert_eq!(
        diagnostic.path,
        "module.recordTypes[0].fields[0].description"
    );
}

#[test]
fn project_urls_and_module_digests_are_read_as_url_and_digest() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance/asset-site-placement/registry.yaml");
    let fixture: Value =
        serde_norway::from_slice(&fs::read(path).expect("the fixture is readable"))
            .expect("the fixture is YAML");
    let distribution = |member: &str, written: &str| {
        let mut distribution = json!({"id": "bulk", "dataset": "asset-site-placement"});
        distribution[member] = json!(written);
        json!([distribution])
    };
    let cases: Vec<(&str, ProjectEdit)> = vec![
        (
            "project.manifestProjection.catalog.baseUrl",
            Box::new(|source| {
                source["manifestProjection"]["catalog"]["baseUrl"] =
                    json!("asset-site-placement.example.gov");
            }),
        ),
        (
            "project.manifestProjection.dataServices[0].endpointUrl",
            Box::new(|source| {
                source["manifestProjection"]["dataServices"][0]["endpointUrl"] = json!("");
            }),
        ),
        (
            "project.manifestProjection.distributions[0].accessUrl",
            Box::new(move |source| {
                source["manifestProjection"]["distributions"] =
                    distribution("accessUrl", "ftp://files.example.gov/bulk");
            }),
        ),
        (
            "project.manifestProjection.distributions[0].downloadUrl",
            Box::new(move |source| {
                source["manifestProjection"]["distributions"] =
                    distribution("downloadUrl", "https://user@files.example.gov/bulk.csv");
            }),
        ),
        (
            "project.modules[0].digest",
            Box::new(|source| {
                source["modules"][0]["digest"] = json!("sha256:MARKER");
            }),
        ),
        (
            "project.accessProfiles[0].taskGrant.sourceIssuer",
            Box::new(|source| {
                source["accessProfiles"][0]["taskGrant"] =
                    json!({"sourceIssuer": "urn:casework:issuer"});
            }),
        ),
    ];
    for (refused_at, mutate) in cases {
        let mut source = fixture.clone();
        mutate(&mut source);
        let failure = parse_project_yaml(
            serde_norway::to_string(&source)
                .expect("the project serializes")
                .as_bytes(),
        )
        .expect_err("a member that is not a URL or a digest is refused");
        let refused = failure
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            refused,
            vec![("config.invalid-value", refused_at)],
            "{failure:?}"
        );
        for written in ["MARKER", "files.example.gov", "casework:issuer"] {
            assert!(
                !failure.diagnostics()[0].message.contains(written),
                "{failure:?}"
            );
        }
    }
}

#[test]
fn integer_members_are_read_within_their_stated_bounds() {
    let fixture = |project: &str| -> Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/acceptance")
            .join(project)
            .join("registry.yaml");
        serde_norway::from_slice(&fs::read(path).expect("the fixture is readable"))
            .expect("the fixture is YAML")
    };
    let field = |written: Value| {
        move |source: &mut Value| {
            let mut field = json!({"id": "probe", "classification": "internal"});
            for (key, value) in written.as_object().expect("a field is a mapping") {
                field[key] = value.clone();
            }
            source["recordTypes"][0]["fields"][0] = field;
        }
    };
    let set = |pointer: &'static str, written: Value| {
        move |source: &mut Value| {
            *source
                .pointer_mut(pointer)
                .expect("the fixture has the member") = written.clone();
        }
    };
    let cases: Vec<(&str, ProjectEdit, &str, &str)> = vec![
        (
            "asset-site-placement",
            Box::new(field(json!({"type": "string", "maximumLength": 0}))),
            "config.out-of-range",
            "project.recordTypes[0].fields[0].maximumLength",
        ),
        (
            "asset-site-placement",
            Box::new(field(json!({"type": "text", "maximumLength": 10_000_001}))),
            "config.out-of-range",
            "project.recordTypes[0].fields[0].maximumLength",
        ),
        (
            "asset-site-placement",
            Box::new(field(
                json!({"type": "string", "minimumLength": 1_000_001, "maximumLength": 64}),
            )),
            "config.out-of-range",
            "project.recordTypes[0].fields[0].minimumLength",
        ),
        (
            "asset-site-placement",
            Box::new(field(json!({"type": "string", "maximumLength": 1_000_001}))),
            "config.invalid-value",
            "project.recordTypes[0].fields[0]",
        ),
        (
            "asset-site-placement",
            Box::new(field(
                json!({"type": "decimal", "precision": 39, "scale": 0}),
            )),
            "config.out-of-range",
            "project.recordTypes[0].fields[0].precision",
        ),
        (
            "asset-site-placement",
            Box::new(field(
                json!({"type": "decimal", "precision": 0, "scale": 0}),
            )),
            "config.invalid-value",
            "project.recordTypes[0].fields[0]",
        ),
        (
            "asset-site-placement",
            Box::new(field(
                json!({"type": "decimal", "precision": 10, "scale": 39}),
            )),
            "config.out-of-range",
            "project.recordTypes[0].fields[0].scale",
        ),
        (
            "asset-site-placement",
            Box::new(field(json!({"type": "crs84-point", "precision": 10}))),
            "config.invalid-value",
            "project.recordTypes[0].fields[0]",
        ),
        (
            "asset-site-placement",
            Box::new(field(
                json!({"type": "structured", "maximumBytes": 1_048_577, "schema": {"type": "object"}}),
            )),
            "config.out-of-range",
            "project.recordTypes[0].fields[0].maximumBytes",
        ),
        (
            "asset-site-placement",
            Box::new(set("/recordTypes/0/batch/maximumItems", json!(101))),
            "config.out-of-range",
            "project.recordTypes[0].batch.maximumItems",
        ),
        (
            "asset-site-placement",
            Box::new(set("/recordTypes/0/batch/maximumItems", json!(0))),
            "config.out-of-range",
            "project.recordTypes[0].batch.maximumItems",
        ),
        (
            "asset-site-placement",
            Box::new(set("/recordTypes/0/batch/maximumBytes", json!(2_097_153))),
            "config.out-of-range",
            "project.recordTypes[0].batch.maximumBytes",
        ),
        (
            "farmer-landholding-evidence",
            Box::new(set(
                "/actions/0/evidence/0/maximumObservationAgeSeconds",
                json!(301),
            )),
            "config.out-of-range",
            "project.actions[0].evidence[0].maximumObservationAgeSeconds",
        ),
        (
            "farmer-landholding-evidence",
            Box::new(set(
                "/actions/0/evidence/0/maximumObservationAgeSeconds",
                json!(0),
            )),
            "config.out-of-range",
            "project.actions[0].evidence[0].maximumObservationAgeSeconds",
        ),
        (
            "facility",
            Box::new(set(
                "/statisticalDatasets/0/disclosure/minimumCount",
                json!(1),
            )),
            "config.out-of-range",
            "project.statisticalDatasets[0].disclosure.minimumCount",
        ),
        (
            "facility",
            Box::new(set(
                "/statisticalDatasets/0/disclosure/roundingBase",
                json!(9_007_199_254_740_992_u64),
            )),
            "config.out-of-range",
            "project.statisticalDatasets[0].disclosure.roundingBase",
        ),
    ];
    for (project, mutate, code, path) in cases {
        let mut source = fixture(project);
        mutate(&mut source);
        let failure = parse_project_yaml(
            serde_norway::to_string(&source)
                .expect("the project serializes")
                .as_bytes(),
        )
        .expect_err("a value outside the stated bounds is refused");
        let refused = failure
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(refused, vec![(code, path)], "{failure:?}");
    }
}

#[test]
fn a_set_written_as_a_list_refuses_a_repeated_item_when_the_project_is_read() {
    let cases = [
        (
            "asset-site-placement",
            "/accessProfiles/0/permissions/records/0/operations",
            "project.accessProfiles[0].permissions.records[0].operations[5]",
        ),
        (
            "asset-site-placement",
            "/accessProfiles/0/permissions/records/0/readableFields",
            "project.accessProfiles[0].permissions.records[0].readableFields[3]",
        ),
        (
            "asset-site-placement",
            "/accessProfiles/0/requiredPurposes",
            "project.accessProfiles[0].requiredPurposes[1]",
        ),
        (
            "person-registration-rhai",
            "/recordTypes/0/hooks/0/projection",
            "project.recordTypes[0].hooks[0].projection[1]",
        ),
    ];
    for (project, pointer, path) in cases {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/acceptance")
            .join(project)
            .join("registry.yaml");
        let mut source: Value =
            serde_norway::from_slice(&fs::read(fixture).expect("the fixture is readable"))
                .expect("the fixture is YAML");
        let items = source
            .pointer_mut(pointer)
            .and_then(Value::as_array_mut)
            .expect("the fixture has the list");
        let repeated = items[0].clone();
        items.push(repeated);
        let failure = parse_project_yaml(
            serde_norway::to_string(&source)
                .expect("the project serializes")
                .as_bytes(),
        )
        .expect_err("a repeated item is refused rather than collapsed");
        let refused = failure
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect::<Vec<_>>();
        assert_eq!(
            refused,
            vec![("config.duplicate-item", path)],
            "{failure:?}"
        );
    }
}

/// A module holding one entity whose access profile carries `member`.
fn module_with_profile_member(member: &str, value: Value) -> Vec<u8> {
    let mut profile = json!({
        "id": "historian", "principalClaim": "registry_principal",
        "operations": ["get", "list", "revisions"], "revisionAccess": true,
        "readableFields": ["label"],
        "requiredScopes": "unrestricted", "rowBoundaries": "unrestricted"
    });
    profile[member] = value;
    serde_json::to_vec(&json!({
        "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule",
        "id": "memo-core", "version": "1",
        "recordTypes": [{
            "id": "memo", "primaryDataset": "test-dataset", "route": "memos",
            "mutationMode": "mutable", "classification": "internal",
            "fields": [{"id": "label", "type": "string", "maximumLength": 32, "required": true, "classification": "internal"}],
            "accessProfiles": [profile]
        }]
    }))
    .expect("the module serializes")
}

fn refusals(failure: &CompileFailure) -> Vec<(&str, &str)> {
    failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.severity == DiagnosticSeverity::Error)
        .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
        .collect()
}

fn project_with_authored_index_fields(count: usize) -> Vec<u8> {
    let mut source: Value =
        serde_json::from_slice(MULTI_DATASET_PROJECT).expect("multi-dataset source is JSON");
    let ids = (0..count)
        .map(|index| format!("key-{index}"))
        .collect::<Vec<_>>();
    let person = &mut source["recordTypes"][0];
    person["fields"]
        .as_array_mut()
        .expect("the entity declares fields")
        .extend(ids.iter().map(|id| {
            json!({"id": id, "type": "string", "maximumLength": 8, "classification": "restricted"})
        }));
    person["indexes"] = json!([{"id": "wide", "fields": ids}]);
    serde_json::to_vec(&source).expect("project source serializes")
}

#[test]
fn an_authored_index_declares_at_most_31_fields() {
    let widest = compile_json(&project_with_authored_index_fields(31))
        .expect("31 fields leave the last index key column to the record identifier");
    let statement = widest
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.id == "entity.person.index.wide")
        .expect("the authored index compiles to a statement");
    let (_, columns) = statement
        .sql
        .split_once(" (")
        .expect("the index statement lists its key columns");
    assert_eq!(columns.split(", ").count(), 32);
    assert!(columns.ends_with(", record_id)"));

    let failure = compile_json(&project_with_authored_index_fields(32))
        .expect_err("a 32-field index leaves no key column for the record identifier");
    assert_eq!(
        refusals(&failure),
        vec![(
            "breg.index.fields-too-many",
            "recordTypes[id=person].indexes[id=wide].fields"
        )]
    );
    assert_eq!(
        failure.diagnostics()[0].message,
        "an index may declare at most 31 fields; the record identifier takes the last of the 32 key columns PostgreSQL allows in an index"
    );
}

#[test]
fn provenance_fields_are_read_as_a_set_in_a_project_and_a_module() {
    parse_module_yaml(&module_with_profile_member(
        "provenanceFields",
        json!(["sourceReferences", "kind"]),
    ))
    .expect("distinct provenance fields are read in the order written");
    let failure = parse_module_yaml(&module_with_profile_member(
        "provenanceFields",
        json!(["kind", "reasonCode", "kind"]),
    ))
    .expect_err("a repeated provenance field is refused rather than collapsed");
    assert_eq!(
        refusals(&failure),
        vec![(
            "config.duplicate-item",
            "module.recordTypes[0].accessProfiles[0].provenanceFields[2]"
        )],
        "{failure:?}"
    );

    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance/asset-site-placement/registry.yaml");
    let mut source: Value =
        serde_norway::from_slice(&fs::read(fixture).expect("the fixture is readable"))
            .expect("the fixture is YAML");
    source["accessProfiles"][0]["permissions"]["records"][0]["provenanceFields"] =
        json!(["reasonText", "reasonText"]);
    let failure = parse_project_yaml(
        serde_norway::to_string(&source)
            .expect("the project serializes")
            .as_bytes(),
    )
    .expect_err("a repeated provenance field is refused rather than collapsed");
    assert_eq!(
        refusals(&failure),
        vec![(
            "config.duplicate-item",
            "project.accessProfiles[0].permissions.records[0].provenanceFields[1]"
        )],
        "{failure:?}"
    );
}

#[test]
fn a_module_profile_task_grant_issuer_is_read_as_a_url() {
    let failure = parse_module_yaml(&module_with_profile_member(
        "taskGrant",
        json!({"sourceIssuer": "urn:casework:issuer", "permissions": []}),
    ))
    .expect_err("an issuer that is not a URL is refused when the module is read");
    assert_eq!(
        refusals(&failure),
        vec![(
            "config.invalid-value",
            "module.recordTypes[0].accessProfiles[0].taskGrant.sourceIssuer"
        )],
        "{failure:?}"
    );
    assert!(
        !failure.diagnostics()[0].message.contains("casework:issuer"),
        "{failure:?}"
    );
}

#[test]
fn a_repeated_entity_id_is_refused_at_the_second_id_when_the_file_is_read() {
    let acceptance =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../products/breg/acceptance");
    let repeated = |file: &str| {
        let mut source: Value = serde_norway::from_slice(
            &fs::read(acceptance.join(file)).expect("the fixture is readable"),
        )
        .expect("the fixture is YAML");
        let entities = source
            .pointer_mut("/recordTypes")
            .and_then(Value::as_array_mut)
            .expect("the fixture lists entities");
        let first = entities[0].clone();
        entities.push(first);
        let last = entities.len() - 1;
        (
            serde_norway::to_string(&source).expect("the source serializes"),
            last,
        )
    };
    let refused = |failure: &CompileFailure| {
        failure
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
            .collect::<Vec<_>>()
    };

    let (project, last) = repeated("person-registration-rhai/registry.yaml");
    let failure = parse_project_yaml(project.as_bytes())
        .expect_err("a project that names one entity twice is refused when read");
    assert_eq!(
        refused(&failure),
        vec![(
            "config.duplicate-id".to_owned(),
            format!("project.recordTypes[{last}].id")
        )],
        "{failure:?}"
    );

    let (module, last) = repeated("inspection/modules/inspection-core/module.yaml");
    let failure = parse_module_yaml(module.as_bytes())
        .expect_err("a module that names one entity twice is refused when read");
    assert_eq!(
        refused(&failure),
        vec![(
            "config.duplicate-id".to_owned(),
            format!("module.recordTypes[{last}].id")
        )],
        "{failure:?}"
    );
}

#[test]
fn an_entity_two_files_contribute_is_refused_by_the_compiler() {
    let mut project = acceptance_project("inspection");
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance/inspection/modules")
        .join("inspection-core/module.yaml");
    let module = parse_module_yaml(&fs::read(path).expect("the module is readable"))
        .expect("the module follows the authoring contract");
    project.entities.push(module.entities[0].clone());

    let failure = compile_project(&project, &[module], CompileProfile::Authoring)
        .expect_err("one entity contributed by the project and by a module is refused");
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "breg.record-type.id-duplicate"),
        "{:?}",
        failure.diagnostics()
    );
}

#[test]
fn source_parse_diagnostics_name_the_member_the_alternatives_and_the_location() {
    let unknown_yaml_member = parse_project_yaml(
        br#"
apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project:
  id: neutral
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://authoring.example.test
  secretField: do-not-echo
"#,
    )
    .expect_err("an unknown YAML member is refused");
    let diagnostic = &unknown_yaml_member.diagnostics()[0];
    assert_eq!(diagnostic.code, "config.unknown-key");
    assert_eq!(diagnostic.path, "project.project.secretField");
    assert!(diagnostic
        .message
        .contains("`secretField` is not a member of this mapping"));
    assert!(diagnostic.message.contains("the accepted keys are"));
    assert!(diagnostic.message.contains("canonicalBaseIri"));
    assert!(diagnostic.message.contains("line 9"));
    assert!(!diagnostic.message.contains("do-not-echo"));

    let missing_yaml_member = parse_project_yaml(
        br#"
apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project:
  id: neutral
  defaultLanguage: en
  canonicalBaseIri: https://authoring.example.test
"#,
    )
    .expect_err("a missing YAML member is refused");
    assert_eq!(
        missing_yaml_member.diagnostics()[0].code,
        "config.missing-key"
    );
    assert!(missing_yaml_member.diagnostics()[0]
        .message
        .contains("`version`"));

    let wrong_yaml_type = parse_project_yaml(
        br#"
apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project:
  id: neutral
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://authoring.example.test
recordTypes: do-not-echo
"#,
    )
    .expect_err("a wrongly typed YAML member is refused");
    let diagnostic = &wrong_yaml_type.diagnostics()[0];
    assert_eq!(diagnostic.code, "config.invalid-type");
    assert_eq!(diagnostic.path, "project.recordTypes");
    assert!(diagnostic.message.contains("expected a list"));
    assert!(!diagnostic.message.contains("do-not-echo"));

    let unknown_enum_value = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"neutral","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{"id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"append_only"}]
        }"#,
    )
    .expect_err("an unknown enum value is refused");
    let diagnostic = &unknown_enum_value.diagnostics()[0];
    assert_eq!(diagnostic.code, "config.unknown-variant");
    assert_eq!(diagnostic.path, "project.recordTypes[0].mutationMode");
    assert!(!diagnostic.message.contains("append_only"));
    assert!(diagnostic.message.contains("create-only"));

    let malformed_json =
        parse_project_json(b"{\"apiVersion\":}").expect_err("malformed JSON is refused");
    let diagnostic = &malformed_json.diagnostics()[0];
    assert_eq!(diagnostic.code, "breg.source.json-invalid");
    assert_eq!(diagnostic.path, "project");
    assert!(diagnostic.message.contains("line 1"));
}

#[test]
fn generic_decimal_crs84_point_and_structured_fields_compile_to_deterministic_ddl_and_schema() {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"generic-scalars","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"reading","primaryDataset":"test-dataset","route":"readings","mutationMode":"mutable",
            "fields":[
              {"id":"amount","type":"decimal","precision":6,"scale":2,"minimum":"-10.00","maximum":"9999.99","classification":"internal"},
              {"id":"location","type":"crs84-point","precision":4,"bbox":{"west":"100.0000","south":"10.0000","east":"110.0000","north":"20.0000"},"classification":"internal"},
              {"id":"payload","type":"structured","maximumBytes":256,"classification":"internal","schema":{
                "$schema":"https://json-schema.org/draft/2020-12/schema",
                "type":"object",
                "additionalProperties":false,
                "properties":{"batch":{"type":"string","maxLength":32}},
                "required":["batch"]
              }}
            ]
          }],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
              "recordType":"reading","operations":["create","get","list","patch"],
              "readableFields":["amount","location","payload"],
              "writableFields":["amount","location","payload"],
              "rowBoundaries": "unrestricted"
            }]}
          }]
        }"#,
    )
    .expect("generic scalar source parses");
    let first =
        compile_project(&project, &[], CompileProfile::Authoring).expect("project compiles");
    let second =
        compile_project(&project, &[], CompileProfile::Authoring).expect("project compiles twice");
    assert_eq!(first, second);

    let ddl = first.ddl().script();
    assert!(ddl.contains("numeric(6,2)"));
    assert!(ddl.contains("jsonb_typeof"));
    assert!(ddl.contains("octet_length"));
    assert!(ddl.contains("^-?(0|[1-9]|[1-8][0-9]|90)(\\.[0-9]{1,4})?$"));
    let lower = ddl.to_ascii_lowercase();
    assert!(!lower.contains("postgis"));
    assert!(!lower.contains("geometry"));
    assert!(!lower.contains("geography"));

    let schema = first
        .artifacts()
        .get("generated/schemas/reading.schema.json")
        .expect("entity schema generated");
    let schema: Value = parse_json_strict(&schema.bytes).expect("schema is strict JSON");
    for name in ["amount", "location", "payload"] {
        assert_eq!(
            schema["properties"][name]["anyOf"][1],
            json!({"type": "null"})
        );
    }
    assert_eq!(schema["properties"]["amount"]["anyOf"][0]["type"], "string");
    assert_eq!(
        schema["properties"]["amount"]["anyOf"][0]["x-registry-decimalScale"],
        2
    );
    assert_eq!(
        schema["properties"]["location"]["anyOf"][0]["description"],
        "CRS84 GeoJSON Point with coordinates in [longitude, latitude] order."
    );
    assert_eq!(
        schema["properties"]["payload"]["anyOf"][0]["properties"]["batch"]["type"],
        "string"
    );
    assert_eq!(
        schema["properties"]["payload"]["anyOf"][0]["x-registry-maxBytes"],
        256
    );
}

#[test]
fn scalar_field_sources_reject_incompatible_type_options_during_strict_parse() {
    let failure = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"generic-scalars","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"reading","primaryDataset":"test-dataset","route":"readings","mutationMode":"mutable",
            "fields":[{"id":"flag","type":"boolean","precision":2,"classification":"internal"}]
          }]
        }"#,
    )
    .expect_err("type-incompatible option is refused during parse");
    assert_eq!(failure.diagnostics()[0].code, "config.invalid-value");
}

#[test]
fn scalar_grammar_is_exactly_the_typed_allowlist_and_rejects_json_or_reference_lists() {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"scalar-allowlist","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[
            {"id":"target","primaryDataset":"test-dataset","route":"targets","mutationMode":"create-only"},
            {
              "id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"create-only",
              "fields":[
                {"id":"flag","type":"boolean","classification":"internal"},
                {"id":"code","type":"string","maximumLength":32,"classification":"internal"},
                {"id":"notes","type":"text","maximumLength":1024,"classification":"internal"},
                {"id":"count","type":"int64","classification":"internal"},
                {"id":"amount","type":"decimal","precision":6,"scale":2,"classification":"internal"},
                {"id":"day","type":"date","classification":"internal"},
                {"id":"observed-at","type":"timestamp","classification":"internal"},
                {"id":"external-id","type":"uuid","classification":"internal"},
                {"id":"status","type":"vocabulary-code","vocabulary":"status","classification":"internal"},
                {"id":"target","type":"reference","target":"target","classification":"internal"},
                {"id":"location","type":"crs84-point","precision":4,"classification":"internal"},
                {"id":"payload","type":"structured","maximumBytes":256,"classification":"internal","schema":{"type":"object","additionalProperties":false}}
              ]
            }
          ],
          "vocabularies":[{"id":"status","values":["active","closed"]}]
        }"#,
    )
    .expect("every approved scalar form parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("every approved scalar form compiles");

    let approved: Vec<_> = project.entities[1]
        .fields
        .iter()
        .map(|field| match &field.field_type {
            FieldTypeSource::Boolean => "boolean",
            FieldTypeSource::String { .. } => "string",
            FieldTypeSource::Text { .. } => "text",
            FieldTypeSource::Int64 => "int64",
            FieldTypeSource::Decimal { .. } => "decimal",
            FieldTypeSource::Date => "date",
            FieldTypeSource::Timestamp => "timestamp",
            FieldTypeSource::Uuid => "uuid",
            FieldTypeSource::VocabularyCode { .. } => "vocabulary-code",
            FieldTypeSource::Reference { .. } => "reference",
            FieldTypeSource::Crs84Point { .. } => "crs84-point",
            FieldTypeSource::Structured { .. } => "structured",
        })
        .collect();
    assert_eq!(
        approved,
        [
            "boolean",
            "string",
            "text",
            "int64",
            "decimal",
            "date",
            "timestamp",
            "uuid",
            "vocabulary-code",
            "reference",
            "crs84-point",
            "structured",
        ]
    );

    let refused = [
        (
            r#"{"id":"unvalidated-json-canary","type":"json","classification":"internal"}"#,
            "unvalidated-json-canary",
        ),
        (
            r#"{"id":"reference-list-canary","type":"reference-list","target":"target","classification":"internal"}"#,
            "reference-list-canary",
        ),
        (
            r#"{"id":"reference-target-list-canary","type":"reference","target":["target"],"classification":"internal"}"#,
            "reference-target-list-canary",
        ),
    ];
    for (field, canary) in refused {
        let source = format!(
            r#"{{"datasets":[{{"id": "test-dataset"}}],
              "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
              "kind":"BRegProject",
              "project":{{"id":"scalar-allowlist","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
              "recordTypes":[{{
                "id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"create-only",
                "fields":[{field}]
              }}]
            }}"#
        );
        let failure = parse_project_json(source.as_bytes())
            .expect_err("unapproved scalar or reference-list forms fail strict parsing");
        assert_eq!(
            failure.diagnostics()[0].code,
            if canary == "reference-target-list-canary" {
                "config.expected-string"
            } else {
                "config.unknown-variant"
            }
        );
        let rendered = format!(
            "{failure:?}\n{failure}\n{}",
            serde_json::to_string(&failure).expect("diagnostic serializes")
        );
        assert!(!rendered.contains(canary));
    }
}

#[test]
fn generic_scalar_option_and_schema_negatives_fail_before_ddl_generation() {
    let cases = [
        (
            r#"{"id":"amount","type":"decimal","precision":39,"scale":2,"classification":"internal"}"#,
            "config.out-of-range",
        ),
        (
            r#"{"id":"amount","type":"decimal","precision":4,"scale":2,"minimum":"01.00","classification":"internal"}"#,
            "breg.field.decimal-bounds-invalid",
        ),
        (
            r#"{"id":"location","type":"crs84-point","precision":10,"classification":"internal"}"#,
            "config.invalid-value",
        ),
        (
            r#"{"id":"location","type":"crs84-point","precision":4,"bbox":{"west":"110.0000","south":"10.0000","east":"100.0000","north":"20.0000"},"classification":"internal"}"#,
            "breg.field.crs84-point-bounds-invalid",
        ),
        (
            r#"{"id":"payload","type":"structured","maximumBytes":0,"classification":"internal","schema":{"type":"object","additionalProperties":false}}"#,
            "config.out-of-range",
        ),
        (
            r#"{"id":"payload","type":"structured","maximumBytes":256,"classification":"internal","schema":{"type":"object","properties":{"code":{"type":"string"}}}}"#,
            "breg.field.structured-schema-invalid",
        ),
        (
            r#"{"id":"payload","type":"structured","maximumBytes":256,"classification":"internal","schema":{}}"#,
            "breg.field.structured-schema-invalid",
        ),
        (
            r#"{"id":"payload","type":"structured","maximumBytes":256,"classification":"internal","schema":{"$ref":"https://schema.example.invalid/payload"}}"#,
            "breg.field.structured-schema-invalid",
        ),
    ];

    for (field, code) in cases {
        let source = format!(
            r#"{{"datasets":[{{"id": "test-dataset"}}],
              "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
              "kind":"BRegProject",
              "project":{{"id":"generic-scalars","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
              "recordTypes":[{{
                "id":"reading","primaryDataset":"test-dataset","route":"readings","mutationMode":"mutable",
                "fields":[{field}]
              }}],
              "accessProfiles":[{{"id":"operator","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{{"records":[{{"rowBoundaries": "unrestricted", "recordType":"reading","operations":["get"],"readableFields":["{}"]}}]}}}}]
            }}"#,
            if field.contains("\"amount\"") {
                "amount"
            } else if field.contains("\"location\"") {
                "location"
            } else {
                "payload"
            }
        );
        // A bound the reader states is refused when the project is read; a
        // rule that relates members or reads the embedded schema is refused
        // when it compiles.
        let failure = match parse_project_yaml(source.as_bytes()) {
            Ok(project) => compile_project(&project, &[], CompileProfile::Authoring)
                .expect_err("invalid generic scalar configuration fails compilation"),
            Err(failure) => failure,
        };
        assert!(
            failure
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.code == code),
            "{failure:?}"
        );
    }
}

#[test]
fn decimal_bound_diagnostic_names_the_record_field_and_scale_rule() {
    let mut project = multi_dataset_project();
    let field = project.entities[0]
        .fields
        .iter_mut()
        .find(|field| field.id == "name")
        .unwrap();
    field.field_type = registry_breg::contract::FieldTypeSource::Decimal {
        precision: 6,
        scale: 2,
        minimum: Some("1.0".to_owned()),
        maximum: Some("99.99".to_owned()),
    };
    let failure = compile_project(&project, &[], CompileProfile::Authoring).unwrap_err();
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.field.decimal-bounds-invalid")
        .unwrap();
    assert_eq!(diagnostic.path, "recordTypes[id=person].fields[id=name]");
    assert!(diagnostic
        .message
        .contains("exactly scale fractional digits"));
}

#[test]
fn decimal_bound_diagnostic_names_the_scale_and_ordering_rules() {
    for (precision, scale, minimum, maximum, rule) in [
        (2, 3, None, None, "scale must not exceed precision"),
        (
            6,
            2,
            Some("50.00"),
            Some("10.00"),
            "minimum must not exceed maximum",
        ),
    ] {
        let mut project = multi_dataset_project();
        let field = project.entities[0]
            .fields
            .iter_mut()
            .find(|field| field.id == "name")
            .unwrap();
        field.field_type = registry_breg::contract::FieldTypeSource::Decimal {
            precision,
            scale,
            minimum: minimum.map(str::to_owned),
            maximum: maximum.map(str::to_owned),
        };
        let failure = compile_project(&project, &[], CompileProfile::Authoring).unwrap_err();
        let diagnostic = failure
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == "breg.field.decimal-bounds-invalid")
            .unwrap();
        assert!(diagnostic.message.contains(rule), "{}", diagnostic.message);
    }
}

#[test]
fn reusable_decimal_bound_diagnostic_names_capacity_and_preserves_valid_bounds() {
    let mut project = multi_dataset_project();
    project.value_types.insert(
        "bounded-decimal".to_owned(),
        registry_breg::contract::FieldTypeSource::Decimal {
            precision: 2,
            scale: 0,
            minimum: Some("100".to_owned()),
            maximum: None,
        },
    );
    let failure = compile_project(&project, &[], CompileProfile::Authoring).unwrap_err();
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.field.decimal-bounds-invalid")
        .expect("the reusable decimal refusal is reported");
    assert_eq!(diagnostic.path, "valueTypes.bounded-decimal");
    assert!(
        diagnostic
            .message
            .contains("integer digits that fit precision minus scale"),
        "{diagnostic:?}"
    );

    project.value_types.insert(
        "bounded-decimal".to_owned(),
        registry_breg::contract::FieldTypeSource::Decimal {
            precision: 2,
            scale: 0,
            minimum: Some("-99".to_owned()),
            maximum: Some("99".to_owned()),
        },
    );
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("canonical reusable bounds that fit the declared precision compile");
}

#[test]
fn action_decimal_bound_diagnostic_names_capacity_and_preserves_valid_bounds() {
    let source = |minimum: &str, maximum: Option<&str>| {
        let mut input = json!({
            "id": "amount",
            "type": "decimal",
            "precision": 2,
            "scale": 0,
            "minimum": minimum,
            "required": true,
            "classification": "internal"
        });
        if let Some(maximum) = maximum {
            input["maximum"] = json!(maximum);
        }
        json!({
            "datasets": [{"id": "test-dataset"}],
            "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
            "kind": "BRegProject",
            "project": {
                "id": "decimal-action",
                "version": "1",
                "defaultLanguage": "en",
                "canonicalBaseIri": "https://authoring.example.test"
            },
            "recordTypes": [{
                "id": "entry",
                "primaryDataset": "test-dataset",
                "route": "entries",
                "mutationMode": "create-only",
                "fields": [{
                    "id": "amount",
                    "type": "decimal",
                    "precision": 2,
                    "scale": 0,
                    "minimum": "-99",
                    "maximum": "99",
                    "classification": "internal"
                }]
            }],
            "actions": [{
                "execution": {"mode": "immediate"},
                "id": "create-entry",
                "inputs": [input],
                "plan": {"type": "fixed", "effects": [{
                    "id": "entry",
                    "target": {"recordType": "entry"},
                    "operation": "create",
                    "set": {"amount": {"fromInput": "amount"}}
                }]}
            }],
            "accessProfiles": [{
                "id": "operator",
                "default": true,
                "principalClaim": "principal",
                "requiredScopes": "unrestricted",
                "permissions": {"actions": [{
                    "action": "create-entry",
                    "operations": ["invoke"],
                    "targets": [{"recordType": "entry", "rowBoundaries": "unrestricted"}],
                    "results": ["entry"]
                }]}
            }]
        })
    };

    let project =
        parse_project_json(&serde_json::to_vec(&source("100", None)).expect("source serializes"))
            .expect("invalid decimal bounds remain compiler input");
    let failure = compile_project(&project, &[], CompileProfile::Authoring).unwrap_err();
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.action.input-decimal-bounds-invalid")
        .expect("the action input decimal refusal is reported");
    assert_eq!(diagnostic.path, "actions[create-entry].inputs[]");
    assert!(
        diagnostic
            .message
            .contains("integer digits that fit precision minus scale"),
        "{diagnostic:?}"
    );

    let project = parse_project_json(
        &serde_json::to_vec(&source("-99", Some("99"))).expect("source serializes"),
    )
    .expect("valid decimal bounds parse");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("canonical action input bounds that fit the declared precision compile");
}

#[test]
fn crs84_point_and_structured_fields_cannot_be_row_boundaries_until_equality_is_defined() {
    for field in [
        r#"{"id":"location","type":"crs84-point","precision":4,"classification":"internal"}"#,
        r#"{"id":"payload","type":"structured","maximumBytes":256,"classification":"internal","schema":{"type":"object","additionalProperties":false}}"#,
    ] {
        let field_id = if field.contains("\"location\"") {
            "location"
        } else {
            "payload"
        };
        let source = format!(
            r#"{{"datasets":[{{"id": "test-dataset"}}],
              "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
              "kind":"BRegProject",
              "project":{{"id":"generic-scalars","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
              "recordTypes":[{{
                "id":"reading","primaryDataset":"test-dataset","route":"readings","mutationMode":"mutable",
                "fields":[{field}]
              }}],
              "accessProfiles":[{{
                "id":"operator","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{{"records":[{{
                  "recordType":"reading","operations":["get"],
                  "readableFields":["{field_id}"],
                  "rowBoundaries":[{{"field":"{field_id}","claim":"claim","operator":"equals"}}]
                }}]}}
              }}]
            }}"#
        );
        let project = parse_project_json(source.as_bytes()).expect("source shape parses");
        let failure = compile_project(&project, &[], CompileProfile::Authoring)
            .expect_err("unsupported row-boundary field type fails compilation");
        assert!(failure.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == "breg.access-profile.row-boundary-type-unsupported"
        }));
    }
}

#[test]
fn geojson_and_bbox_compile_only_for_direct_current_lists() {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"spatial-authoring","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable","classification":"internal",
            "fields":[
              {"id":"code","type":"string","maximumLength":32,"required":true,"classification":"internal"},
              {"id":"location","type":"crs84-point","precision":6,"required":true,"classification":"internal"},
              {"id":"valid-from","type":"timestamp","validTimeRole":"valid-from","required":true,"classification":"internal"},
              {"id":"valid-to","type":"timestamp","validTimeRole":"valid-to","classification":"internal"},
              {"id":"scope","type":"string","maximumLength":32,"required":true,"classification":"internal"}
            ],
            "geojson":{"geometryField":"location"},
            "temporal":{"startField":"valid-from","endField":"valid-to"},
            "constraints":[{
              "id":"scope-time",
              "type":"temporal-non-overlap",
              "scopeFields":["scope"],
              "startField":"valid-from",
              "endField":"valid-to"
            }]
          }],
          "accessProfiles":[{
            "id":"map-reader","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
              "recordType":"site","operations":["get","list"],"readableFields":["code","location","valid-from","valid-to","scope"],
              "spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":0.25,"maximumLatitudeSpanDegrees":1.5}},
              "rowBoundaries": "unrestricted"
            }]}
          }]
        }"#,
    )
    .expect("spatial source shape parses");
    let compiled = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("spatial authoring compiles");
    assert_eq!(
        compiled.entities()["site"]
            .geojson
            .as_ref()
            .expect("GeoJSON binding compiles")
            .geometry_field,
        "location"
    );

    let base = compiled
        .queries()
        .operations
        .iter()
        .find(|operation| operation.id == "records.site.map-reader.list")
        .expect("direct list query compiles");
    let bbox = base
        .spatial
        .as_ref()
        .and_then(|spatial| spatial.bbox.as_ref())
        .expect("direct current list carries bbox capability");
    assert_eq!(bbox.geometry_field, "location");
    assert_eq!(bbox.maximum_longitude_span_degrees.to_string(), "0.25");
    assert_eq!(bbox.maximum_latitude_span_degrees.to_string(), "1.5");
    assert!(base.processing_fields.contains(&"location".to_owned()));

    for id in [
        "records.site.map-reader.current",
        "records.site.map-reader.as-of",
    ] {
        let operation = compiled
            .queries()
            .operations
            .iter()
            .find(|operation| operation.id == id)
            .expect("temporal query variant compiles");
        assert!(
            operation.spatial.is_none(),
            "temporal query inventory must not inherit bbox authority"
        );
    }

    let ordinary = compile_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"ordinary","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable",
            "fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"}]
          }],
          "accessProfiles":[{
            "id":"reader","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
              "recordType":"entry","operations":["list"],"readableFields":["code"],
              "rowBoundaries": "unrestricted"
            }]}
          }]
        }"#,
    )
    .expect("ordinary project compiles");
    let ordinary_json =
        serde_json::to_value(&ordinary).expect("compiled ordinary project serializes");
    assert!(!ordinary_json["entities"]["entry"]
        .as_object()
        .expect("compiled entity is an object")
        .contains_key("geojson"));
    assert!(ordinary_json["queryInventory"]["operations"]
        .as_array()
        .expect("operations are serialized")
        .iter()
        .all(|operation| !operation
            .as_object()
            .expect("operation is an object")
            .contains_key("spatial")));
}

#[test]
fn bbox_authoring_requires_declared_readable_primary_point_and_bounded_spans() {
    let cases = [
        (
            r#""geojson":{"geometryField":"missing"}"#,
            r#""operations":["list"],"readableFields":["code","location"],"spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":2,"maximumLatitudeSpanDegrees":2}}"#,
            "breg.geojson.geometry-field-unknown",
            "recordTypes[id=site].geojson.geometryField",
        ),
        (
            r#""geojson":{"geometryField":"code"}"#,
            r#""operations":["list"],"readableFields":["code","location"],"spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":2,"maximumLatitudeSpanDegrees":2}}"#,
            "breg.geojson.geometry-field-type-unsupported",
            "recordTypes[id=site].geojson.geometryField",
        ),
        (
            r#""geojson":{"geometryField":"location"}"#,
            r#""operations":["list"],"readableFields":["code","location"],"spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":0,"maximumLatitudeSpanDegrees":2}}"#,
            "breg.access-profile.spatial-queries-bbox-maximum-longitude-span-degrees-invalid",
            "recordTypes[id=site].accessProfiles[].spatialQueries.bbox.maximumLongitudeSpanDegrees",
        ),
        (
            r#""geojson":{"geometryField":"location"}"#,
            r#""operations":["list"],"readableFields":["code","location"],"spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":361,"maximumLatitudeSpanDegrees":2}}"#,
            "breg.access-profile.spatial-queries-bbox-maximum-longitude-span-degrees-invalid",
            "recordTypes[id=site].accessProfiles[].spatialQueries.bbox.maximumLongitudeSpanDegrees",
        ),
        (
            r#""geojson":{"geometryField":"location"}"#,
            r#""operations":["list"],"readableFields":["code","location"],"spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":2,"maximumLatitudeSpanDegrees":181}}"#,
            "breg.access-profile.spatial-queries-bbox-maximum-latitude-span-degrees-invalid",
            "recordTypes[id=site].accessProfiles[].spatialQueries.bbox.maximumLatitudeSpanDegrees",
        ),
        (
            r#""geojson":{"geometryField":"location"}"#,
            r#""operations":["list"],"readableFields":["code","location"],"spatialQueries":{}"#,
            "breg.access-profile.spatial-queries-empty",
            "recordTypes[id=site].accessProfiles[].spatialQueries",
        ),
        (
            r#""geojson":{"geometryField":"location"}"#,
            r#""operations":["list"],"readableFields":["code"],"spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":2,"maximumLatitudeSpanDegrees":2}}"#,
            "breg.access-profile.spatial-queries-bbox-geometry-not-readable",
            "recordTypes[id=site].accessProfiles[].readableFields",
        ),
        (
            r#""geojson":{"geometryField":"location"}"#,
            r#""operations":["get"],"readableFields":["code","location"],"spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":2,"maximumLatitudeSpanDegrees":2}}"#,
            "breg.access-profile.spatial-queries-bbox-list-required",
            "recordTypes[id=site].accessProfiles[].spatialQueries.bbox",
        ),
    ];

    for (geojson, grant, code, path) in cases {
        let source = format!(
            r#"{{"datasets":[{{"id":"test-dataset"}}],
              "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
              "kind":"BRegProject",
              "project":{{"id":"spatial-negative","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
              "recordTypes":[{{
                "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable","classification":"internal",
                "fields":[
                  {{"id":"code","type":"string","maximumLength":32,"classification":"internal"}},
                  {{"id":"location","type":"crs84-point","precision":6,"classification":"internal"}}
                ],
                {geojson}
              }}],
              "accessProfiles":[{{
                "id":"map-reader","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{{"records":[{{
                  "rowBoundaries": "unrestricted", "recordType":"site",{grant}
                }}]}}
              }}]
            }}"#
        );
        let project = parse_project_json(source.as_bytes()).expect("source shape parses");
        let failure = compile_project(&project, &[], CompileProfile::Authoring)
            .expect_err("invalid bbox authoring is refused");
        let diagnostic = failure
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == code)
            .expect("expected spatial diagnostic is reported");
        assert_eq!(diagnostic.path, path);
    }
}

#[test]
fn bbox_authoring_is_strict_and_does_not_make_points_scalar_query_fields() {
    let strict_failure = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"spatial-strict","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable",
            "fields":[{"id":"location","type":"crs84-point","precision":6,"classification":"internal"}],
            "geojson":{"geometryField":"location"}
          }],
          "accessProfiles":[{
            "id":"map-reader","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
              "recordType":"site","operations":["list"],"readableFields":["location"],
              "spatialQueries":{"bbox":{"geometryField":"location","maximumLongitudeSpanDegrees":2,"maximumLatitudeSpanDegrees":2}},
              "rowBoundaries": "unrestricted"
            }]}
          }]
        }"#,
    )
    .expect_err("bbox does not accept duplicate geometry declaration");
    assert_eq!(strict_failure.diagnostics()[0].code, "config.unknown-key");

    for (member, code, message_fragment) in [
        (
            r#""filterableFields":["location"]"#,
            "breg.query.filter-field-type-unsupported",
            "spatialQueries.bbox",
        ),
        (
            r#""sortableFields":["location"]"#,
            "breg.query.sort-field-type-unsupported",
            "spatialQueries.bbox",
        ),
    ] {
        let source = format!(
            r#"{{"datasets":[{{"id":"test-dataset"}}],
              "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
              "kind":"BRegProject",
              "project":{{"id":"point-scalar-negative","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
              "recordTypes":[{{
                "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable",
                "fields":[{{"id":"location","type":"crs84-point","precision":6,"classification":"internal"}}]
              }}],
              "accessProfiles":[{{
                "id":"reader","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{{"records":[{{
                  "rowBoundaries": "unrestricted", "recordType":"site","operations":["list"],"readableFields":["location"],{member}
                }}]}}
              }}]
            }}"#
        );
        let project = parse_project_json(source.as_bytes()).expect("source shape parses");
        let failure = compile_project(&project, &[], CompileProfile::Authoring)
            .expect_err("point scalar query field is refused");
        let diagnostic = failure
            .diagnostics()
            .iter()
            .find(|diagnostic| diagnostic.code == code)
            .expect("expected scalar query diagnostic is reported");
        assert!(diagnostic.message.contains(message_fragment));
    }
}

#[test]
fn modules_can_add_geojson_once_but_conflicting_geometry_is_refused() {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"module-spatial","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "modules":[{"id":"maps","version":"1"}],
          "recordTypes":[{
            "id":"site","primaryDataset":"test-dataset","route":"sites","mutationMode":"mutable",
            "fields":[
              {"id":"code","type":"string","maximumLength":32,"classification":"internal"},
              {"id":"location","type":"crs84-point","precision":6,"classification":"internal"},
              {"id":"alternate","type":"crs84-point","precision":6,"classification":"internal"}
            ]
          }],
          "accessProfiles":[{
            "id":"map-reader","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
              "recordType":"site","operations":["list"],"readableFields":["code","location"],
              "spatialQueries":{"bbox":{"maximumLongitudeSpanDegrees":2,"maximumLatitudeSpanDegrees":2}},
              "rowBoundaries": "unrestricted"
            }]}
          }]
        }"#,
    )
    .expect("project parses");
    let module = parse_module_json(
        br#"{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"maps","version":"1",
          "extendRecordTypes":[{"recordType":"site","geojson":{"geometryField":"location"}}]
        }"#,
    )
    .expect("module parses");
    let compiled = compile_project(&project, &[module], CompileProfile::Authoring)
        .expect("module may add a missing GeoJSON geometry binding");
    assert_eq!(
        compiled.entities()["site"]
            .geojson
            .as_ref()
            .expect("module binding compiles")
            .geometry_field,
        "location"
    );

    let mut project_with_geojson = project.clone();
    project_with_geojson.entities[0].geojson = Some(registry_breg::contract::GeoJsonSource {
        geometry_field: "location".to_owned(),
    });
    let conflicting = parse_module_json(
        br#"{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"maps","version":"1",
          "extendRecordTypes":[{"recordType":"site","geojson":{"geometryField":"alternate"}}]
        }"#,
    )
    .expect("conflicting module parses");
    let failure = compile_project(
        &project_with_geojson,
        &[conflicting],
        CompileProfile::Authoring,
    )
    .expect_err("conflicting GeoJSON geometry binding is refused");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.extension.geojson-conflict")
        .expect("conflict diagnostic is reported");
    assert_eq!(
        diagnostic.path,
        "recordTypes[id=site].geojson.geometryField"
    );
}

#[test]
fn closed_constraint_grammar_compiles_typed_checks_and_refuses_expression_escape_hatches() {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"constraint-matrix","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[
            {"id":"parent","primaryDataset":"test-dataset","route":"parents","mutationMode":"create-only"},
            {
              "id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"create-only",
              "fields":[
                {"id":"jurisdiction","type":"string","maximumLength":32,"required":true,"classification":"internal"},
                {"id":"code","type":"string","maximumLength":32,"required":true,"classification":"internal"},
                {"id":"revoked-at","type":"timestamp","classification":"internal"},
                {"id":"status","type":"vocabulary-code","vocabulary":"status","required":true,"classification":"internal"},
                {"id":"count","type":"int64","required":true,"classification":"internal"},
                {"id":"capacity","type":"int64","required":true,"classification":"internal"},
                {"id":"floor","type":"int64","required":true,"classification":"internal"},
                {"id":"ceiling","type":"int64","required":true,"classification":"internal"},
                {"id":"starts-on","type":"date","required":true,"classification":"internal"},
                {"id":"ends-on","type":"date","required":true,"classification":"internal"},
                {"id":"observed-at","type":"timestamp","required":true,"classification":"internal"},
                {"id":"expires-at","type":"timestamp","required":true,"classification":"internal"},
                {"id":"quantity","type":"int64","required":true,"classification":"internal"},
                {"id":"amount","type":"decimal","precision":8,"scale":2,"minimum":"-100.00","maximum":"100.00","classification":"internal"},
                {"id":"parent","type":"reference","target":"parent","onDelete":"restrict","required":true,"classification":"internal"},
                {"id":"alternate-parent","type":"reference","target":"parent","onDelete":"restrict","classification":"internal"},
                {"id":"scope","type":"string","maximumLength":32,"required":true,"classification":"internal"},
                {"id":"valid-from","type":"timestamp","validTimeRole":"valid-from","required":true,"classification":"internal"},
                {"id":"valid-to","type":"timestamp","validTimeRole":"valid-to","classification":"internal"}
              ],
              "temporal":{"startField":"valid-from","endField":"valid-to"},
              "constraints":[
                {"id":"composite-key","type":"unique","fields":["jurisdiction","code"]},
                {"id":"active-code","type":"unique","fields":["code"],"when":[
                  {"type":"field-equals","field":"status","value":"active"},
                  {"type":"field-is-null","field":"revoked-at"},
                  {"type":"active-lifecycle"}
                ]},
                {"id":"int-less","type":"compare","left":"count","operator":"less-than","right":"capacity"},
                {"id":"date-less-or-equal","type":"compare","left":"starts-on","operator":"less-than-or-equal","right":"ends-on"},
                {"id":"timestamp-greater","type":"compare","left":"expires-at","operator":"greater-than","right":"observed-at"},
                {"id":"int-greater-or-equal","type":"compare","left":"ceiling","operator":"greater-than-or-equal","right":"floor"},
                {"id":"quantity-range","type":"int-range","field":"quantity","minimum":0,"maximum":100},
                {"id":"status-membership","type":"vocabulary","field":"status","values":["active","paused"]},
                {"id":"scope-time","type":"temporal-non-overlap","scopeFields":["scope"],"startField":"valid-from","endField":"valid-to"}
              ]
            }
          ],
          "vocabularies":[{"id":"status","values":["active","paused","closed"]}]
        }"#,
    )
    .expect("the closed typed constraint matrix parses");
    let compiled = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("the closed typed constraint matrix compiles");
    let record = &compiled.entities()["record"];

    let kinds = record
        .constraints
        .values()
        .map(|constraint| match constraint {
            ConstraintSource::Unique { when: None, .. } => "composite-unique",
            ConstraintSource::Unique { when: Some(_), .. } => "partial-unique",
            ConstraintSource::Compare { .. } => "compare",
            ConstraintSource::IntRange { .. } => "int-range",
            ConstraintSource::Vocabulary { .. } => "vocabulary",
            ConstraintSource::TemporalNonOverlap { .. } => "temporal-non-overlap",
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        kinds,
        [
            "compare",
            "composite-unique",
            "int-range",
            "partial-unique",
            "temporal-non-overlap",
            "vocabulary",
        ]
        .into_iter()
        .collect()
    );
    assert!(matches!(
        &record.constraints["composite-key"],
        ConstraintSource::Unique { fields, when: None, .. }
            if fields == &["jurisdiction".to_owned(), "code".to_owned()]
    ));
    assert!(matches!(
        &record.constraints["active-code"],
        ConstraintSource::Unique { fields, when: Some(when), .. }
            if fields == &["code".to_owned()] && when.len() == 3
    ));

    let comparison_operators = record
        .constraints
        .values()
        .filter_map(|constraint| match constraint {
            ConstraintSource::Compare { operator, .. } => Some(match operator {
                ComparisonOperator::LessThan => "less-than",
                ComparisonOperator::LessThanOrEqual => "less-than-or-equal",
                ComparisonOperator::GreaterThan => "greater-than",
                ComparisonOperator::GreaterThanOrEqual => "greater-than-or-equal",
            }),
            _ => None,
        })
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        comparison_operators,
        [
            "greater-than",
            "greater-than-or-equal",
            "less-than",
            "less-than-or-equal",
        ]
        .into_iter()
        .collect()
    );

    for (field, required) in [("parent", true), ("alternate-parent", false)] {
        let compiled_field = &record.fields[field];
        assert_eq!(compiled_field.required, required);
        assert!(matches!(
            &compiled_field.field_type,
            FieldTypeSource::Reference {
                target,
                on_delete: ReferenceDelete::Restrict,
            } if target == "parent"
        ));
        let reference = compiled
            .ddl()
            .statements
            .iter()
            .find(|statement| statement.id == format!("entity.record.field.{field}.reference"))
            .expect("each reference has compiler-owned DDL");
        assert_eq!(reference.kind, DdlStatementKind::Reference);
        assert!(reference.sql.ends_with("ON DELETE RESTRICT"));
    }

    let table = compiled
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.id == "entity.record.table")
        .expect("record table DDL exists");
    let optional_reference = &record.fields["alternate-parent"].physical_name;
    assert!(table
        .sql
        .contains(&format!("\"{optional_reference}\" uuid")));
    assert!(!table
        .sql
        .contains(&format!("\"{optional_reference}\" uuid NOT NULL")));
    let amount = &record.fields["amount"].physical_name;
    assert!(table.sql.contains(&format!(
        "\"{amount}\" numeric(8,2) CHECK (\"{amount}\" >= -100.00 AND \"{amount}\" <= 100.00)"
    )));

    let statement = |id: &str| {
        compiled
            .ddl()
            .statements
            .iter()
            .find(|statement| statement.id == format!("entity.record.constraint.{id}"))
            .unwrap_or_else(|| panic!("constraint DDL exists for {id}"))
    };
    assert!(statement("composite-key").sql.contains(" UNIQUE ("));
    assert!(statement("active-code")
        .sql
        .starts_with("CREATE UNIQUE INDEX "));
    for id in [
        "int-less",
        "date-less-or-equal",
        "timestamp-greater",
        "int-greater-or-equal",
        "quantity-range",
        "status-membership",
    ] {
        assert!(statement(id).sql.contains(" CHECK ("));
    }
    assert!(statement("quantity-range").sql.contains(" >= 0 AND "));
    assert!(statement("quantity-range").sql.contains(" <= 100"));
    assert!(statement("status-membership")
        .sql
        .contains(" IN ('active', 'paused')"));
    assert!(statement("scope-time").sql.contains("EXCLUDE USING gist"));
    assert!(statement("scope-time").sql.contains("tstzrange"));
    assert!(compiled.ddl().statements.iter().any(|statement| {
        statement.id == "entity.record.constraint.temporal-order"
            && statement.sql.contains(" IS NULL OR ")
            && statement.sql.contains(" < ")
    }));

    for (constraint, canary) in [
        (
            r#"{"kind":"check","expression":"sql-expression-canary"}"#,
            "sql-expression-canary",
        ),
        (
            r#"{"type":"compare","left":"left","operator":"less-than","right":"right","sql":"sql-fragment-canary"}"#,
            "sql-fragment-canary",
        ),
        (
            r#"{"type":"int-range","field":"left","minimum":0,"expression":"general-expression-canary"}"#,
            "general-expression-canary",
        ),
    ] {
        let source = format!(
            r#"{{"datasets":[{{"id": "test-dataset"}}],
              "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
              "kind":"BRegProject",
              "project":{{"id":"constraint-matrix","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
              "recordTypes":[{{
                "id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"create-only",
                "fields":[
                  {{"id":"left","type":"int64","classification":"internal"}},
                  {{"id":"right","type":"int64","classification":"internal"}}
                ],
                "constraints":[{constraint}]
              }}]
            }}"#
        );
        let failure = parse_project_json(source.as_bytes())
            .expect_err("SQL and general expression forms fail strict parsing");
        assert_eq!(
            failure.diagnostics()[0].code,
            if constraint.contains("\"kind\"") {
                "config.missing-key"
            } else {
                "config.unknown-key"
            }
        );
        let rendered = format!(
            "{failure:?}\n{failure}\n{}",
            serde_json::to_string(&failure).expect("diagnostic serializes")
        );
        assert!(!rendered.contains(canary));
    }

    let cascade = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"constraint-matrix","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"create-only",
            "fields":[{"id":"cascade-reference-canary","type":"reference","target":"record","onDelete":"cascade","classification":"internal"}]
          }]
        }"#,
    )
    .expect_err("reference deletion behavior is closed to restrict");
    assert_eq!(cascade.diagnostics()[0].code, "config.unknown-variant");
    let rendered = format!(
        "{cascade:?}\n{cascade}\n{}",
        serde_json::to_string(&cascade).expect("diagnostic serializes")
    );
    assert!(!rendered.contains("cascade-reference-canary"));
}

#[test]
fn partial_unique_when_predicates_are_strictly_tagged_and_closed() {
    let unknown_member = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"partial-unique","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable",
            "fields":[
              {"id":"code","type":"string","maximumLength":32,"required":true,"classification":"internal"},
              {"id":"status","type":"vocabulary-code","vocabulary":"status","required":true,"classification":"internal"}
            ],
            "constraints":[{
              "type":"unique","fields":["code"],
              "when":[{"type":"field-equals","field":"status","value":"active","sql":"record_lifecycle = 'active'"}]
            }]
          }],
          "vocabularies":[{"id":"status","values":["active","closed"]}]
        }"#,
    )
    .expect_err("predicate members are closed");
    assert_eq!(unknown_member.diagnostics()[0].code, "config.unknown-key");
    assert!(!serde_json::to_string(&unknown_member)
        .expect("diagnostic serializes")
        .contains("record_lifecycle"));

    let arbitrary_lifecycle = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"partial-unique","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable",
            "fields":[{"id":"code","type":"string","maximumLength":32,"required":true,"classification":"internal"}],
            "constraints":[{
              "type":"unique","fields":["code"],
              "when":[{"type":"active-lifecycle","value":"tombstoned"}]
            }]
          }]
        }"#,
    )
    .expect_err("lifecycle predicates have no caller-provided value");
    assert_eq!(
        arbitrary_lifecycle.diagnostics()[0].code,
        "config.unknown-key"
    );
}

#[test]
fn partial_unique_typed_literals_are_canonical_for_each_supported_field_type() {
    let source = br#"{"datasets":[{"id": "test-dataset"}],
      "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
      "kind":"BRegProject",
      "project":{"id":"partial-unique","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
      "recordTypes":[{
        "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable",
        "fields":[
          {"id":"code","type":"string","maximumLength":32,"required":true,"classification":"internal"},
          {"id":"flag","type":"boolean","classification":"internal"},
          {"id":"count","type":"int64","classification":"internal"},
          {"id":"amount","type":"decimal","precision":6,"scale":2,"minimum":"0.00","maximum":"9999.99","classification":"internal"},
          {"id":"day","type":"date","classification":"internal"},
          {"id":"seen-at","type":"timestamp","classification":"internal"},
          {"id":"owner","type":"uuid","classification":"internal"},
          {"id":"status","type":"vocabulary-code","vocabulary":"status","classification":"internal"}
        ],
        "constraints":[{
          "type":"unique","fields":["code"],
          "when":[
            {"type":"field-equals","field":"flag","value":true},
            {"type":"field-equals","field":"count","value":42},
            {"type":"field-equals","field":"amount","value":"12.30"},
            {"type":"field-equals","field":"day","value":"2026-08-29"},
            {"type":"field-equals","field":"seen-at","value":"2026-08-29T10:20:30Z"},
            {"type":"field-equals","field":"owner","value":"123e4567-e89b-12d3-a456-426614174000"},
            {"type":"field-equals","field":"status","value":"active"}
          ]
        }]
      }],
      "vocabularies":[{"id":"status","values":["active","closed"]}]
    }"#;
    let compiled = compile_json(source).expect("canonical literals compile");
    let ddl = compiled.ddl().script();
    assert!(ddl.contains("'true'::boolean"));
    assert!(ddl.contains("'42'::bigint"));
    assert!(ddl.contains("'12.30'::numeric(6,2)"));
    assert!(ddl.contains("'2026-08-29'::date"));
    assert!(ddl.contains("'2026-08-29T10:20:30Z'::timestamptz"));
    assert!(ddl.contains("'123e4567-e89b-12d3-a456-426614174000'::uuid"));
}

#[test]
fn partial_unique_rejects_invalid_literals_and_json_predicate_fields() {
    let cases = [
        (
            r#"{"id":"amount","type":"decimal","precision":6,"scale":2,"classification":"internal"}"#,
            r#"{"type":"field-equals","field":"amount","value":"1.2"}"#,
            "breg.constraint.unique-when-literal-invalid",
        ),
        (
            r#"{"id":"seen-at","type":"timestamp","classification":"internal"}"#,
            r#"{"type":"field-equals","field":"seen-at","value":"2026-08-29T10:20:30+00:00"}"#,
            "breg.constraint.unique-when-literal-invalid",
        ),
        (
            r#"{"id":"owner","type":"uuid","classification":"internal"}"#,
            r#"{"type":"field-equals","field":"owner","value":"123E4567-E89B-12D3-A456-426614174000"}"#,
            "breg.constraint.unique-when-literal-invalid",
        ),
        (
            r#"{"id":"shape","type":"crs84-point","precision":4,"classification":"internal"}"#,
            r#"{"type":"field-is-not-null","field":"shape"}"#,
            "breg.constraint.unique-when-field-unsupported",
        ),
        (
            r#"{"id":"payload","type":"structured","maximumBytes":256,"classification":"internal","schema":{"type":"object","additionalProperties":false}}"#,
            r#"{"type":"field-equals","field":"payload","value":{}}"#,
            "breg.constraint.unique-when-field-unsupported",
        ),
    ];

    for (field, predicate, code) in cases {
        let source = format!(
            r#"{{"datasets":[{{"id": "test-dataset"}}],
              "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
              "kind":"BRegProject",
              "project":{{"id":"partial-unique","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
              "recordTypes":[{{
                "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable",
                "fields":[
                  {{"id":"code","type":"string","maximumLength":32,"required":true,"classification":"internal"}},
                  {field}
                ],
                "constraints":[{{"type":"unique","fields":["code"],"when":[{predicate}]}}]
              }}]
            }}"#
        );
        let failure = compile_json(source.as_bytes()).expect_err("invalid partial predicate fails");
        assert!(failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == code));
    }
}

#[test]
fn partial_unique_rejects_empty_unknown_duplicate_and_contradictory_when_predicates() {
    let cases = [
        ("[]", "breg.constraint.unique-when-empty"),
        (
            r#"[{"type":"active-lifecycle"},{"type":"active-lifecycle"}]"#,
            "breg.constraint.unique-when-duplicate",
        ),
        (
            r#"[{"type":"field-is-null","field":"optional"},{"type":"field-is-not-null","field":"optional"}]"#,
            "breg.constraint.unique-when-contradiction",
        ),
        (
            r#"[{"type":"field-equals","field":"optional","value":"one"},{"type":"field-equals","field":"optional","value":"two"}]"#,
            "breg.constraint.unique-when-contradiction",
        ),
        (
            r#"[{"type":"field-is-not-null","field":"required"}]"#,
            "breg.constraint.unique-when-null-invalid",
        ),
        (
            r#"[{"type":"field-equals","field":"missing","value":"one"}]"#,
            "breg.constraint.unique-when-field-unknown",
        ),
    ];

    for (when, code) in cases {
        let source = format!(
            r#"{{"datasets":[{{"id": "test-dataset"}}],
              "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
              "kind":"BRegProject",
              "project":{{"id":"partial-unique","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
              "recordTypes":[{{
                "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable",
                "fields":[
                  {{"id":"code","type":"string","maximumLength":32,"required":true,"classification":"internal"}},
                  {{"id":"required","type":"string","maximumLength":32,"required":true,"classification":"internal"}},
                  {{"id":"optional","type":"string","maximumLength":32,"classification":"internal"}}
                ],
                "constraints":[{{"type":"unique","fields":["code"],"when":{when}}}]
              }}]
            }}"#
        );
        let failure = compile_json(source.as_bytes()).expect_err("invalid when fails");
        assert!(failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == code));
    }
}

#[test]
fn partial_unique_ddl_is_quoted_and_deterministic_across_predicate_order() {
    let left = br#"{"datasets":[{"id": "test-dataset"}],
      "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
      "kind":"BRegProject",
      "project":{"id":"partial-unique","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
      "recordTypes":[{
        "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable",
        "fields":[
          {"id":"code","type":"string","maximumLength":32,"required":true,"classification":"internal"},
          {"id":"ended-on","type":"date","classification":"internal"},
          {"id":"marker","type":"string","maximumLength":96,"classification":"internal"}
        ],
        "constraints":[{
          "type":"unique","fields":["code"],
          "when":[
            {"type":"active-lifecycle"},
            {"type":"field-equals","field":"marker","value":"O'Hare'); DROP TABLE registry_data.x; --"},
            {"type":"field-is-null","field":"ended-on"}
          ]
        }]
      }]
    }"#;
    let right = br#"{"datasets":[{"id": "test-dataset"}],
      "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
      "kind":"BRegProject",
      "project":{"id":"partial-unique","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
      "recordTypes":[{
        "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable",
        "fields":[
          {"id":"code","type":"string","maximumLength":32,"required":true,"classification":"internal"},
          {"id":"ended-on","type":"date","classification":"internal"},
          {"id":"marker","type":"string","maximumLength":96,"classification":"internal"}
        ],
        "constraints":[{
          "type":"unique","fields":["code"],
          "when":[
            {"type":"field-is-null","field":"ended-on"},
            {"type":"field-equals","field":"marker","value":"O'Hare'); DROP TABLE registry_data.x; --"},
            {"type":"active-lifecycle"}
          ]
        }]
      }]
    }"#;

    let left = compile_json(left).expect("left order compiles");
    let right = compile_json(right).expect("right order compiles");
    assert_eq!(
        left.ddl(),
        right.ddl(),
        "equivalent predicate order keeps DDL"
    );
    assert_eq!(
        left.entities(),
        right.entities(),
        "equivalent predicate order keeps compiled Record semantics"
    );
    assert_eq!(
        left.revision(),
        right.revision(),
        "equivalent predicate order keeps the governed registry revision"
    );
    assert_eq!(left, right);
    let statement = left
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.kind == DdlStatementKind::Index)
        .expect("partial unique renders as an index");
    assert!(statement.sql.starts_with("CREATE UNIQUE INDEX "));
    assert!(statement.sql.contains(" WHERE "));
    assert!(statement
        .sql
        .contains("'O''Hare''); DROP TABLE registry_data.x; --'"));
    assert!(statement.sql.contains(" IS NULL"));
    assert!(statement.sql.ends_with("record_lifecycle = 'active'"));
}

#[test]
fn equivalent_partial_unique_extension_constraints_merge_deterministically() {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
          "project":{"id":"partial-unique","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "modules":[{"id":"a","version":"1"},{"id":"b","version":"1"}],
          "recordTypes":[{"id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable","fields":[
            {"id":"code","type":"string","maximumLength":32,"required":true,"classification":"internal"},
            {"id":"ended-on","type":"date","classification":"internal"}
          ]}]
        }"#,
    )
    .expect("project parses");
    let a = parse_module_json(
        br#"{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"a","version":"1","extendRecordTypes":[{"recordType":"entry","constraints":[{
          "type":"unique","fields":["code"],"when":[{"type":"active-lifecycle"},{"type":"field-is-null","field":"ended-on"}]
        }]}]}"#,
    )
    .expect("module parses");
    let b = parse_module_json(
        br#"{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"b","version":"1","extendRecordTypes":[{"recordType":"entry","constraints":[{
          "type":"unique","fields":["code"],"when":[{"type":"field-is-null","field":"ended-on"},{"type":"active-lifecycle"}]
        }]}]}"#,
    )
    .expect("module parses");

    for modules in [vec![a.clone(), b.clone()], vec![b, a]] {
        let failure = compile_project(&project, &modules, CompileProfile::Authoring)
            .expect_err("equivalent partial unique extensions are duplicates");
        assert!(failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "breg.extension.constraint-duplicate"));
    }
}

#[test]
fn authenticated_profiles_may_process_governed_non_public_constraint_fields() {
    let source = br#"{"datasets":[{"id": "test-dataset"}],
      "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
      "kind":"BRegProject",
      "project":{"id":"constraint-processing","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
      "recordTypes":[{
        "id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"mutable","classification":"public",
        "fields":[
          {"id":"label","type":"string","maximumLength":32,"required":true,"classification":"public"},
          {"id":"unique-field","type":"string","maximumLength":32,"required":true,"classification":"public"},
          {"id":"partial-field","type":"string","maximumLength":32,"required":true,"classification":"public"},
          {"id":"predicate-field","type":"string","maximumLength":32,"classification":"public"},
          {"id":"compare-left","type":"int64","required":true,"classification":"public"},
          {"id":"compare-right","type":"int64","required":true,"classification":"public"},
          {"id":"range-field","type":"int64","classification":"public"},
          {"id":"vocabulary-field","type":"vocabulary-code","vocabulary":"status","classification":"public"},
          {"id":"temporal-start","type":"date","required":true,"classification":"public"},
          {"id":"temporal-end","type":"date","classification":"public"},
          {"id":"temporal-scope","type":"string","maximumLength":32,"required":true,"classification":"public"}
        ],
        "temporal":{"startField":"temporal-start","endField":"temporal-end"},
        "constraints":[
          {"type":"unique","fields":["unique-field"]},
          {"type":"unique","fields":["partial-field"],"when":[{"type":"field-is-not-null","field":"predicate-field"}]},
          {"type":"compare","left":"compare-left","operator":"less-than","right":"compare-right"},
          {"type":"int-range","field":"range-field","minimum":0,"maximum":10},
          {"type":"vocabulary","field":"vocabulary-field","values":["active"]},
          {"type":"temporal-non-overlap","scopeFields":["temporal-scope"],"startField":"temporal-start","endField":"temporal-end"}
        ]
      }],
      "accessProfiles":[{
        "id":"reader","principalClaim":"principal","requiredScopes":["records.read"],"default":true,"permissions":{"records":[{
          "recordType":"record","operations":["get"],"readableFields":["label"],
          "rowBoundaries": "unrestricted"
        }]}
      }],
      "vocabularies":[{"id":"status","values":["active","inactive"]}]
    }"#;
    let mut project =
        parse_project_json(source).expect("closed constraint processing fixture parses");
    for field_id in [
        "unique-field",
        "partial-field",
        "predicate-field",
        "compare-left",
        "compare-right",
        "range-field",
        "vocabulary-field",
        "temporal-start",
        "temporal-end",
        "temporal-scope",
    ] {
        project.entities[0]
            .fields
            .iter_mut()
            .find(|field| field.id == field_id)
            .expect("constraint field exists")
            .classification = Classification::Restricted;
    }
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("authenticated entities may process governed non-public constraint fields");
}

#[test]
fn compiled_partial_unique_constraint_keeps_closed_predicates_in_the_model() {
    let source = br#"{"datasets":[{"id": "test-dataset"}],
      "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
      "kind":"BRegProject",
      "project":{"id":"partial-unique","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
      "recordTypes":[{
        "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable","classification":"public",
        "fields":[
          {"id":"code","type":"string","maximumLength":32,"required":true,"classification":"public"},
          {"id":"status","type":"vocabulary-code","vocabulary":"status","classification":"public"}
        ],
        "constraints":[{
          "type":"unique","fields":["code"],
          "when":[{"type":"active-lifecycle"},{"type":"field-equals","field":"status","value":"active"}]
        }]
      }],
      "accessProfiles":[{
        "id":"reader","principalClaim":"principal","requiredScopes":["entries.read"],"default":true,"permissions":{"records":[{
          "recordType":"entry","operations":["get"],"readableFields":["code","status"],"filterableFields":["status"],
          "rowBoundaries": "unrestricted"
        }]}
      }],
      "vocabularies":[{"id":"status","values":["active","closed"]}]
    }"#;

    let compiled = compile_json(source).expect("public partial unique compiles");
    let constraint = compiled
        .entities()
        .get("entry")
        .expect("entity compiled")
        .constraints
        .values()
        .find(|constraint| matches!(constraint, ConstraintSource::Unique { .. }))
        .expect("unique constraint compiled");
    assert!(matches!(
        constraint,
        ConstraintSource::Unique {
            when: Some(when),
            ..
        } if when == &[
            UniqueWhenPredicate::FieldEquals {
                field: "status".to_owned(),
                value: Value::String("active".to_owned()),
            },
            UniqueWhenPredicate::ActiveLifecycle {},
        ]
    ));
}

#[test]
fn create_only_operation_conflict_fails_before_artifact_generation() {
    let mut project = asset_project();
    let profile = project
        .access_profiles
        .first_mut()
        .expect("fixture has an access profile");
    let grant = profile
        .permissions
        .entities
        .iter_mut()
        .find(|grant| grant.entity == "inspection-event")
        .expect("fixture grants the create-only entity");
    grant.operations.insert(Operation::Patch);

    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("create-only patch is refused");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.access-profile.operation-unavailable"));
}

#[test]
fn generated_openapi_routes_and_physical_names_share_one_compiled_inventory() {
    let compiled = compile_project(&asset_project(), &[], CompileProfile::Authoring)
        .expect("asset fixture compiles");
    let openapi = compiled
        .artifacts()
        .get("generated/openapi.json")
        .expect("OpenAPI is generated");
    let value = parse_json_strict(&openapi.bytes).expect("OpenAPI is strict JSON");
    assert_eq!(
        canonicalize_json(&value).expect("OpenAPI canonicalizes"),
        openapi.bytes
    );
    let generated_compiled_operation_ids = value["paths"]
        .as_object()
        .expect("paths is an object")
        .values()
        .flat_map(|entry| entry.as_object().expect("path item is an object").values())
        .filter(|operation| operation.get("x-registry-recordType").is_some())
        .map(|operation| {
            operation["operationId"]
                .as_str()
                .expect("compiled OpenAPI operation has an identifier")
        })
        .collect::<BTreeSet<_>>();
    let compiled_operation_ids = compiled
        .routes()
        .routes
        .iter()
        .map(|route| route.id.as_str())
        .collect::<BTreeSet<_>>();
    assert_eq!(generated_compiled_operation_ids, compiled_operation_ids);
    let review_completion = &value["paths"]["/v1/review-completions"]["post"];
    assert_eq!(review_completion["operationId"], "receiveReviewCompletion");
    assert!(review_completion.get("x-registry-recordType").is_none());
    assert_eq!(
        value["components"]["securitySchemes"]["bearerAuth"],
        json!({"type": "http", "scheme": "bearer", "bearerFormat": "JWT"})
    );
    assert_eq!(
        value["components"]["schemas"]["Problem"]["properties"]["code"]["enum"],
        json!([
            "action.evidence_failed",
            "action.guard_failed",
            "action.handler_failed",
            "action.refused",
            "authentication.refused",
            "idempotency.conflict",
            "idempotency.expired",
            "ingestion.chunk_mismatch",
            "ingestion.profile_mismatch",
            "ingestion.receipt_erased",
            "ingestion.run_blocked",
            "ingestion.run_not_open",
            "lookup.unresolved",
            "mutation.conflict",
            "precondition.failed",
            "precondition.required",
            "proposal.rejected",
            "proposal.review_result_mismatch",
            "proposal.submission_expired",
            "query.cursor_invalid",
            "query.invalid",
            "request.invalid",
            "request.timeout",
            "resource.not_found",
            "runtime.field_encryption.unavailable",
            "service.unavailable",
            "source.unavailable",
            "statistical_dataset.domain_violation",
            "statistical_dataset.release_refused",
            "statistical_dataset.version_conflict",
            "statistical_dataset.version_withdrawn",
            "unsupported.media_type"
        ])
    );
    assert_eq!(
        value["components"]["schemas"]["Problem"]["required"],
        json!(["type", "title", "status", "detail", "code", "traceId"])
    );
    assert_eq!(
        value["components"]["schemas"]["Problem"]["properties"]["traceId"]["pattern"],
        "^[0-9a-f]{32}$"
    );

    let list = &value["paths"]["/v1/records/assets"]["get"];
    assert_eq!(list["security"], json!([{"bearerAuth": []}]));
    assert!(list["responses"]["200"]["headers"]
        .get("traceparent")
        .is_some());
    assert!(
        list["responses"]["200"]["content"]["application/json"]["schema"]["required"]
            .as_array()
            .expect("list response required members")
            .contains(&json!("pageInfo"))
    );
    assert!(
        list["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
            .get("count")
            .is_some()
    );
    assert!(
        list["responses"]["200"]["content"]["application/json"]["schema"]["properties"]
            .get("totalCount")
            .is_none()
    );
    assert_eq!(
        list["x-registry-queryProfiles"]["asset-operator"]["selectableProperties"],
        json!(["assetClass", "assetCode", "label"])
    );
    assert_eq!(
        list["x-registry-queryProfiles"]["site-planner"]["selectableProperties"],
        json!(["assetCode", "label"])
    );
    assert!(list["x-registry-queryProfiles"]["asset-operator"]["filterableProperties"].is_array());

    let detail = &value["paths"]["/v1/records/assets/{record_id}"]["get"];
    assert_eq!(
        query_parameter_names(&detail["parameters"]),
        [
            "$select",
            "Accept",
            "accessProfile",
            "record_id",
            "traceparent"
        ]
    );
    assert!(detail["responses"]["200"]["headers"].get("ETag").is_some());
    assert!(detail["responses"]["200"]["headers"]
        .get("traceparent")
        .is_some());
    assert!(detail["responses"]["504"]["headers"]
        .get("traceparent")
        .is_some());
    assert_eq!(
        detail["responses"]["504"]["content"]["application/problem+json"]["examples"]
            ["request.timeout"]["value"]["traceId"],
        "11111111111111111111111111111111"
    );
    assert_eq!(
        detail["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["data"],
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["recordIdentifier", "revisionIdentifier", "domainData"],
            "properties": {
                "recordIdentifier": {"type": "string", "format": "uuid"},
                "revisionIdentifier": {"type": "string", "pattern": "^[1-9][0-9]*$"},
                "domainData": {"type":"object","additionalProperties":false,"properties":value["components"]["schemas"]["asset-item"]["properties"].clone()}
            }
        })
    );

    let create = &value["paths"]["/v1/records/assets"]["post"];
    assert_eq!(
        query_parameter_names(&create["parameters"]),
        ["Accept", "Idempotency-Key", "accessProfile", "traceparent"]
    );
    assert!(create["responses"]["201"]["headers"].get("ETag").is_some());
    assert!(create["responses"]["201"]["headers"]
        .get("Location")
        .is_some());
    assert!(create["responses"]["201"]["headers"]
        .get("traceparent")
        .is_some());
    assert_eq!(
        create["requestBody"]["content"]["application/json"]["schema"]["properties"]["data"],
        json!({"$ref": "#/components/schemas/asset-item-create-input"})
    );

    let patch = &value["paths"]["/v1/records/assets/{record_id}"]["patch"];
    assert_eq!(
        query_parameter_names(&patch["parameters"]),
        [
            "Accept",
            "Idempotency-Key",
            "If-Match",
            "accessProfile",
            "record_id",
            "traceparent"
        ]
    );
    assert!(patch["requestBody"]["content"]
        .get("application/json-patch+json")
        .is_some());
    assert!(patch["responses"]["428"]["headers"]
        .get("traceparent")
        .is_some());
    assert!(
        patch["responses"]["428"]["content"]["application/problem+json"]["schema"]
            .get("$ref")
            .is_some()
    );

    for names in compiled.physical_names().entities.values() {
        let all = std::iter::once(&names.table)
            .chain(names.fields.values())
            .chain(names.constraints.values())
            .chain(names.indexes.values())
            .chain(names.policies.values());
        for name in all {
            assert!(name.len() <= 63);
            assert!(name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'));
        }
    }
}

#[test]
fn generated_openapi_separates_security_and_mutation_input_from_read_schema() {
    let compiled = compile_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"business-contract","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"business-record","primaryDataset":"test-dataset","route":"business-records","mutationMode":"mutable","classification":"public",
            "fields":[
              {"id":"code","type":"string","required":true,"maximumLength":32,"classification":"public"},
              {"id":"business-note","apiName":"businessNote","type":"string","maximumLength":80,"classification":"public"},
              {"id":"draft-note","apiName":"draftNote","type":"string","maximumLength":80,"classification":"internal"}
            ]
          }],
          "accessProfiles":[{
            "id":"public",
            "default":true,
            "principalClaim":"registry_principal",
            "requiredScopes":["records.read"],
            "permissions":{"records":[{
              "recordType":"business-record",
              "operations":["get","list"],
              "readableFields":["code","business-note"],
              "rowBoundaries": "unrestricted"
            }]}
          },{
            "id":"business",
            "principalClaim":"registry_principal",
            "requiredScopes":"unrestricted",
            "requiredPurposes":["business"],
            "permissions":{"records":[{
              "recordType":"business-record",
              "operations":["create","get"],
              "readableFields":["code","business-note"],
              "writableFields":["code","draft-note"],
              "rowBoundaries": "unrestricted"
            }]}
          }]
        }"#,
    )
    .expect("business contract compiles");
    let openapi = compiled
        .artifacts()
        .get("generated/openapi.json")
        .expect("OpenAPI is generated");
    let openapi = parse_json_strict(&openapi.bytes).expect("OpenAPI is strict JSON");

    assert_eq!(
        openapi["paths"]["/v1/records/business-records/{record_id}"]["get"]["security"],
        json!([{"bearerAuth": []}])
    );
    assert_eq!(
        openapi["paths"]["/v1/records/business-records"]["post"]["security"],
        json!([{"bearerAuth": []}])
    );
    assert_eq!(
        openapi["paths"]["/v1/records/business-records"]["post"]["requestBody"]["content"]
            ["application/json"]["schema"]["properties"]["data"],
        json!({"$ref": "#/components/schemas/business-record-create-input"})
    );
    assert_eq!(
        openapi["paths"]["/v1/records/business-records"]["post"]["responses"]["201"]["content"]
            ["application/json"]["schema"]["properties"]["data"],
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["recordIdentifier", "revisionIdentifier", "domainData", "snapshot"],
            "properties": {
                "recordIdentifier": {"type": "string", "format": "uuid"},
                "revisionIdentifier": {"type": "string", "pattern": "^[1-9][0-9]*$"},
                "domainData": {"$ref": "#/components/schemas/business-record"},
                "snapshot": {"type": "string", "maxLength": 4096}
            }
        })
    );
    assert_eq!(
        openapi["components"]["schemas"]["business-record-create-input"]["properties"],
        json!({
            "code": {"type": "string", "minLength": 0, "maxLength": 32},
            "draftNote": {"anyOf": [{"type": "string", "minLength": 0, "maxLength": 80}, {"type": "null"}]}
        })
    );
    assert_eq!(
        openapi["components"]["schemas"]["business-record-create-input"]["required"],
        json!(["code"])
    );
    assert!(
        openapi["components"]["schemas"]["business-record"]["properties"]
            .get("businessNote")
            .is_some()
    );
    assert_ne!(
        openapi["components"]["schemas"]["business-record-create-input"]["properties"],
        openapi["components"]["schemas"]["business-record"]["properties"]
    );
}

#[test]
fn entity_schema_uses_compiled_api_names_and_preserves_field_contracts() {
    let compiled = compile_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"logical-schema","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"household","primaryDataset":"test-dataset","route":"households","mutationMode":"mutable",
            "fields":[
              {"id":"household-code","type":"string","required":true,"maximumLength":64,"classification":"restricted"},
              {"id":"household-kind-code","apiName":"householdKind","type":"vocabulary-code","vocabulary":"household-kind","required":true,"classification":"restricted"},
              {"id":"case-note","apiName":"caseNoteText","type":"text","maximumLength":200,"classification":"restricted"}
            ]
          }],
          "vocabularies":[{"id":"household-kind","values":["single","extended"]}]
        }"#,
    )
    .expect("logical field names compile");
    let artifact = compiled
        .artifacts()
        .get("generated/schemas/household.schema.json")
        .expect("entity schema is generated");
    let schema: Value = parse_json_strict(&artifact.bytes).expect("entity schema is strict JSON");

    assert_eq!(
        schema["properties"],
        json!({
            "caseNoteText": {"anyOf": [{"type": "string", "maxLength": 200}, {"type": "null"}]},
            "householdCode": {"type": "string", "minLength": 0, "maxLength": 64},
            "householdKind": {
                "type": "string",
                "enum": ["single", "extended"],
                "x-registry-vocabulary": "household-kind"
            }
        })
    );
    assert_eq!(
        schema["required"],
        json!(["householdCode", "householdKind"])
    );
    for internal_id in ["household-code", "household-kind-code", "case-note"] {
        assert!(schema["properties"].get(internal_id).is_none());
    }
}

#[test]
fn compiled_metadata_inventory_is_bijective_canonical_schema_bound_and_deterministic() {
    let first = compile_project(&asset_project(), &[], CompileProfile::Authoring)
        .expect("asset fixture compiles");
    let second = compile_project(&asset_project(), &[], CompileProfile::Authoring)
        .expect("asset fixture compiles twice");

    assert_eq!(first.metadata(), second.metadata());
    let expected_route_profiles = first
        .routes()
        .routes
        .iter()
        .flat_map(|route| {
            route
                .access_profiles
                .iter()
                .map(move |profile| (route.id.clone(), profile.clone()))
        })
        .collect::<BTreeSet<_>>();
    let actual_route_profiles = first
        .metadata()
        .entities
        .iter()
        .flat_map(|entity| {
            entity
                .entries
                .iter()
                .map(|entry| (entry.route_id.clone(), entry.access_profile.clone()))
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_route_profiles, expected_route_profiles,
        "metadata entries must be in bijection with compiled route/profile pairs"
    );

    for metadata_entity in &first.metadata().entities {
        let entity = first
            .entities()
            .get(&metadata_entity.id)
            .expect("metadata entity refers to a compiled entity");
        assert_eq!(metadata_entity.route, entity.route);
        assert_eq!(
            metadata_entity.schema_path,
            format!("/v1/schemas/{}", metadata_entity.id)
        );
        assert!(first
            .artifacts()
            .get(&format!(
                "generated/schemas/{}.schema.json",
                metadata_entity.id
            ))
            .is_some());
        for entry in &metadata_entity.entries {
            let route = first
                .routes()
                .routes
                .iter()
                .find(|route| route.id == entry.route_id)
                .expect("metadata route id refers to a compiled route");
            assert_eq!(route.entity_id, metadata_entity.id);
            assert_eq!(route.operation, entry.operation);
            assert!(route.access_profiles.contains(&entry.access_profile));
            let profile = entity
                .access_profiles
                .get(&entry.access_profile)
                .expect("metadata access profile refers to a compiled profile");
            assert!(entry.readable_fields.is_subset(&profile.readable_fields));
        }
    }

    for path in [
        "compiled/metadata-inventory.json",
        REGISTRY_METADATA_ARTIFACT_PATH,
    ] {
        let first_artifact = first
            .artifacts()
            .get(path)
            .expect("metadata artifact exists");
        let second_artifact = second
            .artifacts()
            .get(path)
            .expect("metadata artifact exists on recompilation");
        assert_eq!(first_artifact.bytes, second_artifact.bytes);
        let value = parse_json_strict(&first_artifact.bytes).expect("metadata is strict JSON");
        assert_eq!(
            canonicalize_json(&value).expect("metadata canonicalizes"),
            first_artifact.bytes
        );
        assert!(value.get("revision").is_none());
        let parsed: CompiledMetadataInventory =
            serde_json::from_value(value).expect("metadata artifact has the typed schema");
        assert_eq!(&parsed, first.metadata());
    }
}

#[test]
fn compiler_produces_both_revision_routes_when_explicitly_configured() {
    let compiled = compile_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"revision-surface","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"create-only","classification":"internal",
            "fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"}]
          }],
          "accessProfiles":[{
            "id":"auditor","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
              "recordType":"entry","operations":["revisions"],"revisionAccess":true,"readableFields":["code"],
              "rowBoundaries": "unrestricted"
            }]}
          }]
        }"#,
    )
    .expect("explicit authenticated revision access compiles");
    let routes = compiled
        .routes()
        .routes
        .iter()
        .filter(|route| route.operation == Operation::Revisions)
        .collect::<Vec<_>>();
    assert_eq!(routes.len(), 2);
    let list = routes
        .iter()
        .find(|route| route.revision_kind == Some(CompiledRevisionKind::List))
        .expect("revision list route exists");
    assert_eq!(list.id, "records.entry.revisions.list");
    assert_eq!(list.path, "/v1/records/entries/{record_id}/revisions");
    assert_eq!(list.maximum_records, Some(MAX_REVISION_HISTORY_RECORDS));
    let detail = routes
        .iter()
        .find(|route| route.revision_kind == Some(CompiledRevisionKind::Detail))
        .expect("revision detail route exists");
    assert_eq!(detail.id, "records.entry.revisions.detail");
    assert_eq!(
        detail.path,
        "/v1/records/entries/{record_id}/revisions/{revision}"
    );
    assert_eq!(detail.maximum_records, Some(1));

    let openapi = compiled
        .artifacts()
        .get("generated/openapi.json")
        .expect("OpenAPI is generated");
    let openapi = parse_json_strict(&openapi.bytes).expect("OpenAPI is strict JSON");
    assert_eq!(
        openapi["paths"]["/v1/records/entries/{record_id}/revisions"]["get"]["operationId"],
        "records.entry.revisions.list"
    );
    assert_eq!(
        openapi["paths"]["/v1/records/entries/{record_id}/revisions/{revision}"]["get"]
            ["operationId"],
        "records.entry.revisions.detail"
    );
    assert_eq!(
        query_parameter_names(
            &openapi["paths"]["/v1/records/entries/{record_id}/revisions"]["get"]["parameters"]
        ),
        ["Accept", "accessProfile", "record_id", "traceparent"]
    );
    let revision_list_schema = &openapi["paths"]["/v1/records/entries/{record_id}/revisions"]
        ["get"]["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["items"]
        ["items"];
    assert_eq!(
        revision_list_schema["properties"]["mutationKind"]["enum"],
        json!(["create", "patch", "tombstone", "migration"])
    );
    assert!(revision_list_schema["properties"]
        .as_object()
        .expect("revision item properties render")
        .get("changeContext")
        .is_none());
    let revision_detail_schema = &openapi["paths"]
        ["/v1/records/entries/{record_id}/revisions/{revision}"]["get"]["responses"]["200"]
        ["content"]["application/json"]["schema"]["properties"]["data"];
    assert_eq!(
        revision_detail_schema["properties"]["mutationKind"]["enum"],
        json!(["create", "patch", "tombstone", "migration"])
    );
    assert!(revision_detail_schema["properties"]
        .as_object()
        .expect("revision detail properties render")
        .get("changeContext")
        .is_none());
}

#[test]
fn compiler_omits_revision_routes_when_not_configured_or_revision_access_is_false() {
    for (operations, revision_access) in [(r#"["get"]"#, "true"), (r#"["revisions"]"#, "false")] {
        let source = format!(
            r#"{{"datasets":[{{"id": "test-dataset"}}],
              "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
              "kind":"BRegProject",
              "project":{{"id":"revision-surface","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
              "recordTypes":[{{
                "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"create-only","classification":"public",
                "fields":[{{"id":"code","type":"string","maximumLength":32,"classification":"public"}}]
              }}],
              "accessProfiles":[{{
                "id":"reader","default":true,"principalClaim":"principal","requiredScopes":["entries.read"],"permissions":{{"records":[{{
                  "rowBoundaries": "unrestricted", "recordType":"entry","operations":{operations},"revisionAccess":{revision_access},"readableFields":["code"]
                }}]}}
              }}]
            }}"#
        );
        let compiled = compile_json(source.as_bytes()).expect("fixture compiles");
        assert!(compiled
            .routes()
            .routes
            .iter()
            .all(|route| route.operation != Operation::Revisions));
        let openapi = compiled
            .artifacts()
            .get("generated/openapi.json")
            .expect("OpenAPI is generated");
        let openapi = parse_json_strict(&openapi.bytes).expect("OpenAPI is strict JSON");
        assert!(openapi["paths"]
            .as_object()
            .expect("paths object")
            .keys()
            .all(|path| !path.contains("revisions")));
    }
}

#[test]
fn unresolved_reference_is_value_free_and_fails_before_ddl() {
    let mut project = asset_project();
    let field = project
        .entities
        .iter_mut()
        .find(|entity| entity.id == "inspection-event")
        .and_then(|entity| entity.fields.iter_mut().find(|field| field.id == "asset"))
        .expect("reference field exists");
    if let registry_breg::contract::FieldTypeSource::Reference { target, .. } =
        &mut field.field_type
    {
        *target = "classified-target-name".to_owned();
    } else {
        panic!("fixture field is a reference");
    }
    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("unresolved reference fails compilation");
    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.field.reference-target-unknown"));
    assert!(!serde_json::to_string(&failure)
        .expect("diagnostics serialize")
        .contains("classified-target-name"));
}

#[test]
fn additive_module_conflicts_fail_instead_of_using_input_precedence() {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
          "project":{"id":"neutral","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "modules":[{"id":"core","version":"1"},{"id":"a","version":"1"},{"id":"b","version":"1"}],
          "recordTypes":[{"id":"object","primaryDataset":"test-dataset","route":"objects","mutationMode":"mutable","fields":[
            {"id":"code","type":"string","maximumLength":8,"classification":"internal"}
          ]}],
          "accessProfiles":[{"id":"operator","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{"recordType":"object","operations":["get"],"readableFields":["code"], "rowBoundaries": "unrestricted"}]}}]
        }"#,
    )
    .expect("project parses");
    let a = parse_module_json(
        br#"{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"a","version":"1","dependencies":["core"],"extendRecordTypes":[{"recordType":"object","fields":[{"id":"collision","type":"boolean","classification":"internal"}]}]}"#,
    )
    .expect("module parses");
    let b = parse_module_json(
        br#"{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"b","version":"1","dependencies":["core"],"extendRecordTypes":[{"recordType":"object","fields":[{"id":"collision","type":"int64","classification":"internal"}]}]}"#,
    )
    .expect("module parses");
    for modules in [vec![a.clone(), b.clone()], vec![b.clone(), a.clone()]] {
        let failure = compile_project(&project, &modules, CompileProfile::Authoring)
            .expect_err("conflicting additive extensions fail");
        assert!(failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "breg.extension.field-duplicate"));
    }
}

#[test]
fn operation_ids_preserve_distinct_valid_entity_ids_without_collisions() {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
          "project":{"id":"neutral","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[
            {"id":"case-file","primaryDataset":"test-dataset","route":"case-files","mutationMode":"create-only","fields":[
              {"id":"code","type":"string","maximumLength":8,"classification":"internal"}
            ]},
            {"id":"case_file_record","primaryDataset":"test-dataset","route":"case_file_records","mutationMode":"create-only","fields":[
              {"id":"code","type":"string","maximumLength":8,"classification":"internal"}
            ]}
          ],
          "accessProfiles":[{"id":"reader","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{
            "records":[
              {"recordType":"case-file","operations":["get"],"readableFields":["code"], "rowBoundaries": "unrestricted"},
              {"recordType":"case_file_record","operations":["get"],"readableFields":["code"], "rowBoundaries": "unrestricted"}
            ]
          }}]
        }"#,
    )
    .expect("project parses");
    let compiled = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("both valid entity identifiers compile");
    let operation_ids: Vec<_> = compiled
        .routes()
        .routes
        .iter()
        .map(|route| route.id.as_str())
        .collect();
    let unique: std::collections::BTreeSet<_> = operation_ids.iter().copied().collect();

    assert_eq!(unique.len(), operation_ids.len());
    assert!(unique.contains("records.case-file.get"));
    assert!(unique.contains("records.case_file_record.get"));
}

#[test]
fn separator_equivalent_entity_ids_are_refused_while_reading() {
    let failure = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
          "project":{"id":"neutral","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[
            {"id":"case-file","primaryDataset":"test-dataset","route":"case-files","mutationMode":"create-only","fields":[
              {"id":"code","type":"string","maximumLength":8,"classification":"internal"}
            ]},
            {"id":"case_file","primaryDataset":"test-dataset","route":"case_files","mutationMode":"create-only","fields":[
              {"id":"code","type":"string","maximumLength":8,"classification":"internal"}
            ]}
          ],
          "accessProfiles":[{"id":"reader","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{
            "records":[
              {"recordType":"case-file","operations":["get"],"readableFields":["code"], "rowBoundaries": "unrestricted"},
              {"recordType":"case_file","operations":["get"],"readableFields":["code"], "rowBoundaries": "unrestricted"}
            ]
          }}]
        }"#,
    )
    .expect_err("separator-equivalent record type identifiers are refused during reading");

    let [diagnostic] = failure.diagnostics() else {
        panic!("one identifier collision is reported: {failure:?}");
    };
    assert_eq!(diagnostic.code, "breg.record-type.id-collision");
    assert_eq!(diagnostic.path, "project.recordTypes[1].id");
    assert!(diagnostic.message.contains("`case-file`"));
    assert!(diagnostic.message.contains("`case_file`"));
}

#[test]
fn temporal_non_overlap_refuses_a_nullable_scope_field() {
    let mut project = asset_project();
    let scope = project
        .entities
        .iter_mut()
        .find(|entity| entity.id == "asset-placement")
        .and_then(|entity| entity.fields.iter_mut().find(|field| field.id == "asset"))
        .expect("temporal scope field exists");
    scope.required = false;

    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("nullable temporal scope is refused before DDL generation");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.constraint.temporal-scope-nullable")
        .expect("nullable temporal scope has a stable diagnostic");
    assert_eq!(
        diagnostic.path,
        "recordTypes[id=asset-placement].constraints[].scopeFields"
    );
    assert!(!diagnostic.message.contains("asset-placement"));
}

#[test]
fn temporal_non_overlap_refuses_structured_and_crs84_point_scope_fields() {
    let unsupported = [
        FieldTypeSource::Structured {
            max_bytes: 128,
            schema: json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "scope-canary": {"type": "string"}
                }
            }),
        },
        FieldTypeSource::Crs84Point {
            precision: 4,
            bbox: None,
        },
    ];

    for field_type in unsupported {
        let mut project = asset_project();
        let scope = project
            .entities
            .iter_mut()
            .find(|entity| entity.id == "asset-placement")
            .and_then(|entity| entity.fields.iter_mut().find(|field| field.id == "asset"))
            .expect("temporal scope field exists");
        scope.field_type = field_type;

        let failure = compile_project(&project, &[], CompileProfile::Authoring)
            .expect_err("jsonb temporal scopes are refused before DDL generation");
        let diagnostics = failure
            .diagnostics()
            .iter()
            .filter(|diagnostic| {
                diagnostic.code == "breg.constraint.temporal-scope-type-unsupported"
            })
            .collect::<Vec<_>>();
        assert_eq!(diagnostics.len(), 1);
        let diagnostic = diagnostics[0];
        assert_eq!(
            diagnostic.path,
            "recordTypes[id=asset-placement].constraints[].scopeFields"
        );
        assert_eq!(
            diagnostic.message,
            "a temporal non-overlap scope field must use a supported scalar type"
        );
        for value in ["asset-placement", "asset-item", "scope-canary"] {
            assert!(!diagnostic.message.contains(value));
        }
    }
}

#[test]
fn temporal_non_overlap_accepts_every_btree_gist_equality_scalar_scope_type() {
    let supported = [
        FieldTypeSource::Boolean,
        FieldTypeSource::String {
            min_length: 0,
            max_length: 32,
        },
        FieldTypeSource::Text { max_length: 32 },
        FieldTypeSource::Int64,
        FieldTypeSource::Decimal {
            precision: 8,
            scale: 2,
            minimum: None,
            maximum: None,
        },
        FieldTypeSource::Date,
        FieldTypeSource::Timestamp,
        FieldTypeSource::Uuid,
        FieldTypeSource::VocabularyCode {
            vocabulary: "asset-classification".to_owned(),
            values: Vec::new(),
        },
        FieldTypeSource::Reference {
            target: "asset-item".to_owned(),
            on_delete: ReferenceDelete::Restrict,
        },
    ];

    for field_type in supported {
        let mut project = asset_project();
        let scope = project
            .entities
            .iter_mut()
            .find(|entity| entity.id == "asset-placement")
            .and_then(|entity| entity.fields.iter_mut().find(|field| field.id == "asset"))
            .expect("temporal scope field exists");
        scope.field_type = field_type;

        let compiled = compile_project(&project, &[], CompileProfile::Authoring)
            .expect("every btree_gist equality scalar compiles as a temporal scope");
        assert!(compiled.ddl().script().contains("EXCLUDE USING gist"));
    }
}

#[test]
fn compiled_query_inventory_is_profile_scoped_bounded_and_temporal() {
    let mut project = asset_project();
    let grant = project
        .access_profiles
        .first_mut()
        .expect("fixture has an access profile")
        .permissions
        .entities
        .iter_mut()
        .find(|grant| grant.entity == "asset-placement")
        .expect("fixture grants placement access");
    grant.filterable_fields = ["asset".to_owned(), "valid-from".to_owned()]
        .into_iter()
        .collect();
    grant.sortable_fields = ["valid-from".to_owned()].into_iter().collect();

    let compiled = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("temporal list fixture compiles");
    let temporal = compiled
        .entities()
        .get("asset-placement")
        .expect("placement entity compiled")
        .temporal
        .as_ref()
        .expect("temporal declaration is preserved in the compiled model");
    assert_eq!(temporal.start_field, "valid-from");
    assert_eq!(temporal.end_field, "valid-to");

    let operations = &compiled.queries().operations;
    let route = compiled
        .routes()
        .routes
        .iter()
        .find(|route| route.id == "records.asset-placement.list")
        .expect("base list route is compiled");
    assert_eq!(route.path, "/v1/records/placements");
    assert_eq!(route.query_kind, Some(CompiledQueryKind::List));
    let current_route = compiled
        .routes()
        .routes
        .iter()
        .find(|route| route.id == "records.asset-placement.current")
        .expect("current temporal route is compiled");
    assert_eq!(current_route.path, "/v1/records/placements:current");
    assert_eq!(current_route.query_kind, Some(CompiledQueryKind::Current));
    let as_of_route = compiled
        .routes()
        .routes
        .iter()
        .find(|route| route.id == "records.asset-placement.as-of")
        .expect("as-of temporal route is compiled");
    assert_eq!(as_of_route.path, "/v1/records/placements:as-of");
    assert_eq!(as_of_route.query_kind, Some(CompiledQueryKind::AsOf));
    assert!(compiled.routes().routes.iter().all(|route| {
        !matches!(
            route.entity_id.as_str(),
            "asset-item" | "asset-site" | "inspection-event"
        ) || route.query_kind != Some(CompiledQueryKind::Current)
            && route.query_kind != Some(CompiledQueryKind::AsOf)
    }));

    let base = operations
        .iter()
        .find(|operation| operation.id == "records.asset-placement.asset-operator.list")
        .expect("base list query is compiled");
    assert_eq!(base.kind, CompiledQueryKind::List);
    assert_eq!(base.route_id, "records.asset-placement.list");
    assert_eq!(base.profile_id, "asset-operator");
    assert_eq!(base.max_page_size, 100);
    assert_eq!(base.stable_tie_breaker, "record_id");
    assert_eq!(
        base.projection_fields,
        ["asset", "site", "valid-from", "valid-to"]
    );
    assert!(base.temporal.is_none());
    assert_eq!(base.sort_fields.len(), 1);
    assert_eq!(base.sort_fields[0].field, "valid-from");
    assert_eq!(
        base.sort_fields[0].directions,
        [CompiledQuerySortDirection::Asc]
    );
    let valid_from_filter = base
        .filter_fields
        .iter()
        .find(|field| field.field == "valid-from")
        .expect("configured date filter is present");
    assert!(valid_from_filter
        .operators
        .contains(&CompiledQueryFilterOperator::Range));
    let asset_filter = base
        .filter_fields
        .iter()
        .find(|field| field.field == "asset")
        .expect("configured reference filter is present");
    assert!(asset_filter
        .operators
        .contains(&CompiledQueryFilterOperator::Equals));
    assert!(!asset_filter
        .operators
        .contains(&CompiledQueryFilterOperator::Prefix));

    let current = operations
        .iter()
        .find(|operation| operation.id == "records.asset-placement.asset-operator.current")
        .expect("current temporal query is compiled");
    let as_of = operations
        .iter()
        .find(|operation| operation.id == "records.asset-placement.asset-operator.as-of")
        .expect("as-of temporal query is compiled");
    assert_eq!(current.kind, CompiledQueryKind::Current);
    assert_eq!(as_of.kind, CompiledQueryKind::AsOf);
    assert_eq!(current.route_id, "records.asset-placement.current");
    assert_eq!(as_of.route_id, "records.asset-placement.as-of");
    for operation in [current, as_of] {
        let binding = operation
            .temporal
            .as_ref()
            .expect("temporal query carries a fixed temporal binding");
        assert_eq!(binding.start_field, "valid-from");
        assert_eq!(binding.end_field, "valid-to");
        assert_eq!(
            binding.semantics,
            CompiledQueryTemporalSemantics::StartInclusiveEndExclusive
        );
    }

    assert!(compiled
        .artifacts()
        .get("compiled/query-inventory.json")
        .is_some());
    let effective = compiled
        .artifacts()
        .get("compiled/effective-model.json")
        .expect("effective model generated");
    let value = parse_json_strict(&effective.bytes).expect("effective model is strict JSON");
    assert_eq!(
        value["queryInventory"]["operations"]
            .as_array()
            .expect("query operations are rendered")
            .len(),
        compiled.queries().operations.len()
    );
    let openapi = compiled
        .artifacts()
        .get("generated/openapi.json")
        .expect("OpenAPI is generated");
    let openapi = parse_json_strict(&openapi.bytes).expect("OpenAPI is strict JSON");
    assert_eq!(
        openapi["paths"]["/v1/records/placements"]["get"]["x-registry-queryKind"],
        "list"
    );
    assert_eq!(
        openapi["paths"]["/v1/records/placements:current"]["get"]["x-registry-queryKind"],
        "current"
    );
    assert_eq!(
        openapi["paths"]["/v1/records/placements:as-of"]["get"]["x-registry-queryKind"],
        "as-of"
    );
    assert!(
        openapi["paths"]["/v1/records/placements:as-of"]["get"]["x-registry-queryProfiles"]
            ["asset-operator"]["temporal"]
            .get("scopeProperties")
            .is_none()
    );
    let list_parameter_names =
        query_parameter_names(&openapi["paths"]["/v1/records/placements"]["get"]["parameters"]);
    assert_eq!(
        list_parameter_names,
        [
            "$count",
            "$filter",
            "$orderby",
            "$select",
            "$skiptoken",
            "$top",
            "Accept",
            "accessProfile",
            "traceparent",
        ]
    );
    let as_of_parameter_names = query_parameter_names(
        &openapi["paths"]["/v1/records/placements:as-of"]["get"]["parameters"],
    );
    assert_eq!(
        as_of_parameter_names,
        [
            "$count",
            "$filter",
            "$orderby",
            "$select",
            "$skiptoken",
            "$top",
            "Accept",
            "accessProfile",
            "asOf",
            "traceparent",
        ]
    );
    let as_of_parameters = openapi["paths"]["/v1/records/placements:as-of"]["get"]["parameters"]
        .as_array()
        .expect("as-of parameters are rendered");
    let as_of = as_of_parameters
        .iter()
        .find(|parameter| parameter["name"] == "asOf")
        .expect("asOf parameter is rendered");
    assert_eq!(as_of["required"], true);
    assert_eq!(
        as_of["schema"],
        json!({"type": "string", "format": "date-time"})
    );
    let page_size = as_of_parameters
        .iter()
        .find(|parameter| parameter["name"] == "$top")
        .expect("$top parameter is rendered");
    assert_eq!(
        page_size["schema"],
        json!({"type": "integer", "minimum": 1, "maximum": 100})
    );
    for path in [
        "/v1/records/placements",
        "/v1/records/placements:current",
        "/v1/records/placements:as-of",
    ] {
        let operation = &openapi["paths"][path]["get"];
        let cursor_parameter = operation["parameters"]
            .as_array()
            .unwrap()
            .iter()
            .find(|parameter| parameter["name"] == "$skiptoken")
            .expect("continuation query parameter is rendered");
        assert_eq!(
            cursor_parameter["schema"]["maxLength"],
            registry_breg::query::MAX_CURSOR_TOKEN_BYTES
        );
        for media in ["application/json", "application/ld+json"] {
            let response_cursor = &operation["responses"]["200"]["content"][media]["schema"]
                ["properties"]["pageInfo"]["properties"]["nextCursor"];
            assert_eq!(
                response_cursor["maxLength"],
                registry_breg::query::MAX_CURSOR_TOKEN_BYTES
            );
        }
    }
    assert!(compiled.ddl().statements.iter().any(|statement| {
        statement.id == "entity.asset-placement.constraint.temporal-order"
            && statement.sql.contains(" IS NULL OR ")
            && statement.sql.contains(" < ")
    }));
    assert!(compiled.ddl().statements.iter().any(|statement| {
        statement
            .id
            .starts_with("entity.asset-placement.constraint.temporal-non-overlap-")
            && statement.sql.starts_with("ALTER TABLE registry_data.")
            && statement.sql.contains("EXCLUDE USING gist")
            && statement.sql.contains("DEFERRABLE INITIALLY IMMEDIATE")
    }));
}

#[test]
fn temporal_validity_compiles_without_non_overlap_constraint() {
    let compiled = compile_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"temporal-open","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"membership","primaryDataset":"test-dataset","route":"memberships","mutationMode":"mutable","classification":"internal",
            "fields":[
              {"id":"person","type":"string","maximumLength":32,"required":true,"classification":"internal"},
              {"id":"role","type":"string","maximumLength":32,"required":true,"classification":"internal"},
              {"id":"valid-from","type":"date","required":true,"classification":"internal"},
              {"id":"valid-to","type":"date","classification":"internal"}
            ],
            "temporal":{"startField":"valid-from","endField":"valid-to"}
          }],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
              "recordType":"membership","operations":["list"],
              "readableFields":["person","role","valid-from","valid-to"],
              "rowBoundaries": "unrestricted"
            }]}
          }]
        }"#,
    )
    .expect("temporal validity does not require non-overlap");
    let entity = &compiled.entities()["membership"];
    assert!(entity.constraints.is_empty());
    assert!(entity.temporal.is_some(), "temporal metadata is compiled");
    assert!(compiled.ddl().statements.iter().any(|statement| {
        statement.id == "entity.membership.constraint.temporal-order"
            && statement.sql.contains(" IS NULL OR ")
            && statement.sql.contains(" < ")
            && !statement.sql.contains("DEFERRABLE")
    }));
    assert!(compiled.ddl().statements.iter().all(|statement| {
        !statement.id.contains("temporal-non-overlap")
            && !statement.sql.contains("EXCLUDE USING gist")
    }));
}

#[test]
fn temporal_scope_fields_predecessor_spelling_is_refused() {
    let failure = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"temporal-bridge","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"membership","primaryDataset":"test-dataset","route":"memberships","mutationMode":"mutable","classification":"internal",
            "fields":[
              {"id":"person","type":"string","maximumLength":32,"required":true,"classification":"internal"},
              {"id":"household","type":"string","maximumLength":32,"required":true,"classification":"internal"},
              {"id":"valid-from","type":"date","required":true,"classification":"internal"},
              {"id":"valid-to","type":"date","classification":"internal"}
            ],
            "temporal":{"startField":"valid-from","endField":"valid-to","scopeFields":["person"]},
            "constraints":[
              {"type":"temporal-non-overlap","scopeFields":["household"],"startField":"valid-from","endField":"valid-to"}
            ]
          }],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
              "recordType":"membership","operations":["list"],
              "readableFields":["person","household","valid-from","valid-to"],
              "rowBoundaries": "unrestricted"
            }]}
          }]
        }"#,
    )
    .expect_err("temporal scopeFields is no longer an authoring member");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "config.unknown-key"
            && diagnostic.path.ends_with(".temporal.scopeFields")
    }));
}

#[test]
fn snapshot_operation_is_authenticated_stored_field_history_contract() {
    let project = br#"{"datasets":[{"id": "test-dataset"}],
      "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
      "kind":"BRegProject",
      "project":{"id":"snapshot-demo","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
      "recordTypes":[{
        "id":"household","primaryDataset":"test-dataset","route":"households","mutationMode":"mutable","classification":"internal",
        "fields":[
          {"id":"household-code","type":"string","maximumLength":32,"required":true,"classification":"internal"},
          {"id":"administrative-area","type":"string","maximumLength":32,"required":true,"classification":"internal"},
          {"id":"valid-from","type":"date","required":true,"classification":"internal"},
          {"id":"valid-to","type":"date","classification":"internal"}
        ],
        "temporal":{"startField":"valid-from","endField":"valid-to"},
        "derived":[{
          "id":"rollup","sql":"sql/household-rollup.sql","key":"id","execution":"live",
          "fields":[{"id":"member-count","type":"int64","classification":"restricted"}]
        }]
      }],
      "accessProfiles":[{
        "id":"historian","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
          "recordType":"household","operations":["list","snapshot","revisions"],"revisionAccess":true,
          "readableFields":["household-code","administrative-area","valid-from","valid-to","member-count"],
          "filterableFields":["administrative-area","member-count"],
          "sortableFields":["member-count"],
          "allowCount":true,
          "provenanceFields":["kind","reasonCode","sourceReferences"],
          "rowBoundaries": "unrestricted"
        }]}
      }]
    }"#;
    let sql = "SELECT h.id AS id, 1::bigint AS member_count FROM registry_source.household h";
    let compiled = compile_json_with_assets(
        project,
        vec![derived_sql_asset("sql/household-rollup.sql", sql)],
    )
    .expect("snapshot profile with live derived fields compiles");

    let route = compiled
        .routes()
        .routes
        .iter()
        .find(|route| route.operation == Operation::Snapshot)
        .expect("snapshot route is compiled");
    assert_eq!(route.id, "records.household.snapshot");
    assert_eq!(route.path, "/v1/records/households:snapshot");
    assert_eq!(route.query_kind, Some(CompiledQueryKind::Snapshot));
    assert_eq!(route.access_profiles, ["historian"]);
    let access = compiled
        .access()
        .entries
        .iter()
        .find(|entry| entry.route_id == "records.household.snapshot")
        .expect("snapshot has its own access inventory entry");
    assert_eq!(access.operation, Operation::Snapshot);

    let query = compiled
        .queries()
        .operations
        .iter()
        .find(|operation| operation.id == "records.household.historian.snapshot")
        .expect("snapshot query inventory is compiled");
    assert_eq!(query.kind, CompiledQueryKind::Snapshot);
    assert_eq!(query.route_id, "records.household.snapshot");
    assert_eq!(
        query.projection_fields,
        [
            "administrative-area",
            "household-code",
            "valid-from",
            "valid-to"
        ]
    );
    assert_eq!(query.filter_fields.len(), 1);
    assert_eq!(query.filter_fields[0].field, "administrative-area");
    assert!(query.sort_fields.is_empty());
    assert!(!query.processing_fields.contains(&"member-count".to_owned()));
    let temporal = query
        .temporal
        .as_ref()
        .expect("temporal entities allow snapshot validAt");
    assert_eq!(temporal.start_field, "valid-from");
    assert_eq!(temporal.end_field, "valid-to");

    let snapshot_metadata = compiled
        .metadata()
        .entities
        .iter()
        .find(|entity| entity.id == "household")
        .and_then(|entity| {
            entity
                .entries
                .iter()
                .find(|entry| entry.route_id == "records.household.snapshot")
        })
        .expect("snapshot metadata entry exists");
    assert_eq!(
        snapshot_metadata.readable_fields,
        [
            "administrative-area",
            "household-code",
            "valid-from",
            "valid-to"
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>(),
        "snapshot metadata exposes only stored fields, matching the snapshot query inventory"
    );
    assert!(
        snapshot_metadata.provenance_fields.is_empty(),
        "snapshot metadata never advertises context or provenance release"
    );
    let revision_metadata = compiled
        .metadata()
        .entities
        .iter()
        .find(|entity| entity.id == "household")
        .expect("household metadata exists")
        .entries
        .iter()
        .filter(|entry| entry.operation == Operation::Revisions)
        .collect::<Vec<_>>();
    assert_eq!(revision_metadata.len(), 2);
    for metadata in revision_metadata {
        assert_eq!(
            metadata.provenance_fields,
            [
                registry_breg::contract::ProvenanceFieldSource::Kind,
                registry_breg::contract::ProvenanceFieldSource::ReasonCode,
                registry_breg::contract::ProvenanceFieldSource::SourceReferences,
            ]
        );
    }

    let openapi = compiled
        .artifacts()
        .get("generated/openapi.json")
        .expect("OpenAPI is generated");
    let openapi = parse_json_strict(&openapi.bytes).expect("OpenAPI is strict JSON");
    let operation = &openapi["paths"]["/v1/records/households:snapshot"]["get"];
    assert_eq!(operation["operationId"], "records.household.snapshot");
    assert_eq!(operation["x-registry-operation"], "snapshot");
    assert_eq!(operation["x-registry-queryKind"], "snapshot");
    assert_eq!(
        query_parameter_names(&operation["parameters"]),
        [
            "$count",
            "$filter",
            "$orderby",
            "$select",
            "$skiptoken",
            "$top",
            "Accept",
            "accessProfile",
            "snapshot",
            "traceparent",
            "validAt",
        ]
    );
    assert_eq!(
        operation["parameters"]
            .as_array()
            .expect("parameters are rendered")
            .iter()
            .find(|parameter| parameter["name"] == "validAt")
            .expect("validAt parameter exists")["schema"],
        json!({"type": "string", "format": "date"})
    );
    let response_schema = &operation["responses"]["200"]["content"]["application/json"]["schema"];
    assert!(response_schema["required"]
        .as_array()
        .expect("required properties render")
        .contains(&json!("snapshot")));
    assert_eq!(
        response_schema["properties"]["validAt"],
        json!({"type": "string", "format": "date"})
    );
    assert!(response_schema["properties"]["items"]["items"]["required"]
        .as_array()
        .expect("snapshot record required properties render")
        .contains(&json!("revisionIdentifier")));
    assert!(!serde_json::to_string(response_schema)
        .expect("schema serializes")
        .contains("reasonCode"));

    let revision_schema = &openapi["paths"]["/v1/records/households/{record_id}/revisions"]["get"]
        ["responses"]["200"]["content"]["application/json"]["schema"]["properties"]["items"]
        ["items"];
    assert!(!revision_schema["required"]
        .as_array()
        .expect("revision item required properties render")
        .contains(&json!("changeContext")));
    let change_context = &revision_schema["properties"]["changeContext"];
    assert_eq!(change_context["additionalProperties"], false);
    let mut context_properties = change_context["properties"]
        .as_object()
        .expect("revision context properties render")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    context_properties.sort();
    assert_eq!(
        context_properties,
        ["kind", "reasonCode", "sourceReferences"]
    );
    assert_eq!(
        change_context["properties"]["reasonCode"]["x-registry-maxBytes"],
        64
    );
    assert_eq!(change_context["properties"]["reasonCode"]["minLength"], 1);
    assert_eq!(
        change_context["properties"]["sourceReferences"]["items"]["x-registry-maxBytes"],
        256
    );
    let revision_detail_schema = &openapi["paths"]
        ["/v1/records/households/{record_id}/revisions/{revision}"]["get"]["responses"]["200"]
        ["content"]["application/json"]["schema"]["properties"]["data"];
    assert!(revision_detail_schema["properties"]
        .as_object()
        .expect("revision detail properties render")
        .contains_key("changeContext"));
}

#[test]
fn snapshot_operation_rejects_unauthorized_provenance() {
    let provenance = compile_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"snapshot-provenance","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"mutable","classification":"internal",
            "fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"}]
          }],
          "accessProfiles":[{
            "id":"reader","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
              "recordType":"record","operations":["snapshot"],"readableFields":["code"],
              "provenanceFields":["kind"],
              "rowBoundaries": "unrestricted"
            }]}
          }]
        }"#,
    )
    .expect_err("provenance fields require revision access");
    assert!(provenance
        .diagnostics()
        .iter()
        .any(|diagnostic| { diagnostic.code == "breg.access-profile.provenance-fields-invalid" }));
}

#[test]
fn snapshot_valid_at_openapi_schema_matches_temporal_value_type() {
    let compiled = compile_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"snapshot-timestamp","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"mutable","classification":"internal",
            "fields":[
              {"id":"code","type":"string","maximumLength":32,"classification":"internal"},
              {"id":"valid-from","type":"timestamp","required":true,"classification":"internal"},
              {"id":"valid-to","type":"timestamp","classification":"internal"}
            ],
            "temporal":{"startField":"valid-from","endField":"valid-to"}
          }],
          "accessProfiles":[{
            "id":"historian","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
              "recordType":"record","operations":["snapshot"],"allowCount":true,
              "readableFields":["code","valid-from","valid-to"],
              "rowBoundaries": "unrestricted"
            }]}
          }]
        }"#,
    )
    .expect("timestamp temporal snapshot compiles");
    assert!(compiled.queries().operations.iter().any(|operation| {
        operation.kind == CompiledQueryKind::Snapshot && operation.allow_count
    }));
    assert!(compiled
        .routes()
        .routes
        .iter()
        .all(|route| route.operation != Operation::List));
    let openapi = compiled
        .artifacts()
        .get("generated/openapi.json")
        .expect("OpenAPI is generated");
    let openapi = parse_json_strict(&openapi.bytes).expect("OpenAPI is strict JSON");
    let valid_at = openapi["paths"]["/v1/records/records:snapshot"]["get"]["parameters"]
        .as_array()
        .expect("parameters are rendered")
        .iter()
        .find(|parameter| parameter["name"] == "validAt")
        .expect("validAt parameter exists");
    assert_eq!(
        valid_at["schema"],
        json!({"type": "string", "format": "date-time"})
    );
    let response_schema = &openapi["paths"]["/v1/records/records:snapshot"]["get"]["responses"]
        ["200"]["content"]["application/json"]["schema"];
    assert_eq!(
        response_schema["properties"]["validAt"],
        json!({"type": "string", "format": "date-time"})
    );
}

fn query_parameter_names(parameters: &Value) -> Vec<String> {
    let mut names = parameters
        .as_array()
        .expect("parameters are an array")
        .iter()
        .map(|parameter| {
            parameter["name"]
                .as_str()
                .expect("parameter has a name")
                .to_owned()
        })
        .collect::<Vec<_>>();
    names.sort();
    names
}

#[test]
fn query_inventory_rejects_unsupported_filter_and_sort_field_types() {
    for (member, code) in [
        (
            r#""filterableFields":["payload"]"#,
            "breg.query.filter-field-type-unsupported",
        ),
        (
            r#""sortableFields":["payload"]"#,
            "breg.query.sort-field-type-unsupported",
        ),
    ] {
        let source = format!(
            r#"{{"datasets":[{{"id":"test-dataset"}}],
              "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
              "kind":"BRegProject",
              "project":{{"id":"query-shape","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
              "recordTypes":[{{
                "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable",
                "fields":[
                  {{"id":"payload","type":"structured","maximumBytes":256,"classification":"internal","schema":{{"type":"object","additionalProperties":false}}}}
                ]
              }}],
              "accessProfiles":[{{
                "id":"operator","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{{"records":[{{
                  "rowBoundaries": "unrestricted", "recordType":"entry","operations":["list"],"readableFields":["payload"],{member}
                }}]}}
              }}]
            }}"#
        );
        let project = parse_project_json(source.as_bytes()).expect("project shape parses");
        let failure = compile_project(&project, &[], CompileProfile::Authoring)
            .expect_err("unsupported query field type is refused");
        assert!(failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == code));
    }
}

#[test]
fn temporal_queries_require_profile_readable_boundary_fields() {
    let mut project = asset_project();
    let grant = project
        .access_profiles
        .first_mut()
        .expect("fixture has an access profile")
        .permissions
        .entities
        .iter_mut()
        .find(|grant| grant.entity == "asset-placement")
        .expect("fixture grants placement access");
    grant.readable_fields.remove("valid-to");

    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("temporal query cannot process hidden boundary fields");
    assert!(failure.diagnostics().iter().any(|diagnostic| {
        diagnostic.code == "breg.query.temporal-field-not-readable"
            && diagnostic.path
                == "recordTypes[id=asset-placement].accessProfiles[id=asset-operator].readableFields"
            && diagnostic.message.contains("asset-operator")
            && diagnostic.message.contains("valid-to")
    }));
}

#[test]
fn temporal_start_required_diagnostic_names_the_record_and_field() {
    let mut project = asset_project();
    let field = project
        .entities
        .iter_mut()
        .find(|entity| entity.id == "asset-placement")
        .expect("fixture has temporal placements")
        .fields
        .iter_mut()
        .find(|field| field.id == "valid-from")
        .expect("fixture has a valid-time start");
    field.required = false;

    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("a temporal start cannot be optional");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.field.valid-time-start-required")
        .expect("the optional start is diagnosed");
    assert_eq!(
        diagnostic.path,
        "recordTypes[id=asset-placement].fields[id=valid-from].required"
    );
}

#[test]
fn duplicate_record_api_name_diagnostic_names_the_conflicting_record() {
    let failure = compile_json(
        br#"{"datasets":[{"id":"records"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"api-names","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://api-names.example.test"},
          "recordTypes":[
            {"id":"operator","apiName":"Operator","primaryDataset":"records","route":"operators","mutationMode":"create-only","fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"}]},
            {"id":"directory-entry","apiName":"Operator","primaryDataset":"records","route":"directory-entries","mutationMode":"create-only","fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"}]}
          ]
        }"#,
    )
    .expect_err("duplicate Record API names are refused");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.record-type.api-name-invalid")
        .expect("the duplicate name is diagnosed");
    assert_eq!(diagnostic.path, "recordTypes[id=directory-entry].apiName");
}

#[test]
fn reordered_stored_field_authoring_changes_revision_but_not_query_inventory() {
    let left = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
          "project":{"id":"query-shape","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable",
            "fields":[
              {"id":"code","type":"string","maximumLength":32,"classification":"internal"},
              {"id":"count","type":"int64","classification":"internal"}
            ]
          }],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
              "recordType":"entry","operations":["list"],
              "readableFields":["code","count"],"filterableFields":["count","code"],"sortableFields":["count","code"],
              "rowBoundaries": "unrestricted"
            }]}
          }]
        }"#,
    )
    .expect("left source parses");
    let right = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
          "project":{"id":"query-shape","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable",
            "fields":[
              {"id":"count","type":"int64","classification":"internal"},
              {"id":"code","type":"string","maximumLength":32,"classification":"internal"}
            ]
          }],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{
              "recordType":"entry","operations":["list"],
              "readableFields":["count","code"],"filterableFields":["code","count"],"sortableFields":["code","count"],
              "rowBoundaries": "unrestricted"
            }]}
          }]
        }"#,
    )
    .expect("right source parses");

    let left =
        compile_project(&left, &[], CompileProfile::Authoring).expect("left query source compiles");
    let right = compile_project(&right, &[], CompileProfile::Authoring)
        .expect("right query source compiles");
    assert_eq!(left.queries(), right.queries());
    assert_ne!(
        left.revision(),
        right.revision(),
        "stored field authoring order is now part of the compiled model"
    );
}

#[test]
fn duplicate_routes_fail_before_artifact_generation() {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
          "project":{"id":"neutral","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[
            {"id":"first-record","primaryDataset":"test-dataset","route":"hidden-route-value","mutationMode":"create-only","fields":[
              {"id":"code","type":"string","maximumLength":8,"classification":"internal"}
            ]},
            {"id":"second-record","primaryDataset":"test-dataset","route":"hidden-route-value","mutationMode":"create-only","fields":[
              {"id":"code","type":"string","maximumLength":8,"classification":"internal"}
            ]}
          ],
          "accessProfiles":[{"id":"reader","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{
            "records":[
              {"recordType":"first-record","operations":["get"],"readableFields":["code"], "rowBoundaries": "unrestricted"},
              {"recordType":"second-record","operations":["get"],"readableFields":["code"], "rowBoundaries": "unrestricted"}
            ]
          }}]
        }"#,
    )
    .expect("project parses");

    let failure = compile_project(&project, &[], CompileProfile::Authoring)
        .expect_err("duplicate routes fail before artifact generation");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.record-type.route-duplicate")
        .expect("duplicate route has a stable diagnostic");
    assert_eq!(diagnostic.path, "recordTypes[id=second-record].route");
    let rendered = serde_json::to_string(&failure).expect("failure serializes");
    assert!(!rendered.contains("hidden-route-value"));
    for authored_value in ["hidden-route-value", "first-record", "second-record"] {
        assert!(!diagnostic.message.contains(authored_value));
    }
    for record_type in ["first-record", "second-record"] {
        assert!(failure.diagnostics().iter().any(|diagnostic| {
            diagnostic.severity == DiagnosticSeverity::Finding
                && diagnostic.code == "breg.access.profile-unrestricted-rows"
                && diagnostic.path
                    == format!(
                        "recordTypes[id={record_type}].accessProfiles[id=reader].rowBoundaries"
                    )
        }));
    }
}

#[test]
fn production_refuses_a_digest_present_lock_without_module_source() {
    let project = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
          "project":{"id":"neutral","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "package":{"sourceRevision":"revision-1"},
          "modules":[{"id":"missing-module","version":"1","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}],
          "recordTypes":[{"id":"object","primaryDataset":"test-dataset","route":"objects","mutationMode":"create-only","fields":[
            {"id":"code","type":"string","maximumLength":8,"classification":"internal"}
          ]}],
          "accessProfiles":[{"id":"reader","principalClaim":"principal","requiredScopes":"unrestricted","permissions":{"records":[{"recordType":"object","operations":["get"],"readableFields":["code"], "rowBoundaries": "unrestricted"}]}}]
        }"#,
    )
    .expect("project parses");

    let failure = compile_project(&project, &[], CompileProfile::Production)
        .expect_err("a lock digest cannot substitute for loaded module source");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "breg.module.source-required")
        .expect("missing source has a stable production diagnostic");
    assert_eq!(diagnostic.path, "project.modules[].id");
    let rendered = serde_json::to_string(&failure).expect("failure serializes");
    for authored_value in ["missing-module", "sha256:000000"] {
        assert!(!rendered.contains(authored_value));
    }
}

#[test]
fn verified_module_digest_changes_compiled_closure_artifact_and_revision() {
    let project_source = br#"{"datasets":[{"id": "neutral"}],
      "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
      "project":{"id":"neutral","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://neutral.example.test"},
      "package":{"sourceRevision":"revision-1"},
      "manifestProjection":{"accessProfile":"reader","classificationCeiling":"internal","catalog":{"baseUrl":"https://neutral.example.test","title":"Neutral Catalog","publisher":{"id":"neutral-authority","name":"Neutral Publisher"}},"publicService":{"id":"neutral-service","title":"Neutral service"},"datasets":[{"id":"neutral","title":"Neutral Dataset"}],"dataServices":[{"id":"neutral-api","title":"Neutral API","endpointUrl":"https://neutral.example.test","servesDatasets":["neutral"]}]},
      "modules":[{"id":"core","version":"1","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}]
    }"#;
    let module_source = br#"{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"core","version":"1","recordTypes":[
        {"id":"alpha-record","primaryDataset":"neutral","route":"alpha-records","mutationMode":"create-only","fields":[
          {"id":"code","type":"string","maximumLength":8,"classification":"internal"}
        ],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get"],"readableFields":["code"], "requiredScopes":"unrestricted","rowBoundaries":"unrestricted"}]},
        {"id":"beta-record","primaryDataset":"neutral","route":"beta-records","mutationMode":"create-only","fields":[
          {"id":"code","type":"string","maximumLength":8,"classification":"internal"}
        ],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get"],"readableFields":["code"], "requiredScopes":"unrestricted","rowBoundaries":"unrestricted"}]}
      ]
    }"#;
    let first_module = parse_module_json(module_source).expect("module parses");
    let mut second_module = first_module.clone();
    second_module.entities.reverse();
    let first_digest = module_digest(&first_module);
    let second_digest = module_digest(&second_module);
    assert_ne!(first_digest, second_digest);

    let mut first_project = parse_project_json(project_source).expect("project parses");
    first_project.modules[0].digest = Some(first_digest);
    let mut second_project = first_project.clone();
    second_project.modules[0].digest = Some(second_digest);

    let first = compile_project(&first_project, &[first_module], CompileProfile::Production)
        .expect("first verified closure compiles");
    let second = compile_project(
        &second_project,
        &[second_module],
        CompileProfile::Production,
    )
    .expect("second verified closure compiles");

    assert_ne!(first.module_closure(), second.module_closure());
    assert_ne!(
        first
            .artifacts()
            .get("compiled/modules.json")
            .expect("module closure artifact exists")
            .bytes,
        second
            .artifacts()
            .get("compiled/modules.json")
            .expect("module closure artifact exists")
            .bytes
    );
    assert_ne!(first.revision(), second.revision());
}

fn selector_project(fields: &str) -> Vec<u8> {
    format!(
        r#"{{"datasets":[{{"id": "test-dataset"}}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{{"id":"selector-grammar","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
          "recordTypes":[{{
            "id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"mutable",
            "fields":[
              {{"id":"code","type":"string","maximumLength":32,"classification":"internal"}},
              {{"id":"area","type":"string","maximumLength":32,"classification":"internal"}},
              {{"id":"location","type":"crs84-point","precision":6,"classification":"internal"}}
            ],
            "selectorProfiles":[{{"id":"by-code","fields":{fields}}}]
          }}],
          "accessProfiles":[{{
            "id":"operator","default":true,"principalClaim":"sub","requiredScopes":"unrestricted","permissions":{{"records":[{{
              "rowBoundaries": "unrestricted", "recordType":"record","operations":["get"],"readableFields":["code","area"]
            }}]}}
          }}]
        }}"#
    )
    .into_bytes()
}

#[test]
fn selector_profile_field_refusals_separate_unknown_names_from_cardinality() {
    let failure = compile_json(&selector_project(r#"["code","missing-field"]"#))
        .expect_err("an unknown selector field is refused");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|item| item.code == "breg.selector-profile.fields-unknown")
        .unwrap_or_else(|| panic!("the unknown selector field is named: {failure:?}"));
    assert_eq!(
        diagnostic.path,
        "recordTypes[id=record].selectorProfiles[].fields"
    );
    assert!(
        diagnostic.message.contains("`missing-field`"),
        "{diagnostic:?}"
    );
    assert!(!diagnostic.message.contains("`code`"), "{diagnostic:?}");

    let failure =
        compile_json(&selector_project("[]")).expect_err("an empty selector profile is refused");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|item| item.code == "breg.selector-profile.fields-invalid")
        .unwrap_or_else(|| panic!("the empty selector profile is reported: {failure:?}"));
    assert!(
        diagnostic.message.contains("one to sixteen"),
        "{diagnostic:?}"
    );

    let failure = compile_json(&selector_project(r#"["code","code"]"#))
        .expect_err("a duplicated selector field is refused");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|item| item.code == "breg.selector-profile.fields-duplicate")
        .unwrap_or_else(|| panic!("the duplicated selector field is named: {failure:?}"));
    assert!(diagnostic.message.contains("`code`"), "{diagnostic:?}");

    let failure = compile_json(&selector_project(r#"["location"]"#))
        .expect_err("a CRS84 point selector field is refused");
    let diagnostic = failure
        .diagnostics()
        .iter()
        .find(|item| item.code == "breg.selector-profile.field-type-unsupported")
        .unwrap_or_else(|| panic!("the unsupported selector field is named: {failure:?}"));
    assert!(diagnostic.message.contains("`location`"), "{diagnostic:?}");

    compile_json(&selector_project(r#"["code","area"]"#))
        .expect("a selector profile over stored scalar fields compiles");
}

#[test]
fn entity_classification_defaults_while_field_classification_stays_explicit() {
    let compiled = compile_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"classification-defaults","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"mutable",
            "fields":[{"id":"code","type":"string","maximumLength":32,"classification":"internal"}]
          }],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"sub","requiredScopes":"unrestricted","permissions":{"records":[{
              "recordType":"record","operations":["get"],"readableFields":["code"],
              "rowBoundaries": "unrestricted"
            }]}
          }]
        }"#,
    )
    .expect("an entity without an explicit classification compiles");
    let entity = &compiled.entities()["record"];
    assert_eq!(entity.classification, Classification::Internal);
    let field = &entity.stored_fields[0];
    assert_eq!(field.logical.classification, Classification::Internal);
    assert!(
        !field.required,
        "a field without `required` is optional by default"
    );

    let failure = parse_project_json(
        br#"{"datasets":[{"id": "test-dataset"}],
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"classification-defaults","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "recordTypes":[{
            "id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"mutable",
            "fields":[{"id":"code","type":"string","maximumLength":32}]
          }]
        }"#,
    )
    .expect_err("a field never inherits its classification from the entity");
    let diagnostic = &failure.diagnostics()[0];
    assert_eq!(diagnostic.code, "config.missing-key");
    assert!(
        diagnostic
            .message
            .contains("the required member `classification` is missing"),
        "{diagnostic:?}"
    );
}

#[test]
fn structured_root_arrays_preserve_schema_and_closed_nested_object_validation() {
    for (schema, accepted) in [
        (
            json!({"type":"array","items":{"type":"string","enum":["a","b"]},"minItems":1,"maxItems":2,"uniqueItems":true}),
            true,
        ),
        (
            json!({"type":"array","items":{"type":"object","additionalProperties":false,"properties":{"code":{"type":"string"}}}}),
            true,
        ),
        (
            json!({"type":"array","items":{"type":"object","properties":{"code":{"type":"string"}}}}),
            false,
        ),
        (
            json!({"type":"array","items":{"$ref":"https://example.invalid/schema"}}),
            false,
        ),
        (json!({"type":"string"}), false),
        (json!({"type":"array"}), false),
        (json!({"type":"array","items":true}), false),
    ] {
        let source = json!({"datasets":[{"id": "test-dataset"}],
            "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
            "project":{"id":"array-schema","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://example.test"},
            "recordTypes":[{"id":"record","primaryDataset":"test-dataset","route":"records","mutationMode":"create-only",
                "fields":[{"id":"codes","type":"structured","required":true,"classification":"internal","maximumBytes":512,"schema":schema}]}]
        });
        let project = parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap();
        let result = compile_project(&project, &[], CompileProfile::Authoring);
        assert_eq!(result.is_ok(), accepted, "schema: {schema}");
        if let Ok(compiled) = result {
            assert_eq!(
                compiled.entities()["record"].fields["codes"].field_type,
                FieldTypeSource::Structured {
                    max_bytes: 512,
                    schema
                }
            );
        }
    }
}

fn headed_project(api_version: &str, kind: &str, identity_block: &str) -> Vec<u8> {
    let mut project = json!({"apiVersion": api_version, "kind": kind});
    project[identity_block] = json!({
        "id":"header-check","version":"1","defaultLanguage":"en",
        "canonicalBaseIri":"https://registry.example.test/header-check"
    });
    serde_json::to_vec(&project).expect("the project serializes")
}

fn read_refusals(bytes: &[u8]) -> Vec<(String, String, String)> {
    parse_project_yaml(bytes)
        .expect_err("the project is refused when it is read")
        .diagnostics()
        .iter()
        .map(|diagnostic| {
            (
                diagnostic.code.clone(),
                diagnostic.path.clone(),
                diagnostic.message.clone(),
            )
        })
        .collect()
}

#[test]
fn a_project_opens_with_the_breg_project_header_and_a_project_block() {
    let project = parse_project_yaml(&headed_project(
        "id.registrystack.org/formats/breg/project/v1alpha1",
        "BRegProject",
        "project",
    ))
    .expect("the stable project header is read");
    assert_eq!(project.project.id, "header-check");
    assert_eq!(project.project.version, "1");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("a project under the stable header compiles");
}

#[test]
fn the_retired_project_api_version_is_refused_with_its_replacement_named() {
    let refused = read_refusals(&headed_project(
        "registry.registrystack.org/v1alpha1",
        "BRegProject",
        "project",
    ));
    let [(code, path, message)] = refused.as_slice() else {
        panic!("one diagnostic refuses the retired apiVersion: {refused:?}");
    };
    assert_eq!(code, "config.retired-api-version");
    assert_eq!(path, "project.apiVersion");
    assert!(
        message.contains("id.registrystack.org/formats/breg/project/v1alpha1"),
        "the refusal names the replacement: {message}"
    );
}

#[test]
fn the_retired_project_kind_is_refused_with_the_stable_kind_named() {
    let refused = read_refusals(&headed_project(
        "registry.registrystack.org/v1alpha1",
        "RegistryProject",
        "project",
    ));
    // The retired apiVersion is reported beside the kind, each at its own member.
    let [(retired, _, _), (code, path, message)] = refused.as_slice() else {
        panic!("the retired apiVersion and the retired kind are each refused: {refused:?}");
    };
    assert_eq!(retired, "config.retired-api-version");
    assert_eq!(code, "config.wrong-kind");
    assert_eq!(path, "project.kind");
    assert!(
        message.contains("BRegProject"),
        "the refusal names the stable kind: {message}"
    );
}

fn module_read_refusals(bytes: &[u8]) -> Vec<(String, String, String)> {
    parse_module_yaml(bytes)
        .expect_err("the module is refused when it is read")
        .diagnostics()
        .iter()
        .map(|diagnostic| {
            (
                diagnostic.code.clone(),
                diagnostic.path.clone(),
                diagnostic.message.clone(),
            )
        })
        .collect()
}

#[test]
fn a_module_opens_with_the_breg_module_header() {
    let module = parse_module_yaml(
        b"apiVersion: id.registrystack.org/formats/breg/module/v1alpha1\n\
          kind: BRegModule\nid: header-check\nversion: 0.1.0\n",
    )
    .expect("the module header is read");
    assert_eq!(module.id, "header-check");
    assert_eq!(module.version, "0.1.0");
}

#[test]
fn a_module_without_its_header_is_refused() {
    let refused = module_read_refusals(b"id: header-check\nversion: 0.1.0\n");
    let [(code, path, _)] = refused.as_slice() else {
        panic!("one diagnostic refuses the module without a header: {refused:?}");
    };
    assert_eq!(code, "config.missing-envelope");
    assert_eq!(path, "module");
}

#[test]
fn a_module_under_another_kind_or_api_version_is_refused_with_the_expected_one_named() {
    let refused = module_read_refusals(
        b"apiVersion: id.registrystack.org/formats/breg/module/v1alpha1\n\
          kind: BRegProject\nid: header-check\nversion: 0.1.0\n",
    );
    let [(code, path, message)] = refused.as_slice() else {
        panic!("one diagnostic refuses the other kind: {refused:?}");
    };
    assert_eq!(code, "config.wrong-kind");
    assert_eq!(path, "module.kind");
    assert!(
        message.contains("BRegModule"),
        "the refusal names the module kind: {message}"
    );

    let refused = module_read_refusals(
        b"apiVersion: id.registrystack.org/formats/breg/project/v1alpha1\n\
          kind: BRegModule\nid: header-check\nversion: 0.1.0\n",
    );
    let [(code, path, message)] = refused.as_slice() else {
        panic!("one diagnostic refuses the other apiVersion: {refused:?}");
    };
    assert_eq!(code, "config.unsupported-api-version");
    assert_eq!(path, "module.apiVersion");
    assert!(
        message.contains("id.registrystack.org/formats/breg/module/v1alpha1"),
        "the refusal names the module apiVersion: {message}"
    );
}

#[test]
fn a_module_read_as_json_opens_with_the_same_header() {
    let headed = |api_version: Option<&str>, kind: Option<&str>| {
        let mut module = json!({"id": "header-check", "version": "0.1.0"});
        if let Some(api_version) = api_version {
            module["apiVersion"] = json!(api_version);
        }
        if let Some(kind) = kind {
            module["kind"] = json!(kind);
        }
        parse_module_json(&serde_json::to_vec(&module).expect("the module encodes"))
    };
    let refusals = |failure: CompileFailure| -> Vec<(String, String)> {
        failure
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
            .collect()
    };

    let module = headed(Some(MODULE_API_VERSION), Some(MODULE_KIND)).expect("the header is read");
    assert_eq!(module.id, "header-check");

    assert_eq!(
        refusals(headed(None, None).expect_err("a module without a header is refused")),
        [("config.missing-envelope".to_owned(), "module".to_owned())]
    );
    assert_eq!(
        refusals(
            headed(
                Some("id.registrystack.org/formats/breg/project/v1alpha1"),
                Some(MODULE_KIND)
            )
            .expect_err("another apiVersion is refused")
        ),
        [(
            "config.unsupported-api-version".to_owned(),
            "module.apiVersion".to_owned()
        )]
    );
    assert_eq!(
        refusals(
            headed(Some(MODULE_API_VERSION), Some("BRegProject"))
                .expect_err("another kind is refused")
        ),
        [("config.wrong-kind".to_owned(), "module.kind".to_owned())]
    );
}

#[test]
fn the_registry_block_is_refused_with_the_project_block_named() {
    let refused = read_refusals(&headed_project(
        "id.registrystack.org/formats/breg/project/v1alpha1",
        "BRegProject",
        "registry",
    ));
    let removed = refused
        .iter()
        .find(|(code, _, _)| code == "config.removed-key")
        .unwrap_or_else(|| panic!("the registry block is refused as removed: {refused:?}"));
    assert_eq!(removed.1, "project.registry");
    assert!(
        removed.2.contains("project"),
        "the refusal names the project block: {}",
        removed.2
    );
}

/// Entity fields, derived fields, and action inputs that each declare a
/// length or size bound under the given member names. The structured field's
/// `schema` is a JSON Schema, whose own `maxLength` keyword is not a member
/// of this format.
fn bounded_fields(
    minimum_length: &str,
    maximum_length: &str,
    maximum_bytes: &str,
) -> (Value, Value, Value) {
    let mut code =
        json!({"id":"case-code","type":"string","required":true,"classification":"internal"});
    code[minimum_length] = json!(2);
    code[maximum_length] = json!(32);
    let mut note = json!({"id":"note","type":"text","classification":"internal"});
    note[maximum_length] = json!(4096);
    let mut detail = json!({
        "id":"detail","type":"structured","classification":"internal",
        "schema":{"type":"object","additionalProperties":false,
            "properties":{"label":{"type":"string","maxLength":16}}}
    });
    detail[maximum_bytes] = json!(512);
    let mut summary = json!({"id":"summary","type":"string","classification":"internal"});
    summary[maximum_length] = json!(64);
    let mut input = json!({"id":"case-code","type":"string","classification":"internal"});
    input[minimum_length] = json!(2);
    input[maximum_length] = json!(32);
    (
        json!([code, note, detail]),
        json!([{"id":"overview","sql":"sql/overview.sql","key":"id","fields":[summary]}]),
        json!([input]),
    )
}

fn bounded_field_project(
    minimum_length: &str,
    maximum_length: &str,
    maximum_bytes: &str,
) -> Vec<u8> {
    let (fields, derived, inputs) = bounded_fields(minimum_length, maximum_length, maximum_bytes);
    serde_json::to_vec(&json!({"datasets":[{"id": "test-dataset"}],
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
        "kind":"BRegProject",
        "project":{"id":"field-bounds","version":"1","defaultLanguage":"en",
            "canonicalBaseIri":"https://registry.example.test/field-bounds"},
        "recordTypes":[{
            "id":"case-file","primaryDataset":"test-dataset","route":"case-files",
            "mutationMode":"mutable","fields":fields,"derived":derived
        }],
        "actions":[{"execution":{"mode":"immediate"},
            "id":"create-case-file","inputs":inputs,
            "plan":{"type":"fixed","effects":[{"id":"case","target":{"recordType":"case-file"},"operation":"create",
                "set":{"case-code":{"fromInput":"case-code"}}}]}
        }]
    }))
    .expect("the project serializes")
}

fn bounded_field_module(
    minimum_length: &str,
    maximum_length: &str,
    maximum_bytes: &str,
) -> Vec<u8> {
    let (fields, derived, inputs) = bounded_fields(minimum_length, maximum_length, maximum_bytes);
    serde_json::to_vec(&json!({
        "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1",
        "kind":"BRegModule",
        "id":"field-bounds","version":"1",
        "recordTypes":[{
            "id":"case-file","primaryDataset":"test-dataset","route":"case-files",
            "mutationMode":"mutable","fields":fields,"derived":derived
        }],
        "extendRecordTypes":[{"recordType":"ledger","fields":fields,"derived":derived}],
        "actions":[{"execution":{"mode":"immediate"},
            "id":"create-case-file","inputs":inputs,
            "plan":{"type":"fixed","effects":[{"id":"case","target":{"recordType":"case-file"},"operation":"create",
                "set":{"case-code":{"fromInput":"case-code"}}}]}
        }]
    }))
    .expect("the module serializes")
}

/// The `config.removed-key` refusals of a failed read, as path and message.
fn removed_key_refusals(failure: &CompileFailure) -> Vec<(String, String)> {
    let mut removed: Vec<(String, String)> = failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| diagnostic.code == "config.removed-key")
        .map(|diagnostic| (diagnostic.path.clone(), diagnostic.message.clone()))
        .collect();
    removed.sort();
    removed
}

/// The bounds one list of field declarations carries under the retired
/// names, as the refused path and the member that replaces it.
fn retired_bounds(fields: &str, bounds: &[(usize, &str)]) -> Vec<(String, &'static str)> {
    bounds
        .iter()
        .map(|(index, key)| {
            let replacement = match *key {
                "minLength" => "minimumLength",
                "maxLength" => "maximumLength",
                "maxBytes" => "maximumBytes",
                other => panic!("no retired bound is named {other}"),
            };
            (format!("{fields}[{index}].{key}"), replacement)
        })
        .collect()
}

fn assert_retired_bounds_refused(
    removed: &[(String, String)],
    mut expected: Vec<(String, &'static str)>,
) {
    expected.sort();
    assert_eq!(
        removed.iter().map(|(path, _)| path).collect::<Vec<_>>(),
        expected.iter().map(|(path, _)| path).collect::<Vec<_>>(),
        "every retired bound is refused where it is written, and no JSON Schema keyword is"
    );
    for ((path, message), (_, replacement)) in removed.iter().zip(&expected) {
        assert!(
            message.contains(&format!("`{replacement}`")),
            "the refusal at {path} names {replacement}: {message}"
        );
    }
}

const STORED_FIELD_BOUNDS: &[(usize, &str)] = &[
    (0, "minLength"),
    (0, "maxLength"),
    (1, "maxLength"),
    (2, "maxBytes"),
];

#[test]
fn field_bounds_are_written_as_minimum_length_maximum_length_and_maximum_bytes() {
    let project = parse_project_yaml(&bounded_field_project(
        "minimumLength",
        "maximumLength",
        "maximumBytes",
    ))
    .expect("a project that spells its field bounds in full is read");
    let entity = &project.entities[0];
    assert_eq!(
        entity.fields[0].field_type,
        FieldTypeSource::String {
            min_length: 2,
            max_length: 32
        }
    );
    assert_eq!(
        entity.fields[1].field_type,
        FieldTypeSource::Text { max_length: 4096 }
    );
    assert!(matches!(
        entity.fields[2].field_type,
        FieldTypeSource::Structured { max_bytes: 512, .. }
    ));
    assert_eq!(
        entity.derived[0].fields[0].field_type,
        FieldTypeSource::String {
            min_length: 0,
            max_length: 64
        }
    );
    assert_eq!(
        project.actions[0].inputs[0].field_type,
        FieldTypeSource::String {
            min_length: 2,
            max_length: 32
        }
    );

    // The project is written back with the same members it was read from.
    let written = serde_json::to_value(&project).expect("the project serializes");
    assert_eq!(
        written["recordTypes"][0]["fields"][0]["minimumLength"],
        json!(2)
    );
    assert_eq!(
        written["recordTypes"][0]["fields"][0]["maximumLength"],
        json!(32)
    );
    assert_eq!(
        written["recordTypes"][0]["fields"][2]["maximumBytes"],
        json!(512)
    );
    assert_eq!(
        written["recordTypes"][0]["fields"][2]["schema"]["properties"]["label"]["maxLength"],
        json!(16),
        "a structured field's schema keeps its JSON Schema keywords"
    );
    assert_eq!(
        written["actions"][0]["inputs"][0]["maximumLength"],
        json!(32)
    );

    let module = parse_module_yaml(&bounded_field_module(
        "minimumLength",
        "maximumLength",
        "maximumBytes",
    ))
    .expect("a module that spells its field bounds in full is read");
    assert_eq!(
        module.extend_entities[0].fields[1].field_type,
        FieldTypeSource::Text { max_length: 4096 }
    );
}

#[test]
fn the_short_field_bound_names_are_refused_in_a_project_with_their_replacement_named() {
    let failure = parse_project_yaml(&bounded_field_project("minLength", "maxLength", "maxBytes"))
        .expect_err("a project that abbreviates its field bounds is refused");
    let mut expected = retired_bounds("project.recordTypes[0].fields", STORED_FIELD_BOUNDS);
    expected.extend(retired_bounds(
        "project.recordTypes[0].derived[0].fields",
        &[(0, "maxLength")],
    ));
    expected.extend(retired_bounds(
        "project.actions[0].inputs",
        &[(0, "minLength"), (0, "maxLength")],
    ));
    assert_retired_bounds_refused(&removed_key_refusals(&failure), expected);
}

#[test]
fn the_short_field_bound_names_are_refused_in_a_module_with_their_replacement_named() {
    let failure = parse_module_yaml(&bounded_field_module("minLength", "maxLength", "maxBytes"))
        .expect_err("a module that abbreviates its field bounds is refused");
    let mut expected = retired_bounds("module.recordTypes[0].fields", STORED_FIELD_BOUNDS);
    expected.extend(retired_bounds(
        "module.recordTypes[0].derived[0].fields",
        &[(0, "maxLength")],
    ));
    expected.extend(retired_bounds(
        "module.extendRecordTypes[0].fields",
        STORED_FIELD_BOUNDS,
    ));
    expected.extend(retired_bounds(
        "module.extendRecordTypes[0].derived[0].fields",
        &[(0, "maxLength")],
    ));
    expected.extend(retired_bounds(
        "module.actions[0].inputs",
        &[(0, "minLength"), (0, "maxLength")],
    ));
    assert_retired_bounds_refused(&removed_key_refusals(&failure), expected);
}

/// A hook handler tagged by the written union member.
fn tagged_handlers(tag: &str) -> Value {
    let mut hook_handler = json!({"destinationId":"case-intake"});
    hook_handler[tag] = json!("url");
    json!([{"id":"notify-intake","phase":"after","trigger":"created", "projection":["case-code"],"handler":hook_handler}])
}

fn tagged_handler_project(tag: &str) -> Vec<u8> {
    let hooks = tagged_handlers(tag);
    serde_json::to_vec(&json!({"datasets":[{"id": "test-dataset"}],
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
        "kind":"BRegProject",
        "project":{"id":"handler-tags","version":"1","defaultLanguage":"en",
            "canonicalBaseIri":"https://registry.example.test/handler-tags"},
        "recordTypes":[{
            "id":"case-file","primaryDataset":"test-dataset","route":"case-files",
            "mutationMode":"mutable",
            "fields":[{"id":"case-code","type":"string","maximumLength":32,
                "classification":"internal"}],
            "hooks":hooks
        }]
    }))
    .expect("the project serializes")
}

fn tagged_handler_module(tag: &str) -> Vec<u8> {
    let hooks = tagged_handlers(tag);
    serde_json::to_vec(&json!({
        "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1",
        "kind":"BRegModule",
        "id":"handler-tags","version":"1",
        "recordTypes":[{
            "id":"case-file","primaryDataset":"test-dataset","route":"case-files",
            "mutationMode":"mutable",
            "fields":[{"id":"case-code","type":"string","maximumLength":32,
                "classification":"internal"}],
            "hooks":hooks
        }],
        "extendRecordTypes":[{"recordType":"ledger","hooks":hooks}]
    }))
    .expect("the module serializes")
}

fn assert_handler_kind_refused(failure: &CompileFailure, expected: &[&str]) {
    let removed = removed_key_refusals(failure);
    let mut expected = expected.to_vec();
    expected.sort();
    assert_eq!(
        removed
            .iter()
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>(),
        expected,
        "every handler tagged by `kind` is refused where it is written"
    );
    for (path, message) in &removed {
        assert!(
            message.contains("`type`"),
            "the refusal at {path} names `type`: {message}"
        );
    }
}

#[test]
fn a_handler_is_tagged_by_type_in_a_project_and_a_module() {
    let project = parse_project_yaml(&tagged_handler_project("type"))
        .expect("a project that tags its handlers by `type` is read");
    let written = serde_json::to_value(&project).expect("the project serializes");
    assert_eq!(
        written["recordTypes"][0]["hooks"][0]["handler"],
        json!({"type":"url","destinationId":"case-intake"})
    );

    parse_module_yaml(&tagged_handler_module("type"))
        .expect("a module that tags its handlers by `type` is read");
}

#[test]
fn a_handler_tagged_by_kind_is_refused_in_a_project_with_its_replacement_named() {
    let failure = parse_project_yaml(&tagged_handler_project("kind"))
        .expect_err("a project that tags a handler by `kind` is refused");
    assert_handler_kind_refused(&failure, &["project.recordTypes[0].hooks[0].handler.kind"]);
}

#[test]
fn a_handler_tagged_by_kind_is_refused_in_a_module_with_its_replacement_named() {
    let failure = parse_module_yaml(&tagged_handler_module("kind"))
        .expect_err("a module that tags a handler by `kind` is refused");
    assert_handler_kind_refused(
        &failure,
        &[
            "module.recordTypes[0].hooks[0].handler.kind",
            "module.extendRecordTypes[0].hooks[0].handler.kind",
        ],
    );
}

/// One consent-record entity whose validity states its longest duration
/// under `member`.
fn consent_record_entity(member: &str, value: Value) -> Value {
    let mut validity = json!({"from":"effective-at","until":"expires-at"});
    validity[member] = value;
    json!({
        "id":"consent-decision","primaryDataset":"test-dataset","route":"consent-decisions",
        "mutationMode":"mutable",
        "fields":[
            {"id":"effective-at","type":"timestamp","required":true,"classification":"internal"},
            {"id":"expires-at","type":"timestamp","classification":"internal"}
        ],
        "consentRecord":{
            "subject":"subject","recipient":"recipient","purpose":"purpose","scope":"scope",
            "decision":{"field":"decision","gives":["given"],"revokes":["withdrawn"]},
            "validity":validity
        }
    })
}

fn consent_record_project(member: &str, value: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
        "kind":"BRegProject",
        "project":{"id":"consent-duration","version":"1","defaultLanguage":"en",
            "canonicalBaseIri":"https://registry.example.test/consent-duration"},
        "recordTypes":[consent_record_entity(member, value)]
    }))
    .expect("the project serializes")
}

fn consent_record_module(member: &str, value: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1",
        "kind":"BRegModule",
        "id":"consent-duration","version":"1",
        "recordTypes":[consent_record_entity(member, value)]
    }))
    .expect("the module serializes")
}

#[test]
fn a_consent_record_states_its_longest_duration_in_whole_days() {
    let project = parse_project_yaml(&consent_record_project("maximumDurationDays", json!(365)))
        .expect("a project that states the duration in days is read");
    let record = project.entities[0]
        .consent_record
        .as_ref()
        .expect("the consent record");
    assert_eq!(record.validity.maximum_duration_days, 365);

    // The project is written back with the member it was read from.
    let written = serde_json::to_value(&project).expect("the project serializes");
    assert_eq!(
        written["recordTypes"][0]["consentRecord"]["validity"],
        json!({"from":"effective-at","until":"expires-at","maximumDurationDays":365})
    );

    let module = parse_module_yaml(&consent_record_module("maximumDurationDays", json!(365)))
        .expect("a module that states the duration in days is read");
    let record = module.entities[0]
        .consent_record
        .as_ref()
        .expect("the consent record");
    assert_eq!(record.validity.maximum_duration_days, 365);
}

#[test]
fn a_consent_duration_is_an_integer_and_never_an_iso_8601_text() {
    for text in ["P365D", "365", "P1Y"] {
        parse_project_yaml(&consent_record_project("maximumDurationDays", json!(text)))
            .expect_err("a duration written as text is refused");
    }
    for number in [json!(-1), json!(1.5)] {
        parse_project_yaml(&consent_record_project("maximumDurationDays", number))
            .expect_err("a duration that is not a whole number of days is refused");
    }
}

#[test]
fn the_iso_8601_consent_duration_is_refused_in_a_project_with_its_replacement_named() {
    // The replacement text carries its own fixed example, so the value read
    // here is one that example does not use.
    let failure = parse_project_yaml(&consent_record_project("maxDuration", json!("P1Y6M")))
        .expect_err("a project that writes the duration as ISO 8601 text is refused");
    let removed = removed_key_refusals(&failure);
    assert_eq!(
        removed
            .iter()
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>(),
        ["project.recordTypes[0].consentRecord.validity.maxDuration"]
    );
    assert!(
        removed[0].1.contains("`maximumDurationDays`"),
        "the refusal names the replacement: {}",
        removed[0].1
    );
    assert!(
        !removed[0].1.contains("P1Y6M"),
        "the refusal never repeats the value it read: {}",
        removed[0].1
    );
}

#[test]
fn the_iso_8601_consent_duration_is_refused_in_a_module_with_its_replacement_named() {
    let failure = parse_module_yaml(&consent_record_module("maxDuration", json!("P365D")))
        .expect_err("a module that writes the duration as ISO 8601 text is refused");
    let removed = removed_key_refusals(&failure);
    assert_eq!(
        removed
            .iter()
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>(),
        ["module.recordTypes[0].consentRecord.validity.maxDuration"]
    );
    assert!(
        removed[0].1.contains("`maximumDurationDays`"),
        "the refusal names the replacement: {}",
        removed[0].1
    );
}

/// A project whose manifest projection describes one vocabulary and points at
/// where that vocabulary is published, under `member`.
fn external_reference_project(member: &str) -> Vec<u8> {
    let mut project: Value = serde_json::from_slice(&source_bytes::source_bytes(
        &narrowed_vocabulary_project(json!([
            {"code":"pending","label":{"en":"Pending"}},
            {"code":"active","label":{"en":"Active"}},
            {"code":"suspended","label":{"en":"Suspended"}},
            {"code":"cancelled","label":{"en":"Cancelled"}}
        ])),
    ))
    .expect("the project source is JSON");
    project["manifestProjection"]["vocabularies"][0][member] =
        json!("https://codes.example.test/authorization-status.html");
    serde_json::to_vec(&project).expect("the project is JSON")
}

#[test]
fn a_projected_vocabulary_names_where_it_is_published_as_external_reference() {
    let project = parse_project_yaml(&external_reference_project("externalReference"))
        .expect("a project that writes externalReference is read");
    let projection = project
        .manifest_projection
        .as_ref()
        .expect("the project projects a manifest");
    assert_eq!(
        projection.vocabularies[0].external_reference.as_deref(),
        Some("https://codes.example.test/authorization-status.html")
    );

    // The project is written back with the member it was read from.
    let written = serde_json::to_value(&project).expect("the project serializes");
    assert_eq!(
        written["manifestProjection"]["vocabularies"][0]["externalReference"],
        json!("https://codes.example.test/authorization-status.html")
    );

    // The Registry Manifest the projection renders keeps the member its own
    // format defines.
    let compiled =
        compile_project(&project, &[], CompileProfile::Authoring).expect("the project compiles");
    let manifest: Value = serde_json::from_slice(
        &compiled
            .artifacts()
            .get("generated/manifest/registry-manifest.json")
            .expect("the projection renders a manifest")
            .bytes,
    )
    .expect("the manifest is JSON");
    assert_eq!(
        manifest["codelists"][0]["external_ref"],
        json!("https://codes.example.test/authorization-status.html")
    );
}

#[test]
fn the_abbreviated_external_reference_is_refused_with_its_replacement_named() {
    let failure = parse_project_yaml(&external_reference_project("externalRef"))
        .expect_err("a project that abbreviates the member is refused");
    let removed = removed_key_refusals(&failure);
    assert_eq!(
        removed
            .iter()
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>(),
        ["project.manifestProjection.vocabularies[0].externalRef"]
    );
    assert!(
        removed[0].1.contains("`externalReference`"),
        "the refusal names the replacement: {}",
        removed[0].1
    );
    assert!(
        !removed[0].1.contains("codes.example.test"),
        "the refusal never repeats the value it read: {}",
        removed[0].1
    );
}

/// Reads `new` as `T`, writes it back unchanged, and refuses `old` with a
/// diagnostic that lists `new` among the values the reader accepts.
fn assert_word_is_read_and_its_earlier_spelling_refused<T>(new: &str, old: &str)
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let name = std::any::type_name::<T>();
    let read: T = serde_json::from_value(json!(new))
        .unwrap_or_else(|error| panic!("{name} reads `{new}`: {error}"));
    assert_eq!(
        serde_json::to_value(&read).expect("the word serializes"),
        json!(new),
        "{name} writes the word it read"
    );
    let Err(error) = serde_json::from_value::<T>(json!(old)) else {
        panic!("{name} refuses `{old}`");
    };
    assert!(
        error.to_string().contains(&format!("`{new}`")),
        "{name} names `{new}` when it refuses `{old}`: {error}"
    );
}

#[test]
fn an_enumerated_word_is_read_in_kebab_case_and_refused_in_snake_case() {
    use registry_breg::contract::{
        CurrentDatePredicateSource, LookupValueOrigin, ManifestProjectionDatasetStatus,
        MutationMode, ProposalRetentionMode, ValidTimeRole, WebhookAuthenticationProfile,
    };
    use registry_breg::model::{
        ActionRouteKind, CompiledCurrentDateRelation, CompiledProposalRetentionMode,
        CompiledQueryTemporalSemantics, CompiledWebhookDeliveryMode, CompiledWebhookRetryProfile,
    };

    macro_rules! words {
        ($($type:ty: $($new:literal),+;)+) => {
            $($(
                assert_word_is_read_and_its_earlier_spelling_refused::<$type>(
                    $new,
                    &$new.replace('-', "_"),
                );
            )+)+
        };
    }
    words! {
        ComparisonOperator: "less-than", "less-than-or-equal", "greater-than", "greater-than-or-equal";
        CurrentDatePredicateSource: "on-or-after", "on-or-before";
        CompiledCurrentDateRelation: "on-or-after", "on-or-before";
        ProposalRetentionMode: "operator-erase";
        CompiledProposalRetentionMode: "operator-erase";
        MutationMode: "create-only";
        ValidTimeRole: "valid-from", "valid-to";
        LookupValueOrigin: "verified-claim";
        ManifestProjectionDatasetStatus: "under-development";
        WebhookAuthenticationProfile: "hmac-sha256-v1";
        ActionRouteKind: "target-conditions";
        CompiledQueryFilterOperator: "is-null", "is-not-null";
        CompiledQueryKind: "as-of";
        CompiledQueryTemporalSemantics: "start-inclusive-end-exclusive";
        CompiledWebhookDeliveryMode: "after-commit";
        CompiledWebhookRetryProfile: "registry-v1";
    }
}

#[test]
fn a_union_variant_is_named_in_kebab_case_and_refused_in_snake_case() {
    use registry_breg::model::CompiledPlanValue;

    fn check<T: serde::de::DeserializeOwned>(tag: &str, new: &str, rest: Value) {
        let name = std::any::type_name::<T>();
        let document = |word: &str| {
            let mut document = rest.clone();
            document[tag] = json!(word);
            document
        };
        if let Err(error) = serde_json::from_value::<T>(document(new)) {
            panic!("{name} reads `{new}`: {error}");
        }
        let old = new.replace('-', "_");
        let old_camel = {
            let mut parts = new.split('-');
            let first = parts.next().unwrap_or_default().to_owned();
            parts.fold(first, |mut word, part| {
                let mut letters = part.chars();
                if let Some(initial) = letters.next() {
                    word.extend(initial.to_uppercase());
                    word.push_str(letters.as_str());
                }
                word
            })
        };
        for earlier in [old, old_camel] {
            let Err(error) = serde_json::from_value::<T>(document(&earlier)) else {
                panic!("{name} refuses `{earlier}`");
            };
            assert!(
                error.to_string().contains(&format!("`{new}`")),
                "{name} names `{new}` when it refuses `{earlier}`: {error}"
            );
        }
    }

    check::<ConstraintSource>("type", "int-range", json!({"field": "count", "minimum": 0}));
    check::<UniqueWhenPredicate>(
        "type",
        "field-equals",
        json!({"field": "state", "value": "a"}),
    );
    check::<UniqueWhenPredicate>("type", "field-is-null", json!({"field": "state"}));
    check::<UniqueWhenPredicate>("type", "field-is-not-null", json!({"field": "state"}));
    check::<UniqueWhenPredicate>("type", "active-lifecycle", json!({}));
    check::<CompiledPlanValue>("kind", "from-input", json!({"input": "a"}));
    check::<CompiledPlanValue>(
        "kind",
        "from-effect",
        json!({"effect": "a", "target_entity_id": "b"}),
    );
}

// CFG-EMPTY-1: an unset record value is stated with `isNull`, `beforeIsNull`,
// or `afterIsNull`, and `null` is never a comparison literal.
#[test]
fn an_unset_value_is_stated_explicitly_and_a_null_literal_is_refused() {
    use registry_breg::contract::{ActionRequirementSource, EventConditionSource};

    fn reads<T: serde::de::DeserializeOwned + serde::Serialize>(document: Value) {
        let name = std::any::type_name::<T>();
        let read = serde_json::from_value::<T>(document.clone())
            .unwrap_or_else(|error| panic!("{name} reads {document}: {error}"));
        let written = serde_json::to_value(&read).expect("a source type serializes");
        for (member, value) in document.as_object().expect("a mapping") {
            assert_eq!(&written[member], value, "{name} writes `{member}` as read");
        }
    }
    fn refuses<T: serde::de::DeserializeOwned>(document: Value) {
        let name = std::any::type_name::<T>();
        assert!(
            serde_json::from_value::<T>(document.clone()).is_err(),
            "{name} refuses {document}"
        );
    }

    reads::<ActionRequirementSource>(json!({"input": "subject", "field": "note", "isNull": true}));
    reads::<ActionRequirementSource>(json!({"input": "subject", "field": "note", "equals": 3}));
    reads::<EventConditionSource>(json!({
        "type": "fields",
        "beforeIsNull": ["note"],
        "afterIsNull": ["closed-on"],
        "afterEquals": {"state": true}
    }));

    refuses::<ActionRequirementSource>(
        json!({"input": "subject", "field": "note", "equals": null}),
    );
    refuses::<ActionRequirementSource>(
        json!({"input": "subject", "field": "note", "isNull": false}),
    );
    refuses::<EventConditionSource>(json!({"type": "fields", "beforeEquals": {"note": null}}));
    refuses::<EventConditionSource>(json!({"type": "fields", "afterEquals": {"note": null}}));
    refuses::<EventConditionSource>(json!({"type": "fields", "afterEquals": {"note": {"a": 1}}}));
    refuses::<EventConditionSource>(json!({"type": "fields", "afterIsNull": ["note", "note"]}));

    // A condition that names no unset field is written as it was, so the
    // digest of a module that never compared with null does not move.
    let written = serde_json::to_value(
        serde_json::from_value::<EventConditionSource>(
            json!({"type": "fields", "afterEquals": {"state": "open"}}),
        )
        .expect("a fields condition is read"),
    )
    .expect("a condition serializes");
    assert_eq!(
        written,
        json!({"type": "fields", "changed": [], "beforeEquals": {}, "afterEquals": {"state": "open"}})
    );
}

#[test]
fn a_union_is_tagged_by_type_and_refused_under_its_earlier_tag() {
    use registry_breg::contract::EventConditionSource;
    fn check<T: serde::de::DeserializeOwned>(earlier: &str, word: &str, rest: Value) {
        let name = std::any::type_name::<T>();
        let document = |tag: &str| {
            let mut document = rest.clone();
            document[tag] = json!(word);
            document
        };
        if let Err(error) = serde_json::from_value::<T>(document("type")) {
            panic!("{name} reads `type: {word}`: {error}");
        }
        let Err(error) = serde_json::from_value::<T>(document(earlier)) else {
            panic!("{name} refuses `{earlier}: {word}`");
        };
        assert!(
            error.to_string().contains("`type`"),
            "{name} names `type` when it refuses `{earlier}`: {error}"
        );
    }

    check::<ConstraintSource>("kind", "unique", json!({"fields": ["code"]}));
    check::<ConstraintSource>(
        "kind",
        "compare",
        json!({"left": "a", "operator": "less-than", "right": "b"}),
    );
    check::<ConstraintSource>("kind", "int-range", json!({"field": "count", "minimum": 0}));
    check::<ConstraintSource>(
        "kind",
        "vocabulary",
        json!({"field": "state", "values": ["a"]}),
    );
    check::<ConstraintSource>(
        "kind",
        "temporal-non-overlap",
        json!({"scopeFields": ["code"], "startField": "valid_from", "endField": "valid_to"}),
    );
    check::<UniqueWhenPredicate>(
        "kind",
        "field-equals",
        json!({"field": "state", "value": "a"}),
    );
    check::<UniqueWhenPredicate>("kind", "field-is-null", json!({"field": "state"}));
    check::<UniqueWhenPredicate>("kind", "field-is-not-null", json!({"field": "state"}));
    check::<UniqueWhenPredicate>("kind", "active-lifecycle", json!({}));
    check::<EventConditionSource>("kind", "fields", json!({"changed": ["state"]}));
}

#[test]
fn an_identifier_is_read_in_the_local_grammar_and_refused_outside_it() {
    use registry_breg::action_evidence_contracts::{ActionEvidenceSource, EvidenceProviderSource};
    use registry_breg::contract::{
        AccessLogSource, ActionEffectSource, ActionHandlerWriteSource, ActionInputSource,
        ActionSource, AttachmentSlotSource, DerivedFieldSource, DerivedSource, EntitySource,
        EventConditionSource, FieldSource, HookSource, IndexSource, LookupPermissionSource,
        ManifestProjectionApplicationProfileSource, ManifestProjectionDataServiceSource,
        ManifestProjectionDatasetSource, ManifestProjectionDistributionSource,
        ManifestProjectionEntitySource, ManifestProjectionFieldSource,
        ManifestProjectionPublicServiceSource, ManifestProjectionPublisherSource,
        ManifestProjectionVocabularySource, ModuleLockSource, ProjectAccessProfileSource,
        ReadPathSource, RecipientGroupSource, RecipientOrganizationSource, RegistryIdentitySource,
        SelectorProfileSource, VocabularySource,
    };

    const EXPECTED: &str = "a local identifier matching";

    /// Reads the document `write` builds around a well-formed identifier
    /// without refusing the identifier, and refuses it around each
    /// identifier outside the grammar without repeating what was written.
    fn check<T: serde::de::DeserializeOwned>(write: impl Fn(&str) -> Value) {
        let name = std::any::type_name::<T>();
        if let Err(error) = serde_json::from_value::<T>(write("a-b_1")) {
            assert!(
                !error.to_string().contains(EXPECTED),
                "{name} reads a local identifier: {error}"
            );
        }
        for refused in ["Upper-case", "1-leading-digit", "dotted.name", ""] {
            let Err(error) = serde_json::from_value::<T>(write(refused)) else {
                panic!("{name} refuses an identifier outside the grammar");
            };
            let error = error.to_string();
            assert!(
                error.contains(EXPECTED),
                "{name} names the grammar: {error}"
            );
            assert!(
                refused.is_empty() || !error.contains(refused),
                "{name} never repeats what it read: {error}"
            );
        }
    }

    macro_rules! identified {
        ($($type:ty),+ $(,)?) => {
            $( check::<$type>(|id| json!({"id": id})); )+
        };
    }
    identified!(
        ActionEffectSource,
        ActionEvidenceSource,
        ActionHandlerWriteSource,
        ActionInputSource,
        ActionSource,
        AttachmentSlotSource,
        DerivedFieldSource,
        DerivedSource,
        EntitySource,
        EvidenceProviderSource,
        HookSource,
        IndexSource,
        ManifestProjectionApplicationProfileSource,
        ManifestProjectionDataServiceSource,
        ManifestProjectionDatasetSource,
        ManifestProjectionDistributionSource,
        ManifestProjectionEntitySource,
        ManifestProjectionFieldSource,
        ManifestProjectionPublicServiceSource,
        ManifestProjectionPublisherSource,
        ManifestProjectionVocabularySource,
        ModuleLockSource,
        ProjectAccessProfileSource,
        ReadPathSource,
        RecipientGroupSource,
        RecipientOrganizationSource,
        RegistryIdentitySource,
        RegistryModule,
        SelectorProfileSource,
        VocabularySource,
    );
    check::<FieldSource>(|id| json!({"id": id, "type": "boolean"}));
    for kind in [
        "unique",
        "compare",
        "int-range",
        "vocabulary",
        "temporal-non-overlap",
    ] {
        check::<ConstraintSource>(|id| json!({"type": kind, "id": id}));
    }

    check::<AccessLogSource>(|id| json!({"exemptions": {id: {}}}));
    check::<ActionEffectSource>(|id| json!({"set": {id: {}}}));
    check::<EventConditionSource>(|id| json!({"type": "fields", "beforeEquals": {id: true}}));
    check::<EventConditionSource>(|id| json!({"type": "fields", "afterEquals": {id: true}}));
    check::<LookupPermissionSource>(|id| json!({"claimMapping": {id: "claim"}}));
}
