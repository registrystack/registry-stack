//! The authored Output vocabulary must cross compilation into the real runtime unchanged.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    sync::Arc,
};

use chrono::{TimeZone as _, Utc};
use registry_evidence::{
    bundle::{evidence_package_limits, Bundle},
    kernel::{EvidenceScope, OfflineKernel, ValueProjection},
};
use registry_evidence_authoring::{
    compile,
    output::Bound,
    project::{self, EvidenceProject, Output, MAX_OUTPUTS_PER_ASSERTION},
};
use registry_platform_config::{sha256_uri, write_sum_file};
use registry_platform_yaml::{LocalId, Reader};
use serde_json::{json, Value};

const PUBLIC_JWK: &[u8] = include_bytes!(
    "../../../products/evidence/fixtures/conformance/supported-values/public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json"
);

fn project_document() -> Value {
    json!({
        "apiVersion": project::PROJECT_API_VERSION,
        "kind": project::PROJECT_KIND,
        "id": "all-output-forms",
        "selectorProfiles": {
            "record-by-code": {
                "maximumAggregateBytes": 16,
                "fields": {
                    "record-code": {
                        "type": "controlled-code",
                        "codelist": "codelists/codes.yaml",
                        "codelistVersion": "1",
                        "maximumBytes": 8
                    },
                    "record-reference": {"type": "string", "minimumBytes": 1, "maximumBytes": 8}
                }
            }
        },
        "functions": [
            {"id": "derive-values", "interface": "assertion-derive/v1", "source": "functions/derive.rhai"}
        ],
        "sources": {
            "records": {
                "pack": {"id": "output-forms-source", "version": "1"},
                "route": "lookup",
                "connection": "records",
                "inputs": {
                    "recordReference": {
                        "selector": {
                            "role": "subject",
                            "profile": "record-by-code",
                            "field": "record-reference"
                        }
                    }
                },
                "acquisitionPosture": "record-transformed",
            }
        },
        "assertionDefinitions": {
            "all-forms": {
                "question": "Can every retained Evidence value form cross the authored boundary?",
                "semantics": {
                    "requirement": "urn:example:requirement:all-output-forms",
                    "kind": "information-requirement",
                    "evidenceType": "urn:example:evidence-type:all-output-forms",
                    "referenceFrameworks": ["urn:example:framework:all-output-forms"]
                },
                "purpose": "conformance",
                "grantCeiling": {
                    "authorities": ["organizational"],
                    "actorKinds": ["service"],
                    "valueOrigins": ["request"],
                    "audiences": ["urn:example:audience:all-output-forms"]
                },
                "subjects": [{"role": "subject", "selectors": ["record-by-code"]}],
                "acquisition": {"source": "records"},
                "derive": {"function": "derive-values"},
                "outputs": {
                    "boolean": {"concept": "urn:example:concept:boolean", "type": "boolean"},
                    "controlled-code": {"concept": "urn:example:concept:controlled-code", "type": "controlled-code", "codelist": "codelists/codes.yaml", "codelistVersion": "1", "maximumBytes": 8},
                    "controlled-category": {"concept": "urn:example:concept:controlled-category", "type": "controlled-category", "codelist": "codelists/categories.yaml", "categoryScheme": "urn:example:scheme:category", "schemeVersion": "1", "maximumBytes": 16},
                    "bounded-identifier": {"concept": "urn:example:concept:bounded-identifier", "type": "bounded-identifier", "prefix": "urn:example:record:", "minimumBytes": 20, "maximumBytes": 64},
                    "bounded-integer": {"concept": "urn:example:concept:bounded-integer", "type": "bounded-integer", "minimum": -10, "maximum": 10},
                    "bounded-decimal": {"concept": "urn:example:concept:bounded-decimal", "type": "bounded-decimal", "minimum": "-10.5", "maximum": "10.5", "maximumScale": 2},
                    "date-bucket": {"concept": "urn:example:concept:date-bucket", "type": "date-bucket", "bucketScheme": "urn:example:scheme:date-bucket", "schemeVersion": "1", "codelist": "codelists/date-buckets.yaml"},
                    "time-bucket": {"concept": "urn:example:concept:time-bucket", "type": "time-bucket", "bucketScheme": "urn:example:scheme:time-bucket", "schemeVersion": "1", "codelist": "codelists/time-buckets.yaml"},
                    "entity-reference": {"concept": "urn:example:concept:entity-reference", "type": "audience-scoped-entity-reference", "maximumBytes": 160},
                    "controlled-code-list": {"concept": "urn:example:concept:controlled-code-list", "type": "controlled-code-list", "codelist": "codelists/codes.yaml", "codelistVersion": "1", "minimumItems": 1, "maximumItems": 3, "unique": true},
                    "entity-reference-list": {"concept": "urn:example:concept:entity-reference-list", "type": "entity-reference-list", "minimumItems": 1, "maximumItems": 2, "unique": true},
                    "structured": {"concept": "urn:example:concept:structured", "type": "reviewed-structured-value", "schema": "schemas/structured.schema.json", "maximumSerializedBytes": 512}
                },
                "validitySeconds": 300,
                "subjectBinding": "audience-scoped",
                "representations": ["signed-jws"],
                "fixtures": "fixtures/all-forms.yaml"
            }
        }
    })
}

fn project_document_with_output_count(count: usize) -> Value {
    let mut document = project_document();
    let outputs = document["assertionDefinitions"]["all-forms"]["outputs"]
        .as_object_mut()
        .expect("the authored project declares outputs");
    assert!(
        count >= outputs.len(),
        "the bridge helper only adds outputs to the retained vocabulary"
    );
    for index in outputs.len() + 1..=count {
        outputs.insert(
            format!("additional-output-{index}"),
            json!({
                "concept": format!("urn:example:concept:additional-output-{index}"),
                "type": "boolean"
            }),
        );
    }
    document
}

fn authored_project() -> EvidenceProject {
    let bytes = serde_json::to_vec_pretty(&project_document()).expect("project serializes");
    project::read_project("evidence.yaml", &bytes)
        .expect("all Output forms are valid authored configuration")
        .value
}

fn codelist(uri: &str, codes: &[&str]) -> String {
    serde_json::to_string_pretty(&json!({
        "apiVersion": "id.registrystack.org/formats/evidence/codelist/v1alpha1",
        "kind": "EvidenceCodelist",
        "uri": uri,
        "version": "1",
        "type": "code-list",
        "codes": codes
    }))
    .expect("codelist serializes")
}

fn assets() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "functions/derive.rhai".to_owned(),
            r#"fn derive(facts, selectors, context) {
    [
        #{output: "boolean", value: true},
        #{output: "controlled-code", value: "C-A"},
        #{output: "controlled-category", value: "category-a"},
        #{output: "bounded-identifier", value: "urn:example:record:A-01"},
        #{output: "bounded-integer", value: 7},
        #{output: "bounded-decimal", value: decimal("1.25")},
        #{output: "date-bucket", value: #{form: "date-bucket", scheme: "urn:example:scheme:date-bucket", bucket: "current-period"}},
        #{output: "time-bucket", value: #{form: "time-bucket", scheme: "urn:example:scheme:time-bucket", bucket: "within-window"}},
        #{output: "entity-reference", value: entity_reference_seed("entity-a")},
        #{output: "controlled-code-list", value: ["C-A", "C-B"]},
        #{output: "entity-reference-list", value: [entity_reference_seed("entity-a"), entity_reference_seed("entity-b")]},
        #{output: "structured", value: #{form: "reviewed-structured-value", schema: "urn:example:schema:structured", fields: #{status: "C-A", quantity: 4}}}
    ]
}"#
            .to_owned(),
        ),
        (
            "codelists/codes.yaml".to_owned(),
            codelist("urn:example:codelist:codes", &["C-A", "C-B", "C-C"]),
        ),
        (
            "codelists/categories.yaml".to_owned(),
            codelist("urn:example:scheme:category", &["category-a", "category-b"]),
        ),
        (
            "codelists/date-buckets.yaml".to_owned(),
            codelist(
                "urn:example:scheme:date-bucket",
                &["current-period", "boundary-period"],
            ),
        ),
        (
            "codelists/time-buckets.yaml".to_owned(),
            codelist(
                "urn:example:scheme:time-bucket",
                &["within-window", "at-limit"],
            ),
        ),
        (
            "schemas/structured.schema.json".to_owned(),
            serde_json::to_string_pretty(&json!({
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "$id": "urn:example:schema:structured",
                "type": "object",
                "additionalProperties": false,
                "required": ["status", "quantity"],
                "properties": {
                    "status": {"type": "string", "enum": ["C-A", "C-B"]},
                    "quantity": {"type": "integer", "minimum": 0, "maximum": 9}
                }
            }))
            .expect("structured schema serializes"),
        ),
    ])
}

fn checked_pack_route() -> compile::CheckedPackRoute {
    let inputs_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["recordReference"],
        "properties": {
            "recordReference": {"type": "string", "minLength": 1, "maxLength": 8}
        }
    });
    let facts_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["marker"],
        "properties": {"marker": {"type": "boolean"}}
    });
    let provider_schema = facts_schema.clone();
    let inputs_bytes = serde_json::to_vec(&inputs_schema).expect("pack input schema serializes");
    let facts_bytes = serde_json::to_vec(&facts_schema).expect("pack facts schema serializes");
    let provider_bytes =
        serde_json::to_vec(&provider_schema).expect("provider response schema serializes");
    let route_script = br#"fn request(exchange) {
    #{record_reference: exchange.body["recordReference"]}
}

fn facts(exchange) {
    #{marker: exchange.body["marker"]}
}
"#
    .to_vec();
    let pack_bytes = serde_json::to_vec_pretty(&json!({
        "apiVersion": "id.registrystack.org/formats/adapter/pack/v1alpha1",
        "kind": "AdapterPack",
        "id": "output-forms-source",
        "version": "1",
        "testedVersions": [],
        "endpoints": [{
            "id": "records",
            "component": "http",
            "authentication": {"type": "static-authorization"},
            "attemptTimeoutMilliseconds": 2000,
            "maximumResponseBytes": 4096,
            "requestHeaders": ["accept"],
            "operations": [{"id": "lookup", "safeUpstream": true}],
            "testedVersions": []
        }],
        "scripts": [{
            "path": "scripts/records.rhai",
            "digest": sha256_uri(&route_script)
        }],
        "sourceRoutes": [{
            "id": "lookup",
            "evidence": {
                "inputsSchema": {
                    "path": "schemas/inputs.json",
                    "digest": sha256_uri(&inputs_bytes)
                },
                "factsSchema": {
                    "path": "schemas/facts.json",
                    "digest": sha256_uri(&facts_bytes)
                },
                "acquisitionPosture": "record-transformed"
            },
            "steps": [
                {
                    "setHeader": {
                        "name": "Accept",
                        "value": {"constant": "application/json"}
                    }
                },
                {
                    "to": {
                        "uri": "http:records",
                        "parameters": {
                            "httpMethod": "POST",
                            "path": "/records/lookup",
                            "body": {
                                "rhai": {
                                    "file": "scripts/records.rhai",
                                    "entrypoint": "request"
                                }
                            },
                            "operation": "lookup"
                        }
                    }
                },
                {
                    "validateSchema": {
                        "path": "schemas/provider.json",
                        "digest": sha256_uri(&provider_bytes)
                    }
                },
                {
                    "setBody": {
                        "rhai": {
                            "file": "scripts/records.rhai",
                            "entrypoint": "facts"
                        }
                    }
                }
            ]
        }]
    }))
    .expect("pack serializes");
    compile::CheckedPackRoute {
        pack: project::PackReference {
            id: LocalId::new("output-forms-source").expect("pack id"),
            version: "1".to_owned(),
        },
        route: LocalId::new("lookup").expect("route id"),
        digest: sha256_uri(&pack_bytes),
        inputs_schema,
        facts_schema,
        acquisition_posture: project::AcquisitionPosture::RecordTransformed,
        pack_bytes,
        artifacts: BTreeMap::from([
            ("schemas/inputs.json".to_owned(), inputs_bytes),
            ("schemas/facts.json".to_owned(), facts_bytes),
            ("schemas/provider.json".to_owned(), provider_bytes),
            ("scripts/records.rhai".to_owned(), route_script),
        ]),
    }
}

fn compile_project(
    project: &EvidenceProject,
    source_assets: &BTreeMap<String, String>,
) -> Result<compile::CompiledProject, Vec<registry_evidence_authoring::Finding>> {
    compile::compile_with_pack_routes(project, source_assets, &[checked_pack_route()])
}

fn output_mut<'a>(project: &'a mut EvidenceProject, handle: &str) -> &'a mut Output {
    project
        .assertion_definitions
        .values_mut()
        .next()
        .expect("definition")
        .outputs
        .iter_mut()
        .find_map(|(name, output)| (name.as_str() == handle).then_some(output))
        .expect("named Output")
}

#[test]
fn invalid_output_tags_bounds_and_selector_codelist_identity_are_refused_at_their_fields() {
    let mut invalid_type = authored_project();
    output_mut(&mut invalid_type, "boolean").value_type = "boolean-list".to_owned();
    let findings = project::validate_project(&invalid_type);
    assert!(findings.iter().any(|finding| {
        finding.code == "output-type"
            && finding.field.to_json_pointer()
                == "/assertionDefinitions/all-forms/outputs/boolean/type"
    }));

    let mut invalid_bounds = authored_project();
    let integer = output_mut(&mut invalid_bounds, "bounded-integer");
    integer.minimum = Some(Bound::Integer(11));
    integer.maximum = Some(Bound::Integer(10));
    let findings = project::validate_project(&invalid_bounds);
    assert!(findings.iter().any(|finding| {
        finding.code == "output-bounds"
            && finding.field.to_json_pointer()
                == "/assertionDefinitions/all-forms/outputs/bounded-integer"
    }));

    let mut mismatched_assets = assets();
    mismatched_assets.insert(
        "codelists/codes.yaml".to_owned(),
        codelist("urn:example:codelist:codes", &["C-A", "C-B"])
            .replace("\"version\": \"1\"", "\"version\": \"2\""),
    );
    let findings = compile_project(&authored_project(), &mismatched_assets)
        .expect_err("selector codelist version mismatch is refused");
    assert!(findings.iter().any(|finding| {
        finding.code == "codelist-identity"
            && finding.field.to_json_pointer()
                == "/selectorProfiles/record-by-code/fields/record-code/codelist"
    }));
}

#[test]
fn authored_output_ceiling_compiles_into_the_runtime_and_refuses_one_more() {
    let maximum_document = project_document_with_output_count(MAX_OUTPUTS_PER_ASSERTION);
    let maximum_bytes =
        serde_json::to_vec_pretty(&maximum_document).expect("maximum project serializes");
    let maximum_project = project::read_project("evidence.yaml", &maximum_bytes)
        .expect("the authoring ceiling is accepted")
        .value;
    let compiled = compile_project(&maximum_project, &assets()).expect("project compiles");
    assert_eq!(
        compiled.model["requirements"][0]["concepts"]
            .as_array()
            .expect("compiled concepts")
            .len(),
        MAX_OUTPUTS_PER_ASSERTION
    );

    let temporary = tempfile::tempdir().expect("temporary package root");
    let package = temporary.path().join("package");
    fs::create_dir(&package).expect("package directory");
    let _permissions = RestorePermissions(&package);
    write_runtime_bundle(&package, compiled.model, compiled.artifacts);
    seal_tree(&package, 0o400, 0o500);
    let bundle = Bundle::load(&package).expect("the runtime accepts the authored ceiling");
    assert_eq!(
        bundle.config.requirements[0].concepts.len(),
        MAX_OUTPUTS_PER_ASSERTION
    );

    let over_limit = project_document_with_output_count(MAX_OUTPUTS_PER_ASSERTION + 1);
    let over_limit_bytes =
        serde_json::to_vec_pretty(&over_limit).expect("over-limit project serializes");
    let report = project::read_project("evidence.yaml", &over_limit_bytes)
        .expect_err("authoring refuses a project the runtime cannot load");
    let diagnostic = report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.code == "evidence.project.output-count")
        .expect("the output ceiling is diagnosed");
    assert_eq!(diagnostic.path, "/assertionDefinitions/all-forms/outputs");
}

#[test]
fn all_authored_output_forms_compile_load_and_derive_through_the_runtime() {
    let project = authored_project();
    let source_assets = assets();
    let compiled = compile_project(&project, &source_assets).expect("project compiles");
    let concepts = compiled.model["requirements"][0]["concepts"]
        .as_array()
        .expect("compiled concepts");
    assert_eq!(concepts.len(), 12);
    assert_eq!(
        concepts
            .iter()
            .map(|concept| concept["type"].as_str().expect("concept type"))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "audience-scoped-entity-reference",
            "boolean",
            "bounded-decimal",
            "bounded-identifier",
            "bounded-integer",
            "controlled-category",
            "controlled-code",
            "controlled-code-list",
            "date-bucket",
            "entity-reference-list",
            "reviewed-structured-value",
            "time-bucket",
        ])
    );
    for handle in ["date-bucket", "time-bucket"] {
        let concept = concepts
            .iter()
            .find(|concept| concept["handle"] == handle)
            .expect("bucket concept");
        assert!(concept["constraints"].get("codelist").is_none());
    }
    let structured = concepts
        .iter()
        .find(|concept| concept["handle"] == "structured")
        .expect("structured concept");
    assert_eq!(
        structured["constraints"]["schema"],
        "urn:example:schema:structured"
    );
    for path in [
        "codelists/codes.yaml",
        "codelists/categories.yaml",
        "codelists/date-buckets.yaml",
        "codelists/time-buckets.yaml",
        "schemas/structured.schema.json",
    ] {
        assert!(compiled.artifacts.contains_key(path), "missing {path}");
    }
    assert_eq!(
        compiled.artifacts["codelists/codes.yaml"],
        source_assets["codelists/codes.yaml"].as_bytes()
    );

    let temporary = tempfile::tempdir().expect("temporary package root");
    let package = temporary.path().join("package");
    fs::create_dir(&package).expect("package directory");
    let _permissions = RestorePermissions(&package);
    write_runtime_bundle(&package, compiled.model, compiled.artifacts);
    seal_tree(&package, 0o400, 0o500);

    let bundle = Arc::new(Bundle::load(&package).expect("compiled bundle loads in the runtime"));
    let actual_forms = bundle.config.requirements[0]
        .concepts
        .iter()
        .map(|concept| {
            serde_json::to_value(concept.form)
                .expect("concept form serializes")
                .as_str()
                .expect("concept form is a string")
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        actual_forms,
        BTreeSet::from([
            "audience-scoped-entity-reference".to_owned(),
            "boolean".to_owned(),
            "bounded-decimal".to_owned(),
            "bounded-identifier".to_owned(),
            "bounded-integer".to_owned(),
            "controlled-category".to_owned(),
            "controlled-code".to_owned(),
            "controlled-code-list".to_owned(),
            "date-bucket".to_owned(),
            "entity-reference-list".to_owned(),
            "reviewed-structured-value".to_owned(),
            "time-bucket".to_owned(),
        ])
    );
    for path in [
        "codelists/codes.yaml",
        "codelists/categories.yaml",
        "codelists/date-buckets.yaml",
        "codelists/time-buckets.yaml",
    ] {
        assert!(
            bundle.codelists.contains_key(path),
            "runtime omitted {path}"
        );
    }

    let kernel = OfflineKernel::compile(Arc::clone(&bundle)).expect("runtime kernel compiles");
    let values = kernel
        .derive_and_validate(
            "urn:example:requirement:all-output-forms",
            &BTreeMap::from([("marker".to_owned(), json!(true))]),
            Utc.with_ymd_and_hms(2026, 10, 14, 0, 0, 0)
                .single()
                .expect("fixed observation instant"),
            ValueProjection {
                scope: EvidenceScope::AudienceScoped {
                    audience: "urn:example:audience:all-output-forms",
                    request_nonce: "all-output-forms-request",
                },
                binding_key: &[7; 32],
                binding_key_version: 1,
            },
        )
        .expect("all 12 authored values pass the runtime output gate");
    assert_eq!(values.as_slice().len(), 12);
    assert_eq!(
        values
            .as_slice()
            .iter()
            .map(|value| value.provides_value_for.as_str())
            .collect::<BTreeSet<_>>()
            .len(),
        12
    );
}

fn write_runtime_bundle(package: &Path, model: Value, artifacts: BTreeMap<String, Vec<u8>>) {
    let reader = Reader::new("supported-values/evidence.yaml");
    let mut bundle = reader
        .scan(include_bytes!(
            "../../../products/evidence/fixtures/conformance/supported-values/evidence.yaml"
        ))
        .expect("retained bundle parses")
        .expect("retained bundle document")
        .to_json_value();
    let object = bundle.as_object_mut().expect("bundle object");
    for member in [
        "project",
        "acquisitionCapabilities",
        "maximumHolderBoundBatchSize",
        "selectorProfiles",
        "sources",
        "requirements",
        "authorityProfiles",
    ] {
        object.remove(member);
    }
    object.remove("publication");
    bundle["sourceConnections"] = json!({
        "records": {
            "endpoints": [{
                "endpoint": "records",
                "baseUrl": "https://source.invalid",
                "authentication": {"type": "static-authorization"},
                "clientIdentity": "forbidden"
            }]
        }
    });
    bundle["authorityProfiles"] = json!({});
    for (name, value) in model.as_object().expect("compiled model object") {
        bundle[name] = value.clone();
    }
    fs::write(
        package.join("evidence.yaml"),
        serde_json::to_vec_pretty(&bundle).expect("bundle serializes"),
    )
    .expect("bundle writes");
    for (relative, bytes) in artifacts {
        write_asset(package, &relative, &bytes);
    }
    write_asset(
        package,
        "public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json",
        PUBLIC_JWK,
    );
    write_asset(
        package,
        "fixtures/all-forms.yaml",
        br#"apiVersion: id.registrystack.org/formats/evidence/fixture/v1alpha1
kind: EvidenceFixture
syntheticOnly: true
common: {}
privacyExpectation: {}
cases:
  - {id: positive}
  - {id: negative-output}
  - {id: boundary-value}
  - {id: missing-fact}
  - {id: no-match}
  - {id: ambiguous-result}
  - {id: source-failure}
  - {id: anti-reconstruction}
"#,
    );
    write_sum_file(
        package,
        None,
        &evidence_package_limits(),
        "authoring Output form bridge",
    )
    .expect("package checksums write");
}

fn write_asset(root: &Path, relative: &str, bytes: &[u8]) {
    let path = root.join(relative);
    fs::create_dir_all(path.parent().expect("asset parent")).expect("asset parent creates");
    fs::write(path, bytes).expect("asset writes");
}

fn seal_tree(root: &Path, file_mode: u32, directory_mode: u32) {
    for entry in fs::read_dir(root).expect("package directory reads") {
        let path = entry.expect("package member reads").path();
        if path.is_dir() {
            seal_tree(&path, file_mode, directory_mode);
        } else {
            fs::set_permissions(&path, fs::Permissions::from_mode(file_mode))
                .expect("package file permissions change");
        }
    }
    fs::set_permissions(root, fs::Permissions::from_mode(directory_mode))
        .expect("package directory permissions change");
}

struct RestorePermissions<'a>(&'a Path);

impl Drop for RestorePermissions<'_> {
    fn drop(&mut self) {
        seal_tree(self.0, 0o600, 0o700);
    }
}
