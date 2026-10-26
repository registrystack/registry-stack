// SPDX-License-Identifier: Apache-2.0
//! Author inspection retains compiled structure without inventing runtime effects.
use registry_breg::artifacts::{
    inspect_action, inspect_events, inspect_registry, REGISTRY_METADATA_ARTIFACT_PATH,
};
use registry_breg::compiler::{
    compile_project_with_assets, module_digest_with_assets, CompileProfile,
};
use registry_breg::contract::{parse_module_json, parse_project_json, ModuleAssetSource};
use serde_json::{json, Value};

fn source() -> Value {
    registry_platform_yaml::Reader::new("registry.yaml")
        .scan(include_bytes!(
            "../../../products/breg/examples/facility/registry.yaml"
        ))
        .unwrap()
        .unwrap()
        .to_json_value()
}

fn script() -> Vec<u8> {
    let mut bytes = b"// inspection-private-program-canary\n".to_vec();
    bytes.extend_from_slice(include_bytes!(
        "../../../products/breg/examples/facility/plans/correct-address.rhai"
    ));
    bytes
}

fn compile(source: &Value) -> registry_breg::CompiledRegistry {
    compile_project_with_assets(
        &parse_project_json(&serde_json::to_vec(source).unwrap()).unwrap(),
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "plans/correct-address.rhai".into(),
            bytes: script(),
        }],
        CompileProfile::Authoring,
    )
    .unwrap()
}

fn definition<'a>(definitions: &'a Value, id: &str) -> &'a Value {
    definitions
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["id"] == id)
        .unwrap()
}

fn record_mut<'a>(source: &'a mut Value, id: &str) -> &'a mut Value {
    source["recordTypes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|value| value["id"] == id)
        .unwrap()
}

fn validates(subject: &str, mut value: Value) {
    let (schema, kind, version) = match subject {
        "model" => (
            include_str!("../../../products/breg/contracts/explain/ModelExplanation.schema.json"),
            "BRegModelExplanation",
            "v1alpha7",
        ),
        "actions" => (
            include_str!("../../../products/breg/contracts/explain/ActionsExplanation.schema.json"),
            "BRegActionsExplanation",
            "v1alpha7",
        ),
        "access" => (
            include_str!("../../../products/breg/contracts/explain/AccessExplanation.schema.json"),
            "BRegAccessExplanation",
            "v1alpha7",
        ),
        "events" => (
            include_str!("../../../products/breg/contracts/explain/EventsExplanation.schema.json"),
            "BRegEventsExplanation",
            "v1alpha6",
        ),
        _ => unreachable!(),
    };
    if subject == "actions" {
        // Display grouping is a model-explanation member; the actions explanation omits it.
        for action in value["actions"].as_array_mut().unwrap() {
            action.as_object_mut().unwrap().remove("grouping");
        }
    }
    if subject == "model" {
        // The CLI adds source presence; this test covers the compiler projection.
        value["authoring"] = json!({"documents":[{
            "kind":"BRegProject", "file":"registry.yaml", "authoredPaths":[""], "bindings":[]
        }]});
    }
    value["apiVersion"] = json!(format!(
        "id.registrystack.org/formats/breg/{subject}-explanation/{version}"
    ));
    value["kind"] = json!(kind);
    let schema: Value = serde_json::from_str(schema).unwrap();
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .unwrap();
    if let Err(errors) = validator.validate(&value) {
        panic!(
            "{subject} schema: {:?}",
            errors.map(|error| error.to_string()).collect::<Vec<_>>()
        );
    };
}

#[test]
fn model_retains_record_policy_shape_read_paths_and_field_classification() {
    let mut source = source();
    record_mut(&mut source, "directory-entry")["batch"] =
        json!({"maximumItems": 12, "maximumBytes": 16384});
    let registry = compile(&source);
    let model = inspect_registry(&registry);
    let facility = definition(&model["recordTypes"], "facility");
    assert_eq!(
        facility["mutationPolicy"],
        json!({"patch": "proposal-required"})
    );
    assert_eq!(facility["mutationMode"], "mutable");
    assert_eq!(facility["primaryDataset"], "facility-registry");
    assert_eq!(facility["route"], "facilities");
    assert_eq!(
        facility["readPaths"]["operators"]["through"],
        "facility-assignment"
    );
    let assignments = definition(&model["recordTypes"], "facility-assignment");
    assert_eq!(assignments["mutationMode"], "create-only");
    assert_eq!(assignments["indexes"]["by-facility"], json!(["facility"]));
    let directory = definition(&model["recordTypes"], "directory-entry");
    assert_eq!(directory["batch"]["maximumItems"], 12);
    assert_eq!(
        definition(&directory["fields"], "name")["classification"],
        "public"
    );
    assert_eq!(
        definition(&directory["fields"], "email")["classification"],
        "internal"
    );
    let access = serde_json::to_value(registry_breg::access::explain_access(&registry)).unwrap();
    let access_facility = access["recordTypes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|value| value["recordType"] == "facility")
        .unwrap();
    assert_eq!(
        access_facility["mutationPolicy"],
        facility["mutationPolicy"]
    );
    let mut with_modules = model;
    with_modules["version"] = json!(registry.version());
    with_modules["moduleOrder"] = json!(registry.module_order());
    with_modules["moduleClosure"] = json!(registry.module_closure());
    validates("model", with_modules);
    validates("access", access);
}

#[test]
fn author_inspection_identifies_encrypted_fields() {
    let mut source = source();
    record_mut(&mut source, "facility")["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"private-note", "type":"string", "maximumLength":200,
            "classification":"restricted", "encrypted":true
        }));
    let registry = compile(&source);
    let inspection = inspect_registry(&registry);
    let fields = &definition(&inspection["recordTypes"], "facility")["fields"];
    assert_eq!(definition(fields, "private-note")["encrypted"], true);
    assert_eq!(definition(fields, "address-line")["encrypted"], false);
    validates("actions", inspection.clone());
    let mut model = inspection;
    model["version"] = json!(registry.version());
    model["moduleOrder"] = json!(registry.module_order());
    model["moduleClosure"] = json!(registry.module_closure());
    validates("model", model);
}

#[test]
fn model_retains_authored_display_without_inventing_input_labels() {
    let mut source = source();
    let baseline = compile(&source);
    source["accessProfiles"][1]["display"] =
        json!({"label":"Facility reader", "description":"Read the facility directory."});
    source["accessProfiles"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "id":"no-grants", "principalClaim":"registry_principal",
            "requiredScopes":"unrestricted", "display":{"label":"Awaiting permission"}
        }));
    record_mut(&mut source, "facility")["fields"][1]["display"] =
        json!({"label":"Facility name", "description":"Name recorded by the registry."});
    source["actions"][0]["inputs"][1]["display"] = json!({"label":"Operating organisation"});
    let registry = compile(&source);
    let model = inspect_registry(&registry);
    assert_eq!(model["datasets"], source["datasets"]);
    assert_eq!(
        definition(&model["accessProfiles"], "facility-reader")["display"],
        source["accessProfiles"][1]["display"]
    );
    assert_eq!(
        definition(&model["accessProfiles"], "no-grants")["display"]["label"],
        "Awaiting permission"
    );
    let record = definition(&model["recordTypes"], "facility");
    let field_id = source["recordTypes"][2]["fields"][1]["id"]
        .as_str()
        .unwrap();
    assert_eq!(
        definition(&record["fields"], field_id)["display"],
        source["recordTypes"][2]["fields"][1]["display"]
    );
    let action = &source["actions"][0];
    // Action inventory order is an implementation detail; locate the Action by id.
    let inputs = &definition(&model["actions"], action["id"].as_str().unwrap())["inputs"];
    let fallback = definition(inputs, action["inputs"][0]["id"].as_str().unwrap());
    assert_eq!(fallback["label"], fallback["apiName"]);
    assert!(fallback.get("display").is_none());
    let authored = definition(inputs, action["inputs"][1]["id"].as_str().unwrap());
    assert_eq!(authored["display"], action["inputs"][1]["display"]);
    assert_eq!(authored["label"], "Operating organisation");
    let access = serde_json::to_value(registry_breg::access::explain_access(&registry)).unwrap();
    assert_eq!(access["accessProfiles"], model["accessProfiles"]);
    assert_eq!(
        registry.routes(),
        baseline.routes(),
        "display adds no route or grant"
    );
    assert_ne!(
        registry.revision(),
        baseline.revision(),
        "authored display is hash-covered"
    );
}

#[test]
fn omitted_and_empty_profile_display_have_identical_compiled_meaning() {
    let mut source = source();
    let omitted = compile(&source);
    for profile in source["accessProfiles"].as_array_mut().unwrap() {
        profile["display"] = json!({});
    }
    let explicit_empty = compile(&source);
    assert_eq!(omitted, explicit_empty);
}

#[test]
fn profile_dataset_and_hook_displays_refuse_record_title_selection() {
    let mut source = source();
    source["statisticalDatasets"] = json!([{
        "id":"counts", "unit":"facility", "population":"active eq true",
        "period":{"type":"flow", "field":"date", "granularity":"month", "firstPeriod":"2025-01"},
        "dimensions":["active"]
    }]);
    source["recordTypes"][0]["hooks"] = json!([{
        "id":"record-observer", "phase":"after", "trigger":"patched", "projection":["name"],
        "handler":{"type":"url", "destinationId":"record-events"}
    }]);
    let proposal = source["actions"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|action| action["execution"]["mode"] == "proposal")
        .unwrap();
    proposal["execution"]["proposal"]["hooks"] = json!([{
        "id":"proposal-observer", "handler":{"type":"url", "destinationId":"proposal-events"}
    }]);
    let proposal_index = source["actions"]
        .as_array()
        .unwrap()
        .iter()
        .position(|action| action["execution"]["mode"] == "proposal")
        .unwrap();
    for pointer in [
        "/accessProfiles/0".to_owned(),
        "/statisticalDatasets/0".to_owned(),
        "/recordTypes/0/hooks/0".to_owned(),
        format!("/actions/{proposal_index}/execution/proposal/hooks/0"),
    ] {
        let mut changed = source.clone();
        changed.pointer_mut(&pointer).unwrap()["display"] = json!({"titleField":"name"});
        let report = registry_breg::contract::read_project_yaml(
            "registry.json",
            &serde_json::to_vec(&changed).unwrap(),
        )
        .expect_err("only Record display selects a title field");
        assert!(
            report.diagnostics().iter().any(|diagnostic| {
                diagnostic.code == "config.unknown-key"
                    && diagnostic.path == format!("{pointer}/display/titleField")
            }),
            "{report:?}"
        );
    }
}

#[test]
fn function_ceilings_fixed_clears_and_literal_null_remain_distinct() {
    let mut source = source();
    let city = record_mut(&mut source, "facility")["fields"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|value| value["id"] == "city")
        .unwrap();
    city["required"] = json!(false);
    let effect = source["actions"][2]["plan"]["effects"][0]
        .as_object_mut()
        .unwrap();
    effect.remove("set");
    effect.insert("clear".into(), json!(["city"]));
    let registry = compile(&source);
    let model = inspect_registry(&registry);
    let function = definition(&model["actions"], "correct-address");
    assert_eq!(function["plan"]["type"], "function");
    assert!(function["plan"].get("effects").is_none());
    assert!(function["plan"].get("order").is_none());
    assert_eq!(
        function["plan"]["function"]["source"],
        "plans/correct-address.rhai"
    );
    assert!(function["plan"]["function"]["sourceModule"].is_null());
    assert_eq!(
        function["plan"]["function"]["writes"][0]["fields"],
        json!(["address-line", "city", "postal-code"])
    );
    let fixed = definition(&model["actions"], "deactivate-facility");
    assert_eq!(fixed["plan"]["type"], "fixed");
    assert!(fixed["plan"].get("function").is_none());
    assert_eq!(
        fixed["plan"]["effects"][0]["mutations"][0],
        json!({"kind":"clear", "field":"city"})
    );
    // The source reader requires explicit clear, but the compiled value algebra
    // also represents literal null. Preserve that value for a fixed plan rather
    // than applying the function-ceiling placeholder rule to every mutation.
    let mut fixed_literal = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "deactivate-facility")
        .unwrap()
        .clone();
    fixed_literal.effects[0].mutations = vec![registry_breg::model::CompiledPlanMutation::Set {
        field: "city".into(),
        value: registry_breg::model::CompiledPlanValue::Literal { value: Value::Null },
    }];
    assert_eq!(
        inspect_action(&fixed_literal)["plan"]["effects"][0]["mutations"][0],
        json!({"kind":"set", "field":"city", "value":{"kind":"literal", "value":null}})
    );
    let revision_guard = &function["commitGuards"][0];
    assert_eq!(revision_guard["revisionUnchanged"], true);
    for unused in ["field", "atLeast", "atMost", "currentDate"] {
        assert!(
            revision_guard.get(unused).is_none(),
            "unused guard member {unused}"
        );
    }
    let access = serde_json::to_value(registry_breg::access::explain_access(&registry)).unwrap();
    let mut model_actions = model["actions"].clone();
    for action in model_actions.as_array_mut().unwrap() {
        action.as_object_mut().unwrap().remove("grouping");
    }
    assert_eq!(access["actions"]["actions"], model_actions);
    assert!(!function["permissions"].as_array().unwrap().is_empty());
    let public: Value = serde_json::from_slice(
        &registry
            .artifacts()
            .get(REGISTRY_METADATA_ARTIFACT_PATH)
            .unwrap()
            .bytes,
    )
    .unwrap();
    let public_function = definition(&public["actions"], "correct-address");
    for author_only in ["plan", "handler", "permissions", "commitGuards"] {
        assert!(public_function.get(author_only).is_none());
    }
    assert!(!public.to_string().contains("plans/correct-address.rhai"));
    validates("actions", model.clone());
    validates("access", access.clone());
    for output in [model, access, public] {
        assert!(!output
            .to_string()
            .contains("inspection-private-program-canary"));
        assert!(!output.to_string().contains("scriptBytes"));
    }
}

#[test]
fn function_inspection_retains_relative_asset_and_module_identity() {
    let mut source = source();
    let module = parse_module_json(
        &serde_json::to_vec(&json!({
            "apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1", "kind":"BRegModule",
            "id":"address-functions", "version":"1", "functions":source["functions"]
        }))
        .unwrap(),
    )
    .unwrap();
    source["functions"] = json!([]);
    let assets = [ModuleAssetSource {
        module: Some("address-functions".into()),
        path: "plans/correct-address.rhai".into(),
        bytes: script(),
    }];
    source["modules"] = json!([{"id":"address-functions", "version":"1", "digest":module_digest_with_assets(&module, &assets)}]);
    let registry = compile_project_with_assets(
        &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
        &[module],
        &assets,
        CompileProfile::Authoring,
    )
    .unwrap();
    let action = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "correct-address")
        .unwrap();
    let function = &inspect_action(action)["plan"]["function"];
    assert_eq!(function["source"], "plans/correct-address.rhai");
    assert_eq!(function["sourceModule"], "address-functions");
}

#[test]
fn dataset_inventory_includes_dataset_only_profile_authentication() {
    let mut source = source();
    record_mut(&mut source, "directory-entry")["fields"]
        .as_array_mut()
        .unwrap()
        .extend([
            json!({"id":"active", "type":"boolean", "required":true, "classification":"internal"}),
            json!({"id":"event-date", "type":"date", "required":true, "classification":"internal"}),
        ]);
    source["statisticalDatasets"] = json!([{"id":"directory-counts", "display":{"label":"Directory counts"}, "unit":"directory-entry", "population":"active eq true",
        "period":{"type":"flow", "field":"event-date", "granularity":"month", "firstPeriod":"2025-01"},
        "dimensions":["active"], "disclosure":{"minimumCount":5, "roundingBase":5}}]);
    source["accessProfiles"].as_array_mut().unwrap().extend([
        json!({"id":"statistics-publisher", "principalClaim":"registry_principal", "requiredScopes":["statistics:publish"],
            "permissions":{"records":[{"recordType":"directory-entry", "operations":["list"], "readableFields":["active","event-date"],
                "filterableFields":["active","event-date"], "rowBoundaries":"unrestricted", "allowCount":true}],
                "datasets":[{"dataset":"directory-counts", "operations":["publish","read-releases"]}]}}),
        json!({"id":"statistics-reader", "default":true, "actorKind":"service", "principalClaim":"dataset_subject",
            "requesterClients":["statistics-reader-client"],
            "requiredScopes":["statistics:read"], "requiredPurposes":["research"],
            "permissions":{"datasets":[{"dataset":"directory-counts", "operations":["read-releases"]}]}}),
    ]);
    let registry = compile(&source);
    let model = inspect_registry(&registry);
    let dataset = definition(&model["statisticalDatasets"], "directory-counts");
    assert_eq!(dataset["display"]["label"], "Directory counts");
    assert_eq!(dataset["unitEntityId"], "directory-entry");
    assert_eq!(dataset["dimensions"][0]["field"], "active");
    let access = serde_json::to_value(registry_breg::access::explain_access(&registry)).unwrap();
    let audience = &access["statisticalDatasets"][0];
    assert_eq!(audience["display"], dataset["display"]);
    let publisher = &access["recordTypes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|record| record["recordType"] == "directory-entry")
        .unwrap()["profiles"];
    let publisher = definition(publisher, "statistics-publisher");
    assert_eq!(publisher["rowBoundaries"], "unrestricted");
    assert_eq!(publisher["allowCount"], true);
    let warning = registry
        .findings()
        .iter()
        .find(|finding| {
            finding.code == "breg.access.profile-unrestricted-collection"
                && finding.path.contains("statistics-publisher")
        })
        .expect("publisher-wide access remains reviewable");
    assert!(warning
        .message
        .contains("publishers require unrestricted reads"));
    validates("access", access.clone());
    assert!(audience["readReleases"]
        .as_array()
        .unwrap()
        .contains(&json!("statistics-reader")));
    let reader = definition(&audience["accessProfiles"], "statistics-reader");
    assert_eq!(reader["principalClaim"], "dataset_subject");
    assert_eq!(reader["requiredScopes"], json!(["statistics:read"]));
    assert_eq!(reader["requiredPurposes"], json!(["research"]));
    assert_eq!(reader["actorKind"], "service");
    assert_eq!(reader["default"], true);
    assert!(access["recordTypes"]
        .as_array()
        .unwrap()
        .iter()
        .all(|record| {
            record["profiles"]
                .as_array()
                .unwrap()
                .iter()
                .all(|profile| profile["id"] != "statistics-reader")
        }));
}

#[test]
fn event_inspection_uses_owner_hooks_for_phase_and_transitions() {
    let mut source = source();
    record_mut(&mut source, "facility")["hooks"] = json!([{"id":"facility-patched", "display":{"label":"Facility changed"}, "phase":"after", "trigger":"patched",
        "projection":["address-line"], "when":{"type":"fields", "changed":["address-line"]},
        "handler":{"type":"url", "destinationId":"facility-observer"}}]);
    source["actions"][1]["execution"]["proposal"]["hooks"] = json!([
        {"id":"proposal-settled", "display":{"label":"Proposal update"}, "transitions":["applied","submitted"], "handler":{"type":"url", "destinationId":"proposal-observer"}},
        {"id":"proposal-any", "handler":{"type":"url", "destinationId":"all-transitions"}},
    ]);
    let registry = compile(&source);
    let events = inspect_events(&registry);
    let deliveries = events["deliveries"].as_array().unwrap();
    let record = deliveries
        .iter()
        .find(|event| event["eventId"] == "facility-patched")
        .unwrap();
    assert_eq!(record["phase"], "after");
    assert_eq!(record["handlerType"], "url");
    assert_eq!(record["projectionFields"], json!(["address-line"]));
    assert!(record.get("envelopeFields").is_none());
    assert!(record.get("includesRecordValues").is_none());
    assert_eq!(
        record["when"],
        json!({"type":"fields", "changed":["address-line"]})
    );
    assert!(record.get("transitions").is_none());
    let proposal = deliveries
        .iter()
        .find(|event| event["eventId"] == "proposal-settled")
        .unwrap();
    assert_eq!(proposal["phase"], "after");
    assert_eq!(proposal["handlerType"], "url");
    let schema = registry_breg::proposal_hooks::proposal_event_schema();
    assert_eq!(
        proposal["envelopeFields"],
        json!(schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>())
    );
    assert_eq!(proposal["includesRecordValues"], false);
    assert_eq!(proposal["projectionFields"], json!([]));
    assert!(!proposal["envelopeFields"]
        .as_array()
        .unwrap()
        .contains(&json!("address-line")));
    assert_eq!(proposal["transitions"], json!(["submitted", "applied"]));
    let all = deliveries
        .iter()
        .find(|event| event["eventId"] == "proposal-any")
        .unwrap();
    assert_eq!(
        all["transitions"],
        json!([
            "started",
            "edited",
            "submitted",
            "revised",
            "rebased",
            "retried",
            "cancelled",
            "applied",
            "rejected",
            "review-returned"
        ])
    );
    let model = inspect_registry(&registry);
    assert_eq!(
        definition(&model["recordTypes"], "facility")["hooks"]["facility-patched"]["display"]
            ["label"],
        "Facility changed"
    );
    let proposal_hooks =
        &definition(&model["actions"], "correct-address")["execution"]["proposal"]["hooks"];
    assert_eq!(
        definition(proposal_hooks, "proposal-settled")["display"]["label"],
        "Proposal update"
    );
    assert_eq!(
        definition(&model["recordTypes"], "facility")["hooks"]["facility-patched"]["when"],
        record["when"]
    );
    assert!(!events
        .to_string()
        .contains("inspection-private-program-canary"));
    validates("events", events);
}

#[test]
fn derived_field_inspection_keeps_schema_and_asset_identity_without_sql_bytes() {
    let mut source = source();
    record_mut(&mut source, "directory-entry")["derived"] = json!([{
        "id":"contact-summary", "sql":"sql/contact-summary.sql", "key":"id", "execution":"live",
        "fields":[{"id":"has-contact", "type":"boolean", "classification":"internal"}]
    }]);
    let registry = compile_project_with_assets(
        &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(), &[],
        &[
            ModuleAssetSource { module:None, path:"plans/correct-address.rhai".into(), bytes:script() },
            ModuleAssetSource { module:None, path:"sql/contact-summary.sql".into(),
                bytes:b"SELECT d.id AS id, true AS has_contact FROM registry_source.directory_entry d -- inspection-private-sql-canary\n".to_vec() },
        ], CompileProfile::Authoring,
    ).unwrap();
    let model = inspect_registry(&registry);
    let directory = definition(&model["recordTypes"], "directory-entry");
    let field = definition(&directory["fields"], "has-contact");
    assert_eq!(field["derivation"], "contact-summary");
    assert_eq!(field["classification"], "internal");
    assert_eq!(
        directory["derivedRelations"][0]["source"],
        "sql/contact-summary.sql"
    );
    assert!(directory["derivedRelations"][0]["sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert!(!model.to_string().contains("inspection-private-sql-canary"));
    assert!(!model.to_string().contains("SELECT d.id"));
    assert!(!model.to_string().contains("sqlBytes"));
}

#[test]
fn project_display_and_review_authorities_are_retained_and_revision_bound() {
    let source = source();
    let original = compile(&source);
    let inspection = inspect_registry(&original);
    assert_eq!(inspection["display"], source["project"]["display"]);
    assert_eq!(inspection["reviewAuthorities"], source["reviewAuthorities"]);
    assert_eq!(
        inspection["reviewAuthorities"][0]["protocol"],
        "id.registrystack.org/protocols/review/v1"
    );
    let effective: Value = serde_json::from_slice(
        &original
            .artifacts()
            .get("compiled/effective-model.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    assert_eq!(effective["display"], inspection["display"]);
    assert_eq!(
        effective["reviewAuthorities"],
        inspection["reviewAuthorities"]
    );
    let serialized = serde_json::to_value(&original).unwrap();
    assert_eq!(serialized["display"], inspection["display"]);
    assert_eq!(
        serialized["reviewAuthorities"],
        inspection["reviewAuthorities"]
    );

    for pointer in [
        "/project/display/label",
        "/reviewAuthorities/0/display/description",
    ] {
        let mut changed = source.clone();
        *changed.pointer_mut(pointer).unwrap() = json!("Changed author display");
        let changed = compile(&changed);
        assert_ne!(
            changed.revision(),
            original.revision(),
            "retained source metadata binds the artifact inventory: {pointer}"
        );
        assert_eq!(
            changed.actions().actions[1].definition_revision,
            original.actions().actions[1].definition_revision,
            "display-only source metadata does not change frozen Action execution semantics"
        );
    }
    validates("actions", inspection.clone());
    let mut model = inspection;
    model["version"] = json!(original.version());
    model["moduleOrder"] = json!(original.module_order());
    model["moduleClosure"] = json!(original.module_closure());
    validates("model", model);
}

#[test]
fn omitted_project_display_and_review_authorities_keep_empty_artifact_shape() {
    let mut source = registry_breg::contract::parse_project_yaml(include_bytes!(
        "../../../products/breg/examples/minimal/registry.yaml"
    ))
    .unwrap();
    source.project.display = Default::default();
    let registry =
        compile_project_with_assets(&source, &[], &[], CompileProfile::Authoring).unwrap();
    let effective: Value = serde_json::from_slice(
        &registry
            .artifacts()
            .get("compiled/effective-model.json")
            .unwrap()
            .bytes,
    )
    .unwrap();
    assert!(effective.get("display").is_none());
    assert!(effective.get("reviewAuthorities").is_none());
    assert_eq!(inspect_registry(&registry)["display"], json!({}));
    assert_eq!(inspect_registry(&registry)["reviewAuthorities"], json!([]));
}

#[test]
fn model_retains_event_record_descriptor_and_display_grouping() {
    let source = registry_platform_yaml::Reader::new("registry.yaml")
        .scan(include_bytes!("fixtures/event-record/shapes.yaml"))
        .unwrap()
        .unwrap()
        .to_json_value();
    let registry = registry_breg::compiler::compile_project(
        &parse_project_json(&serde_json::to_vec(&source).unwrap()).unwrap(),
        &[],
        CompileProfile::Authoring,
    )
    .unwrap();
    let model = inspect_registry(&registry);
    let mut with_modules = model.clone();
    with_modules["version"] = json!(registry.version());
    with_modules["moduleOrder"] = json!(registry.module_order());
    with_modules["moduleClosure"] = json!(registry.module_closure());
    validates("model", with_modules);

    let registration = definition(&model["recordTypes"], "entry-registration");
    assert_eq!(registration["eventRecord"]["descriptorVersion"], 1);
    assert_eq!(registration["eventRecord"]["label"], "Entry registered");
    assert_eq!(
        registration["eventRecord"]["recordedTime"],
        json!({"source": "creation-revision"})
    );
    assert_eq!(
        registration["grouping"],
        json!({"group": "Register", "purpose": "domain"})
    );

    let ordinary = definition(&model["recordTypes"], "entry");
    assert_eq!(
        ordinary["eventRecord"],
        Value::Null,
        "an undeclared descriptor is an explicit null in the author view"
    );
    assert_eq!(
        definition(&model["recordTypes"], "review-note")["grouping"],
        json!({"group": "Register", "purpose": "processing"})
    );
    assert_eq!(
        definition(&model["actions"], "seed-demonstration-entries")["grouping"],
        json!({"group": "Demonstration data", "purpose": "synthetic-seed"})
    );
    for action in model["actions"].as_array().unwrap() {
        assert!(
            action.as_object().unwrap().contains_key("grouping"),
            "every model action carries a grouping key: {}",
            action["id"]
        );
    }

    let grouped = registry
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "seed-demonstration-entries")
        .unwrap();
    assert!(
        inspect_action(grouped).get("grouping").is_none(),
        "grouping is added around inspect_action, not inside it"
    );
}
