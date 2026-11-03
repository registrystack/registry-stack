use registry_evidence_authoring::project::EvidenceProject;
use serde_json::{json, Value};

fn project_value() -> Value {
    json!({
        "id": "acquisition-validation",
        "selectorProfiles": {
            "person-by-id": {
                "maximumAggregateBytes": 64,
                "fields": {"person-id": {"type": "string", "minimumBytes": 1, "maximumBytes": 64}}
            }
        },
        "functions": [
            {"id": "extract", "interface": "source-extract/v1", "source": "functions/extract.rhai"},
            {"id": "derive", "interface": "assertion-derive/v1", "source": "functions/derive.rhai"}
        ],
        "sources": {
            "search": source(
                json!([{"role": "person", "profiles": ["person-by-id"]}]),
                "/search/{person-id}",
                json!({"person-id": {"selector": {"role": "person", "profile": "person-by-id", "field": "person-id"}}}),
                json!({"record-id": {"type": "string", "minimumBytes": 1, "maximumBytes": 64}, "search-state": {"type": "boolean"}})
            ),
            "member-a": source(
                json!([]),
                "/a",
                json!({}),
                json!({"registry-a": {"type": "boolean"}})
            ),
            "member-b": source(
                json!([]),
                "/b",
                json!({}),
                json!({"registry-b": {"type": "boolean"}})
            )
        },
        "assertionDefinitions": {
            "status": {
                "question": "What is the status?",
                "semantics": {"requirement": "urn:example:requirement:status", "kind": "criterion", "evidenceType": "urn:example:evidence:status", "referenceFrameworks": ["urn:example:framework"]},
                "purpose": "status-check",
                "grantCeiling": {"authorities": ["organizational"], "actorKinds": ["service"], "valueOrigins": ["request"], "audiences": ["urn:example:audience"]},
                "subjects": [{"role": "person", "selectors": ["person-by-id"]}],
                "acquisition": {"type": "single", "source": "search"},
                "derive": {"function": "derive"},
                "outputs": {"active": {"concept": "urn:example:active", "type": "boolean"}},
                "validitySeconds": 300,
                "subjectBinding": "audience-scoped",
                "representations": ["signed-jws"]
            }
        }
    })
}

fn source(selectors: Value, path: &str, path_bindings: Value, facts: Value) -> Value {
    json!({
        "type": "http-json",
        "connection": "records",
        "acquisitionPosture": "record-transformed",
        "selectors": selectors,
        "request": {"method": "GET", "path": path, "pathBindings": path_bindings, "fixedHeaders": []},
        "response": {"projection": ["/record"], "shape": {"type": "object", "required": ["record"], "properties": {"record": {"type": "boolean"}}}, "maximumBytes": 4096},
        "extract": {"function": "extract"},
        "facts": facts,
        "limits": {"attemptTimeoutMilliseconds": 2000, "maximumConcurrency": 4}
    })
}

fn fetch_set(value: &mut Value, members: Value) {
    value["acquisitionCapabilities"] = json!(["search-then-fetch-set"]);
    value["assertionDefinitions"]["status"]["acquisition"] = json!({
        "type": "search-then-fetch-set",
        "search": "search",
        "fetch": members,
        "maximumAcquisitionMilliseconds": 3000
    });
}

fn assert_retired_wire_refused(value: Value, member: &str) {
    let refusal = serde_json::from_value::<EvidenceProject>(value)
        .expect_err("the retired source/acquisition grammar must stay closed")
        .to_string();
    assert!(
        refusal.contains(member),
        "the refusal did not identify {member}: {refusal}"
    );
}

#[test]
fn former_valid_two_member_fetch_set_is_refused_by_the_pack_binding_shape() {
    let mut value = project_value();
    fetch_set(
        &mut value,
        json!([
            {"source": "member-a", "factInputs": ["record-id"]},
            {"source": "member-b", "factInputs": ["record-id"]}
        ]),
    );
    assert_retired_wire_refused(value, "acquisitionCapabilities");
}

#[test]
fn retired_fetch_set_cardinalities_are_both_refused_before_semantic_validation() {
    for members in [
        (vec!["member-a"], 1usize),
        (
            vec!["member-a", "member-b", "third", "fourth", "fifth"],
            5usize,
        ),
    ]
    .map(|(members, _)| members)
    {
        let mut value = project_value();
        for source_id in members.iter().skip(2) {
            value["sources"][*source_id] = source(
                json!([]),
                &format!("/{source_id}"),
                json!({}),
                json!({format!("{source_id}-fact"): {"type": "boolean"}}),
            );
        }
        fetch_set(
            &mut value,
            Value::Array(
                members
                    .into_iter()
                    .map(|source| json!({"source": source, "factInputs": ["record-id"]}))
                    .collect(),
            ),
        );
        assert_retired_wire_refused(value, "acquisitionCapabilities");
    }
}

#[test]
fn retired_fetch_member_fact_input_variants_are_all_refused() {
    for inputs in [
        (
            json!([]),
            "acquisition-fact-input-count",
            "/assertionDefinitions/status/acquisition/fetch/0/factInputs",
        ),
        (
            json!(["missing"]),
            "acquisition-fact-input",
            "/assertionDefinitions/status/acquisition/fetch/0/factInputs/0",
        ),
        (
            json!(["Bad_Fact"]),
            "acquisition-fact-input-name",
            "/assertionDefinitions/status/acquisition/fetch/0/factInputs/0",
        ),
    ]
    .map(|(inputs, _, _)| inputs)
    {
        let mut value = project_value();
        fetch_set(
            &mut value,
            json!([
                {"source": "member-a", "factInputs": inputs},
                {"source": "member-b", "factInputs": ["record-id"]}
            ]),
        );
        assert_retired_wire_refused(value, "acquisitionCapabilities");
    }

    let mut duplicate = project_value();
    fetch_set(
        &mut duplicate,
        json!([
            {"source": "member-a", "factInputs": ["record-id", "record-id"]},
            {"source": "member-b", "factInputs": ["record-id"]}
        ]),
    );
    assert!(
        serde_json::from_value::<EvidenceProject>(duplicate).is_err(),
        "the shared UniqueList reader must refuse duplicate factInputs"
    );
}

#[test]
fn retired_fetch_set_overlap_and_width_variants_are_refused() {
    let mut overlap = project_value();
    overlap["sources"]["member-a"]["facts"] =
        json!({"record-id": {"type": "string", "minimumBytes": 1, "maximumBytes": 64}});
    fetch_set(
        &mut overlap,
        json!([
            {"source": "member-a", "factInputs": ["record-id"]},
            {"source": "member-b", "factInputs": ["record-id"]}
        ]),
    );
    assert_retired_wire_refused(overlap, "acquisitionCapabilities");

    let mut too_wide = project_value();
    too_wide["sources"]["search"]["facts"] = facts("search", 22);
    too_wide["sources"]["search"]["facts"]["record-id"] =
        json!({"type": "string", "minimumBytes": 1, "maximumBytes": 64});
    too_wide["sources"]["member-a"]["facts"] = facts("first", 21);
    too_wide["sources"]["member-b"]["facts"] = facts("second", 21);
    fetch_set(
        &mut too_wide,
        json!([
            {"source": "member-a", "factInputs": ["record-id"]},
            {"source": "member-b", "factInputs": ["record-id"]}
        ]),
    );
    assert_retired_wire_refused(too_wide, "acquisitionCapabilities");
}

fn facts(prefix: &str, count: usize) -> Value {
    Value::Object(
        (0..count)
            .map(|index| (format!("{prefix}-{index}"), json!({"type": "boolean"})))
            .collect(),
    )
}

#[test]
fn retired_fetch_set_without_the_capability_is_still_refused() {
    let mut value = project_value();
    fetch_set(
        &mut value,
        json!([
            {"source": "member-a", "factInputs": ["record-id"]},
            {"source": "member-b", "factInputs": ["record-id"]}
        ]),
    );
    value
        .as_object_mut()
        .unwrap()
        .remove("acquisitionCapabilities");
    assert_retired_wire_refused(value, "fetch");
}

#[test]
fn retired_initial_selector_and_fetch_binding_variants_are_refused() {
    let mut no_search_selectors = project_value();
    no_search_selectors["sources"]["search"]["selectors"] = json!([]);
    assert_retired_wire_refused(no_search_selectors, "type");

    let mut narrowed = project_value();
    narrowed["sources"]["member-a"]["request"]["pathBindings"]["record-id"] =
        json!({"fact": {"field": "search-state"}});
    fetch_set(
        &mut narrowed,
        json!([
            {"source": "member-a", "factInputs": ["record-id"]},
            {"source": "member-b", "factInputs": ["record-id"]}
        ]),
    );
    assert_retired_wire_refused(narrowed, "acquisitionCapabilities");
}

#[test]
fn retired_single_and_search_then_fetch_variants_are_refused() {
    assert_retired_wire_refused(project_value(), "type");

    let mut classic = project_value();
    classic["sources"]["member-a"]["facts"] = classic["sources"]["search"]["facts"].clone();
    classic["assertionDefinitions"]["status"]["acquisition"] =
        json!({"type": "search-then-fetch", "search": "search", "fetch": "member-a"});
    assert_retired_wire_refused(classic, "fetch");
}
