use registry_evidence_authoring::{acquisition_validation, project::EvidenceProject};
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

fn project(value: Value) -> EvidenceProject {
    serde_json::from_value(value).expect("test project shape")
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

fn has(findings: &[registry_evidence_authoring::Finding], code: &str, path: &str) -> bool {
    findings
        .iter()
        .any(|finding| finding.code == code && finding.field.to_json_pointer() == path)
}

#[test]
fn valid_two_member_fetch_set_matches_the_retained_runtime_shape() {
    let mut value = project_value();
    fetch_set(
        &mut value,
        json!([
            {"source": "member-a", "factInputs": ["record-id"]},
            {"source": "member-b", "factInputs": ["record-id"]}
        ]),
    );
    assert!(acquisition_validation::validate(&project(value)).is_empty());
}

#[test]
fn fetch_set_refuses_one_or_five_members_at_the_fetch_field() {
    for (members, expected) in [
        (vec!["member-a"], 1usize),
        (
            vec!["member-a", "member-b", "third", "fourth", "fifth"],
            5usize,
        ),
    ] {
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
        let findings = acquisition_validation::validate(&project(value));
        assert!(
            has(
                &findings,
                "acquisition-fetch-count",
                "/assertionDefinitions/status/acquisition/fetch"
            ),
            "{expected} members: {findings:?}"
        );
    }
}

#[test]
fn fetch_member_fact_inputs_are_bounded_named_and_resolved() {
    for (inputs, code, path) in [
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
    ] {
        let mut value = project_value();
        fetch_set(
            &mut value,
            json!([
                {"source": "member-a", "factInputs": inputs},
                {"source": "member-b", "factInputs": ["record-id"]}
            ]),
        );
        let findings = acquisition_validation::validate(&project(value));
        assert!(has(&findings, code, path), "{findings:?}");
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
fn fetch_set_refuses_fact_overlap_and_a_merged_set_above_64() {
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
    let findings = acquisition_validation::validate(&project(overlap));
    assert!(has(
        &findings,
        "acquisition-fact-overlap",
        "/sources/member-a/facts/record-id"
    ));

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
    let findings = acquisition_validation::validate(&project(too_wide));
    assert!(has(
        &findings,
        "acquisition-fact-count",
        "/assertionDefinitions/status/acquisition"
    ));
}

fn facts(prefix: &str, count: usize) -> Value {
    Value::Object(
        (0..count)
            .map(|index| (format!("{prefix}-{index}"), json!({"type": "boolean"})))
            .collect(),
    )
}

#[test]
fn fetch_set_requires_its_package_capability() {
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
    let findings = acquisition_validation::validate(&project(value));
    assert!(has(
        &findings,
        "acquisition-capability",
        "/acquisitionCapabilities"
    ));
}

#[test]
fn initial_selectors_and_fetch_member_path_bindings_keep_their_runtime_roles() {
    let mut no_search_selectors = project_value();
    no_search_selectors["sources"]["search"]["selectors"] = json!([]);
    let findings = acquisition_validation::validate(&project(no_search_selectors));
    assert!(has(
        &findings,
        "acquisition-initial-selectors",
        "/sources/search/selectors"
    ));

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
    let findings = acquisition_validation::validate(&project(narrowed));
    assert!(has(
        &findings,
        "acquisition-binding-input",
        "/sources/member-a/request/pathBindings/record-id"
    ));
}

#[test]
fn classic_single_and_search_then_fetch_keep_their_original_fact_rules() {
    let single = project(project_value());
    assert!(acquisition_validation::validate(&single).is_empty());

    let mut classic = project_value();
    classic["sources"]["member-a"]["facts"] = classic["sources"]["search"]["facts"].clone();
    classic["assertionDefinitions"]["status"]["acquisition"] =
        json!({"type": "search-then-fetch", "search": "search", "fetch": "member-a"});
    let findings = acquisition_validation::validate(&project(classic));
    assert!(
        findings.is_empty(),
        "classic derivation receives only fetch facts and permits names also used by search: {findings:?}"
    );
}
