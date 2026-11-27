// SPDX-License-Identifier: Apache-2.0
//! A Proposal Action's create or patch effect can promote one Proposal file
//! into a record slot of its target record type. The compiler refuses every
//! promotion the record slot could not hold.

use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::CompileFailure;
use serde_json::{json, Value};

const CODE: &str = "breg.action.attachment-invalid";

fn source() -> Value {
    json!({"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject",
        "project":{"id":"promotion-compiler","version":"1","defaultLanguage":"en",
            "canonicalBaseIri":"https://promotion.example.test"},
        "datasets":{"directory":{}},
        "recordTypes":{
            "application":{"primaryDataset":"directory","route":"applications","mutationMode":"mutable",
                "fields":[{"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"},
                    {"id":"note","type":"string","required":false,"maximumLength":64,"classification":"internal"}],
                "attachments":[{"id":"evidence","maximumBytes":64,"contentTypes":["text/plain","application/pdf"],
                    "classification":"restricted","writeOnce":true}]}},
        "actions":{
            "amend":{"execution":{"mode":"proposal","proposal":{"review":{"type":"none"},
                    "application":{"mode":"manual"},"retention":{"mode":"operator-erase"},
                    "attachments":[{"id":"document","required":false,"maximumBytes":64,
                        "contentTypes":["text/plain"],"classification":"restricted"}]}},
                "inputs":[{"id":"target","type":"reference","target":"application","required":true,"classification":"internal"},
                    {"id":"name","type":"string","required":true,"maximumLength":64,"classification":"internal"}],
                "commitGuards":{"targets":[{"input":"target","revision":"unchanged"}]},
                "plan":{"type":"fixed","effects":[
                    {"id":"copy","target":{"recordType":"application"},"operation":"create",
                        "set":{"name":{"fromInput":"name"}},
                        "attachments":{"evidence":{"fromAttachment":"document"}}},
                    {"id":"original","target":{"fromInput":"target"},"operation":"patch",
                        "set":{"name":{"fromInput":"name"}},
                        "attachments":{"evidence":{"fromAttachment":"document"}}}]}}},
        "accessProfiles":{
            "clerk":{"default":true,"principalClaim":"sub","requiredScopes":["application:manage"],
                "requiredPurposes":["registry-administration"],"permissions":{
                    "records":[{"recordType":"application","operations":["get","list"],
                        "readableFields":["name","note"],"readableAttachments":["evidence"],
                        "rowBoundaries":"unrestricted"}],
                    "actions":[{"action":"amend","operations":["start"],"targets":[
                        {"recordType":"application","rowBoundaries":"unrestricted"}]}],
                    "proposals":[{"action":"amend","operations":["get","list","edit","submit","apply"],
                        "ownership":"caller","readableInputs":["target","name"],"readableAttachments":["document"],
                        "writableAttachments":["document"],"targets":[
                            {"recordType":"application","rowBoundaries":"unrestricted"}]}]}}}})
}

fn addition_source() -> Value {
    mutated(|source| {
        source["actions"]["amend"]["execution"]["proposal"]["additions"] = json!({
            "id":"supporting","maximumBytes":64,"maximumCount":2,
            "contentTypes":["text/plain"],"classification":"restricted"});
        let grant = &mut source["accessProfiles"]["clerk"]["permissions"]["proposals"][0];
        grant["operations"]
            .as_array_mut()
            .unwrap()
            .push(json!("add"));
        grant["readableAttachments"]
            .as_array_mut()
            .unwrap()
            .push(json!("supporting"));
        grant["writableAttachments"]
            .as_array_mut()
            .unwrap()
            .push(json!("supporting"));
    })
}

#[test]
fn additions_compile_as_an_optional_bounded_slot() {
    let compiled = compile(&addition_source()).expect("declared additions compile");
    let execution = serde_json::to_value(&compiled.actions().actions[0].execution).unwrap();
    assert_eq!(execution["proposal"]["additions"]["maximumCount"], 2);
    let plain = compile(&source()).unwrap();
    let execution = serde_json::to_value(&plain.actions().actions[0].execution).unwrap();
    assert!(execution["proposal"].get("additions").is_none());
}

#[test]
fn additions_refuse_invalid_bounds_types_and_collisions() {
    for (member, value, code) in [
        (
            "maximumBytes",
            json!(0),
            "breg.addition.maximum-bytes-bounds-invalid",
        ),
        (
            "maximumBytes",
            json!(16777217),
            "breg.addition.maximum-bytes-bounds-invalid",
        ),
        (
            "maximumCount",
            json!(0),
            "breg.addition.maximum-count-bounds-invalid",
        ),
        (
            "maximumCount",
            json!(33),
            "breg.addition.maximum-count-bounds-invalid",
        ),
        (
            "contentTypes",
            json!([]),
            "breg.addition.content-types-bounds-invalid",
        ),
        (
            "contentTypes",
            json!(["text/*"]),
            "breg.addition.content-type-invalid",
        ),
        (
            "contentTypes",
            json!(["text/plain", "text/plain"]),
            "breg.addition.content-type-duplicate",
        ),
        ("id", json!("document"), "breg.addition.id-collision"),
    ] {
        let mut source = addition_source();
        source["actions"]["amend"]["execution"]["proposal"]["additions"][member] = value;
        let failure = compile(&source).expect_err("invalid addition slot");
        assert!(
            failure.diagnostics().iter().any(|d| d.code == code),
            "{code}: {:?}",
            failure.diagnostics()
        );
    }
}

#[test]
fn additions_grants_require_the_declared_slot_and_add_authority() {
    for missing_slot in [true, false] {
        let mut source = addition_source();
        if missing_slot {
            source["actions"]["amend"]["execution"]["proposal"]
                .as_object_mut()
                .unwrap()
                .remove("additions");
        } else {
            source["accessProfiles"]["clerk"]["permissions"]["proposals"][0]["operations"] =
                json!(["get", "edit", "submit", "apply"]);
        }
        let failure = compile(&source).expect_err("invalid addition authority");
        assert!(
            failure
                .diagnostics()
                .iter()
                .any(|d| d.code == "breg.proposal.attachment-grant-invalid"),
            "{:?}",
            failure.diagnostics()
        );
    }
}

#[test]
fn additions_review_context_compiles_a_bounded_document_array() {
    let mut source = addition_source();
    source["actions"]["amend"]["execution"]["proposal"]["reviewContext"] = json!({
        "id":"review","fields":{"otherDocuments":{"type":"additions","slot":"supporting"}}});
    let compiled = compile(&source).expect("additions context compiles");
    let schema = registry_breg::compiler::review_context::compile_schema(
        &compiled,
        &compiled.actions().actions[0],
    )
    .unwrap()
    .unwrap();
    let field = &schema.schema["properties"]["otherDocuments"];
    assert_eq!(field["type"], "array");
    assert_eq!(field["maxItems"], 2);
    assert_eq!(field["items"]["properties"]["type"]["const"], "document");
    assert!(
        field["items"]["properties"]["download"]["properties"]["path"]["pattern"]
            .as_str()
            .unwrap()
            .contains("/additions/")
    );
}

#[test]
fn additions_publish_only_the_declared_slots_paths_and_document_schema() {
    for declared in [false, true] {
        let compiled = compile(&if declared {
            addition_source()
        } else {
            source()
        })
        .unwrap();
        let openapi: Value = serde_json::from_slice(
            &compiled
                .artifacts()
                .get("generated/openapi.json")
                .unwrap()
                .bytes,
        )
        .unwrap();
        let paths = openapi["paths"].as_object().unwrap();
        assert_eq!(
            paths.contains_key("/v1/proposals/{proposal_id}/additions/supporting"),
            declared
        );
        assert_eq!(
            paths.contains_key("/v1/proposals/{proposal_id}/additions/{addition_id}"),
            declared
        );
        let schema = &paths["/v1/proposals/{proposal_id}"]["get"]["responses"]["200"]["content"]
            ["application/json"]["schema"];
        assert_eq!(schema["properties"].get("additions").is_some(), declared);
        assert!(!paths.contains_key("/v1/proposals/{proposal_id}/add"));
    }
}

fn compile_bytes(bytes: &[u8]) -> Result<registry_breg::CompiledRegistry, CompileFailure> {
    let project = parse_project_json(bytes)?;
    compile_project(&project, &[], CompileProfile::Authoring)
}

fn compile(source: &Value) -> Result<registry_breg::CompiledRegistry, CompileFailure> {
    compile_bytes(&serde_json::to_vec(source).unwrap())
}

fn mutated(mutate: impl FnOnce(&mut Value)) -> Value {
    let mut source = source();
    mutate(&mut source);
    source
}

/// Asserts one `breg.action.attachment-invalid` refusal at `path` whose
/// message contains `message`.
fn assert_refused(source: &Value, path: &str, message: &str) {
    let Err(failure) = compile(source) else {
        panic!("expected the promotion to be refused, but the project compiled")
    };
    assert!(
        failure.diagnostics().iter().any(|diagnostic| {
            diagnostic.code == CODE
                && diagnostic.path == path
                && diagnostic.message.contains(message)
        }),
        "expected {CODE} at {path} with {message:?}: {:#?}",
        failure.diagnostics()
    );
}

fn effect_path(effect: &str) -> String {
    format!("actions[id=amend].plan.effects[id={effect}].attachments[slot=evidence]")
}

#[test]
fn create_and_patch_effects_promote_one_proposal_file() {
    let compiled = compile(&source()).expect("a matching promotion compiles");
    let action = compiled
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "amend")
        .unwrap();
    let execution = serde_json::to_value(&action.execution).unwrap();
    assert_eq!(
        execution["proposal"]["promotions"],
        json!([
            {"effectId":"copy","recordType":"application","slotId":"evidence",
                "fromAttachment":"document","maximumBytes":64,
                "contentTypes":["text/plain","application/pdf"]},
            {"effectId":"original","recordType":"application","slotId":"evidence",
                "fromAttachment":"document","maximumBytes":64,
                "contentTypes":["text/plain","application/pdf"]}
        ])
    );
    // A Proposal request carries no record file, so the Action has no
    // request attachments and its start schema has no file member.
    assert!(action.attachments.is_empty());
}

#[test]
fn a_promotion_must_name_a_declared_proposal_slot() {
    assert_refused(
        &mutated(|source| {
            source["actions"]["amend"]["plan"]["effects"][1]["attachments"] =
                json!({"evidence":{"fromAttachment":"missing"}});
        }),
        &format!("{}.fromAttachment", effect_path("original")),
        "Proposal attachment slot",
    );
}

#[test]
fn a_promotion_must_name_a_slot_of_the_effect_target_record_type() {
    assert_refused(
        &mutated(|source| {
            source["actions"]["amend"]["plan"]["effects"][0]["attachments"] =
                json!({"missing":{"fromAttachment":"document"}});
        }),
        "actions[id=amend].plan.effects[id=copy].attachments[slot=missing]",
        "a slot the target record type declares",
    );
}

#[test]
fn a_promotion_refuses_a_content_type_the_record_slot_does_not_accept() {
    assert_refused(
        &mutated(|source| {
            source["actions"]["amend"]["execution"]["proposal"]["attachments"][0]["contentTypes"] =
                json!(["text/plain", "image/png"]);
        }),
        &format!("{}.fromAttachment", effect_path("copy")),
        "content type",
    );
}

#[test]
fn a_promotion_refuses_a_size_the_record_slot_does_not_accept() {
    assert_refused(
        &mutated(|source| {
            source["actions"]["amend"]["execution"]["proposal"]["attachments"][0]["maximumBytes"] =
                json!(65);
        }),
        &format!("{}.fromAttachment", effect_path("copy")),
        "larger",
    );
}

#[test]
fn a_promotion_refuses_a_record_slot_less_restricted_than_the_proposal_slot() {
    for classification in ["internal", "public"] {
        assert_refused(
            &mutated(|source| {
                source["recordTypes"]["application"]["attachments"][0]["classification"] =
                    json!(classification);
            }),
            &format!("{}.fromAttachment", effect_path("copy")),
            "less restricted",
        );
    }
}

#[test]
fn a_promotion_may_fill_a_record_slot_more_restricted_than_the_proposal_slot() {
    let source = mutated(|source| {
        source["actions"]["amend"]["execution"]["proposal"]["attachments"][0]["classification"] =
            json!("internal");
    });
    compile(&source).expect("a more restricted record slot holds the file");
}

#[test]
fn two_effects_cannot_promote_into_one_record_slot_of_one_record() {
    // `again` patches the same target record as `original`, through a
    // different field, so only the promotion overlaps.
    assert_refused(
        &mutated(|source| {
            source["actions"]["amend"]["plan"]["effects"]
                .as_array_mut()
                .unwrap()
                .push(
                    json!({"id":"again","target":{"fromInput":"target"},"operation":"patch",
                    "set":{"note":{"fromInput":"name"}},
                    "attachments":{"evidence":{"fromAttachment":"document"}}}),
                );
        }),
        &effect_path("again"),
        "more than once",
    );
}

#[test]
fn one_effect_cannot_name_one_record_slot_twice() {
    let bytes = serde_json::to_string(&source()).unwrap();
    let single = r#""attachments":{"evidence":{"fromAttachment":"document"}}"#;
    assert!(bytes.contains(single));
    let duplicated = bytes.replacen(
        single,
        r#""attachments":{"evidence":{"fromAttachment":"document"},"evidence":{"fromAttachment":"document"}}"#,
        1,
    );
    let Err(failure) = compile_bytes(duplicated.as_bytes()) else {
        panic!("expected a duplicate slot key to be refused, but the project compiled")
    };
    assert!(
        failure
            .diagnostics()
            .iter()
            .any(|diagnostic| diagnostic.code == "breg.source.json-invalid"),
        "{:#?}",
        failure.diagnostics()
    );
}

#[test]
fn an_immediate_action_still_cannot_take_a_file_from_a_proposal_slot() {
    // An immediate Action has no Proposal slots: its create effect names a
    // file in the same request, and a patch effect cannot attach a file.
    let source = mutated(|source| {
        source["actions"]["amend"]["execution"] = json!({"mode":"immediate"});
        source["accessProfiles"]["clerk"]["permissions"]["actions"][0]["operations"] =
            json!(["invoke"]);
        source["accessProfiles"]["clerk"]["permissions"]
            .as_object_mut()
            .unwrap()
            .remove("proposals");
    });
    assert_refused(
        &source,
        "actions[id=amend].plan.effects[id=original].attachments",
        "only a create effect",
    );
}

#[test]
fn a_tombstone_effect_cannot_promote_a_file() {
    let source = mutated(|source| {
        source["actions"]["amend"]["plan"]["effects"][1] = json!({
            "id":"original","target":{"fromInput":"target"},"operation":"tombstone",
            "attachments":{"evidence":{"fromAttachment":"document"}}});
    });
    assert_refused(
        &source,
        "actions[id=amend].plan.effects[id=original].attachments",
        "only a create or patch effect",
    );
}

fn apply_conflict_description(source: &Value) -> String {
    let compiled = compile(source).expect("the project compiles");
    let openapi: Value = serde_json::from_slice(
        &compiled
            .artifacts()
            .get("generated/openapi.json")
            .expect("generated OpenAPI")
            .bytes,
    )
    .unwrap();
    openapi["paths"]["/v1/proposals/{proposal_id}/apply"]["post"]["responses"]["409"]["description"]
        .as_str()
        .expect("apply documents 409")
        .to_owned()
}

#[test]
fn apply_documents_a_filled_write_once_slot_only_when_a_plan_promotes_a_file() {
    // Every record slot is write-once, so any promotion can meet a filled
    // slot when the Proposal is applied.
    assert!(
        apply_conflict_description(&source()).contains("`attachment.slot-write-once`"),
        "a promotion into a filled slot can be refused"
    );
    let unpromoted = mutated(|source| {
        for effect in source["actions"]["amend"]["plan"]["effects"]
            .as_array_mut()
            .unwrap()
        {
            effect.as_object_mut().unwrap().remove("attachments");
        }
    });
    assert!(
        !apply_conflict_description(&unpromoted).contains("slot-write-once"),
        "a plan that promotes nothing cannot meet a filled slot"
    );
}

/// The same project with one immediate Action whose create effect files the
/// request part `document` into the record slot, or files nothing.
fn immediate_source(binding: Option<&str>) -> Value {
    mutated(|source| {
        source["actions"]["amend"]["execution"] = json!({"mode":"immediate"});
        let effects = source["actions"]["amend"]["plan"]["effects"]
            .as_array_mut()
            .unwrap();
        effects.truncate(1);
        match binding {
            Some(name) => {
                effects[0]["attachments"] = json!({"evidence":{"fromAttachment":name}});
            }
            None => {
                effects[0].as_object_mut().unwrap().remove("attachments");
            }
        }
        source["accessProfiles"]["clerk"]["permissions"]["actions"][0]["operations"] =
            json!(["invoke"]);
        source["accessProfiles"]["clerk"]["permissions"]
            .as_object_mut()
            .unwrap()
            .remove("proposals");
    })
}

fn amend_revision(source: &Value) -> String {
    let compiled = compile(source).expect("the immediate Action compiles");
    compiled
        .actions()
        .actions
        .iter()
        .find(|action| action.id == "amend")
        .unwrap()
        .definition_revision
        .clone()
}

#[test]
fn an_immediate_action_revision_covers_its_request_file_bindings() {
    // The bindings decide which request part fills which record slot, so a
    // request accepted under one set must not be replayed under another.
    let bound = amend_revision(&immediate_source(Some("document")));
    let renamed = amend_revision(&immediate_source(Some("upload")));
    let unbound = amend_revision(&immediate_source(None));
    assert_ne!(
        bound, renamed,
        "renaming the request part moves the revision"
    );
    assert_ne!(bound, unbound, "dropping the binding moves the revision");
}

#[test]
fn an_immediate_action_without_request_files_keeps_its_revision() {
    // An Action that files nothing keeps the revision it had before request
    // files were part of the revision, so its stored retries stay valid.
    assert_eq!(
        amend_revision(&immediate_source(None)),
        "sha256:4d2e0fb342b537ee57675e9600861300709a40058c2cad043144b7d6d27c19d2"
    );
}
