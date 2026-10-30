// SPDX-License-Identifier: Apache-2.0

//! A registry that answers "today" declares the IANA time zone it answers in.

#[path = "support/action_requirements.rs"]
mod action_support;

use registry_breg::compiler::{compile_project, compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_json, ModuleAssetSource};
use registry_breg::diagnostics::{CompileFailure, Diagnostic, DiagnosticSeverity};
use serde_json::{json, Value};

fn compile(source: &Value) -> Result<registry_breg::CompiledRegistry, CompileFailure> {
    compile_with_assets(source, Vec::new())
}

fn compile_with_assets(
    source: &Value,
    assets: Vec<ModuleAssetSource>,
) -> Result<registry_breg::CompiledRegistry, CompileFailure> {
    let project = parse_project_json(&serde_json::to_vec(source).unwrap()).expect("source parses");
    if assets.is_empty() {
        compile_project(&project, &[], CompileProfile::Authoring)
    } else {
        compile_project_with_assets(&project, &[], &assets, CompileProfile::Authoring)
    }
}

fn timezone_errors(failure: &CompileFailure) -> Vec<&Diagnostic> {
    failure
        .diagnostics()
        .iter()
        .filter(|diagnostic| {
            diagnostic.severity == DiagnosticSeverity::Error
                && diagnostic.code.starts_with("breg.timezone.")
        })
        .collect()
}

/// A membership type whose validity is a date interval, listed by one profile.
fn date_interval_project(start_type: &str) -> Value {
    json!({
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {"id": "licences", "version": "1", "defaultLanguage": "en", "canonicalBaseIri": "https://licences.example.test"},
        "datasets": [{"id": "licences"}],
        "recordTypes": [{
            "id": "licence", "primaryDataset": "licences", "route": "licences", "mutationMode": "mutable",
            "fields": [
                {"id": "holder", "type": "string", "maximumLength": 32, "required": true, "classification": "internal"},
                {"id": "valid-from", "type": start_type, "required": true, "classification": "internal"},
                {"id": "valid-to", "type": start_type, "classification": "internal"}
            ],
            "temporal": {"startField": "valid-from", "endField": "valid-to"}
        }],
        "accessProfiles": [{
            "id": "reader", "default": true, "principalClaim": "principal", "requiredScopes": "unrestricted",
            "permissions": {"records": [{
                "recordType": "licence", "operations": ["list"],
                "readableFields": ["holder", "valid-from", "valid-to"],
                "rowBoundaries": "unrestricted"
            }]}
        }]
    })
}

#[test]
fn a_current_read_of_a_date_interval_requires_a_timezone_and_names_the_line_to_add() {
    let failure = compile(&date_interval_project("date"))
        .expect_err("a date-interval :current read without a time zone is refused");
    let errors = timezone_errors(&failure);
    assert_eq!(errors.len(), 1, "{errors:?}");
    let error = errors[0];
    assert_eq!(error.code, "breg.timezone.required");
    assert_eq!(error.path, "project.timezone");
    assert!(
        error.message.contains("records.licence.current"),
        "the refusal names the route: {}",
        error.message
    );
    assert!(
        error.message.contains("timezone: UTC"),
        "the refusal names the line to add: {}",
        error.message
    );
}

#[test]
fn a_declared_timezone_is_compiled_and_satisfies_every_today_site() {
    let mut source = date_interval_project("date");
    source["project"]["timezone"] = json!("Asia/Colombo");
    let compiled = compile(&source).expect("a declared time zone satisfies the :current read");
    assert_eq!(compiled.timezone(), Some("Asia/Colombo"));
}

#[test]
fn a_timestamp_interval_answers_now_without_a_timezone() {
    let compiled = compile(&date_interval_project("timestamp"))
        .expect("a timestamp interval uses the current instant, not a date");
    assert_eq!(compiled.timezone(), None);
}

#[test]
fn a_project_that_never_answers_today_needs_no_timezone() {
    let mut source = date_interval_project("date");
    source["recordTypes"][0]
        .as_object_mut()
        .unwrap()
        .remove("temporal");
    compile(&source).expect("no date interval, no today");
}

#[test]
fn a_name_that_is_not_an_iana_zone_is_refused() {
    for name in ["Mars/Olympus_Mons", "+05:30", "asia/colombo", ""] {
        let mut source = date_interval_project("date");
        source["project"]["timezone"] = json!(name);
        let failure = compile(&source).expect_err("an unknown zone is refused");
        let errors = timezone_errors(&failure);
        assert_eq!(errors.len(), 1, "{name}: {errors:?}");
        assert_eq!(errors[0].code, "breg.timezone.unknown", "{name}");
        assert_eq!(errors[0].path, "project.timezone");
        assert!(
            errors[0].message.contains("Asia/Colombo"),
            "the refusal shows an IANA spelling: {}",
            errors[0].message
        );
    }
}

#[test]
fn a_current_date_requirement_requires_a_timezone() {
    let mut source = action_support::project();
    source["recordTypes"][0]["fields"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "expires-on", "type": "date", "required": true, "classification": "restricted"}));
    source["actions"][0]["commitGuards"]["targets"]
        .as_array_mut()
        .unwrap()
        .push(json!({"input": "parent", "field": "expires-on", "currentDate": "on-or-after"}));
    let failure = compile(&source).expect_err("a currentDate requirement needs today");
    let errors = timezone_errors(&failure);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(errors[0].code, "breg.timezone.required");
    assert!(
        errors[0].message.contains("register-child"),
        "the refusal names the Action: {}",
        errors[0].message
    );
    assert!(
        errors[0].message.contains("expires-on"),
        "the refusal names the requirement's field: {}",
        errors[0].message
    );

    source["project"]["timezone"] = json!("Africa/Nairobi");
    compile(&source).expect("a declared time zone satisfies the requirement");
}

#[test]
fn a_live_derived_field_reading_the_evaluation_date_requires_a_timezone() {
    let mut source = date_interval_project("date");
    source["recordTypes"][0]
        .as_object_mut()
        .unwrap()
        .remove("temporal");
    source["recordTypes"][0]["derived"] = json!([{
        "id": "age", "sql": "sql/age.sql", "key": "id", "execution": "live",
        "fields": [{"id": "observed-on", "type": "date", "classification": "internal"}]
    }]);
    source["accessProfiles"][0]["permissions"]["records"][0]["readableFields"]
        .as_array_mut()
        .unwrap()
        .push(json!("observed-on"));
    let assets = || {
        vec![ModuleAssetSource {
            module: None,
            path: "sql/age.sql".to_owned(),
            bytes: b"SELECT l.id AS id, registry_context.evaluation_date() AS observed_on FROM registry_source.licence l".to_vec(),
        }]
    };
    let failure = compile_with_assets(&source, assets())
        .expect_err("evaluation_date() on a live read needs today");
    let errors = timezone_errors(&failure);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert_eq!(errors[0].code, "breg.timezone.required");
    assert!(
        errors[0].message.contains("observed-on"),
        "the refusal names the derived field: {}",
        errors[0].message
    );

    source["project"]["timezone"] = json!("UTC");
    compile_with_assets(&source, assets()).expect("UTC keeps the earlier dates");
}

#[test]
fn the_timezone_is_part_of_the_effective_model_and_the_revision() {
    let effective = |registry: &registry_breg::CompiledRegistry| -> Value {
        serde_json::from_slice(
            &registry
                .artifacts()
                .get("compiled/effective-model.json")
                .expect("effective model")
                .bytes,
        )
        .expect("effective model is JSON")
    };
    let mut colombo = date_interval_project("date");
    colombo["project"]["timezone"] = json!("Asia/Colombo");
    let mut utc = colombo.clone();
    utc["project"]["timezone"] = json!("UTC");
    let colombo = compile(&colombo).expect("Colombo compiles");
    let utc = compile(&utc).expect("UTC compiles");
    assert_eq!(effective(&colombo)["timezone"], json!("Asia/Colombo"));
    assert_ne!(
        colombo.revision(),
        utc.revision(),
        "a different zone answers a different today, so it is a different registry"
    );
    let undeclared = compile(&date_interval_project("timestamp")).expect("no zone needed");
    assert!(effective(&undeclared).get("timezone").is_none());
}
