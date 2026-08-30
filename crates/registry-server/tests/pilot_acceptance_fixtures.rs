// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use registry_server::compiler::{compile_project_with_assets, CompileProfile};
use registry_server::contract::{
    Classification, ConstraintSource, FieldTypeSource, ModuleAssetSource, MutationMode, Operation,
    RegistryModule, RegistryProject, UniqueWhenPredicate, ValidTimeRole,
};
use registry_server::fixtures::validate_fixture_journeys;
use registry_server::generated_ddl::DdlStatementKind;
use registry_server::model::{CompiledEntity, CompiledRegistry};

fn fixture_root(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/registry-server/acceptance")
        .join(name)
}

fn fixture_sources(name: &str) -> (RegistryProject, Vec<RegistryModule>, Vec<ModuleAssetSource>) {
    let root = fixture_root(name);
    let bytes = fs::read(root.join("registry.yaml")).expect("committed pilot fixture is readable");
    let project = registry_server::contract::parse_project_yaml(&bytes)
        .expect("pilot fixture follows the authoring contract");
    let mut modules = Vec::new();
    let mut assets = Vec::new();
    for locked in &project.modules {
        let module_root = root.join("modules").join(&locked.id);
        let bytes = fs::read(root.join("modules").join(&locked.id).join("module.yaml"))
            .expect("every locked pilot module source is readable");
        let module = registry_server::contract::parse_module_yaml(&bytes)
            .expect("pilot module follows the authoring contract");
        let declared_assets = module
            .entities
            .iter()
            .flat_map(|entity| &entity.derived)
            .chain(
                module
                    .extend_entities
                    .iter()
                    .flat_map(|extension| &extension.derived),
            )
            .map(|derived| derived.sql.clone())
            .collect::<BTreeSet<_>>();
        for path in declared_assets {
            assets.push(ModuleAssetSource {
                module: Some(module.id.clone()),
                bytes: fs::read(module_root.join(&path))
                    .expect("every declared pilot module asset is readable"),
                path,
            });
        }
        modules.push(module);
    }
    (project, modules, assets)
}

fn compile_fixture(name: &str) -> CompiledRegistry {
    let (project, modules, assets) = fixture_sources(name);
    compile_project_with_assets(&project, &modules, &assets, CompileProfile::Production)
        .expect("pilot fixture compiles in production mode")
}

fn entity<'a>(compiled: &'a CompiledRegistry, id: &str) -> &'a CompiledEntity {
    compiled
        .entities()
        .get(id)
        .expect("fixture entity compiled")
}

fn field<'a>(entity: &'a CompiledEntity, id: &str) -> &'a registry_server::model::CompiledField {
    entity.fields.get(id).expect("fixture field compiled")
}

fn has_unique(entity: &CompiledEntity, fields: &[&str]) -> bool {
    entity.constraints.values().any(|constraint| {
        matches!(
            constraint,
            ConstraintSource::Unique { fields: declared, .. }
                if declared.iter().map(String::as_str).eq(fields.iter().copied())
        )
    })
}

fn has_temporal_non_overlap(entity: &CompiledEntity, scope_fields: &[&str]) -> bool {
    entity.constraints.values().any(|constraint| {
        matches!(
            constraint,
            ConstraintSource::TemporalNonOverlap { scope_fields: declared, .. }
                if declared.iter().map(String::as_str).eq(scope_fields.iter().copied())
        )
    })
}

fn has_current_unique(entity: &CompiledEntity, fields: &[&str], open_field: &str) -> bool {
    entity.constraints.values().any(|constraint| {
        matches!(
            constraint,
            ConstraintSource::Unique {
                fields: declared,
                when: Some(when),
                ..
            } if declared.iter().map(String::as_str).eq(fields.iter().copied())
                && when.iter().any(|predicate| matches!(
                    predicate,
                    UniqueWhenPredicate::FieldIsNull { field } if field == open_field
                ))
                && when.iter().any(|predicate| matches!(
                    predicate,
                    UniqueWhenPredicate::ActiveLifecycle {}
                ))
        )
    })
}

fn operations_for(compiled: &CompiledRegistry, entity_id: &str) -> Vec<Operation> {
    let mut operations = compiled
        .routes()
        .routes
        .iter()
        .filter(|route| route.entity_id == entity_id)
        .map(|route| route.operation)
        .collect::<Vec<_>>();
    operations.sort();
    operations.dedup();
    operations
}

#[test]
fn household_pilot_fixture_compiles_person_household_and_time_bounded_membership() {
    let compiled = compile_fixture("publicschema-household");
    assert_eq!(compiled.registry_id(), "publicschema-household");
    assert_eq!(compiled.entities().len(), 3);

    let person = entity(&compiled, "person");
    assert!(person.fields.contains_key("residency-status"));
    assert!(person.fields.contains_key("preferred-language"));

    let membership = entity(&compiled, "group-membership");
    assert_eq!(membership.mutation_mode, MutationMode::Mutable);
    assert!(has_unique(
        membership,
        &["person", "household", "valid-from"]
    ));
    assert!(has_temporal_non_overlap(membership, &["person"]));
    assert_eq!(
        field(membership, "valid-from").valid_time_role,
        Some(ValidTimeRole::ValidFrom)
    );
    assert_eq!(
        field(membership, "valid-to").valid_time_role,
        Some(ValidTimeRole::ValidTo)
    );
    assert!(compiled.ddl().requires_btree_gist);
    assert!(compiled.routes().routes.iter().any(|route| {
        route.entity_id == "group-membership"
            && route.operation == Operation::Patch
            && route.path == "/v1/records/group-memberships/{record_id}"
    }));
}

#[test]
fn household_pilot_fixture_journeys_preflight_against_the_exact_compiled_registry() {
    let compiled = compile_fixture("publicschema-household");
    let journeys = fs::read(fixture_root("publicschema-household").join("tests/journeys.yaml"))
        .expect("committed household journeys are readable");
    if let Err(error) = validate_fixture_journeys(&journeys, &compiled) {
        let document: serde_json::Value =
            serde_norway::from_slice(&journeys).expect("journey YAML has a generic value shape");
        let steps = document["journeys"][0]["steps"]
            .as_array()
            .expect("journey steps are an array");
        for length in 1..=steps.len() {
            let mut prefix = document.clone();
            prefix["journeys"][0]["steps"]
                .as_array_mut()
                .expect("journey steps remain an array")
                .truncate(length);
            let source = serde_norway::to_string(&prefix).expect("journey prefix serializes");
            if let Err(prefix_error) = validate_fixture_journeys(source.as_bytes(), &compiled) {
                let step = steps[length - 1]["id"].as_str().unwrap_or("unknown");
                panic!(
                    "household journey first fails at step {step}: {prefix_error:?}; full error: {error:?}"
                );
            }
        }
        panic!("household journey validation failed after every prefix passed: {error:?}");
    }
}

#[test]
fn disability_pilot_fixture_compiles_protected_observations_and_create_only_certification() {
    let compiled = compile_fixture("disability");
    assert_eq!(compiled.registry_id(), "disability");
    assert_eq!(compiled.entities().len(), 3);
    assert!(compiled
        .entities()
        .values()
        .all(|entity| entity.classification == Classification::Restricted));
    assert!(compiled.entities().values().all(|entity| {
        entity
            .access_profiles
            .values()
            .all(|profile| !profile.anonymous)
    }));

    let observation = entity(&compiled, "functioning-observation");
    assert!(observation.constraints.values().any(|constraint| {
        matches!(
            constraint,
            ConstraintSource::IntRange {
                field,
                minimum: Some(0),
                maximum: Some(4),
                ..
            } if field == "severity-score"
        )
    }));

    let certification = entity(&compiled, "certification");
    assert_eq!(certification.mutation_mode, MutationMode::CreateOnly);
    assert!(certification.fields.contains_key("corrected-certification"));
    assert!(certification.fields.contains_key("correction-reason"));
    assert!(certification.fields.contains_key("provenance-note"));
    assert!(has_temporal_non_overlap(
        certification,
        &["assessment-episode"]
    ));
    assert_eq!(
        operations_for(&compiled, "certification"),
        [Operation::Create, Operation::Get, Operation::List]
    );
}

#[test]
fn farmer_pilot_fixture_compiles_bounded_crs84_scalars_imports_and_temporal_activity() {
    let compiled = compile_fixture("farmer");
    assert_eq!(compiled.registry_id(), "farmer");
    assert_eq!(compiled.entities().len(), 4);

    let plot = entity(&compiled, "plot");
    assert!(matches!(
        field(plot, "centroid").field_type,
        FieldTypeSource::Crs84Point {
            precision: 7,
            bbox: Some(_)
        }
    ));
    assert!(matches!(
        field(plot, "area-value").field_type,
        FieldTypeSource::Decimal {
            precision: 12,
            scale: 4,
            ..
        }
    ));
    assert!(has_unique(plot, &["import-source", "source-record-id"]));
    assert!(matches!(
        field(plot, "area-unit").field_type,
        FieldTypeSource::VocabularyCode { .. }
    ));
    assert!(matches!(
        field(plot, "administrative-boundary").field_type,
        FieldTypeSource::VocabularyCode { .. }
    ));

    let activity = entity(&compiled, "seasonal-activity");
    assert!(has_temporal_non_overlap(
        activity,
        &["plot", "activity-type"]
    ));
    assert_eq!(
        field(activity, "season-start").valid_time_role,
        Some(ValidTimeRole::ValidFrom)
    );
    assert_eq!(
        field(activity, "season-end").valid_time_role,
        Some(ValidTimeRole::ValidTo)
    );
    assert!(matches!(
        field(activity, "quantity-value").field_type,
        FieldTypeSource::Decimal {
            precision: 12,
            scale: 3,
            ..
        }
    ));
    let ddl = compiled.ddl().script().to_ascii_lowercase();
    assert!(!ddl.contains("postgis"));
    assert!(!ddl.contains("geometry"));
    assert!(!ddl.contains("geography"));
    assert!(ddl.contains("jsonb"));
    assert!(ddl.contains("numeric(12,4)"));
    assert!(ddl.contains("numeric(12,3)"));
}

#[test]
fn business_pilot_fixture_compiles_composite_identifiers_temporal_appointments_and_public_views() {
    let compiled = compile_fixture("business");
    assert_eq!(compiled.registry_id(), "business");
    assert_eq!(compiled.entities().len(), 3);

    let legal_entity = entity(&compiled, "legal-entity");
    assert_eq!(legal_entity.classification, Classification::Public);
    assert!(has_unique(
        legal_entity,
        &["jurisdiction-code", "registration-number"]
    ));
    let public_entity = legal_entity
        .access_profiles
        .get("public-register")
        .expect("public profile compiled");
    assert!(public_entity.anonymous);
    assert!(public_entity.readable_fields.contains("legal-name"));
    assert!(!public_entity.readable_fields.contains("protected-contact"));
    assert!(!public_entity.readable_fields.contains("internal-case-note"));

    let registrar_entity = legal_entity
        .access_profiles
        .get("business-registrar")
        .expect("registrar profile compiled");
    assert!(registrar_entity
        .readable_fields
        .contains("protected-contact"));

    let filing = entity(&compiled, "filing");
    assert_eq!(filing.mutation_mode, MutationMode::CreateOnly);
    assert!(has_unique(filing, &["legal-entity", "filing-number"]));
    assert!(has_unique(filing, &["source-system", "source-record-id"]));
    assert_eq!(
        operations_for(&compiled, "filing"),
        [Operation::Create, Operation::Get, Operation::List]
    );

    let appointment = entity(&compiled, "officer-appointment");
    assert_eq!(appointment.classification, Classification::Public);
    assert!(has_unique(
        appointment,
        &["legal-entity", "officer-code", "effective-from"]
    ));
    assert!(has_current_unique(
        appointment,
        &["legal-entity", "officer-role"],
        "effective-to"
    ));
    assert!(has_temporal_non_overlap(
        appointment,
        &["legal-entity", "officer-code"]
    ));
    assert_eq!(
        field(appointment, "effective-from").valid_time_role,
        Some(ValidTimeRole::ValidFrom)
    );
    assert_eq!(
        field(appointment, "effective-to").valid_time_role,
        Some(ValidTimeRole::ValidTo)
    );
    let public_appointment = appointment
        .access_profiles
        .get("public-register")
        .expect("appointment public profile compiled");
    assert!(public_appointment.anonymous);
    assert!(public_appointment
        .filterable_fields
        .contains("effective-from"));
    assert!(!public_appointment.readable_fields.contains("officer-code"));
    assert!(!public_appointment
        .readable_fields
        .contains("protected-officer-id"));

    let get_access = compiled
        .access()
        .entries
        .iter()
        .find(|entry| entry.entity_id == "legal-entity" && entry.operation == Operation::Get)
        .expect("legal entity read access compiles");
    assert_eq!(get_access.default_profile_id, "public-register");
    assert!(get_access.profile_ids.contains("business-registrar"));
    assert!(get_access.profile_ids.contains("public-register"));

    assert!(compiled.ddl().statements.iter().any(|statement| {
        statement.kind == DdlStatementKind::Constraint
            && statement
                .id
                .contains("officer-appointment.constraint.temporal-non-overlap")
    }));
    assert!(compiled.ddl().statements.iter().any(|statement| {
        statement.kind == DdlStatementKind::Index
            && statement
                .id
                .contains("officer-appointment.constraint.unique")
            && statement.sql.contains("CREATE UNIQUE INDEX")
            && statement.sql.contains(" WHERE ")
            && statement.sql.contains("record_lifecycle = 'active'")
    }));
}
