// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

use registry_breg::compiler::{compile_project_with_assets, CompileProfile};
use registry_breg::contract::{
    Classification, ConstraintSource, FieldTypeSource, ModuleAssetSource, MutationMode, Operation,
    RegistryModule, RegistryProject, UniqueWhenPredicate, ValidTimeRole,
};
use registry_breg::fixtures::validate_fixture_journeys;
use registry_breg::generated_ddl::DdlStatementKind;
use registry_breg::model::{CompiledEntity, CompiledRegistry};

fn fixture_root(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance")
        .join(name)
}

fn fixture_sources(name: &str) -> (RegistryProject, Vec<RegistryModule>, Vec<ModuleAssetSource>) {
    let root = fixture_root(name);
    let bytes = fs::read(root.join("registry.yaml")).expect("committed pilot fixture is readable");
    let project = registry_breg::contract::parse_project_yaml(&bytes)
        .expect("pilot fixture follows the authoring contract");
    let mut modules = Vec::new();
    let mut assets = Vec::new();
    for locked in &project.modules {
        let module_root = root.join("modules").join(&locked.id);
        let bytes = fs::read(root.join("modules").join(&locked.id).join("module.yaml"))
            .expect("every locked pilot module source is readable");
        let module = registry_breg::contract::parse_module_yaml(&bytes)
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

fn field<'a>(entity: &'a CompiledEntity, id: &str) -> &'a registry_breg::model::CompiledField {
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
fn asset_placement_change_request_fixture_compiles_site_correction_plan() {
    let compiled = compile_fixture("asset-site-placement-change-requests");
    assert_eq!(
        compiled.registry_id(),
        "asset-site-placement-change-requests"
    );
    assert_eq!(compiled.entities().len(), 5);

    let placement = entity(&compiled, "asset-placement");
    assert_eq!(
        placement.change_control.as_ref().map(|control| {
            control
                .required_for
                .iter()
                .copied()
                .collect::<BTreeSet<_>>()
        }),
        Some(BTreeSet::from([Operation::Patch]))
    );

    let request = entity(&compiled, "placement-correction-request");
    let request_plan = request
        .change_request
        .as_ref()
        .expect("asset placement correction request compiles to a request plan");
    assert_eq!(request_plan.effects.len(), 1);
    assert_eq!(request_plan.stages.len(), 2);
    assert_eq!(
        request_plan.target_entities,
        ["asset-placement"].into_iter().map(str::to_owned).collect()
    );
}

#[test]
fn business_pilot_fixture_compiles_establishment_business_and_time_bounded_assignment() {
    let compiled = compile_fixture("business-establishments");
    assert_eq!(compiled.registry_id(), "business-establishments");
    assert_eq!(compiled.entities().len(), 3);

    let establishment = entity(&compiled, "establishment");
    assert!(establishment.fields.contains_key("operating-status"));
    assert!(establishment.fields.contains_key("preferred-language"));

    let assignment = entity(&compiled, "operator-assignment");
    assert_eq!(assignment.mutation_mode, MutationMode::Mutable);
    assert!(has_unique(
        assignment,
        &["establishment", "business", "valid-from"]
    ));
    assert!(has_temporal_non_overlap(assignment, &["establishment"]));
    assert_eq!(
        field(assignment, "valid-from").valid_time_role,
        Some(ValidTimeRole::ValidFrom)
    );
    assert_eq!(
        field(assignment, "valid-to").valid_time_role,
        Some(ValidTimeRole::ValidTo)
    );
    assert!(compiled.ddl().requires_btree_gist);
    assert!(compiled.routes().routes.iter().any(|route| {
        route.entity_id == "operator-assignment"
            && route.operation == Operation::Patch
            && route.path == "/v1/records/operator-assignments/{record_id}"
    }));
}

#[test]
fn household_change_request_fixture_compiles_contact_registration_plan() {
    let compiled = compile_fixture("publicschema-household-change-requests");
    assert_eq!(
        compiled.registry_id(),
        "publicschema-household-change-requests"
    );
    assert_eq!(compiled.entities().len(), 4);

    let person = entity(&compiled, "person");
    assert!(person.change_control.is_some());
    assert!(person.fields.contains_key("residency-status"));
    assert!(person.fields.contains_key("preferred-language"));

    let household = entity(&compiled, "household");
    assert!(household.change_control.is_some());
    assert!(household.fields.contains_key("contact-person"));

    let membership = entity(&compiled, "group-membership");
    assert!(membership.change_control.is_some());

    let request = entity(&compiled, "register-household-contact-request");
    let request_plan = request
        .change_request
        .as_ref()
        .expect("household contact request compiles to a request plan");
    assert_eq!(request_plan.effects.len(), 3);
    assert_eq!(request_plan.stages.len(), 2);
    assert_eq!(
        request_plan.target_entities,
        ["group-membership", "household", "person"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
}

#[test]
fn business_pilot_fixture_journeys_preflight_against_the_exact_compiled_registry() {
    let compiled = compile_fixture("business-establishments");
    let journeys = fs::read(fixture_root("business-establishments").join("tests/journeys.yaml"))
        .expect("committed business journeys are readable");
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
                    "business journey first fails at step {step}: {prefix_error:?}; full error: {error:?}"
                );
            }
        }
        panic!("business journey validation failed after every prefix passed: {error:?}");
    }
}

#[test]
fn change_request_pilot_fixture_journeys_preflight_against_their_exact_registries() {
    for fixture in [
        "asset-site-placement-change-requests",
        "publicschema-household-change-requests",
    ] {
        let compiled = compile_fixture(fixture);
        let journeys = fs::read(fixture_root(fixture).join("tests/journeys.yaml"))
            .expect("committed change request journeys are readable");
        if let Err(error) = validate_fixture_journeys(&journeys, &compiled) {
            let document: serde_json::Value = serde_norway::from_slice(&journeys)
                .expect("journey YAML has a generic value shape");
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
                        "{fixture} journey first fails at step {step}: {prefix_error:?}; full error: {error:?}"
                    );
                }
            }
            panic!("{fixture} journey validation failed after every prefix passed: {error:?}");
        }
    }
}

#[test]
fn inspection_pilot_fixture_compiles_protected_observations_and_create_only_permit() {
    let compiled = compile_fixture("inspection");
    assert_eq!(compiled.registry_id(), "inspection");
    assert_eq!(compiled.entities().len(), 4);
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

    let observation = entity(&compiled, "inspection-observation");
    assert!(observation.constraints.values().any(|constraint| {
        matches!(
            constraint,
            ConstraintSource::IntRange {
                field,
                minimum: Some(0),
                maximum: Some(4),
                ..
            } if field == "finding-grade"
        )
    }));

    assert!(entity(&compiled, "public-authority")
        .fields
        .contains_key("jurisdiction"));
    let permit = entity(&compiled, "permit");
    assert!(permit.fields.contains_key("issuing-authority"));
    assert_eq!(permit.mutation_mode, MutationMode::CreateOnly);
    assert!(permit.fields.contains_key("corrected-permit"));
    assert!(permit.fields.contains_key("correction-reason"));
    assert!(permit.fields.contains_key("provenance-note"));
    // Corrections retain the original effective period in an append-only record.
    assert!(!has_temporal_non_overlap(permit, &["inspection"]));
    assert_eq!(
        operations_for(&compiled, "permit"),
        [Operation::Create, Operation::Get, Operation::List]
    );
}

#[test]
fn facility_pilot_fixture_compiles_bounded_crs84_scalars_imports_and_temporal_activity() {
    let compiled = compile_fixture("facility");
    assert_eq!(compiled.registry_id(), "facility");
    assert_eq!(compiled.entities().len(), 4);

    let installation = entity(&compiled, "installation");
    assert!(matches!(
        field(installation, "centroid").field_type,
        FieldTypeSource::Crs84Point {
            precision: 7,
            bbox: Some(_)
        }
    ));
    assert!(matches!(
        field(installation, "area-value").field_type,
        FieldTypeSource::Decimal {
            precision: 12,
            scale: 4,
            ..
        }
    ));
    assert!(has_unique(
        installation,
        &["import-source", "source-record-id"]
    ));
    assert!(matches!(
        field(installation, "area-unit").field_type,
        FieldTypeSource::VocabularyCode { .. }
    ));
    assert!(matches!(
        field(installation, "administrative-boundary").field_type,
        FieldTypeSource::VocabularyCode { .. }
    ));

    let activity = entity(&compiled, "discharge-report");
    assert!(has_temporal_non_overlap(
        activity,
        &["installation", "substance-code"]
    ));
    assert_eq!(
        field(activity, "period-start").valid_time_role,
        Some(ValidTimeRole::ValidFrom)
    );
    assert_eq!(
        field(activity, "period-end").valid_time_role,
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
    assert_eq!(
        get_access.default_profile_id.as_deref(),
        Some("public-register")
    );
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
