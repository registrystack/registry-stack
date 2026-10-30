// SPDX-License-Identifier: Apache-2.0
#![cfg(all(feature = "runtime", feature = "tooling"))]

use registry_breg::compiler::{compile_project, module_digest, CompileProfile};
use registry_breg::contract::{parse_module_yaml, parse_project_json};
use registry_breg::migration_plan::{
    ArtifactDigestBinding, ChunkCursorProtocol, MigrationRehearsalReceipt, RehearsalFixture,
    RehearsalRowAssertion, ReviewedChangeCover, ReviewedMigrationAssertionDescriptor,
    ReviewedMigrationDescriptor, ReviewedMigrationFile, ReviewedMigrationObject,
    ReviewedMigrationObjectKind, ReviewedMigrationRecovery, ReviewedMigrationSource,
    ReviewedMigrationStepDescriptor,
};
use registry_breg::package::{
    compiled_registry_change_set, prepare_package, CompiledRegistryChangeClass,
    CompiledRegistryChangeCode, PackageBuildRequest, PackageMigrationPlanInput,
    PackageModuleSource, PackageSourceFile,
};
use registry_breg::CompiledRegistry;
use registry_platform_canonical_json::canonicalize_json;
use serde::Serialize;
use serde_json::json;
use sha2::{Digest, Sha256};

const PRIOR_REVISION: &str =
    "sha256:1111111111111111111111111111111111111111111111111111111111111111";
const PRIOR_FINGERPRINT: &str =
    "sha256:3333333333333333333333333333333333333333333333333333333333333333";
const FINAL_FINGERPRINT: &str =
    "sha256:2222222222222222222222222222222222222222222222222222222222222222";

#[test]
fn generated_identifier_activation_requires_review_and_selects_seed_and_unique_ddl() {
    let baseline_source = source(None);
    let candidate_source = source(Some("REG-"));
    let baseline = compile(&baseline_source);
    let candidate = compile(&candidate_source);
    let changes = compiled_registry_change_set(&baseline, &candidate, PRIOR_REVISION);

    let generation_change = changes
        .changes
        .iter()
        .find(|change| change.code == CompiledRegistryChangeCode::FieldGenerationChanged)
        .expect("adding generation is classified");
    assert_eq!(
        generation_change.class,
        CompiledRegistryChangeClass::DataBackfillRequired
    );

    let reviewed = reviewed_migration(&candidate, generation_change);
    let package = prepare_package(build_request(
        candidate_source,
        PackageMigrationPlanInput::ReviewedSuccessor {
            prior_registry: Box::new(baseline),
            prior_schema_fingerprint: PRIOR_FINGERPRINT.to_owned(),
            migrations: vec![reviewed],
        },
    ))
    .expect("reviewed generated-identifier activation prepares");
    let statement_ids = package
        .manifest()
        .migration_plan
        .statements
        .iter()
        .map(|statement| statement.id.as_str())
        .collect::<Vec<_>>();

    assert!(
        statement_ids.contains(&"entity.record.field.registration-code.generated-identifiers.seed")
    );
    assert!(statement_ids.contains(&"entity.record.constraint.generated:registration-code"));
}

#[test]
fn changing_an_active_generated_identifier_is_unsupported() {
    let active = compile(&source(Some("REG-")));
    let changed = compile(&source(Some("ALT-")));
    let changes = compiled_registry_change_set(&active, &changed, PRIOR_REVISION);

    let generation_change = changes
        .changes
        .iter()
        .find(|change| change.code == CompiledRegistryChangeCode::FieldGenerationChanged)
        .expect("changing generation is classified");
    assert_eq!(
        generation_change.class,
        CompiledRegistryChangeClass::Unsupported
    );
}

#[test]
fn removing_an_active_generated_identifier_is_unsupported() {
    let active = compile(&source(Some("REG-")));
    let removed = compile(&source_without_generated_field());
    let changes = compiled_registry_change_set(&active, &removed, PRIOR_REVISION);

    assert_unsupported_generation_removal(&changes.changes);
    assert!(changes
        .changes
        .iter()
        .any(|change| change.code == CompiledRegistryChangeCode::FieldRemoved));
}

#[test]
fn removing_a_record_type_with_an_active_generated_identifier_is_unsupported() {
    let active = compile(&source(Some("REG-")));
    let removed = compile(&source_without_generated_record_type());
    let changes = compiled_registry_change_set(&active, &removed, PRIOR_REVISION);

    assert_unsupported_generation_removal(&changes.changes);
    assert!(changes
        .changes
        .iter()
        .any(|change| change.code == CompiledRegistryChangeCode::EntityRemoved));
}

fn assert_unsupported_generation_removal(
    changes: &[registry_breg::package::CompiledRegistryChange],
) {
    let generation_change = changes
        .iter()
        .find(|change| change.code == CompiledRegistryChangeCode::FieldGenerationChanged)
        .expect("removing an active generator is classified");
    assert_eq!(
        generation_change.class,
        CompiledRegistryChangeClass::Unsupported
    );
    assert_eq!(
        generation_change.target.record_type_id.as_deref(),
        Some("record")
    );
    assert_eq!(
        generation_change.target.member_id.as_deref(),
        Some("registration-code")
    );
}

struct Source {
    project: Vec<u8>,
    module: Vec<u8>,
}

fn source(prefix: Option<&str>) -> Source {
    let mut generated_field = json!({
        "id": "registration-code",
        "type": "string",
        "minimumLength": 10,
        "maximumLength": 24,
        "required": true,
        "classification": "internal"
    });
    if let Some(prefix) = prefix {
        generated_field["generate"] = json!({
            "type": "sequence",
            "prefix": prefix,
            "minimumDigits": 6,
            "scope": ["jurisdiction"]
        });
    }
    let module = json!({
        "apiVersion": "id.registrystack.org/formats/breg/module/v1alpha1",
        "kind": "BRegModule",
        "id": "core",
        "version": "1",
        "recordTypes": [{
            "id": "record",
            "primaryDataset": "records",
            "route": "records",
            "mutationMode": "mutable",
            "classification": "internal",
            "fields": [
                {
                    "id": "jurisdiction",
                    "type": "string",
                    "maximumLength": 16,
                    "required": true,
                    "classification": "internal"
                },
                generated_field
            ],
            "accessProfiles": [{
                "id": "reader",
                "principalClaim": "registry_principal",
                "requiredScopes": "unrestricted",
                "operations": ["get", "list"],
                "readableFields": ["jurisdiction", "registration-code"],
                "rowBoundaries": "unrestricted"
            }]
        }]
    });
    let module = serde_json::to_vec(&module).expect("module serializes");
    let parsed_module = parse_module_yaml(&module).expect("module parses for its digest");
    let project = json!({
        "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
        "kind": "BRegProject",
        "project": {
            "id": "generated-identifier-migration",
            "version": "1",
            "defaultLanguage": "en",
            "canonicalBaseIri": "https://registry.example.test"
        },
        "package": {"sourceRevision": "compiler-source-revision"},
        "datasets": [{"id": "records"}],
        "manifestProjection": {
            "accessProfile": "reader",
            "classificationCeiling": "internal",
            "catalog": {
                "baseUrl": "https://registry.example.test",
                "title": "Generated Identifier Registry",
                "publisher": {
                    "id": "registry-authority",
                    "name": "Registry Authority"
                }
            },
            "publicService": {
                "id": "generated-identifier-service",
                "title": "Generated Identifier Registry"
            },
            "datasets": [{
                "id": "records",
                "title": "Records",
                "owner": "Registry Authority",
                "status": "active"
            }],
            "dataServices": [{
                "id": "generated-identifier-data-service",
                "title": "Generated Identifier Registry",
                "endpointUrl": "https://registry.example.test",
                "servesDatasets": ["records"]
            }]
        },
        "modules": [{
            "id": "core",
            "version": "1",
            "digest": module_digest(&parsed_module)
        }]
    });
    Source {
        project: serde_json::to_vec(&project).expect("project serializes"),
        module,
    }
}

fn source_without_generated_field() -> Source {
    let source = source(Some("REG-"));
    let mut module: serde_json::Value =
        serde_json::from_slice(&source.module).expect("module JSON parses");
    module["recordTypes"][0]["fields"]
        .as_array_mut()
        .expect("fields are an array")
        .retain(|field| field["id"] != "registration-code");
    module["recordTypes"][0]["accessProfiles"][0]["readableFields"] = json!(["jurisdiction"]);
    source_with_module(source, module)
}

fn source_without_generated_record_type() -> Source {
    let source = source(Some("REG-"));
    let mut module: serde_json::Value =
        serde_json::from_slice(&source.module).expect("module JSON parses");
    let record = &mut module["recordTypes"][0];
    record["id"] = json!("retained-record");
    record["route"] = json!("retained-records");
    record["fields"] = json!([{
        "id": "jurisdiction",
        "type": "string",
        "maximumLength": 16,
        "required": true,
        "classification": "internal"
    }]);
    record["accessProfiles"][0]["readableFields"] = json!(["jurisdiction"]);
    source_with_module(source, module)
}

fn source_with_module(source: Source, module: serde_json::Value) -> Source {
    let module = serde_json::to_vec(&module).expect("module serializes");
    let parsed_module = parse_module_yaml(&module).expect("module parses for its digest");
    let mut project: serde_json::Value =
        serde_json::from_slice(&source.project).expect("project JSON parses");
    project["modules"][0]["digest"] = json!(module_digest(&parsed_module));
    Source {
        project: serde_json::to_vec(&project).expect("project serializes"),
        module,
    }
}

fn compile(source: &Source) -> CompiledRegistry {
    let project = parse_project_json(&source.project).expect("project parses");
    let module = parse_module_yaml(&source.module).expect("module parses");
    compile_project(&project, &[module], CompileProfile::Production)
        .expect("generated identifier migration fixture compiles")
}

fn reviewed_migration(
    candidate: &CompiledRegistry,
    change: &registry_breg::package::CompiledRegistryChange,
) -> ReviewedMigrationSource {
    let entity = &candidate.entities()["record"];
    let field = &entity.fields["registration-code"];
    let base = "modules/core/migrations/activate-generated-identifier";
    let step_path = format!("{base}/steps/inspect-existing-values.sql");
    let pre_path = format!("{base}/assertions/pre.sql");
    let post_path = format!("{base}/assertions/post.sql");
    let fixture_path = format!("{base}/fixtures/existing-values.jsonl");
    let step_sql = format!(
        "UPDATE registry_data.{} SET {} = {} WHERE record_id = ANY($1::pg_catalog.uuid[])",
        entity.physical_table, field.physical_name, field.physical_name
    )
    .into_bytes();
    let assertion_sql = format!(
        "SELECT pg_catalog.count(*) >= 0 FROM registry_data.{}",
        entity.physical_table
    )
    .into_bytes();
    let fixture = b"{\"jurisdiction\":\"CA\",\"registrationCode\":\"REG-000001\"}\n".to_vec();
    let descriptor = ReviewedMigrationDescriptor {
        id: "activate-generated-identifier".to_owned(),
        change_class: CompiledRegistryChangeClass::DataBackfillRequired,
        covers: vec![ReviewedChangeCover::from(change)],
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        history: None,
        lock_timeout_ms: 10_000,
        statement_timeout_ms: 60_000,
        steps: vec![ReviewedMigrationStepDescriptor::ChunkedBackfill {
            id: "inspect-existing-values".to_owned(),
            entity_id: "record".to_owned(),
            sql_path: step_path.clone(),
            objects: vec![ReviewedMigrationObject {
                schema: "registry_data".to_owned(),
                table: entity.physical_table.clone(),
                entity_id: "record".to_owned(),
                kind: ReviewedMigrationObjectKind::Field,
                member_id: Some("registration-code".to_owned()),
                physical_name: field.physical_name.clone(),
            }],
            cursor: ChunkCursorProtocol::RecordIdUuidArray,
            chunk_size: 100,
            max_total_rows: 1_000,
            lock_timeout_ms: 1_000,
            statement_timeout_ms: 10_000,
            exact_affected_rows: true,
        }],
        pre_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "pre".to_owned(),
            sql_path: pre_path.clone(),
        }],
        post_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "post".to_owned(),
            sql_path: post_path.clone(),
        }],
        rehearsal_receipt_path: format!("{base}/rehearsal.json"),
        backup_binding_path: None,
    };
    let descriptor_bytes = canonical(&descriptor);
    let receipt = MigrationRehearsalReceipt {
        prior_package_digest: PRIOR_REVISION.to_owned(),
        prior_schema_fingerprint: PRIOR_FINGERPRINT.to_owned(),
        plan_sha256: digest(&descriptor_bytes),
        sql_sha256: vec![ArtifactDigestBinding {
            path: step_path.clone(),
            sha256: digest(&step_sql),
        }],
        assertion_sha256: vec![
            ArtifactDigestBinding {
                path: pre_path.clone(),
                sha256: digest(&assertion_sql),
            },
            ArtifactDigestBinding {
                path: post_path.clone(),
                sha256: digest(&assertion_sql),
            },
        ],
        fixture_inventory: vec![RehearsalFixture {
            id: "existing-values".to_owned(),
            path: fixture_path.clone(),
            sha256: digest(&fixture),
            row_count: 1,
        }],
        postgres_major: 17,
        row_assertions: vec![RehearsalRowAssertion {
            step_id: "inspect-existing-values".to_owned(),
            affected_rows: 1,
        }],
        final_schema_fingerprint: FINAL_FINGERPRINT.to_owned(),
    };
    let mut files = vec![
        ReviewedMigrationFile {
            path: step_path,
            bytes: step_sql,
        },
        ReviewedMigrationFile {
            path: pre_path,
            bytes: assertion_sql.clone(),
        },
        ReviewedMigrationFile {
            path: post_path,
            bytes: assertion_sql,
        },
        ReviewedMigrationFile {
            path: descriptor.rehearsal_receipt_path.clone(),
            bytes: canonical(&receipt),
        },
        ReviewedMigrationFile {
            path: fixture_path,
            bytes: fixture,
        },
    ];
    files.sort_by(|left, right| left.path.cmp(&right.path));
    ReviewedMigrationSource {
        module_id: "core".to_owned(),
        descriptor: ReviewedMigrationFile {
            path: format!("{base}/descriptor.json"),
            bytes: descriptor_bytes,
        },
        files,
    }
}

fn build_request(source: Source, migration_plan: PackageMigrationPlanInput) -> PackageBuildRequest {
    PackageBuildRequest {
        from_package_digest: Some(PRIOR_REVISION.to_owned()),
        compiler_source_revision: "compiler-source-revision".to_owned(),
        schema_fingerprint: FINAL_FINGERPRINT.to_owned(),
        project: PackageSourceFile {
            path: "source/registry.json".to_owned(),
            bytes: source.project,
        },
        modules: vec![PackageModuleSource {
            id: "core".to_owned(),
            path: "source/modules/core/module.json".to_owned(),
            bytes: source.module,
            assets: Vec::new(),
        }],
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".to_owned(),
            bytes: br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: list-records
    steps:
      - id: list-records
        entity: record
        accessProfile: reader
        claims: {registry_principal: package-reader}
        request: {type: list}
        expect: {outcome: success, status: 200, count: 0}
"#
            .to_vec(),
        },
        migration_plan,
    }
}

fn canonical(value: &impl Serialize) -> Vec<u8> {
    canonicalize_json(&serde_json::to_value(value).expect("value serializes"))
        .expect("value canonicalizes")
}

fn digest(bytes: &[u8]) -> String {
    let value = Sha256::digest(bytes);
    let mut rendered = String::with_capacity(value.len() * 2 + 7);
    rendered.push_str("sha256:");
    for byte in value {
        use std::fmt::Write as _;
        write!(&mut rendered, "{byte:02x}").expect("digest writes");
    }
    rendered
}
