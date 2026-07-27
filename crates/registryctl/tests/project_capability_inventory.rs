// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

#[path = "../src/project_authoring/capability_inventory.rs"]
mod capability_inventory;

use std::collections::BTreeSet;

use capability_inventory::{
    build_capability_inventory, CapabilityDisposition, CapabilityId, CapabilityInventoryError,
    CapabilityInventoryInput, CapabilityUsageCounts, InstalledCapabilityEvidence,
    InstalledCapabilityState, ProjectCapabilityInventoryReportV1, RuntimeActivationEvaluation,
    SupportComponent, SupportEvidence, SupportKind, SupportState, SupportedCapabilityVersion,
    COMPILED_CAPABILITY_RELEASE_FACTS, MAX_CAPABILITY_USAGE_COUNT,
};
use serde_json::{json, Value};

const SCHEMA: &str =
    include_str!("../schemas/project-reports/registry.project.capability_inventory.v1.schema.json");
const FIXTURE: &str =
    include_str!("fixtures/project-reports/registry.project.capability_inventory.v1.json");

fn parse(input: &str) -> Value {
    serde_json::from_str(input).expect("JSON parses")
}

fn validator() -> jsonschema::JSONSchema {
    jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&parse(SCHEMA))
        .expect("capability inventory schema compiles")
}

fn assert_schema_valid(document: &Value) {
    if let Err(errors) = validator().validate(document) {
        let details = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("document should validate: {details:?}");
    }
}

fn assert_schema_invalid(document: &Value) {
    assert!(
        validator().validate(document).is_err(),
        "document should not validate"
    );
}

fn compiled_input() -> CapabilityInventoryInput {
    let mut input = CapabilityInventoryInput::new();
    for (capability, state, evidence) in COMPILED_CAPABILITY_RELEASE_FACTS {
        input
            .record_installed_capability(capability, state, evidence)
            .expect("compiled evidence records");
    }
    for (component, evidence) in [
        (
            SupportComponent::HttpSourceWorker,
            SupportEvidence::LinkedCrate,
        ),
        (
            SupportComponent::RhaiScriptWorker,
            SupportEvidence::LinkedCrate,
        ),
        (
            SupportComponent::RhaiXwProtocolHelper,
            SupportEvidence::LinkedCrate,
        ),
        (
            SupportComponent::RegistryRelayProduct,
            SupportEvidence::LinkedCrate,
        ),
        (
            SupportComponent::RegistryNotaryProduct,
            SupportEvidence::LinkedCrate,
        ),
        (
            SupportComponent::RegistryRelayValidator,
            SupportEvidence::LinkedProductValidator,
        ),
        (
            SupportComponent::RegistryNotaryValidator,
            SupportEvidence::LinkedProductValidator,
        ),
        (
            SupportComponent::ProjectAuthoringSchema,
            SupportEvidence::EmbeddedSchema,
        ),
        (
            SupportComponent::RegistryRelayConfigSchema,
            SupportEvidence::EmbeddedSchema,
        ),
        (
            SupportComponent::RegistryNotaryConfigSchema,
            SupportEvidence::EmbeddedSchema,
        ),
        (
            SupportComponent::RegistryctlDistribution,
            SupportEvidence::ReleaseMetadata,
        ),
    ] {
        input
            .record_support(component, SupportState::Available, evidence)
            .expect("available support records");
    }
    input
        .record_support(
            SupportComponent::SnapshotMaterializationWorker,
            SupportState::Missing,
            SupportEvidence::ExplicitlyMissing,
        )
        .expect("missing worker records");
    for image in [
        SupportComponent::RegistryRelayImage,
        SupportComponent::RegistryNotaryImage,
    ] {
        input
            .record_support(
                image,
                SupportState::NotEvaluated,
                SupportEvidence::NoEvidence,
            )
            .expect("image remains not evaluated");
    }
    input
}

fn canonical_input() -> CapabilityInventoryInput {
    let mut input = compiled_input();
    for capability in [
        CapabilityId::SourceHttp,
        CapabilityId::SourceScript,
        CapabilityId::SourceSnapshot,
        CapabilityId::RegistryRelayProduct,
        CapabilityId::RegistryNotaryProduct,
    ] {
        input
            .record_project_declaration(capability)
            .expect("declaration records");
    }
    for capability in [
        CapabilityId::SourceHttp,
        CapabilityId::SourceScript,
        CapabilityId::RegistryRelayProduct,
        CapabilityId::RegistryNotaryProduct,
    ] {
        input
            .record_environment_enablement(capability)
            .expect("enablement records");
    }
    for (capability, usage) in [
        (
            CapabilityId::SourceHttp,
            CapabilityUsageCounts {
                services: 1,
                consultations: 1,
                claims: 0,
            },
        ),
        (
            CapabilityId::SourceScript,
            CapabilityUsageCounts {
                services: 0,
                consultations: 1,
                claims: 1,
            },
        ),
        (
            CapabilityId::RhaiRuntime,
            CapabilityUsageCounts {
                services: 0,
                consultations: 1,
                claims: 1,
            },
        ),
        (
            CapabilityId::RhaiAbi,
            CapabilityUsageCounts {
                services: 0,
                consultations: 1,
                claims: 1,
            },
        ),
        (
            CapabilityId::RegistryRelayProduct,
            CapabilityUsageCounts {
                services: 1,
                consultations: 2,
                claims: 0,
            },
        ),
        (
            CapabilityId::RegistryNotaryProduct,
            CapabilityUsageCounts {
                services: 0,
                consultations: 0,
                claims: 1,
            },
        ),
    ] {
        input
            .record_usage(capability, usage)
            .expect("usage records");
    }
    input
}

#[test]
fn canonical_fixture_validates_and_roundtrips_exactly() {
    let document = parse(FIXTURE);
    assert_schema_valid(&document);
    let decoded: ProjectCapabilityInventoryReportV1 =
        serde_json::from_value(document.clone()).expect("canonical fixture decodes");
    assert_eq!(
        serde_json::to_value(decoded).expect("canonical fixture re-encodes"),
        document
    );
}

#[test]
fn pure_builder_is_deterministic_and_matches_the_canonical_fixture() {
    let first = build_capability_inventory(canonical_input()).expect("inventory builds");
    let second = build_capability_inventory(canonical_input()).expect("inventory rebuilds");
    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_value(&first).expect("report serializes"),
        parse(FIXTURE)
    );

    let capability_order = first
        .capabilities
        .iter()
        .map(|record| record.capability)
        .collect::<Vec<_>>();
    assert!(capability_order.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(
        capability_order
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
            .len(),
        capability_order.len()
    );
    let support_order = first
        .support
        .iter()
        .map(|record| record.component)
        .collect::<Vec<_>>();
    assert!(support_order.windows(2).all(|pair| pair[0] < pair[1]));
}

#[test]
fn schema_and_typed_ingress_require_every_closed_inventory_row_exactly_once() {
    for (collection, duplicate_index) in [("capabilities", 11), ("support", 13)] {
        let mut duplicate = parse(FIXTURE);
        let first = duplicate[collection][0].clone();
        duplicate[collection][duplicate_index] = first;
        assert_schema_invalid(&duplicate);
        assert!(
            serde_json::from_value::<ProjectCapabilityInventoryReportV1>(duplicate).is_err(),
            "typed ingress must reject a duplicate {collection} row that omits a closed ID"
        );

        let mut omitted = parse(FIXTURE);
        omitted[collection]
            .as_array_mut()
            .expect("inventory collection is an array")
            .pop();
        assert_schema_invalid(&omitted);
        assert!(
            serde_json::from_value::<ProjectCapabilityInventoryReportV1>(omitted).is_err(),
            "typed ingress must reject an omitted {collection} row"
        );
    }
}

#[test]
fn installed_declared_enabled_used_missing_and_inactive_states_stay_distinct() {
    let report = build_capability_inventory(canonical_input()).expect("inventory builds");
    let state = |capability| {
        report
            .capabilities
            .iter()
            .find(|record| record.capability == capability)
            .expect("capability is inventoried")
    };
    assert_eq!(
        state(CapabilityId::SourceHttp).disposition,
        CapabilityDisposition::Used
    );
    assert_eq!(
        state(CapabilityId::SourceSnapshot).disposition,
        CapabilityDisposition::DeclaredInactive
    );
    assert_eq!(
        state(CapabilityId::RegistryRelayValidator).disposition,
        CapabilityDisposition::InstalledUnused
    );
    assert_eq!(report.missing_support.len(), 1);
    assert_eq!(
        report.missing_support[0].component,
        SupportComponent::SnapshotMaterializationWorker
    );
    assert_eq!(report.missing_support[0].kind, SupportKind::Worker);
    assert_eq!(report.inactive_or_unused.len(), 1);
    assert_eq!(
        report.runtime_activation,
        RuntimeActivationEvaluation::NotEvaluated
    );

    let mut missing_worker = CapabilityInventoryInput::new();
    missing_worker
        .record_installed_capability(
            CapabilityId::SourceScript,
            InstalledCapabilityState::Compiled,
            InstalledCapabilityEvidence::EmbeddedCompiler,
        )
        .expect("script compilation records");
    missing_worker
        .record_project_declaration(CapabilityId::SourceScript)
        .expect("script declaration records");
    missing_worker
        .record_environment_enablement(CapabilityId::SourceScript)
        .expect("script enablement records");
    missing_worker
        .record_usage(
            CapabilityId::SourceScript,
            CapabilityUsageCounts {
                services: 0,
                consultations: 1,
                claims: 0,
            },
        )
        .expect("script usage records");
    missing_worker
        .record_support(
            SupportComponent::RhaiScriptWorker,
            SupportState::Missing,
            SupportEvidence::ExplicitlyMissing,
        )
        .expect("missing worker records");
    let report = build_capability_inventory(missing_worker).expect("inventory builds");
    assert_eq!(
        report.capabilities[1].disposition,
        CapabilityDisposition::UsedWithMissingSupport
    );
}

#[test]
fn builder_fails_closed_on_inconsistent_or_duplicate_evidence() {
    let mut enabled_without_declaration = CapabilityInventoryInput::new();
    enabled_without_declaration
        .record_environment_enablement(CapabilityId::SourceHttp)
        .expect("enablement records");
    assert_eq!(
        build_capability_inventory(enabled_without_declaration),
        Err(CapabilityInventoryError::EnabledWithoutDeclaration(
            CapabilityId::SourceHttp
        ))
    );

    let mut used_without_declaration = CapabilityInventoryInput::new();
    used_without_declaration
        .record_usage(
            CapabilityId::SourceScript,
            CapabilityUsageCounts {
                services: 0,
                consultations: 1,
                claims: 0,
            },
        )
        .expect("usage records");
    assert_eq!(
        build_capability_inventory(used_without_declaration),
        Err(CapabilityInventoryError::UsedWithoutDeclaration(
            CapabilityId::SourceScript
        ))
    );

    let mut duplicate = CapabilityInventoryInput::new();
    duplicate
        .record_project_declaration(CapabilityId::SourceSnapshot)
        .expect("first declaration records");
    assert_eq!(
        duplicate.record_project_declaration(CapabilityId::SourceSnapshot),
        Err(CapabilityInventoryError::DuplicateProjectDeclaration(
            CapabilityId::SourceSnapshot
        ))
    );

    let mut invalid_evidence = CapabilityInventoryInput::new();
    assert_eq!(
        invalid_evidence.record_installed_capability(
            CapabilityId::SourceHttp,
            InstalledCapabilityState::Compiled,
            InstalledCapabilityEvidence::NoEvidence,
        ),
        Err(CapabilityInventoryError::InvalidInstalledEvidence)
    );
}

#[test]
fn image_and_runtime_activation_claims_cannot_be_inferred_from_static_input() {
    let mut input = CapabilityInventoryInput::new();
    assert_eq!(
        input.record_support(
            SupportComponent::RegistryRelayImage,
            SupportState::Available,
            SupportEvidence::ReleaseMetadata,
        ),
        Err(CapabilityInventoryError::ImageAvailabilityCannotBeClaimed)
    );
    assert_eq!(
        input.record_support(
            SupportComponent::RegistryRelayImage,
            SupportState::Missing,
            SupportEvidence::ExplicitlyMissing,
        ),
        Err(CapabilityInventoryError::ImageAvailabilityCannotBeClaimed)
    );

    let report = build_capability_inventory(input).expect("empty static inventory builds");
    assert_eq!(
        report.runtime_activation,
        RuntimeActivationEvaluation::NotEvaluated
    );
    for image in report
        .support
        .iter()
        .filter(|assessment| assessment.kind == SupportKind::Image)
    {
        assert_eq!(image.state, SupportState::NotEvaluated);
        assert_eq!(image.evidence, SupportEvidence::NoEvidence);
    }
}

#[test]
fn usage_bound_is_total_and_overflow_safe() {
    let mut exact = CapabilityInventoryInput::new();
    exact
        .record_usage(
            CapabilityId::RegistryRelayProduct,
            CapabilityUsageCounts {
                services: MAX_CAPABILITY_USAGE_COUNT,
                consultations: 0,
                claims: 0,
            },
        )
        .expect("exact maximum records");

    let mut total_too_large = CapabilityInventoryInput::new();
    assert_eq!(
        total_too_large.record_usage(
            CapabilityId::RegistryRelayProduct,
            CapabilityUsageCounts {
                services: MAX_CAPABILITY_USAGE_COUNT,
                consultations: 1,
                claims: 0,
            },
        ),
        Err(CapabilityInventoryError::UsageCountOutOfRange)
    );

    let mut overflow = CapabilityInventoryInput::new();
    assert_eq!(
        overflow.record_usage(
            CapabilityId::RegistryRelayProduct,
            CapabilityUsageCounts {
                services: u32::MAX,
                consultations: u32::MAX,
                claims: u32::MAX,
            },
        ),
        Err(CapabilityInventoryError::UsageCountOutOfRange)
    );

    let schema = parse(SCHEMA);
    assert_eq!(
        schema["$defs"]["usage"]["x-registry-aggregateMaximum"],
        json!(MAX_CAPABILITY_USAGE_COUNT)
    );
    let mut declared_total_too_large = parse(FIXTURE);
    declared_total_too_large["capabilities"][0]["used_by"]["total"] =
        json!(MAX_CAPABILITY_USAGE_COUNT + 1);
    assert_schema_invalid(&declared_total_too_large);

    let mut aggregate_too_large = parse(FIXTURE);
    aggregate_too_large["capabilities"][0]["used_by"] = json!({
        "services": 500_000,
        "consultations": 500_000,
        "claims": 1,
        "total": MAX_CAPABILITY_USAGE_COUNT
    });
    assert_schema_valid(&aggregate_too_large);
    assert!(
        serde_json::from_value::<ProjectCapabilityInventoryReportV1>(aggregate_too_large).is_err(),
        "strict typed ingress must enforce the aggregate ceiling behind the bounded total"
    );

    let mut mismatched_total = parse(FIXTURE);
    mismatched_total["capabilities"][0]["used_by"]["total"] = json!(0);
    assert_schema_valid(&mismatched_total);
    assert!(
        serde_json::from_value::<ProjectCapabilityInventoryReportV1>(mismatched_total).is_err(),
        "strict typed ingress must reject a declared total that does not equal the breakdown"
    );
}

#[test]
fn relay_product_usage_requires_relay_product_support() {
    let mut input = CapabilityInventoryInput::new();
    input
        .record_installed_capability(
            CapabilityId::RegistryRelayProduct,
            InstalledCapabilityState::Compiled,
            InstalledCapabilityEvidence::LinkedCrate,
        )
        .expect("Relay product compilation records");
    input
        .record_project_declaration(CapabilityId::RegistryRelayProduct)
        .expect("Relay product declaration records");
    input
        .record_environment_enablement(CapabilityId::RegistryRelayProduct)
        .expect("Relay product enablement records");
    input
        .record_usage(
            CapabilityId::RegistryRelayProduct,
            CapabilityUsageCounts {
                services: 1,
                consultations: 0,
                claims: 0,
            },
        )
        .expect("Relay product usage records");
    input
        .record_support(
            SupportComponent::RegistryRelayProduct,
            SupportState::Missing,
            SupportEvidence::ExplicitlyMissing,
        )
        .expect("missing Relay product support records");

    let report = build_capability_inventory(input).expect("inventory builds");
    let relay = report
        .capabilities
        .iter()
        .find(|record| record.capability == CapabilityId::RegistryRelayProduct)
        .expect("Relay product capability is inventoried");
    assert_eq!(
        relay.disposition,
        CapabilityDisposition::UsedWithMissingSupport
    );
}

#[test]
fn schema_and_dto_reject_country_value_carriers() {
    let mut root = parse(FIXTURE);
    root["project"] = json!("COUNTRY_PROJECT_SENTINEL");
    assert_schema_invalid(&root);
    assert!(serde_json::from_value::<ProjectCapabilityInventoryReportV1>(root).is_err());

    for (pointer, forbidden_field, sentinel) in [
        (
            "/capabilities/0",
            "origin",
            "https://COUNTRY_ORIGIN_SENTINEL.invalid",
        ),
        ("/capabilities/1", "path", "/COUNTRY/PATH/SENTINEL"),
        ("/support/0", "secret_name", "COUNTRY_SECRET_NAME_SENTINEL"),
        (
            "/support/12",
            "runtime_observation",
            "COUNTRY_RUNTIME_SENTINEL",
        ),
        (
            "/missing_support/0",
            "detail",
            "COUNTRY_SUPPORT_VALUE_SENTINEL",
        ),
    ] {
        let mut document = parse(FIXTURE);
        document
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .expect("test object exists")
            .insert(forbidden_field.to_owned(), json!(sentinel));
        assert_schema_invalid(&document);
        assert!(serde_json::from_value::<ProjectCapabilityInventoryReportV1>(document).is_err());
    }
}

#[test]
fn schema_rejects_image_availability_runtime_activation_and_open_enums() {
    let mut runtime = parse(FIXTURE);
    runtime["runtime_activation"] = json!("active");
    assert_schema_invalid(&runtime);

    let mut image = parse(FIXTURE);
    image["support"][12]["state"] = json!("available");
    image["support"][12]["evidence"] = json!("release_metadata");
    assert_schema_invalid(&image);

    let mut disguised_image = parse(FIXTURE);
    disguised_image["support"][12]["kind"] = json!("worker");
    disguised_image["support"][12]["state"] = json!("available");
    disguised_image["support"][12]["evidence"] = json!("release_metadata");
    assert_schema_invalid(&disguised_image);
    assert!(
        serde_json::from_value::<ProjectCapabilityInventoryReportV1>(disguised_image).is_err(),
        "closed image component identity must not be bypassed through mutable kind metadata"
    );

    let mut claimed_missing_image = parse(FIXTURE);
    claimed_missing_image["support"][12]["state"] = json!("missing");
    claimed_missing_image["support"][12]["evidence"] = json!("explicitly_missing");
    claimed_missing_image["missing_support"]
        .as_array_mut()
        .expect("missing support is an array")
        .push(json!({
            "component": "registry_relay_image",
            "kind": "image",
            "state": "missing",
            "required_by": ["registry_relay_product"]
        }));
    assert_schema_invalid(&claimed_missing_image);
    assert!(
        serde_json::from_value::<ProjectCapabilityInventoryReportV1>(claimed_missing_image)
            .is_err(),
        "offline typed ingress must not infer that an image is missing"
    );

    let mut capability = parse(FIXTURE);
    capability["capabilities"][0]["capability"] = json!("country_specific_connector");
    assert_schema_invalid(&capability);

    let mut unknown_nested = parse(FIXTURE);
    unknown_nested["capabilities"][0]["used_by"]["records"] = json!(1);
    assert_schema_invalid(&unknown_nested);
    assert!(serde_json::from_value::<ProjectCapabilityInventoryReportV1>(unknown_nested).is_err());

    let mut compiled_without_evidence = parse(FIXTURE);
    compiled_without_evidence["capabilities"][0]["installed_evidence"] = json!("no_evidence");
    assert_schema_invalid(&compiled_without_evidence);

    let mut missing_without_evidence = parse(FIXTURE);
    missing_without_evidence["support"][2]["evidence"] = json!("no_evidence");
    assert_schema_invalid(&missing_without_evidence);
}

#[test]
fn typed_ingress_recomputes_derived_support_inactivity_and_dispositions() {
    let mut contradictory_support = parse(FIXTURE);
    contradictory_support["support"][2]["state"] = json!("available");
    contradictory_support["support"][2]["evidence"] = json!("linked_crate");
    assert_schema_valid(&contradictory_support);
    assert!(
        serde_json::from_value::<ProjectCapabilityInventoryReportV1>(contradictory_support)
            .is_err(),
        "missing_support must not contradict the canonical support row"
    );

    let mut missing_inactive_row = parse(FIXTURE);
    missing_inactive_row["inactive_or_unused"] = json!([]);
    assert_schema_valid(&missing_inactive_row);
    assert!(
        serde_json::from_value::<ProjectCapabilityInventoryReportV1>(missing_inactive_row).is_err(),
        "inactive_or_unused must be the exact projection of declared unused capabilities"
    );

    let mut false_disposition = parse(FIXTURE);
    false_disposition["capabilities"][0]["disposition"] = json!("installed_unused");
    assert_schema_valid(&false_disposition);
    assert!(
        serde_json::from_value::<ProjectCapabilityInventoryReportV1>(false_disposition).is_err(),
        "capability disposition must be recomputed from the primary report state"
    );
}

#[test]
fn reported_rhai_abi_version_is_pinned_to_the_linked_runtime() {
    assert_eq!(registry_relay::rhai_worker::xw::XW_ABI_VERSION, "xw.v1");
    let report = build_capability_inventory(canonical_input()).expect("inventory builds");
    let rhai_abi = report
        .capabilities
        .iter()
        .find(|record| record.capability == CapabilityId::RhaiAbi)
        .expect("Rhai ABI is inventoried");
    assert_eq!(
        rhai_abi.supported_versions,
        vec![SupportedCapabilityVersion::RhaiXwV1]
    );
}
