// SPDX-License-Identifier: Apache-2.0

use registry_breg::contract::parse_project_yaml;
use registry_breg::external_views::{ExternalCardinality, ExternalProjectionMode};
use registry_breg::{compile_project, CompileProfile};

#[test]
fn maintained_licensing_example_compiles_both_modes_and_keeps_owned_fields_separate() {
    let project = parse_project_yaml(include_bytes!(
        "../../../products/breg/examples/external-views/registry.yaml"
    ))
    .expect("the hand-authored example parses");
    let compiled = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("the hand-authored example compiles");
    let external = compiled.external_views();

    for (id, mode, cardinality) in [
        (
            "person-live",
            ExternalProjectionMode::Live,
            ExternalCardinality::One,
        ),
        (
            "person-indexed",
            ExternalProjectionMode::Indexed,
            ExternalCardinality::One,
        ),
        (
            "holdings-live",
            ExternalProjectionMode::Live,
            ExternalCardinality::Many,
        ),
        (
            "holdings-indexed",
            ExternalProjectionMode::Indexed,
            ExternalCardinality::Many,
        ),
    ] {
        let projection = &external.projections[id];
        assert_eq!(
            (projection.mode, projection.cardinality),
            (mode, cardinality)
        );
    }
    let holdings = &external.views["business-holdings-indexed"].links[0];
    let label = holdings.label.as_ref().expect("an explicit Person label");
    assert_eq!(label.from_field.as_str(), "person-key");
    assert_eq!(label.projection.as_str(), "person-indexed");
    assert!(!holdings
        .fields
        .iter()
        .any(|field| field.as_str() == "person-key"));
    assert!(!external.grants.contains_key("local-facts"));
    assert!(external.refresh.contains_key("projection-refresh"));
    assert!(!compiled.entities()["licence"]
        .fields
        .contains_key("family-name"));
}

#[test]
fn holdings_label_refresh_requires_both_projection_grants() {
    let source = include_str!("../../../products/breg/examples/external-views/registry.yaml");
    let labels = "/v1/external-views/business-holdings-indexed/holdings/refresh-labels";
    for (source, allowed) in [
        (source.to_owned(), true),
        (
            source.replace("[person-indexed, holdings-indexed]", "[holdings-indexed]"),
            false,
        ),
    ] {
        let project = parse_project_yaml(source.as_bytes()).expect("authoring fixture parses");
        let compiled = compile_project(&project, &[], CompileProfile::Authoring)
            .expect("authoring fixture compiles");
        let document: serde_json::Value = serde_json::from_slice(
            &compiled
                .artifacts()
                .get("generated/openapi.json")
                .unwrap()
                .bytes,
        )
        .unwrap();
        assert_eq!(document["paths"].get(labels).is_some(), allowed);
    }
}
