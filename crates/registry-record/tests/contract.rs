use std::fs;
use std::path::{Path, PathBuf};

use registry_record::{
    RegistryRecordRepresentation, RegistryRecordResponse, REGISTRY_RECORD_CONTEXT_IDENTIFIER,
};
use serde_json::{json, Value};

fn fixture_path(kind: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/registry-record/fixtures")
        .join(kind)
        .join(name)
}

fn fixture(kind: &str, name: &str) -> Vec<u8> {
    fs::read(fixture_path(kind, name)).expect("Registry Record fixture must be readable")
}

#[test]
fn every_compatible_positive_fixture_decodes_under_its_exact_representation() {
    for (name, representation) in [
        ("single.json", RegistryRecordRepresentation::Json),
        ("collection.json", RegistryRecordRepresentation::Json),
        (
            "single.jsonld",
            RegistryRecordRepresentation::JsonLdSharedContext,
        ),
        (
            "collection.jsonld",
            RegistryRecordRepresentation::JsonLdSharedContext,
        ),
        (
            "composed-single.jsonld",
            RegistryRecordRepresentation::JsonLdProductComposition,
        ),
    ] {
        RegistryRecordResponse::from_slice(&fixture("positive", name), representation)
            .unwrap_or_else(|error| panic!("{name} must conform: {error}"));
    }
}

#[test]
fn every_compatible_negative_fixture_is_rejected() {
    for (name, representation) in [
        ("blank-identifier.json", RegistryRecordRepresentation::Json),
        (
            "domain-data-infrastructure-member.json",
            RegistryRecordRepresentation::Json,
        ),
        (
            "duplicate-contexts.jsonld",
            RegistryRecordRepresentation::JsonLdProductComposition,
        ),
        (
            "empty-product-context.jsonld",
            RegistryRecordRepresentation::JsonLdProductComposition,
        ),
        (
            "hostile-context.jsonld",
            RegistryRecordRepresentation::JsonLdSharedContext,
        ),
        (
            "inline-context.jsonld",
            RegistryRecordRepresentation::JsonLdSharedContext,
        ),
        (
            "inline-product-context.jsonld",
            RegistryRecordRepresentation::JsonLdProductComposition,
        ),
        (
            "invalid-next-cursor.json",
            RegistryRecordRepresentation::Json,
        ),
        ("json-context.json", RegistryRecordRepresentation::Json),
        (
            "missing-context.jsonld",
            RegistryRecordRepresentation::JsonLdSharedContext,
        ),
        ("mixed-envelope.json", RegistryRecordRepresentation::Json),
        (
            "nested-context-in-product-extension.jsonld",
            RegistryRecordRepresentation::JsonLdProductComposition,
        ),
        (
            "nested-context.jsonld",
            RegistryRecordRepresentation::JsonLdSharedContext,
        ),
        (
            "non-https-product-context.jsonld",
            RegistryRecordRepresentation::JsonLdProductComposition,
        ),
        (
            "product-only-contexts.jsonld",
            RegistryRecordRepresentation::JsonLdProductComposition,
        ),
        (
            "record-duplicates-response-context.json",
            RegistryRecordRepresentation::Json,
        ),
        (
            "relative-product-context.jsonld",
            RegistryRecordRepresentation::JsonLdProductComposition,
        ),
        (
            "reordered-contexts.jsonld",
            RegistryRecordRepresentation::JsonLdProductComposition,
        ),
        (
            "shared-only-context-array.jsonld",
            RegistryRecordRepresentation::JsonLdProductComposition,
        ),
    ] {
        let result = RegistryRecordResponse::from_slice(&fixture("negative", name), representation);
        assert!(result.is_err(), "{name} unexpectedly conformed");
    }
}

#[test]
fn duplicate_wire_members_are_rejected_before_profile_decoding() {
    let duplicate = br#"{
        "data": {
            "recordIdentifier": "00000000-0000-4000-8000-000000000001",
            "revisionIdentifier": "1",
            "revisionIdentifier": "2",
            "domainData": {}
        },
        "meta": {
            "registryIdentifier": "registry",
            "datasetIdentifier": "dataset",
            "entityTypeIdentifier": "entity"
        }
    }"#;
    assert!(
        RegistryRecordResponse::from_slice(duplicate, RegistryRecordRepresentation::Json).is_err()
    );
}

#[test]
fn product_extensions_are_preserved_at_every_open_level() {
    let document = json!({
        "items": [{
            "recordIdentifier": "company-123",
            "revisionIdentifier": "42",
            "domainData": {
                "legalName": "Example Ltd",
                "nestedDomainValue": {"data": "domain-owned name"}
            },
            "memberExtension": {"classification": "public"}
        }],
        "pageInfo": {
            "nextCursor": "cursor-2",
            "pageExtension": 50
        },
        "meta": {
            "registryIdentifier": "business-registry",
            "datasetIdentifier": "legal-entities",
            "entityTypeIdentifier": "company",
            "metaExtension": true
        },
        "collectionExtension": {
            "selectedFields": ["legalName"]
        }
    });

    let response =
        RegistryRecordResponse::from_value(document.clone(), RegistryRecordRepresentation::Json)
            .expect("open collection response must decode");
    let RegistryRecordResponse::Collection(collection) = &response else {
        panic!("collection decoded as a single response");
    };
    assert_eq!(
        collection.extensions["collectionExtension"]["selectedFields"][0],
        "legalName"
    );
    assert_eq!(
        collection.items[0].extensions["memberExtension"]["classification"],
        "public"
    );
    assert_eq!(
        collection.items[0].domain_data["nestedDomainValue"]["data"],
        "domain-owned name"
    );
    assert_eq!(collection.page_info.extensions["pageExtension"], 50);
    assert_eq!(collection.meta.extensions["metaExtension"], true);
    assert_eq!(
        serde_json::to_value(response).expect("response serializes"),
        document
    );
}

#[test]
fn all_required_identifiers_and_object_domain_data_are_enforced() {
    let base: Value = serde_json::from_slice(&fixture("positive", "single.json"))
        .expect("positive single fixture is JSON");

    for pointer in [
        "/data/recordIdentifier",
        "/data/revisionIdentifier",
        "/meta/registryIdentifier",
        "/meta/datasetIdentifier",
        "/meta/entityTypeIdentifier",
    ] {
        let mut document = base.clone();
        *document
            .pointer_mut(pointer)
            .expect("required fixture identifier exists") = json!("");
        assert!(
            RegistryRecordResponse::from_value(document, RegistryRecordRepresentation::Json,)
                .is_err(),
            "blank identifier at {pointer} unexpectedly conformed"
        );
    }

    let mut missing_identifier = base.clone();
    missing_identifier["meta"]
        .as_object_mut()
        .expect("fixture meta is an object")
        .remove("datasetIdentifier");
    assert!(RegistryRecordResponse::from_value(
        missing_identifier,
        RegistryRecordRepresentation::Json,
    )
    .is_err());

    let mut array_domain_data = base;
    array_domain_data["data"]["domainData"] = json!([]);
    assert!(RegistryRecordResponse::from_value(
        array_domain_data,
        RegistryRecordRepresentation::Json,
    )
    .is_err());
}

#[test]
fn server_and_product_jsonld_context_forms_are_not_interchangeable() {
    let shared = fixture("positive", "single.jsonld");
    let composed = fixture("positive", "composed-single.jsonld");

    assert!(RegistryRecordResponse::from_slice(
        &shared,
        RegistryRecordRepresentation::JsonLdProductComposition,
    )
    .is_err());
    assert!(RegistryRecordResponse::from_slice(
        &composed,
        RegistryRecordRepresentation::JsonLdSharedContext,
    )
    .is_err());
}

#[test]
fn product_context_identifiers_are_inert_and_never_resolved() {
    let document = json!({
        "@context": [
            REGISTRY_RECORD_CONTEXT_IDENTIFIER,
            "https://unresolvable.invalid/contexts/company/v1"
        ],
        "data": {
            "recordIdentifier": "company-123",
            "revisionIdentifier": "42",
            "domainData": {}
        },
        "meta": {
            "registryIdentifier": "business-registry",
            "datasetIdentifier": "legal-entities",
            "entityTypeIdentifier": "company"
        }
    });

    let response = RegistryRecordResponse::from_value(
        document,
        RegistryRecordRepresentation::JsonLdProductComposition,
    )
    .expect("an absolute HTTPS context identifier needs no resolver");
    let context = response.json_ld_context().expect("JSON-LD context");
    assert_eq!(
        context.product_contexts(),
        ["https://unresolvable.invalid/contexts/company/v1"]
    );
}

#[test]
fn decode_errors_never_render_response_controlled_member_names() {
    let sensitive_member = "citizenNationalIdentifier";
    let document = json!({
        "data": {
            "recordIdentifier": "company-123",
            "revisionIdentifier": "42",
            "domainData": {
                sensitive_member: {"@context": "https://attacker.invalid/context"}
            }
        },
        "meta": {
            "registryIdentifier": "business-registry",
            "datasetIdentifier": "legal-entities",
            "entityTypeIdentifier": "company"
        }
    });

    let error = RegistryRecordResponse::from_value(document, RegistryRecordRepresentation::Json)
        .expect_err("nested context must be refused");
    assert!(!error.to_string().contains(sensitive_member));
    assert!(!format!("{error:?}").contains(sensitive_member));
}

#[test]
fn infrastructure_cannot_be_duplicated_into_another_profile_level() {
    let base: Value = serde_json::from_slice(&fixture("positive", "collection.json"))
        .expect("positive collection fixture is JSON");

    for mut document in [
        {
            let mut value = base.clone();
            value["recordIdentifier"] = json!("misplaced");
            value
        },
        {
            let mut value = base.clone();
            value["items"][0]["meta"] = json!({});
            value
        },
        {
            let mut value = base.clone();
            value["meta"]["recordIdentifier"] = json!("duplicated");
            value
        },
        {
            let mut value = base.clone();
            value["pageInfo"]["registryIdentifier"] = json!("duplicated");
            value
        },
    ] {
        assert!(RegistryRecordResponse::from_value(
            document.take(),
            RegistryRecordRepresentation::Json,
        )
        .is_err());
    }
}
