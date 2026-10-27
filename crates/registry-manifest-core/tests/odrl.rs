// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;

use oxjsonld::JsonLdParser;
use registry_manifest_core::odrl::{
    render_policy_collection, Constraint, OdrlError, Operand, Permission, Policy, PolicyAsset,
};
use serde_json::{json, Value};

fn asset(uid: &str) -> PolicyAsset {
    PolicyAsset {
        uid: uid.to_owned(),
        part_of: None,
        properties: BTreeMap::new(),
    }
}

fn policy(uid: &str, target: &str) -> Policy {
    Policy {
        uid: uid.to_owned(),
        profile: vec!["https://example.test/odrl/profile/v1".to_owned()],
        permissions: vec![Permission {
            target: asset(target),
            action: "http://www.w3.org/ns/odrl/2/read".to_owned(),
            constraints: Vec::new(),
        }],
    }
}

#[test]
fn empty_collection_is_valid_and_fabricates_no_policy() {
    let rendered = render_policy_collection("urn:registry:policies", &[])
        .expect("empty collection is a valid publication");

    assert_eq!(rendered["@id"], "urn:registry:policies");
    assert_eq!(rendered["@graph"], json!([]));
}

#[test]
fn renders_typed_assets_and_explicit_literal_operands_as_valid_json_ld() {
    let mut properties = BTreeMap::new();
    properties.insert(
        "https://example.test/ns/classification".to_owned(),
        json!("restricted"),
    );
    let policies = [Policy {
        uid: "urn:registry:policy:reader".to_owned(),
        profile: vec!["https://example.test/odrl/profile/v1".to_owned()],
        permissions: vec![Permission {
            target: PolicyAsset {
                uid: "https://example.test/datasets/people".to_owned(),
                part_of: Some("urn:registry:catalog:main".to_owned()),
                properties,
            },
            action: "http://www.w3.org/ns/odrl/2/read".to_owned(),
            constraints: vec![
                Constraint {
                    left_operand: "http://www.w3.org/ns/odrl/2/purpose".to_owned(),
                    operator: "http://www.w3.org/ns/odrl/2/isA".to_owned(),
                    right_operand: Operand::Literal(json!("case-management")),
                },
                Constraint {
                    left_operand: "urn:registry:constraint:scope".to_owned(),
                    operator: "http://www.w3.org/ns/odrl/2/isAnyOf".to_owned(),
                    right_operand: Operand::Set(vec![json!("district-a"), json!(7), json!(true)]),
                },
            ],
        }],
    }];

    let rendered = render_policy_collection("https://example.test/policies", &policies)
        .expect("valid policy renders");
    let policy = &rendered["@graph"][0];
    let permission = &policy["odrl:permission"][0];

    assert_eq!(rendered["@context"]["odrl"], "http://www.w3.org/ns/odrl/2/");
    assert_eq!(rendered["@context"]["dcterms"], "http://purl.org/dc/terms/");
    assert_eq!(policy["@type"], "odrl:Set");
    assert_eq!(
        policy["odrl:uid"],
        json!({"@id": "urn:registry:policy:reader"})
    );
    assert_eq!(
        policy["odrl:profile"],
        json!([{"@id": "https://example.test/odrl/profile/v1"}])
    );
    assert_eq!(
        permission["odrl:action"],
        json!({"@id": "http://www.w3.org/ns/odrl/2/read"})
    );
    assert_eq!(
        permission["odrl:target"],
        json!({
            "@id": "https://example.test/datasets/people",
            "@type": "odrl:Asset",
            "odrl:partOf": {"@id": "urn:registry:catalog:main"},
            "https://example.test/ns/classification": "restricted"
        })
    );
    assert_eq!(
        permission["odrl:constraint"][0]["odrl:rightOperand"],
        json!({"@value": "case-management"})
    );
    assert_eq!(
        permission["odrl:constraint"][1]["odrl:rightOperand"],
        json!({"@list": [{"@value": "district-a"}, {"@value": 7}, {"@value": true}]})
    );
    assert!(parse_jsonld_to_rdf(&rendered).expect("ODRL JSON-LD parses as RDF") > 0);
}

#[test]
fn policies_are_ordered_by_uid_and_properties_by_iri() {
    let first = policy("urn:registry:policy:a", "urn:registry:asset:a");
    let second = policy("urn:registry:policy:b", "urn:registry:asset:b");

    let rendered =
        render_policy_collection("urn:registry:policies", &[second.clone(), first.clone()])
            .expect("valid policies render");
    let reordered = render_policy_collection("urn:registry:policies", &[first, second])
        .expect("valid policies render");

    assert_eq!(rendered, reordered);
    assert_eq!(rendered["@graph"][0]["@id"], "urn:registry:policy:a");
    assert_eq!(rendered["@graph"][1]["@id"], "urn:registry:policy:b");
}

#[test]
fn refuses_duplicate_or_empty_policies() {
    let duplicate = policy("urn:registry:policy:duplicate", "urn:registry:asset:a");
    assert!(matches!(
        render_policy_collection("urn:registry:policies", &[duplicate.clone(), duplicate]),
        Err(OdrlError::DuplicatePolicyUid { .. })
    ));

    let empty = Policy {
        uid: "urn:registry:policy:empty".to_owned(),
        profile: Vec::new(),
        permissions: Vec::new(),
    };
    assert!(matches!(
        render_policy_collection("urn:registry:policies", &[empty]),
        Err(OdrlError::EmptyPolicy { .. })
    ));
}

#[test]
fn refuses_invalid_identifiers_empty_sets_and_nonprimitive_literals() {
    let mut invalid_iri = policy("not-an-iri", "urn:registry:asset:a");
    assert!(matches!(
        render_policy_collection("urn:registry:policies", &[invalid_iri.clone()]),
        Err(OdrlError::InvalidIri { .. })
    ));

    invalid_iri.uid = "urn:registry:policy:invalid".to_owned();
    invalid_iri.permissions[0].constraints.push(Constraint {
        left_operand: "urn:registry:constraint:scope".to_owned(),
        operator: "http://www.w3.org/ns/odrl/2/isAnyOf".to_owned(),
        right_operand: Operand::Set(Vec::new()),
    });
    assert!(matches!(
        render_policy_collection("urn:registry:policies", &[invalid_iri]),
        Err(OdrlError::EmptySet { .. })
    ));

    let mut invalid_literal = policy("urn:registry:policy:invalid", "urn:registry:asset:a");
    invalid_literal.permissions[0].constraints.push(Constraint {
        left_operand: "urn:registry:constraint:value".to_owned(),
        operator: "http://www.w3.org/ns/odrl/2/eq".to_owned(),
        right_operand: Operand::Literal(json!({"nested": true})),
    });
    assert!(matches!(
        render_policy_collection("urn:registry:policies", &[invalid_literal]),
        Err(OdrlError::InvalidLiteral { .. })
    ));
}

#[test]
fn refuses_asset_properties_that_alias_structural_members() {
    let mut properties = BTreeMap::new();
    properties.insert(
        "http://www.w3.org/ns/odrl/2/partOf".to_owned(),
        json!("urn:registry:catalog:other"),
    );
    let mut invalid = policy("urn:registry:policy:invalid", "urn:registry:asset:a");
    invalid.permissions[0].target.properties = properties;

    assert!(matches!(
        render_policy_collection("urn:registry:policies", &[invalid]),
        Err(OdrlError::StructuralAssetProperty { .. })
    ));
}

fn parse_jsonld_to_rdf(document: &Value) -> Result<usize, String> {
    let raw = serde_json::to_string(document).map_err(|error| error.to_string())?;
    let parser = JsonLdParser::new()
        .with_base_iri("https://example.test/policies")
        .map_err(|error| error.to_string())?;
    let mut quad_count = 0;
    for quad in parser.for_slice(&raw) {
        quad.map_err(|error| error.to_string())?;
        quad_count += 1;
    }
    Ok(quad_count)
}
