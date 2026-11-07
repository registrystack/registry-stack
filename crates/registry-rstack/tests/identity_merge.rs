// SPDX-License-Identifier: Apache-2.0

//! The facts of all four products that admit OIDC tokens, merged.
//!
//! The four files under `tests/fixtures/identity` are the output of
//! `bregctl`, `caseworkctl`, `evidencectl` and `messagingctl`
//! `generate identity-facts` on the products' own examples (the BReg
//! generic operator workflows fixture, the Casework canonical review example
//! with the task-authority runtime fixture, the Evidence standalone example,
//! and the Messaging starter). Each product crate's own test pins the same
//! bytes. They are committed rather than regenerated here because a test in
//! this crate cannot build four product tools.

use std::fs;
use std::path::{Path, PathBuf};

use registry_thunderid_tooling::identity_facts::{self, ClaimType, MergedFacts};
use registry_thunderid_tooling::ToolingError;

const PRODUCTS: [&str; 4] = ["breg", "casework", "evidence", "messaging"];

fn fixture(product: &str) -> String {
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/identity")
        .join(format!("{product}-facts.yaml"));
    fs::read_to_string(path).unwrap()
}

fn merged(texts: &[String]) -> Result<MergedFacts, ToolingError> {
    let documents = texts
        .iter()
        .enumerate()
        .map(|(index, text)| identity_facts::read(&format!("facts-{index}"), text.as_bytes()))
        .collect::<Result<Vec<_>, _>>()?;
    identity_facts::merge(documents)
}

fn all() -> Vec<String> {
    PRODUCTS.iter().map(|product| fixture(product)).collect()
}

/// The four examples agree on one issuer.
fn with_one_issuer(texts: Vec<String>) -> Vec<String> {
    texts
        .into_iter()
        .map(|text| {
            text.lines()
                .map(|line| {
                    if line.starts_with("issuer: ") {
                        "issuer: https://id.registry.example".to_owned()
                    } else {
                        line.to_owned()
                    }
                })
                .collect::<Vec<_>>()
                .join("\n")
                + "\n"
        })
        .collect()
}

fn refused_code(result: Result<MergedFacts, ToolingError>) -> (&'static str, String) {
    match result {
        Err(ToolingError::IdentityRefused { code, location, .. }) => (code, location),
        other => panic!("expected an identity refusal, got {other:?}"),
    }
}

#[test]
fn the_examples_as_shipped_trust_different_issuers_and_are_refused() {
    // BReg, Evidence and the Casework/Messaging pair each state their own
    // example issuer, so an operator must point the products at one.
    let (code, location) = refused_code(merged(&all()));
    assert_eq!(code, "identity.facts.issuer-mismatch");
    assert_eq!(location, "facts[1]/issuer");
}

#[test]
fn four_products_with_one_issuer_merge() {
    let merged = merged(&with_one_issuer(all())).unwrap();
    assert_eq!(merged.issuer, "https://id.registry.example");
    let products: Vec<&str> = merged.products.keys().map(String::as_str).collect();
    assert_eq!(products, PRODUCTS);
    let claims: Vec<(&str, ClaimType)> = merged
        .claims
        .iter()
        .map(|(name, kind)| (name.as_str(), *kind))
        .collect();
    assert_eq!(
        claims,
        [
            ("evidence_audience", ClaimType::String),
            ("evidence_tags", ClaimType::StringArray),
            ("registry_actor_kind", ClaimType::String),
            ("registry_principal", ClaimType::String),
            ("registry_purpose", ClaimType::String),
            ("registry_record_status", ClaimType::String),
        ]
    );
    // Casework's and Messaging's `registry_actor_kind` agree, so they share
    // one claim; each product keeps its own audience and profiles.
    assert_eq!(merged.products["breg"].access_profiles.len(), 3);
    assert_eq!(merged.products["casework"].access_profiles.len(), 6);
    assert_eq!(merged.products["evidence"].access_profiles.len(), 1);
    assert_eq!(merged.products["messaging"].access_profiles.len(), 2);
    assert_eq!(merged.assertion_issuers.len(), 1);
    // Each product keeps the claims its own profiles require; Casework does
    // not inherit what BReg requires of `registry_principal`.
    let required = |product: &str, profile: &str| {
        merged.products[product].access_profiles[profile]
            .required_claims
            .clone()
    };
    assert_eq!(
        required("breg", "record-reader"),
        ["registry_principal", "registry_record_status"]
    );
    assert!(required("casework", "staff").is_empty());
}

#[test]
fn the_merge_does_not_depend_on_the_order_products_are_given() {
    let forward = merged(&with_one_issuer(all())).unwrap();
    let mut reversed = with_one_issuer(all());
    reversed.reverse();
    assert_eq!(forward, merged(&reversed).unwrap());
}

#[test]
fn one_claim_with_two_types_is_refused() {
    let mut texts = with_one_issuer(all());
    // BReg, Evidence and Messaging declare `registry_actor_kind` as a string;
    // Casework now declares it as a list, so the conflict surfaces at the
    // product that states it after BReg. Its profiles' actor-kind
    // requirements go too, since a document that requires a kind must
    // declare the claim as a string.
    texts[1] = texts[1]
        .replace(
            "registry_actor_kind: string",
            "registry_actor_kind: string-array",
        )
        .replace("  actorKind: human\n", "")
        .replace("  actorKind: service\n", "")
        .replace("  actorKind: agent\n", "");
    let (code, location) = refused_code(merged(&texts));
    assert_eq!(code, "identity.facts.claim-conflict");
    assert_eq!(location, "facts[1]/claims");
}

#[test]
fn two_products_sharing_an_audience_are_refused() {
    let mut texts = with_one_issuer(all());
    texts[3] = texts[3].replace("urn:example:messaging", "urn:example:casework");
    let (code, _) = refused_code(merged(&texts));
    assert_eq!(code, "identity.facts.duplicate-audience");
}

#[test]
fn a_product_stated_twice_is_refused() {
    let mut texts = with_one_issuer(all());
    texts.push(texts[0].clone());
    let (code, _) = refused_code(merged(&texts));
    assert_eq!(code, "identity.facts.duplicate-product");
}
