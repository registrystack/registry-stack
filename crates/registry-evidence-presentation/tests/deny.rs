// SPDX-License-Identifier: Apache-2.0
//! The issuer deny-list: checked before the allow-list and before any
//! signature work, by issuer identifier and by certificate fingerprint.

mod common;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use common::*;
use registry_evidence_presentation::{
    verify_sd_jwt_vc, IssuerDenyList, IssuerDenyListConfig, PresentationRefusal as R,
    TrustConfigError,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn fingerprint(der: &[u8]) -> [u8; 32] {
    Sha256::digest(der).into()
}

fn x5c_der(scenario: &Scenario, index: usize) -> Vec<u8> {
    let x5c = scenario.header["x5c"].as_array().unwrap();
    STANDARD.decode(x5c[index].as_str().unwrap()).unwrap()
}

fn verify_denying(scenario: &Scenario, deny: IssuerDenyList) -> Result<(), R> {
    let trust = scenario.trust().with_deny_list(deny);
    verify_sd_jwt_vc(&scenario.build(), &ctx(), &trust, &policy(true), NOW).map(|_| ())
}

#[test]
fn an_empty_deny_list_changes_nothing() {
    let scenario = Scenario::certified();
    assert_eq!(verify_denying(&scenario, IssuerDenyList::default()), Ok(()));
}

#[test]
fn a_denied_issuer_is_refused_even_though_it_is_trusted() {
    let scenario = Scenario::pinned();
    let deny = IssuerDenyList::new(vec![ISS.to_owned()], Vec::new());
    assert_eq!(verify_denying(&scenario, deny), Err(R::IssuerDenied));
}

#[test]
fn a_denied_issuer_is_refused_before_the_allow_list_lookup() {
    let mut scenario = Scenario::pinned();
    scenario.trusted_issuer = "https://someone-else.example".to_owned();
    let deny = IssuerDenyList::new(vec![ISS.to_owned()], Vec::new());
    assert_eq!(verify_denying(&scenario, deny), Err(R::IssuerDenied));
}

#[test]
fn a_denied_issuer_is_refused_before_any_signature_work() {
    let mut scenario = Scenario::pinned();
    scenario.header.insert("kid".into(), json!("unknown-key"));
    let deny = IssuerDenyList::new(vec![ISS.to_owned()], Vec::new());
    assert_eq!(
        verify_denying(&scenario, deny),
        Err(R::IssuerDenied),
        "an unknown key would otherwise refuse as IssuerKeyIdUnknown"
    );
}

#[test]
fn another_denied_issuer_does_not_affect_this_one() {
    let scenario = Scenario::pinned();
    let deny = IssuerDenyList::new(vec!["https://other.example".to_owned()], Vec::new());
    assert_eq!(verify_denying(&scenario, deny), Ok(()));
}

#[test]
fn a_denied_leaf_certificate_is_refused() {
    let scenario = Scenario::certified();
    let deny = IssuerDenyList::new(Vec::new(), vec![fingerprint(&x5c_der(&scenario, 0))]);
    assert_eq!(verify_denying(&scenario, deny), Err(R::IssuerDenied));
}

#[test]
fn a_denied_intermediate_under_a_trusted_anchor_is_refused() {
    let scenario = Scenario::certified();
    assert_eq!(
        verify_denying(&scenario, IssuerDenyList::default()),
        Ok(()),
        "the chain is valid without the deny-list"
    );
    let deny = IssuerDenyList::new(Vec::new(), vec![fingerprint(&x5c_der(&scenario, 1))]);
    assert_eq!(verify_denying(&scenario, deny), Err(R::IssuerDenied));
}

#[test]
fn a_denied_certificate_is_refused_before_chain_verification() {
    let mut scenario = Scenario::certified();
    let denied = fingerprint(&x5c_der(&scenario, 1));
    // A chain of leaf plus intermediate only verifies against its own anchor;
    // swap the trusted anchors for another PKI so the chain would not verify.
    let other = Scenario::certified();
    scenario.issuer.key_source = other.issuer.key_source.clone();
    let deny = IssuerDenyList::new(Vec::new(), vec![denied]);
    assert_eq!(verify_denying(&scenario, deny), Err(R::IssuerDenied));
}

#[test]
fn an_unrelated_certificate_fingerprint_does_not_deny() {
    let scenario = Scenario::certified();
    let deny = IssuerDenyList::new(Vec::new(), vec![[7u8; 32]]);
    assert_eq!(verify_denying(&scenario, deny), Ok(()));
}

#[test]
fn the_deny_list_is_read_from_configuration() {
    let fingerprint_hex = "ab".repeat(32);
    let config: IssuerDenyListConfig = serde_json::from_value(json!({
        "issuers": [ISS],
        "certificateSha256": [fingerprint_hex.to_uppercase()]
    }))
    .unwrap();
    let deny = IssuerDenyList::try_from(config).unwrap();
    assert_eq!(
        deny,
        IssuerDenyList::new(vec![ISS.to_owned()], vec![[0xab; 32]])
    );
}

#[test]
fn configuration_requires_both_members_and_refuses_unknown_ones() {
    for config in [
        json!({"issuers": []}),
        json!({"certificateSha256": []}),
        json!({"issuers": [], "certificateSha256": [], "extra": 1}),
    ] {
        assert!(
            serde_json::from_value::<IssuerDenyListConfig>(config).is_err(),
            "a closed, fully stated deny-list is required"
        );
    }
    let empty: IssuerDenyListConfig =
        serde_json::from_value(json!({"issuers": [], "certificateSha256": []})).unwrap();
    assert_eq!(
        IssuerDenyList::try_from(empty).unwrap(),
        IssuerDenyList::default()
    );
}

#[test]
fn configuration_refuses_an_empty_issuer_and_a_malformed_fingerprint() {
    let bad: [Value; 4] = [
        json!({"issuers": [""], "certificateSha256": []}),
        json!({"issuers": [], "certificateSha256": ["abcd"]}),
        json!({"issuers": [], "certificateSha256": ["zz".repeat(32)]}),
        json!({"issuers": [], "certificateSha256": ["ab".repeat(33)]}),
    ];
    for config in bad {
        let config: IssuerDenyListConfig = serde_json::from_value(config).unwrap();
        assert_eq!(
            IssuerDenyList::try_from(config).unwrap_err(),
            TrustConfigError::InvalidDenyList
        );
    }
}

#[test]
fn the_debug_output_of_a_deny_list_holds_no_identifier() {
    let deny = IssuerDenyList::new(vec![ISS.to_owned()], vec![[0xcd; 32]]);
    let text = format!("{deny:?}");
    assert!(!text.contains(ISS) && !text.to_lowercase().contains("cdcd"));
}
