// SPDX-License-Identifier: Apache-2.0
//! Configuration types: the camelCase wire form and the construction refusals.

mod common;

use common::*;
use registry_evidence_presentation::{
    ChannelPolicy, IssuerAlgorithm, IssuerTrust, KeySource, TrustConfigError, TrustEntry,
};
use serde_json::{json, Value};

fn pem(der: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    let body = STANDARD.encode(der);
    let lines: Vec<&str> = body
        .as_bytes()
        .chunks(64)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect();
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        lines.join("\n")
    )
}

fn jwks_entry(id: &str, issuer: &str) -> Value {
    let mut public = serde_json::to_value(es256().public()).unwrap();
    public["kid"] = json!("k1");
    public.as_object_mut().unwrap().remove("alg");
    json!({"id": id, "issuer": issuer, "vct": ["urn:t"], "keys": {"jwks": [public]}})
}

fn parse(value: Value) -> Result<IssuerTrust, serde_json::Error> {
    serde_json::from_value(value)
}

#[test]
fn reads_x5c_and_jwks_entries_from_configuration() {
    let pki = pki("a");
    let trust = parse(json!([
        {
            "id": "agency-x5c",
            "issuer": "https://a.example",
            "vct": ["urn:t"],
            "keys": {"x5c": {"anchorsPem": [pem(pki.root.der())], "maxPathLength": 0,
                             "leafKeyTypes": ["ed25519"]}}
        },
        jwks_entry("agency-jwks", "https://b.example"),
    ]))
    .unwrap();
    let text = format!("{trust:?}");
    assert!(text.contains("agency-x5c") && text.contains("agency-jwks"));
}

#[test]
fn a_configured_x5c_entry_verifies_a_certified_credential() {
    let pki = pki("a");
    let mut scenario = Scenario::new(Issuer::certified(&pki, &["issuer.example"], &[]));
    scenario.disclose("family_name", json!("Tane"));
    let trust = parse(json!([{
        "id": ENTRY_ID, "issuer": ISS, "vct": [VCT],
        "keys": {"x5c": {"anchorsPem": [pem(pki.root.der())], "maxPathLength": 1}}
    }]))
    .unwrap();
    let credential = registry_evidence_presentation::verify_sd_jwt_vc(
        &scenario.build(),
        &ctx(),
        &trust,
        &policy(true),
        NOW,
    )
    .unwrap();
    assert_eq!(credential.trust_entry, ENTRY_ID);
}

#[test]
fn refuses_unusable_trust_configuration() {
    let pki = pki("a");
    let anchors = pem(pki.root.der());
    let good = |id: &str, issuer: &str| jwks_entry(id, issuer);

    assert!(parse(json!([])).is_err(), "empty list");
    assert!(
        parse(json!([
            good("a", "https://a.example"),
            good("a", "https://b.example")
        ]))
        .is_err(),
        "duplicate id"
    );
    assert!(
        parse(json!([
            good("a", "https://a.example"),
            good("b", "https://a.example")
        ]))
        .is_err(),
        "duplicate issuer"
    );
    let mut empty_vct = good("a", "https://a.example");
    empty_vct["vct"] = json!([]);
    assert!(parse(json!([empty_vct])).is_err(), "empty vct list");
    let mut blank_vct = good("a", "https://a.example");
    blank_vct["vct"] = json!([""]);
    assert!(parse(json!([blank_vct])).is_err(), "empty vct value");
    let mut no_keys = good("a", "https://a.example");
    no_keys["keys"] = json!({"jwks": []});
    assert!(parse(json!([no_keys])).is_err(), "empty jwks");
    let mut no_anchors = good("a", "https://a.example");
    no_anchors["keys"] = json!({"x5c": {"anchorsPem": []}});
    assert!(parse(json!([no_anchors])).is_err(), "empty anchors");
    let mut no_leaf_types = good("a", "https://a.example");
    no_leaf_types["keys"] = json!({"x5c": {"anchorsPem": [anchors], "leafKeyTypes": []}});
    assert!(parse(json!([no_leaf_types])).is_err(), "no leaf key types");
    let mut unknown = good("a", "https://a.example");
    unknown["extra"] = json!(1);
    assert!(parse(json!([unknown])).is_err(), "unknown field");
    let mut both = good("a", "https://a.example");
    both["keys"] = json!({"jwks": [], "x5c": {"anchorsPem": []}});
    assert!(parse(json!([both])).is_err(), "two key sources");
}

#[test]
fn refuses_unusable_pinned_keys() {
    let entry = |keys: Value| {
        parse(
            json!([{"id": "a", "issuer": "https://a.example", "vct": ["urn:t"],
                      "keys": {"jwks": keys}}]),
        )
    };
    let mut ok = serde_json::to_value(es256().public()).unwrap();
    ok["kid"] = json!("k1");
    assert!(entry(json!([ok.clone()])).is_ok());

    let mut no_kid = ok.clone();
    no_kid.as_object_mut().unwrap().remove("kid");
    assert!(entry(json!([no_kid])).is_err(), "no kid");
    assert!(
        entry(json!([ok.clone(), ok.clone()])).is_err(),
        "repeated kid"
    );
    let mut private = ok.clone();
    private["d"] = json!("AAAA");
    assert!(entry(json!([private])).is_err(), "private material");
    let rsa = json!({"kty": "RSA", "kid": "k2", "n": "AQAB", "e": "AQAB"});
    assert!(entry(json!([rsa])).is_err(), "RSA key");
    let mut p384 = serde_json::to_value(
        private_key(registry_platform_crypto::GeneratedKeyAlgorithm::Es384).public(),
    )
    .unwrap();
    p384["kid"] = json!("k3");
    assert!(entry(json!([p384])).is_err(), "P-384 key");
}

#[test]
fn rust_construction_applies_the_same_refusals() {
    let issuer = Issuer::pinned();
    let entry = |id: &str, issuer_name: &str, vct: &[&str]| TrustEntry {
        id: id.into(),
        issuer: issuer_name.into(),
        vct: vct.iter().map(ToString::to_string).collect(),
        key_source: issuer.key_source.clone(),
    };
    assert_eq!(
        IssuerTrust::new(vec![]).unwrap_err(),
        TrustConfigError::NoEntries
    );
    assert_eq!(
        IssuerTrust::new(vec![entry("a", "i1", &["t"]), entry("a", "i2", &["t"])]).unwrap_err(),
        TrustConfigError::DuplicateId { entry: 1 }
    );
    assert_eq!(
        IssuerTrust::new(vec![entry("a", "i1", &["t"]), entry("b", "i1", &["t"])]).unwrap_err(),
        TrustConfigError::DuplicateIssuer { entry: 1 }
    );
    assert_eq!(
        IssuerTrust::new(vec![entry("a", "i1", &[])]).unwrap_err(),
        TrustConfigError::EmptyVct { entry: 0 }
    );
    let mut empty = entry("a", "i1", &["t"]);
    empty.key_source = KeySource::Jwks(vec![]);
    assert_eq!(
        IssuerTrust::new(vec![empty]).unwrap_err(),
        TrustConfigError::EmptyKeySource { entry: 0 }
    );
}

#[test]
fn channel_policy_reads_camel_case_and_states_key_binding_explicitly() {
    let policy: ChannelPolicy = serde_json::from_value(json!({
        "vct": ["urn:t"], "keyBindingRequired": true, "kbIatWindowSeconds": 90,
        "clockSkewSeconds": 30, "issuerAlgorithms": ["EdDSA"]
    }))
    .unwrap();
    assert_eq!(policy.kb_iat_window_seconds, 90);
    assert_eq!(policy.clock_skew_seconds, 30);
    assert_eq!(policy.issuer_algorithms, vec![IssuerAlgorithm::EdDsa]);

    let defaults: ChannelPolicy =
        serde_json::from_value(json!({"vct": ["urn:t"], "keyBindingRequired": false})).unwrap();
    assert_eq!(defaults, ChannelPolicy::new(vec!["urn:t".into()], false));
    assert_eq!(
        defaults.issuer_algorithms,
        vec![IssuerAlgorithm::Es256, IssuerAlgorithm::EdDsa]
    );

    // Key binding is never a default: leaving it out is an error.
    assert!(serde_json::from_value::<ChannelPolicy>(json!({"vct": ["urn:t"]})).is_err());
    assert!(serde_json::from_value::<ChannelPolicy>(
        json!({"vct": ["urn:t"], "keyBindingRequired": true, "extra": 1})
    )
    .is_err());
    assert!(serde_json::from_value::<ChannelPolicy>(
        json!({"vct": ["urn:t"], "keyBindingRequired": true, "issuerAlgorithms": ["RS256"]})
    )
    .is_err());
}
