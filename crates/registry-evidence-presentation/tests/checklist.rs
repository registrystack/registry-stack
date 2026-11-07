// SPDX-License-Identifier: Apache-2.0
//! The research checklist (section 3) as accepted cases and the pitfalls
//! (section 4) as refusals, one test per refusal category.

mod common;

use common::*;
use registry_evidence_presentation::{
    verify_sd_jwt_vc, ChannelPolicy, IssuerAlgorithm, PresentationRefusal as R, SessionContext,
    VerifiedCredential,
};
use registry_platform_crypto::did_jwk_from_public_jwk;
use serde_json::{json, Value};

fn verify(scenario: &Scenario, policy: &ChannelPolicy) -> Result<VerifiedCredential, R> {
    verify_at(scenario, policy, NOW)
}

fn verify_at(
    scenario: &Scenario,
    policy: &ChannelPolicy,
    now: i64,
) -> Result<VerifiedCredential, R> {
    verify_sd_jwt_vc(&scenario.build(), &ctx(), &scenario.trust(), policy, now)
}

fn refused(scenario: &Scenario) -> R {
    verify(scenario, &policy(true)).expect_err("must refuse")
}

// ---- accepted ---------------------------------------------------------------

#[test]
fn accepts_a_key_bound_credential_from_a_pinned_key() {
    let scenario = Scenario::pinned();
    let credential = verify(&scenario, &policy(true)).unwrap();
    assert_eq!(credential.trust_entry, ENTRY_ID);
    assert_eq!(credential.issuer, ISS);
    assert_eq!(credential.vct, VCT);
    assert_eq!(credential.issued_at, NOW - 100);
    assert_eq!(credential.expires_at, Some(NOW + 3600));
    assert!(credential.key_bound);
    assert!(!credential.status_reference_present);
    assert_eq!(credential.claims["family_name"], "Tane");
    assert!(!credential.claims.contains_key("cnf"));
    assert!(!credential.claims.contains_key("_sd"));
    assert!(!credential.claims.contains_key("_sd_alg"));
}

#[test]
fn accepts_an_x5c_credential_bound_to_the_dns_name_of_iss() {
    let scenario = Scenario::certified();
    assert!(verify(&scenario, &policy(true)).unwrap().key_bound);
}

#[test]
fn accepts_an_x5c_credential_bound_by_a_uri_san() {
    let pki = pki("a");
    let mut scenario = Scenario::new(Issuer::certified(&pki, &[], &["urn:example:issuer:7"]));
    scenario
        .payload
        .insert("iss".into(), json!("urn:example:issuer:7"));
    scenario.trusted_issuer = "urn:example:issuer:7".into();
    assert!(verify(&scenario, &policy(true)).is_ok());
}

#[test]
fn accepts_without_key_binding_when_policy_does_not_require_it() {
    let mut scenario = Scenario::pinned();
    scenario.kb_payload = None;
    let credential = verify(&scenario, &policy(false)).unwrap();
    assert!(!credential.key_bound);
}

#[test]
fn accepts_extra_key_binding_claims() {
    let mut scenario = Scenario::pinned();
    scenario.kb_payload = Some(object(
        json!({"jti": "abc", "transaction_data_hashes": ["x"]}),
    ));
    assert!(verify(&scenario, &policy(true)).unwrap().key_bound);
}

#[test]
fn accepts_a_cnf_kid_that_is_a_did_jwk() {
    // The platform's did:jwk decoder supports Ed25519 keys only.
    let mut scenario = Scenario::pinned();
    let holder = ed25519();
    let mut public = holder.public();
    public.kid = None;
    public.alg = None;
    let did = did_jwk_from_public_jwk(&public).unwrap();
    scenario
        .payload
        .insert("cnf".into(), json!({"kid": format!("{did}#0")}));
    scenario.holder = holder;
    scenario.kb_header = object(json!({"alg": "EdDSA", "typ": "kb+jwt"}));
    assert!(verify(&scenario, &policy(true)).unwrap().key_bound);
}

#[test]
fn accepts_an_ed25519_issuer_and_holder() {
    let mut scenario = Scenario::certified();
    let holder = ed25519();
    let mut jwk = serde_json::to_value(holder.public()).unwrap();
    jwk.as_object_mut().unwrap().remove("kid");
    scenario.payload.insert("cnf".into(), json!({"jwk": jwk}));
    scenario.holder = holder;
    scenario.kb_header = object(json!({"alg": "EdDSA", "typ": "kb+jwt"}));
    assert!(verify(&scenario, &policy(true)).unwrap().key_bound);
}

#[test]
fn resolves_recursive_array_and_decoy_disclosures() {
    let mut scenario = Scenario::pinned();
    // address.street is itself selectively disclosed inside a disclosed object.
    let (street, street_digest) = disclosure("s1", "street", &json!("Lambton Quay 1"));
    let (address, address_digest) = disclosure(
        "s2",
        "address",
        &json!({"_sd": [street_digest], "city": "Wellington"}),
    );
    scenario.reference(&address_digest);
    // nationalities is an array whose second element is selectively disclosed.
    let (nz, nz_digest) = element_disclosure("s3", &json!("NZ"));
    scenario
        .payload
        .insert("nationalities".into(), json!(["FR", {"...": nz_digest}]));
    // A decoy digest has no matching disclosure.
    scenario.reference(&b64(&[7u8; 32]));
    scenario.disclosures.extend([street, address, nz]);
    let claims = verify(&scenario, &policy(true)).unwrap().claims;
    assert_eq!(
        claims["address"],
        json!({"city": "Wellington", "street": "Lambton Quay 1"})
    );
    assert_eq!(claims["nationalities"], json!(["FR", "NZ"]));
    assert_eq!(claims["family_name"], "Tane");
}

#[test]
fn reports_a_status_reference_without_checking_it() {
    let mut scenario = Scenario::pinned();
    scenario.payload.insert(
        "status".into(),
        json!({"status_list": {"idx": 3, "uri": "https://issuer.example/status/1"}}),
    );
    assert!(
        verify(&scenario, &policy(true))
            .unwrap()
            .status_reference_present
    );
}

#[test]
fn clock_skew_tolerates_a_just_expired_credential() {
    let scenario = Scenario::pinned();
    let exp = NOW + 3600;
    assert!(verify_at(&scenario, &policy(true), exp + 59).is_ok());
}

// ---- refusals, one per category ---------------------------------------------

#[test]
fn refuses_an_oversized_presentation() {
    let scenario = Scenario::pinned();
    let huge = format!("{}{}", scenario.build(), "a".repeat(300 * 1024));
    let result = verify_sd_jwt_vc(&huge, &ctx(), &scenario.trust(), &policy(true), NOW);
    assert_eq!(result.unwrap_err(), R::PresentationTooLarge);
}

#[test]
fn refuses_a_malformed_presentation() {
    let scenario = Scenario::pinned();
    for input in ["", "not-a-jwt", "a.b.c", "a.b~", "a.b.c~~~x"] {
        let result = verify_sd_jwt_vc(input, &ctx(), &scenario.trust(), &policy(true), NOW);
        assert_eq!(result.unwrap_err(), R::MalformedPresentation, "{input}");
    }
}

#[test]
fn refuses_a_wrong_issuer_typ() {
    for typ in ["vc+sd-jwt", "JWT", "DC+SD-JWT"] {
        let mut scenario = Scenario::pinned();
        scenario.header.insert("typ".into(), json!(typ));
        assert_eq!(refused(&scenario), R::IssuerTypeInvalid, "{typ}");
    }
    let mut scenario = Scenario::pinned();
    scenario.header.remove("typ");
    assert_eq!(refused(&scenario), R::IssuerTypeInvalid);
}

#[test]
fn refuses_alg_none_and_algorithms_off_the_policy_list() {
    let mut scenario = Scenario::pinned();
    scenario.header.insert("alg".into(), json!("none"));
    assert_eq!(refused(&scenario), R::IssuerAlgorithmNotAllowed);

    let scenario = Scenario::pinned();
    let mut only_eddsa = policy(true);
    only_eddsa.issuer_algorithms = vec![IssuerAlgorithm::EdDsa];
    assert_eq!(
        verify(&scenario, &only_eddsa).unwrap_err(),
        R::IssuerAlgorithmNotAllowed
    );

    let mut scenario = Scenario::pinned();
    scenario.header.insert("alg".into(), json!("HS256"));
    assert_eq!(refused(&scenario), R::IssuerAlgorithmNotAllowed);
}

#[test]
fn refuses_key_nominating_header_parameters() {
    for (name, value) in [
        ("jku", json!("https://evil.example/jwks")),
        ("jwk", json!({"kty": "EC"})),
        ("x5u", json!("https://evil.example/chain")),
        ("crit", json!(["exp"])),
        ("b64", json!(false)),
    ] {
        let mut scenario = Scenario::pinned();
        scenario.header.insert(name.into(), value);
        assert_eq!(refused(&scenario), R::ForbiddenHeaderParameter, "{name}");
    }
    // An x5c on a pinned-key entry is not a key source for that entry.
    let mut scenario = Scenario::pinned();
    scenario.header.insert("x5c".into(), json!(["AAAA"]));
    assert_eq!(refused(&scenario), R::ForbiddenHeaderParameter);
}

#[test]
fn refuses_a_credential_without_iss() {
    let mut scenario = Scenario::pinned();
    scenario.payload.remove("iss");
    assert_eq!(refused(&scenario), R::IssuerMissing);
}

#[test]
fn refuses_an_issuer_that_is_not_configured() {
    let mut scenario = Scenario::pinned();
    scenario
        .payload
        .insert("iss".into(), json!("https://other.example"));
    assert_eq!(refused(&scenario), R::IssuerUntrusted);
    // Not even a different spelling of a configured issuer matches.
    scenario
        .payload
        .insert("iss".into(), json!("https://issuer.example/"));
    assert_eq!(refused(&scenario), R::IssuerUntrusted);
}

#[test]
fn refuses_a_chain_to_a_different_anchor() {
    let trusted = pki("trusted");
    let mut scenario = Scenario::certified();
    scenario.issuer.key_source =
        common::Issuer::certified(&trusted, &["issuer.example"], &[]).key_source;
    assert_eq!(refused(&scenario), R::CertificateChainInvalid);
}

#[test]
fn refuses_an_x5c_entry_whose_header_has_no_chain() {
    let mut scenario = Scenario::certified();
    scenario.header.remove("x5c");
    assert_eq!(refused(&scenario), R::CertificateChainInvalid);
}

#[test]
fn refuses_an_expired_chain_at_the_injected_time() {
    let scenario = Scenario::certified();
    let far_future = NOW + 2 * 365 * 24 * 3600;
    assert_eq!(
        verify_at(&scenario, &policy(true), far_future).unwrap_err(),
        R::CertificateChainInvalid
    );
}

#[test]
fn refuses_a_leaf_whose_san_does_not_bind_iss() {
    // The chain is valid, but the certificate names another host.
    let pki = pki("a");
    let scenario = Scenario::new(Issuer::certified(&pki, &["other.example"], &[]));
    assert_eq!(refused(&scenario), R::IssuerNotBoundToCertificate);

    // A host that merely contains the issuer host is not a match.
    let scenario = Scenario::new(Issuer::certified(&pki, &["evil-issuer.example"], &[]));
    assert_eq!(refused(&scenario), R::IssuerNotBoundToCertificate);

    // A URI SAN must equal iss exactly.
    let scenario = Scenario::new(Issuer::certified(
        &pki,
        &[],
        &["https://issuer.example/other"],
    ));
    assert_eq!(refused(&scenario), R::IssuerNotBoundToCertificate);

    // A non-https iss can only bind through a URI SAN.
    let mut scenario = Scenario::new(Issuer::certified(&pki, &["issuer.example"], &[]));
    scenario
        .payload
        .insert("iss".into(), json!("urn:example:issuer"));
    scenario.trusted_issuer = "urn:example:issuer".into();
    assert_eq!(refused(&scenario), R::IssuerNotBoundToCertificate);
}

#[test]
fn refuses_an_unknown_or_missing_kid() {
    let mut scenario = Scenario::pinned();
    scenario.header.insert("kid".into(), json!("someone-else"));
    assert_eq!(refused(&scenario), R::IssuerKeyIdUnknown);
    scenario.header.remove("kid");
    assert_eq!(refused(&scenario), R::IssuerKeyIdUnknown);
}

#[test]
fn refuses_a_signature_from_another_key() {
    let mut scenario = Scenario::pinned();
    scenario.issuer.key = es256();
    assert_eq!(refused(&scenario), R::IssuerSignatureInvalid);
}

#[test]
fn refuses_a_tampered_payload() {
    let scenario = Scenario::pinned();
    let presentation = scenario.build();
    let mut parts: Vec<&str> = presentation.split('.').collect();
    let forged =
        b64(&serde_json::to_vec(&json!({"iss": ISS, "vct": VCT, "iat": NOW, "x": 1})).unwrap());
    parts[1] = &forged;
    let result = verify_sd_jwt_vc(
        &parts.join("."),
        &ctx(),
        &scenario.trust(),
        &policy(true),
        NOW,
    );
    assert_eq!(result.unwrap_err(), R::IssuerSignatureInvalid);
}

#[test]
fn refuses_a_signature_under_the_wrong_algorithm_for_the_key() {
    let mut scenario = Scenario::pinned();
    scenario.header.insert("alg".into(), json!("EdDSA"));
    assert_eq!(refused(&scenario), R::IssuerSignatureInvalid);
}

#[test]
fn refuses_a_missing_vct() {
    let mut scenario = Scenario::pinned();
    scenario.payload.remove("vct");
    assert_eq!(refused(&scenario), R::CredentialTypeMissing);
}

#[test]
fn refuses_a_vct_outside_the_policy_or_the_trust_entry() {
    let scenario = Scenario::pinned();
    let other_policy = ChannelPolicy::new(vec!["urn:other".into()], true);
    assert_eq!(
        verify(&scenario, &other_policy).unwrap_err(),
        R::CredentialTypeNotAccepted
    );

    let mut scenario = Scenario::pinned();
    scenario.entry_vct = vec!["urn:other".into()];
    assert_eq!(refused(&scenario), R::CredentialTypeNotAccepted);

    // Exact match only: a prefix or a different case is another type.
    let mut scenario = Scenario::pinned();
    scenario
        .payload
        .insert("vct".into(), json!(format!("{VCT}/v2")));
    assert_eq!(refused(&scenario), R::CredentialTypeNotAccepted);
}

#[test]
fn refuses_claims_that_may_not_be_selectively_disclosed() {
    for name in ["iss", "nbf", "exp", "cnf", "vct", "status"] {
        let mut scenario = Scenario::pinned();
        scenario.payload.remove(name);
        let value = match name {
            "iss" => json!(ISS),
            "vct" => json!(VCT),
            "nbf" => json!(NOW - 100),
            "exp" => json!(NOW + 3600),
            "cnf" => json!({"jwk": {"kty": "EC"}}),
            _ => json!({"status_list": {"idx": 1, "uri": "https://issuer.example/s"}}),
        };
        scenario.disclose(name, value);
        // iss and vct are needed before disclosures are read, so those two are
        // refused as missing; every other claim reaches the disclosure check.
        let expected = match name {
            "iss" => R::IssuerMissing,
            "vct" => R::CredentialTypeMissing,
            _ => R::ClaimNotDisclosable,
        };
        assert_eq!(refused(&scenario), expected, "{name}");
    }
}

#[test]
fn refuses_a_subclaim_of_cnf_that_is_selectively_disclosed() {
    let mut scenario = Scenario::pinned();
    let (jwk, digest) = disclosure("sc", "jwk", &scenario.payload["cnf"]["jwk"].clone());
    scenario
        .payload
        .insert("cnf".into(), json!({"_sd": [digest]}));
    scenario.disclosures.push(jwk);
    assert_eq!(refused(&scenario), R::ClaimNotDisclosable);
}

#[test]
fn refuses_invalid_disclosures() {
    // A disclosure no digest references.
    let mut scenario = Scenario::pinned();
    let (stray, _) = disclosure("x", "stray", &json!(1));
    scenario.disclosures.push(stray);
    assert_eq!(refused(&scenario), R::DisclosureInvalid);

    // The same digest referenced twice.
    let mut scenario = Scenario::pinned();
    let digest = scenario.payload["_sd"][0].as_str().unwrap().to_owned();
    scenario.reference(&digest);
    assert_eq!(refused(&scenario), R::DisclosureInvalid);

    // A disclosed name that already exists in the signed payload.
    let mut scenario = Scenario::pinned();
    scenario
        .payload
        .insert("family_name".into(), json!("Other"));
    assert_eq!(refused(&scenario), R::DisclosureInvalid);

    // Not a disclosure at all.
    let mut scenario = Scenario::pinned();
    scenario.disclosures.push(b64(b"not json"));
    assert_eq!(refused(&scenario), R::DisclosureInvalid);

    // An unsupported hash algorithm.
    let mut scenario = Scenario::pinned();
    scenario.payload.insert("_sd_alg".into(), json!("sha-512"));
    assert_eq!(refused(&scenario), R::DisclosureInvalid);
}

#[test]
fn refuses_time_claims_that_are_not_integers() {
    for (name, value) in [
        ("exp", json!("soon")),
        ("nbf", json!(1.5)),
        ("iat", json!(null)),
    ] {
        let mut scenario = Scenario::pinned();
        scenario.payload.insert(name.into(), value);
        assert_eq!(refused(&scenario), R::TimeClaimMalformed, "{name}");
    }
}

#[test]
fn refuses_an_expired_credential_at_the_injected_time() {
    let scenario = Scenario::pinned();
    let result = verify_at(&scenario, &policy(true), NOW + 3600 + 60);
    assert_eq!(result.unwrap_err(), R::CredentialExpired);
    assert!(verify_at(&scenario, &policy(true), NOW + 3600 + 59).is_ok());
}

#[test]
fn refuses_a_credential_that_is_not_yet_valid() {
    let mut scenario = Scenario::pinned();
    scenario.payload.insert("nbf".into(), json!(NOW + 61));
    assert_eq!(refused(&scenario), R::CredentialNotYetValid);
    scenario.payload.insert("nbf".into(), json!(NOW + 60));
    assert!(verify(&scenario, &policy(true)).is_ok());
}

#[test]
fn refuses_a_credential_without_iat() {
    let mut scenario = Scenario::pinned();
    scenario.payload.remove("iat");
    assert_eq!(refused(&scenario), R::IssuedAtMissing);
}

#[test]
fn refuses_a_credential_issued_in_the_future() {
    let mut scenario = Scenario::pinned();
    scenario.payload.insert("iat".into(), json!(NOW + 61));
    assert_eq!(refused(&scenario), R::IssuedAtInFuture);
}

#[test]
fn refuses_unsupported_holder_key_forms() {
    let holder_jwk = {
        let mut jwk = serde_json::to_value(Scenario::pinned().holder.public()).unwrap();
        jwk.as_object_mut().unwrap().remove("kid");
        jwk
    };
    let cases: Vec<Value> = vec![
        json!({"kid": "holder-key-1"}),
        json!({"kid": "did:web:holder.example#key-1"}),
        json!({"kid": "did:jwk:not-base64!"}),
        json!({"jku": "https://holder.example/jwks"}),
        json!({"x5c": ["AAAA"]}),
        json!({"jkt": "abc"}),
        json!({"jwk": holder_jwk.clone(), "kid": "x"}),
        json!({"jwk": {"kty": "RSA", "n": "AQAB", "e": "AQAB"}}),
        json!({}),
        json!("jwk"),
    ];
    for cnf in cases {
        let mut scenario = Scenario::pinned();
        scenario.payload.insert("cnf".into(), cnf.clone());
        assert_eq!(refused(&scenario), R::HolderKeyInvalid, "{cnf}");
        // The same holds when key binding is not required and none is sent.
        scenario.kb_payload = None;
        assert_eq!(
            verify(&scenario, &policy(false)).unwrap_err(),
            R::HolderKeyInvalid,
            "{cnf}"
        );
    }
    // A private key in the holder JWK is refused.
    let mut private = holder_jwk;
    private["d"] = json!("AAAA");
    let mut scenario = Scenario::pinned();
    scenario
        .payload
        .insert("cnf".into(), json!({"jwk": private}));
    assert_eq!(refused(&scenario), R::HolderKeyInvalid);
}

#[test]
fn refuses_a_key_binding_jwt_when_the_credential_confirms_no_holder_key() {
    let mut scenario = Scenario::pinned();
    scenario.payload.remove("cnf");
    assert_eq!(refused(&scenario), R::HolderKeyInvalid);
}

#[test]
fn refuses_when_key_binding_is_required_and_absent() {
    let mut scenario = Scenario::pinned();
    scenario.kb_payload = None;
    assert_eq!(refused(&scenario), R::KeyBindingRequired);
    // A credential with no cnf and no KB-JWT still fails the required policy.
    scenario.payload.remove("cnf");
    assert_eq!(refused(&scenario), R::KeyBindingRequired);
}

#[test]
fn refuses_a_bad_key_binding_jwt_even_when_it_is_not_required() {
    let bad = [
        object(json!({"nonce": "other-nonce"})),
        object(json!({"aud": "verifier.example"})),
        object(json!({"aud": "x509_san_dns:other.example"})),
        object(json!({"sd_hash": b64(&[1u8; 32])})),
        object(json!({"iat": NOW - 121})),
        object(json!({"iat": NOW + 61})),
        object(json!({"nonce": null})),
        object(json!({"aud": null})),
        object(json!({"iat": null})),
        object(json!({"sd_hash": null})),
    ];
    for overrides in bad {
        let mut scenario = Scenario::pinned();
        scenario.kb_payload = Some(overrides.clone());
        assert_eq!(refused(&scenario), R::KeyBindingInvalid, "{overrides:?}");
        assert_eq!(
            verify(&scenario, &policy(false)).unwrap_err(),
            R::KeyBindingInvalid,
            "{overrides:?}"
        );
    }
}

#[test]
fn refuses_a_key_binding_jwt_with_the_wrong_type_or_key() {
    let mut scenario = Scenario::pinned();
    scenario.kb_header.insert("typ".into(), json!("JWT"));
    assert_eq!(refused(&scenario), R::KeyBindingInvalid);

    let mut scenario = Scenario::pinned();
    scenario.kb_key = Some(es256());
    assert_eq!(refused(&scenario), R::KeyBindingInvalid);

    let mut scenario = Scenario::pinned();
    scenario.kb_header.insert("alg".into(), json!("none"));
    assert_eq!(refused(&scenario), R::KeyBindingInvalid);
}

#[test]
fn binds_the_key_binding_jwt_to_the_presented_disclosures() {
    // Dropping a disclosure after the holder signed changes sd_hash.
    let mut scenario = Scenario::pinned();
    scenario.disclose("given_name", json!("Aroha"));
    let presentation = scenario.build();
    let without_last = {
        let mut parts: Vec<&str> = presentation.split('~').collect();
        let kb = parts.pop().unwrap();
        parts.pop();
        format!("{}~{kb}", parts.join("~"))
    };
    let result = verify_sd_jwt_vc(&without_last, &ctx(), &scenario.trust(), &policy(true), NOW);
    assert!(result.is_err());
}

#[test]
fn key_binding_window_is_taken_around_the_response_arrival() {
    let scenario = Scenario::pinned();
    let late = SessionContext {
        received_at: NOW + 120,
        ..ctx()
    };
    let result = verify_sd_jwt_vc(
        &scenario.build(),
        &late,
        &scenario.trust(),
        &policy(true),
        NOW,
    );
    assert!(result.is_ok());
    let later = SessionContext {
        received_at: NOW + 121,
        ..ctx()
    };
    let result = verify_sd_jwt_vc(
        &scenario.build(),
        &later,
        &scenario.trust(),
        &policy(true),
        NOW,
    );
    assert_eq!(result.unwrap_err(), R::KeyBindingInvalid);
}

// ---- diagnostics never carry input ------------------------------------------

#[test]
fn refusal_text_and_debug_output_carry_no_input() {
    let mut scenario = Scenario::pinned();
    scenario.disclose("secret_claim", json!("secret-value-91"));
    scenario.kb_payload = Some(object(json!({"nonce": "attacker-nonce-55"})));
    let presentation = scenario.build();
    let refusal =
        verify_sd_jwt_vc(&presentation, &ctx(), &scenario.trust(), &policy(true), NOW).unwrap_err();
    let text = format!("{refusal} {refusal:?}");
    for needle in [
        NONCE,
        "attacker-nonce-55",
        CLIENT_ID,
        ISS,
        VCT,
        "secret_claim",
        "secret-value-91",
        "issuer-key-1",
    ] {
        assert!(!text.contains(needle), "{needle} leaked into {text}");
    }
}

#[test]
fn debug_output_redacts_the_nonce_and_the_claims() {
    let scenario = Scenario::pinned();
    let mut with_claim = Scenario::pinned();
    with_claim.disclose("secret_claim", json!("secret-value-91"));
    let credential = verify(&with_claim, &policy(true)).unwrap();
    let text = format!("{credential:?}");
    assert!(!text.contains("secret-value-91") && !text.contains("secret_claim"));
    assert!(text.contains("key_bound"));
    let text = format!("{:?}", ctx());
    assert!(!text.contains(NONCE));
    let text = format!("{:?}", scenario.trust());
    assert!(text.contains(ENTRY_ID));
}
