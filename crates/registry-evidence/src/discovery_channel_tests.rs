//! Discovery for a definition that accepts both acquisition channels: one
//! entry per handle, the source channel's shape as the entry's own, and the
//! other channel the caller is entitled to as an alternative.
#![cfg(feature = "wallet-presentation")]

use super::wallet_channel_tests::{
    Deployment, TrustedIssuer, WalletRuntime, ADULT_REQUIREMENT, SESSION_PROFILE,
};
use super::*;
use crate::model::{ChannelKind, EvidenceDefinition, EvidenceDefinitions};
use crate::runtime::{merge_channel_alternatives, RuntimeFailure};

const SOURCE_PROFILE: &str = "person-demographics-v1";

/// The adult-status entry of a published document, which must be the only
/// one for its handle however many channels the caller is granted.
fn adult_entry(published: &EvidenceDefinitions) -> &EvidenceDefinition {
    let mut entries = published
        .definitions
        .iter()
        .filter(|entry| entry.requirement == ADULT_REQUIREMENT);
    let entry = entries.next().expect("the adult-status entry is published");
    assert!(
        entries.next().is_none(),
        "one entry per handle, whatever the number of granted channels"
    );
    entry
}

fn profile_of(subjects: &[crate::model::EvidenceDefinitionSubject]) -> Vec<&str> {
    subjects
        .iter()
        .map(|subject| subject.selector.profile.as_str())
        .collect()
}

fn assert_contract_accepts(published: &EvidenceDefinitions) {
    let value = serde_json::to_value(published).expect("the document serializes");
    assert!(
        crate::contracts::definitions_contract_accepts(&value).expect("the contract compiles"),
        "the published document passes the definitions contract"
    );
}

async fn discover(deployment: &Deployment) -> Result<EvidenceDefinitions, RuntimeFailure> {
    let issuer = TrustedIssuer::generate();
    let fixture = WalletRuntime::start(&issuer, deployment).await;
    fixture.runtime.discover(&access_token(None)).await
}

/// Give another requester the adult-status grants that fail `keep`, and leave
/// the caller only the ones that satisfy it. Every channel stays reachable
/// from some authority profile, so the configuration stays valid.
fn grant_adult_status_to_the_caller_on(configuration: &mut Value, keep: fn(&str) -> bool) {
    let grants = configuration["authorityProfiles"][AUTHORITY]["grants"]
        .as_array_mut()
        .expect("the authority profile declares grants");
    let is_kept = |grant: &Value| {
        grant["requirement"] != ADULT_REQUIREMENT
            || keep(grant["subjects"][0]["selectorProfile"].as_str().unwrap())
    };
    let others = grants
        .iter()
        .filter(|grant| !is_kept(grant))
        .cloned()
        .collect::<Vec<_>>();
    grants.retain(is_kept);
    configuration["authorityProfiles"]["another-caseworker-v1"] = json!({
        "kind": "statutory",
        "requesterTags": ["another-agency"],
        "grants": others,
    });
}

#[tokio::test]
async fn discovery_publishes_one_entry_with_the_other_granted_channel_as_an_alternative() {
    let published = discover(&Deployment::standard())
        .await
        .expect("discovery publishes the definition");

    let entry = adult_entry(&published);
    assert_eq!(entry.channel, Some(ChannelKind::Source));
    assert_eq!(profile_of(&entry.subjects), [SOURCE_PROFILE]);
    assert_eq!(entry.alternatives.len(), 1);
    let alternative = &entry.alternatives[0];
    assert_eq!(alternative.channel, ChannelKind::HolderPresented);
    assert_eq!(profile_of(&alternative.subjects), [SESSION_PROFILE]);
    // The formats are each channel's own grant. A definition with a
    // holder-presented channel offers only the signed assertion, so both
    // grants carry it.
    assert_eq!(entry.response_formats, [ResponseFormat::SignedJws]);
    assert_eq!(alternative.response_formats, [ResponseFormat::SignedJws]);
    assert_contract_accepts(&published);
    let wire = serde_json::to_value(&published).unwrap();
    assert_eq!(wire["definitions"][0]["channel"], json!("source"));
    assert_eq!(
        wire["definitions"][0]["alternatives"][0]["channel"],
        json!("holder-presented")
    );
}

#[tokio::test]
async fn a_caller_with_only_the_holder_presented_grant_sees_that_channel_alone() {
    let published = discover(&Deployment {
        edit: |configuration| {
            grant_adult_status_to_the_caller_on(configuration, |profile| profile == SESSION_PROFILE)
        },
        ..Deployment::standard()
    })
    .await
    .expect("discovery publishes the definition");

    let entry = adult_entry(&published);
    assert_eq!(entry.channel, Some(ChannelKind::HolderPresented));
    assert_eq!(profile_of(&entry.subjects), [SESSION_PROFILE]);
    assert!(entry.alternatives.is_empty());
    assert_contract_accepts(&published);
    let wire = serde_json::to_value(&published).unwrap();
    assert!(wire["definitions"][0].get("alternatives").is_none());
}

#[tokio::test]
async fn a_caller_with_only_the_source_grant_of_a_two_channel_definition_sees_no_alternative() {
    let published = discover(&Deployment {
        edit: |configuration| {
            grant_adult_status_to_the_caller_on(configuration, |profile| profile == SOURCE_PROFILE)
        },
        ..Deployment::standard()
    })
    .await
    .expect("discovery publishes the definition");

    let entry = adult_entry(&published);
    assert_eq!(
        entry.channel, None,
        "a caller with no holder-presented grant is not told a second channel exists"
    );
    assert_eq!(profile_of(&entry.subjects), [SOURCE_PROFILE]);
    assert!(
        entry.alternatives.is_empty(),
        "a channel the caller is not entitled to is never revealed"
    );
    assert_contract_accepts(&published);
    let wire = serde_json::to_value(&published).unwrap();
    assert!(wire["definitions"][0].get("channel").is_none());
    assert!(wire["definitions"][0].get("alternatives").is_none());
}

#[tokio::test]
async fn two_channels_granted_for_different_purposes_still_refuse() {
    let refused = discover(&Deployment {
        edit: |configuration| {
            configuration_requirement_mut(configuration, "adult-status")["purposes"] =
                json!(["fixture-eligibility", "fixture-appeal"]);
            let grants = configuration["authorityProfiles"][AUTHORITY]["grants"]
                .as_array_mut()
                .expect("the authority profile declares grants");
            let appeals = grants
                .iter()
                .filter(|grant| grant["requirement"] == ADULT_REQUIREMENT)
                .map(|grant| {
                    let mut appeal = grant.clone();
                    appeal["purpose"] = json!("fixture-appeal");
                    appeal
                })
                .collect::<Vec<_>>();
            grants.extend(appeals);
        },
        ..Deployment::standard()
    })
    .await;

    assert_eq!(
        refused.err().map(RuntimeFailure::category),
        Some("discovery-ambiguous-handle")
    );
}

fn entry(channel: Option<ChannelKind>, profile: &str) -> EvidenceDefinition {
    EvidenceDefinition {
        handle: "adult-status".to_owned(),
        requirement: ADULT_REQUIREMENT.to_owned(),
        configuration_revision: format!("sha256:{}", "0".repeat(64)),
        kind: "criterion".to_owned(),
        subject_binding_mode: None,
        evidence_type: "urn:example:evidence-type".to_owned(),
        purpose: "fixture-eligibility".to_owned(),
        response_formats: vec![ResponseFormat::SignedJws],
        reference_frameworks: vec!["urn:example:framework".to_owned()],
        subjects: vec![crate::model::EvidenceDefinitionSubject {
            role: "subject".to_owned(),
            cardinality: "one".to_owned(),
            selector: crate::model::EvidenceDefinitionSelector {
                profile: profile.to_owned(),
                value_origin: "request".to_owned(),
                fields: Vec::new(),
            },
        }],
        concepts: Vec::new(),
        channel,
        alternatives: Vec::new(),
    }
}

#[test]
fn two_entries_on_one_channel_or_without_a_channel_still_refuse() {
    for channels in [
        (Some(ChannelKind::Source), Some(ChannelKind::Source)),
        (
            Some(ChannelKind::HolderPresented),
            Some(ChannelKind::HolderPresented),
        ),
        (None, None),
        (Some(ChannelKind::Source), None),
    ] {
        let refused = merge_channel_alternatives(vec![
            entry(channels.0, SOURCE_PROFILE),
            entry(channels.1, "other-profile-v1"),
        ]);
        assert_eq!(
            refused.err().map(RuntimeFailure::category),
            Some("discovery-ambiguous-handle"),
            "{channels:?}"
        );
    }
}

#[test]
fn the_source_entry_stays_primary_whatever_the_order_of_the_grants() {
    for entries in [
        vec![
            entry(Some(ChannelKind::HolderPresented), SESSION_PROFILE),
            entry(Some(ChannelKind::Source), SOURCE_PROFILE),
        ],
        vec![
            entry(Some(ChannelKind::Source), SOURCE_PROFILE),
            entry(Some(ChannelKind::HolderPresented), SESSION_PROFILE),
        ],
    ] {
        let merged = merge_channel_alternatives(entries).expect("both channels fold");
        assert_eq!(merged.len(), 1);
        assert_eq!(merged[0].channel, Some(ChannelKind::Source));
        assert_eq!(profile_of(&merged[0].subjects), [SOURCE_PROFILE]);
        assert_eq!(
            profile_of(&merged[0].alternatives[0].subjects),
            [SESSION_PROFILE]
        );
    }
}

/// The document a source-only deployment published before the second channel
/// existed, taken from the acceptance fixture.
const SOURCE_ONLY_DOCUMENT: &str = r#"{"schema":"registry.evidence-definitions/v1","assuranceProfile":"local","audience":"https://relying.invalid/procedure","issuedBy":"urn:example:fixture:issuer:authority","providedBy":"urn:example:fixture:provider:evidence","maximumHolderBoundBatchSize":1,"definitions":[{"handle":"adult-status","requirement":"urn:example:fixture:requirement:adult-status:v1","configurationRevision":"sha256:65068400a0267c215524544277e90d089040e1e3e05df83ec736045b6be59ba5","kind":"criterion","evidenceType":"urn:example:fixture:evidence-type:adult-status:v1","purpose":"fixture-eligibility","responseFormats":["signed-jws","unsigned-json"],"referenceFrameworks":["urn:example:fixture:framework:adult-status:v1"],"subjects":[{"role":"subject","cardinality":"one","selector":{"profile":"person-demographics-v1","valueOrigin":"request","fields":[{"type":"date","name":"birth_date"},{"type":"string","name":"family_name","minimumBytes":1,"maximumBytes":200},{"type":"string","name":"given_name","minimumBytes":1,"maximumBytes":200}]}}],"concepts":[{"handle":"is_adult","concept":"urn:example:fixture:concept:adult-status","required":true,"form":{"type":"boolean"}}]},{"handle":"professional-licence-status","requirement":"urn:example:fixture:requirement:professional-licence-status:v1","configurationRevision":"sha256:a4828f2f13fa30ede3c0dc1cbb967b1391fc5417b2cafd2842bf7efa07c12d9f","kind":"criterion","evidenceType":"urn:example:fixture:evidence-type:professional-licence-status:v1","purpose":"fixture-registration","responseFormats":["signed-jws","unsigned-json"],"referenceFrameworks":["urn:example:fixture:framework:professional-licence:v1"],"subjects":[{"role":"subject","cardinality":"one","selector":{"profile":"licence-register-v1","valueOrigin":"request","fields":[{"type":"string","name":"licence_reference","minimumBytes":1,"maximumBytes":96},{"type":"controlled-code","name":"registry_region","scheme":"urn:example:fixture:codelist:registry-regions","version":"1","maximumBytes":16}]}}],"concepts":[{"handle":"licence-active","concept":"urn:example:fixture:concept:licence-active","required":true,"form":{"type":"boolean"}},{"handle":"licence-expiry-category","concept":"urn:example:fixture:concept:licence-expiry-category","required":true,"form":{"type":"string"}}]},{"handle":"residence-region","requirement":"urn:example:fixture:requirement:residence-region:v1","configurationRevision":"sha256:f167a8593dd010a01ee71f85cb57e9e3e929aa79f0ff857110fa8c93ee6bf597","kind":"information-requirement","evidenceType":"urn:example:fixture:evidence-type:residence-region:v1","purpose":"fixture-routing","responseFormats":["signed-jws","unsigned-json"],"referenceFrameworks":["urn:example:fixture:framework:residence-region:v1"],"subjects":[{"role":"subject","cardinality":"one","selector":{"profile":"residence-record-v1","valueOrigin":"request","fields":[{"type":"string","name":"record_reference","minimumBytes":1,"maximumBytes":96}]}}],"concepts":[{"handle":"region","concept":"urn:example:fixture:concept:residence-region","required":true,"form":{"type":"string"}}]}]}"#;

#[tokio::test]
async fn a_source_only_deployment_publishes_the_document_it_always_did() {
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("the source-only deployment initializes");

    let published = runtime
        .discover(&access_token(None))
        .await
        .expect("discovery publishes the definition");

    // The revisions hash the fixture's generated artifacts, which differ per
    // run; every other byte is the golden document's.
    let mask = |mut document: Value| {
        for entry in document["definitions"].as_array_mut().unwrap() {
            entry["configurationRevision"] = json!("masked");
        }
        serde_json::to_string(&document).unwrap()
    };
    assert_eq!(
        mask(serde_json::to_value(&published).unwrap()),
        mask(serde_json::from_str(SOURCE_ONLY_DOCUMENT).unwrap())
    );
}
