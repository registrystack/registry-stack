// SPDX-License-Identifier: Apache-2.0

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_platform_consent::{
    consent_evidence_commitment, verify_consent, ConsentArtifact, ConsentAssurance, ConsentError,
    ConsentEvidenceV1, ConsentVerifierSpec, ConsentingParty, ConsentingPartyRelationship,
    EvaluationConsentEvidence, ExactIdentifier, NoticeModality, PinnedConsentKeys,
    PurposeCoverageRule, RevocationModel, SubjectBindingRule, TargetProfileBinding,
    TargetProfileBindingKind, UnavailableBehavior, VerificationContext, MAX_CONSENT_EVIDENCE_BYTES,
};
use registry_platform_crypto::{PrivateJwk, PublicJwk};
use std::collections::BTreeSet;

const PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"consent-test-key-1"}"#;

fn identifier(value: &str) -> ExactIdentifier {
    ExactIdentifier {
        identifier_type: "programme_id".to_string(),
        value: value.to_string(),
    }
}

fn target_profile() -> TargetProfileBinding {
    TargetProfileBinding {
        kind: TargetProfileBindingKind::ProfileId,
        value: "humanitarian-referral-v1".to_string(),
    }
}

fn evidence() -> ConsentEvidenceV1 {
    ConsentEvidenceV1 {
        version: 1,
        subject: identifier("P-123"),
        consenting_party: ConsentingParty {
            identifier: identifier("P-123"),
            relationship: ConsentingPartyRelationship::Self_,
        },
        purposes: ["humanitarian.referral".to_string()].into(),
        recipient: "referral-partner.example".to_string(),
        controller: "programme.example".to_string(),
        assurance: ConsentAssurance::SystemOfRecordSigned,
        collection_method: "registration_desk".to_string(),
        collection_context: "voluntary referral choice".to_string(),
        collected_at: 1_783_731_600,
        issued_at: 1_783_731_660,
        expires_at: 1_783_732_260,
        consent_id: "consent-2026-0001".to_string(),
        notice_reference: "notice/referral/v1".to_string(),
        notice_language: "en".to_string(),
        notice_content_digest: format!("sha256:{}", "a".repeat(64)),
        notice_modality: NoticeModality::Written,
        target_profile: Some(target_profile()),
        verifier_section_hash: Some(format!("sha256:{}", "b".repeat(64))),
        status_revision: Some("42".to_string()),
    }
}

fn keypair() -> (PrivateJwk, PublicJwk) {
    let private = PrivateJwk::parse(PRIVATE_JWK).expect("private key");
    let public = private.public();
    (private, public)
}

fn spec() -> ConsentVerifierSpec {
    ConsentVerifierSpec {
        verifier_id: "humanitarian-referral-sor".to_string(),
        revision: "2026-07-11".to_string(),
        evidence_format_profile: "registry.consent-evidence".to_string(),
        evidence_format_version: 1,
        maximum_evidence_age_seconds: 300,
        revocation: RevocationModel::LifetimeOnly,
        revocation_propagation_seconds: 300,
        unavailable: UnavailableBehavior::Deny,
        subject_binding: SubjectBindingRule::ExactIdentifier,
        accepted_assurance: [ConsentAssurance::SystemOfRecordSigned].into(),
        purpose_coverage: PurposeCoverageRule::AllRequired,
    }
}

#[test]
fn golden_vector_parses_and_verifies() {
    let (private, public) = keypair();
    assert_eq!(
        evidence().to_json_bytes().expect("payload"),
        include_bytes!("fixtures/valid-ed25519.payload.json")
            .strip_suffix(b"\n")
            .expect("fixture newline")
    );
    assert_eq!(
        public,
        PublicJwk::parse(include_str!("fixtures/valid-ed25519.public.jwk").trim())
            .expect("golden public key")
    );
    let artifact = evidence().sign_compact(&private).expect("sign");
    assert_eq!(
        artifact.as_str(),
        include_str!("fixtures/valid-ed25519.jws").trim()
    );
    let parsed = ConsentArtifact::parse(artifact.as_str().to_string()).expect("parse");
    let keys = PinnedConsentKeys::new([public]).expect("keys");
    let required_purposes = ["humanitarian.referral".to_string()].into();
    let subject = identifier("P-123");
    let target_profile = target_profile();
    let verified = verify_consent(
        &parsed,
        &keys,
        &spec(),
        &VerificationContext {
            subject: &subject,
            recipient: "referral-partner.example",
            required_purposes: &required_purposes,
            now: 1_783_731_900,
            required_target_profile: Some(&target_profile),
            required_verifier_section_hash: Some(
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            ),
            required_status_revision: Some("42"),
        },
    )
    .expect("verify");
    assert_eq!(verified.signer_key_id, "consent-test-key-1");
    assert_eq!(verified.expires_at, 1_783_732_260);
}

#[test]
fn parse_rejects_unknown_and_duplicate_payload_members() {
    let json = evidence().to_json_bytes().expect("json");
    let mut value = String::from_utf8(json).expect("utf8");
    value.insert_str(value.len() - 1, ",\"unexpected\":true");
    assert_eq!(
        ConsentEvidenceV1::parse_json(value.as_bytes()).err(),
        Some(ConsentError::Malformed)
    );

    let duplicate = value.replace(",\"unexpected\":true", ",\"version\":1");
    assert_eq!(
        ConsentEvidenceV1::parse_json(duplicate.as_bytes()).err(),
        Some(ConsentError::Malformed)
    );
}

#[test]
fn parse_rejects_unknown_and_duplicate_protected_header_members() {
    let (private, _) = keypair();
    let artifact = evidence().sign_compact(&private).expect("sign");
    let segments: Vec<_> = artifact.as_str().split('.').collect();
    for header in [
        r#"{"alg":"EdDSA","typ":"consent-evidence+jws","kid":"consent-test-key-1","jku":"https://attacker.test"}"#,
        r#"{"alg":"EdDSA","alg":"EdDSA","typ":"consent-evidence+jws","kid":"consent-test-key-1"}"#,
    ] {
        let compact = format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            segments[1],
            segments[2]
        );
        assert_eq!(
            ConsentArtifact::parse(compact).err(),
            Some(ConsentError::Malformed)
        );
    }
}

#[test]
fn verification_denies_each_bound_dimension() {
    let (private, public) = keypair();
    let artifact = evidence().sign_compact(&private).expect("sign");
    let keys = PinnedConsentKeys::new([public]).expect("keys");
    let purposes: BTreeSet<_> = ["humanitarian.referral".to_string()].into();
    let subject = identifier("P-123");
    let target_profile = target_profile();
    let verify = |subject: &ExactIdentifier, recipient: &str, purposes: &BTreeSet<String>, now| {
        verify_consent(
            &artifact,
            &keys,
            &spec(),
            &VerificationContext {
                subject,
                recipient,
                required_purposes: purposes,
                now,
                required_target_profile: Some(&target_profile),
                required_verifier_section_hash: Some(
                    "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ),
                required_status_revision: Some("42"),
            },
        )
    };
    assert_eq!(
        verify(
            &identifier("other"),
            "referral-partner.example",
            &purposes,
            1_783_731_900
        ),
        Err(ConsentError::Denied)
    );
    assert_eq!(
        verify(&subject, "other.example", &purposes, 1_783_731_900),
        Err(ConsentError::Denied)
    );
    assert_eq!(
        verify(
            &subject,
            "referral-partner.example",
            &["other".to_string()].into(),
            1_783_731_900
        ),
        Err(ConsentError::Denied)
    );
    assert_eq!(
        verify(
            &subject,
            "referral-partner.example",
            &purposes,
            1_783_731_961
        ),
        Err(ConsentError::Denied)
    );
    assert_eq!(
        verify(
            &subject,
            "referral-partner.example",
            &purposes,
            1_783_732_260
        ),
        Err(ConsentError::Denied)
    );

    let mut wrong_assurance = spec();
    wrong_assurance.accepted_assurance = [ConsentAssurance::OrganizationAttested].into();
    assert_eq!(
        verify_consent(
            &artifact,
            &keys,
            &wrong_assurance,
            &VerificationContext {
                subject: &subject,
                recipient: "referral-partner.example",
                required_purposes: &purposes,
                now: 1_783_731_900,
                required_target_profile: Some(&target_profile),
                required_verifier_section_hash: None,
                required_status_revision: None,
            }
        ),
        Err(ConsentError::Denied)
    );
    let wrong_target = TargetProfileBinding {
        kind: TargetProfileBindingKind::ContractHash,
        value: format!("sha256:{}", "c".repeat(64)),
    };
    assert_eq!(
        verify_consent(
            &artifact,
            &keys,
            &spec(),
            &VerificationContext {
                subject: &subject,
                recipient: "referral-partner.example",
                required_purposes: &purposes,
                now: 1_783_731_900,
                required_target_profile: Some(&wrong_target),
                required_verifier_section_hash: None,
                required_status_revision: None,
            }
        ),
        Err(ConsentError::Denied)
    );
}

#[test]
fn pinned_keys_reject_duplicate_kids_and_unknown_signer_denies() {
    let (private, public) = keypair();
    assert!(matches!(
        PinnedConsentKeys::new([public.clone(), public]),
        Err(ConsentError::DuplicatePinnedKeyId)
    ));

    let mut other = private.public();
    other.kid = Some("other-key".to_string());
    let keys = PinnedConsentKeys::new([other]).expect("other pin");
    let artifact = evidence().sign_compact(&private).expect("sign");
    let purposes = ["humanitarian.referral".to_string()].into();
    let subject = identifier("P-123");
    assert_eq!(
        verify_consent(
            &artifact,
            &keys,
            &spec(),
            &VerificationContext {
                subject: &subject,
                recipient: "referral-partner.example",
                required_purposes: &purposes,
                now: 1_783_731_900,
                required_target_profile: None,
                required_verifier_section_hash: None,
                required_status_revision: None,
            }
        ),
        Err(ConsentError::Denied)
    );
}

#[test]
fn evaluation_cardinality_and_closed_surface_are_enforced() {
    let (private, _) = keypair();
    let first = evidence().sign_compact(&private).expect("first");
    let second = evidence().sign_compact(&private).expect("second");
    assert!(matches!(
        EvaluationConsentEvidence::from_artifacts([first, second]),
        Err(ConsentError::TooManyArtifacts)
    ));
    assert_eq!(
        EvaluationConsentEvidence::none().validate_requirement(true),
        Err(ConsentError::InvalidEvaluationEvidence)
    );
    let supplied = EvaluationConsentEvidence::one(evidence().sign_compact(&private).expect("one"));
    assert_eq!(
        supplied.validate_requirement(false),
        Err(ConsentError::InvalidEvaluationEvidence)
    );
}

#[test]
fn verifier_and_runtime_context_fail_closed_when_incomplete() {
    let (private, public) = keypair();
    let artifact = evidence().sign_compact(&private).expect("sign");
    let keys = PinnedConsentKeys::new([public]).expect("keys");
    let subject = identifier("P-123");

    let mut invalid_spec = spec();
    invalid_spec.maximum_evidence_age_seconds = 301;
    assert_eq!(
        verify_consent(
            &artifact,
            &keys,
            &invalid_spec,
            &VerificationContext {
                subject: &subject,
                recipient: "referral-partner.example",
                required_purposes: &["humanitarian.referral".to_string()].into(),
                now: 1_783_731_900,
                required_target_profile: None,
                required_verifier_section_hash: None,
                required_status_revision: None,
            },
        ),
        Err(ConsentError::InvalidVerifierSpec)
    );

    assert_eq!(
        verify_consent(
            &artifact,
            &keys,
            &spec(),
            &VerificationContext {
                subject: &subject,
                recipient: "referral-partner.example",
                required_purposes: &BTreeSet::new(),
                now: 1_783_731_900,
                required_target_profile: None,
                required_verifier_section_hash: None,
                required_status_revision: None,
            },
        ),
        Err(ConsentError::InvalidVerificationContext)
    );
}

#[test]
fn maximum_size_vector_exercises_every_field_cap_and_fits_compact_jws() {
    let (private, _) = keypair();
    let exact = ExactIdentifier {
        identifier_type: "t".repeat(64),
        value: "v".repeat(256),
    };
    let maximum = ConsentEvidenceV1 {
        version: 1,
        subject: exact.clone(),
        consenting_party: ConsentingParty {
            identifier: exact,
            relationship: ConsentingPartyRelationship::Self_,
        },
        purposes: (0..8)
            .map(|index| format!("{index}{}", "p".repeat(127)))
            .collect(),
        recipient: "r".repeat(256),
        controller: "c".repeat(256),
        assurance: ConsentAssurance::SystemOfRecordSigned,
        collection_method: "m".repeat(64),
        collection_context: "x".repeat(512),
        collected_at: 1,
        issued_at: 2,
        expires_at: i64::MAX,
        consent_id: "i".repeat(256),
        notice_reference: "n".repeat(256),
        notice_language: "a".repeat(35),
        notice_content_digest: format!("sha256:{}", "a".repeat(64)),
        notice_modality: NoticeModality::Interpreted,
        target_profile: Some(TargetProfileBinding {
            kind: TargetProfileBindingKind::ProfileId,
            value: "t".repeat(256),
        }),
        verifier_section_hash: Some(format!("sha256:{}", "b".repeat(64))),
        status_revision: Some("s".repeat(64)),
    };
    let artifact = maximum.sign_compact(&private).expect("maximum signs");
    assert_eq!(artifact.as_str().len(), 5_971);
    assert!(artifact.as_str().len() <= MAX_CONSENT_EVIDENCE_BYTES);

    let oversized = "a".repeat(MAX_CONSENT_EVIDENCE_BYTES + 1);
    assert_eq!(
        ConsentArtifact::parse(oversized).err(),
        Some(ConsentError::Malformed)
    );
}

#[test]
fn commitment_is_domain_separated_and_stable() {
    let (private, _) = keypair();
    let artifact = evidence().sign_compact(&private).expect("sign");
    assert_eq!(
        consent_evidence_commitment(
            b"01234567890123456789012345678901",
            "registry-relay:consent-evidence:v1",
            "humanitarian-referral-sor",
            &artifact,
        )
        .expect("commitment"),
        include_str!("fixtures/valid-ed25519.commitment").trim()
    );
}
