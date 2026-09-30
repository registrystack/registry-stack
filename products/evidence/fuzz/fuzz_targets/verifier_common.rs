//! Shared fixture setup for the two verifier fuzz targets.
//!
//! The targets sign inputs with the same ES256 test key the verifier's own
//! tests use, so verification reaches the payload contract and policy stages
//! behind the signature check instead of stopping at it. The startup round-trip check fails loudly the day this canonical
//! assertion no longer verifies, because silent drift would hollow out both
//! targets while they kept reporting clean runs.

use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Utc};
use registry_evidence_verifier::{
    fixtures::{jwks_document, EvidenceSigner},
    model::{
        Evidence, EvidenceObjectType, JwksDocument, PublicValue, SubjectBinding,
        SubjectBindingMode, SupportedValue,
    },
    verifier::{verify_flattened_jws, EvidenceVerificationPolicy},
    AssuranceProfile, EVIDENCE_SCHEMA_V1,
};
use registry_platform_crypto::{LocalJwkSigner, PrivateJwk, SigningProvider};

// The P-256 test key the verifier crate's own tests sign with. Its key
// identifier is the canonical SHA-256 thumbprint the protected header must
// carry.
const PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#;
const KEY_ID: &str = "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo";

// The request nonce the verifier crate's own round-trip fixture carries.
const CANONICAL_NONCE: &str = "r1N1mq48U3PpZ5keuZEgmA5KMC2KDrF1hT6640koy6I";

/// The instant the fixture policy verifies at: inside the canonical
/// assertion's validity window.
const VERIFY_AT: &str = "2026-08-02T12:00:00Z";

pub struct VerifierFixture {
    pub signer: EvidenceSigner,
    pub jwks: JwksDocument,
    pub policy: EvidenceVerificationPolicy,
}

pub fn fixture() -> &'static VerifierFixture {
    static FIXTURE: OnceLock<VerifierFixture> = OnceLock::new();
    FIXTURE.get_or_init(|| {
        let canonical = canonical_evidence();
        let now: DateTime<Utc> = VERIFY_AT.parse().expect("verification instant parses");
        let private = PrivateJwk::parse(PRIVATE_JWK).expect("test key parses");
        let provider: Arc<dyn SigningProvider> =
            Arc::new(LocalJwkSigner::new(private).expect("test signer builds"));
        let signer = runtime()
            .block_on(EvidenceSigner::initialize(provider, KEY_ID))
            .expect("fixture signer initializes");
        let jwks = jwks_document(signer.public_jwk(), []).expect("fixture JWKS builds");
        let policy = EvidenceVerificationPolicy::from_accepted_transaction(
            &canonical,
            canonical
                .request_nonce
                .as_deref()
                .expect("canonical evidence carries a nonce"),
            48 * 60 * 60,
            now,
            30,
        )
        .expect("fixture policy states bounds the contract allows");

        // Drift guard: if the canonical assertion stops verifying, every
        // later input would fail before the stages this target exists to
        // reach. Fail at startup instead of fuzzing a hollow surface.
        let jws = runtime()
            .block_on(signer.sign_json(&canonical))
            .expect("canonical evidence signs");
        let serialized = serde_json::to_vec(&jws).expect("canonical JWS serializes");
        verify_flattened_jws(&serialized, &jwks, &policy)
            .expect("canonical assertion still verifies; the fuzz fixture drifted");

        VerifierFixture {
            signer,
            jwks,
            policy,
        }
    })
}

pub fn canonical_evidence() -> Evidence {
    Evidence {
        schema: EVIDENCE_SCHEMA_V1.to_owned(),
        assurance_profile: AssuranceProfile::EvidenceGrade,
        subject_binding: SubjectBindingMode::AudienceScoped,
        request_nonce: Some(CANONICAL_NONCE.to_owned()),
        id: "urn:ulid:01K1EXAMPLE0000000000000000".to_owned(),
        evidence_type_name: EvidenceObjectType::Evidence,
        supports_requirement: "urn:example:requirement:v1".to_owned(),
        is_conformant_to: "urn:example:type:v1".to_owned(),
        issued_by: "urn:example:issuer".to_owned(),
        provided_by: "urn:example:provider".to_owned(),
        issued_at: "2026-08-02T00:00:00Z".to_owned(),
        observed_at: "2026-08-02T00:00:00Z".to_owned(),
        valid_until: "2026-08-03T00:00:00Z".to_owned(),
        purpose: "casework".to_owned(),
        audience: Some("urn:example:audience".to_owned()),
        configuration_revision: format!("sha256:{}", "0".repeat(64)),
        subjects: vec![SubjectBinding {
            role: "subject".to_owned(),
            binding: format!("urn:evidence:subject:v1_{}", "A".repeat(43)),
        }],
        supported_values: vec![SupportedValue {
            provides_value_for: "urn:example:concept".to_owned(),
            value: PublicValue::Boolean(false),
        }],
    }
}

/// Interpret the input as a bounded Evidence payload, or leave it as raw
/// untrusted bytes for the parsing stages to reject.
pub fn parse_bounded_evidence(data: &[u8]) -> Option<Evidence> {
    let text = std::str::from_utf8(data).ok()?;
    serde_json::from_str(&take_chars(text, 8192)).ok()
}

pub fn runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("fuzz runtime builds")
    })
}

pub fn take_chars(input: &str, limit: usize) -> String {
    input.chars().take(limit).collect()
}
