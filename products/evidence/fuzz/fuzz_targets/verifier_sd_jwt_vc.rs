#![no_main]

//! SD-JWT VC response verification: the compact serialization split, the
//! issuer-signed credential check, complete disclosure resolution, the
//! rebuilt payload contract, and the policy comparison
//! (`registry-evidence-verifier`).

mod verifier_common;

use std::collections::BTreeMap;
use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use registry_evidence_verifier::{
    model::{HolderPublicKey, SubjectBindingMode},
    sdjwt_vc::issuance_input,
    verifier::{verify_sd_jwt_vc, verify_sd_jwt_vc_report},
};
use verifier_common::{canonical_evidence, fixture, parse_bounded_evidence, runtime};

// Test-only holder key: the P-256 generator point, a published constant that
// belongs to nobody and the same point the Evidence runtime's offline
// evaluation confirms. It is deliberately distinct from the issuer key the
// fixture signs with, so a confirmation never coincides with the issuer's own
// key.
fn holder_key() -> HolderPublicKey {
    HolderPublicKey {
        kty: "EC".to_owned(),
        crv: "P-256".to_owned(),
        x: "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY".to_owned(),
        y: "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU".to_owned(),
        alg: Some("ES256".to_owned()),
        kid: Some("holder-1".to_owned()),
    }
}

fn startup_round_trip(fixture: &verifier_common::VerifierFixture) {
    // An unacceptable holder key would be refused before signing, and every
    // holder-bound input would silently stop reaching a signature.
    assert!(
        holder_key().is_acceptable(),
        "the test holder key is an acceptable P-256 key; the fuzz fixture drifted"
    );
    let input = issuance_input(&canonical_evidence(), None, &BTreeMap::new())
        .expect("canonical evidence maps to an issuance input");
    let serialized = runtime()
        .block_on(fixture.signer.sign_sd_jwt_vc(input))
        .expect("canonical SD-JWT VC serializes");
    verify_sd_jwt_vc(serialized.as_bytes(), &fixture.jwks, &fixture.policy)
        .expect("canonical SD-JWT VC still verifies; the fuzz fixture drifted");
}

fuzz_target!(|data: &[u8]| {
    let fixture = fixture();
    static ROUND_TRIP: OnceLock<()> = OnceLock::new();
    ROUND_TRIP.get_or_init(|| startup_round_trip(fixture));

    let serialized = match parse_bounded_evidence(data) {
        Some(evidence) => {
            // Holder-bound inputs confirm the test holder key and
            // audience-scoped inputs carry no confirmation, so both the
            // confirmed and unconfirmed credential shapes are exercised.
            let holder = matches!(evidence.subject_binding, SubjectBindingMode::HolderBound)
                .then(holder_key);
            match issuance_input(&evidence, holder.as_ref(), &BTreeMap::new()) {
                Ok(input) => match runtime().block_on(fixture.signer.sign_sd_jwt_vc(input)) {
                    Ok(serialized) => serialized.into_bytes(),
                    Err(_) => data.to_vec(),
                },
                // Evidence whose binding mode disagrees with its members is
                // refused before signing; verify it as raw bytes instead.
                Err(_) => data.to_vec(),
            }
        }
        None => data.to_vec(),
    };
    let _ = verify_sd_jwt_vc_report(&serialized, &fixture.jwks, &fixture.policy);
});
