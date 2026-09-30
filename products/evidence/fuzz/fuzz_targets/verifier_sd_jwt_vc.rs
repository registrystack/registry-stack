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
    model::HolderPublicKey,
    sdjwt_vc::issuance_input,
    verifier::{verify_sd_jwt_vc, verify_sd_jwt_vc_report},
};
use verifier_common::{canonical_evidence, fixture, parse_bounded_evidence, runtime};

fn holder_key() -> HolderPublicKey {
    HolderPublicKey {
        kty: "EC".to_owned(),
        crv: "P-256".to_owned(),
        x: "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4".to_owned(),
        y: "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU".to_owned(),
        alg: Some("ES256".to_owned()),
        kid: Some("holder-1".to_owned()),
    }
}

fn startup_round_trip(fixture: &verifier_common::VerifierFixture) {
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
            // Half the inputs confirm a holder key, so both the confirmed and
            // unconfirmed credential shapes are exercised.
            let holder = (data.first().copied().unwrap_or_default() % 2 == 0).then(holder_key);
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
