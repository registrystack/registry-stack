// SPDX-License-Identifier: Apache-2.0
//! Fixture generator for the SD-JWT VC verifier compatibility harness.
//!
//! Run with:
//!   cargo run -p xtask -- gen-sd-jwt-vc-fixtures
//!   cargo run -p xtask -- gen-oid4vci-algorithm-fixtures
//!
//! Writes synthetic fixtures to tests/fixtures/sd_jwt_vc/.
//! Keys and timestamps are fixed so the JWTs are reproducible, but
//! SdJwtIssuer generates random disclosure salts on each call, so re-running
//! this command will produce byte-for-byte different fixture files even though
//! the decoded credential content is functionally equivalent. Commit only when
//! the fixture content has materially changed.
//! All key material is throwaway and clearly marked as test-only.
//! Do not use any of the keys or tokens produced here outside of tests.

use std::collections::BTreeMap;
use std::path::PathBuf;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_platform_crypto::{did_jwk_from_public_jwk, sign, PrivateJwk};
use registry_platform_sdjwt::{Disclosure, HolderConfirmation, SdJwtIssuanceInput, SdJwtIssuer};
use serde_json::{json, Value};

// Deterministic synthetic key pairs. Generated once and hardcoded so fixtures
// are fully reproducible without a random source at generation time. These keys
// are test-only material and carry no trust outside of the fixture set.
const ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:fixture.test#key-1"}"#;
const ES256_ISSUER_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"did:web:fixture.test#p256-key-1"}"#;
const HOLDER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"f4QIxnAyRWzhuBOmNRgvBTE56mWePdsPL0mvCtl8Gys","x":"pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec","alg":"EdDSA","kid":"did:web:fixture.test#holder-key-1"}"#;

const ISSUER: &str = "did:web:fixture.test";
const VCT: &str = "https://fixture.test/credentials/registry-witness/v1";
// Fixed timestamp: 2024-01-15T00:00:00Z. Far enough in the future that the
// harness can override the verifier clock to match.
const IAT: i64 = 1_705_276_800;
const EXP: i64 = 1_705_276_800 + 3600;
const PROOF_AUDIENCE: &str = "https://fixture.test/oid4vci";
const PROOF_NONCE: &str = "fixture-transaction-nonce";

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    match cmd {
        "gen-sd-jwt-vc-fixtures" => generate_fixtures().await,
        "gen-oid4vci-algorithm-fixtures" => generate_algorithm_fixtures().await,
        _ => {
            eprintln!(
                "usage: cargo run -p xtask -- \
                 <gen-sd-jwt-vc-fixtures|gen-oid4vci-algorithm-fixtures>"
            );
            std::process::exit(1);
        }
    }
}

async fn generate_fixtures() {
    let workspace_root = workspace_root();
    let fixture_dir = workspace_root.join("tests/fixtures/sd_jwt_vc");
    std::fs::create_dir_all(&fixture_dir).expect("fixture dir created");

    let issuer_jwk = PrivateJwk::parse(ISSUER_JWK).expect("issuer jwk parses");
    let es256_issuer_jwk = PrivateJwk::parse(ES256_ISSUER_JWK).expect("ES256 issuer jwk parses");
    let holder_jwk = PrivateJwk::parse(HOLDER_JWK).expect("holder jwk parses");
    let issuer = SdJwtIssuer::from_jwk(issuer_jwk.clone()).expect("issuer builds");
    let holder_did = did_jwk_from_public_jwk(&holder_jwk.public()).expect("holder did encodes");

    // Write the public issuer JWKS so the harness can load it without
    // embedding raw key material.
    let public_jwk = serde_json::to_value(issuer_jwk.public()).expect("public jwk serialises");
    let es256_public_jwk =
        serde_json::to_value(es256_issuer_jwk.public()).expect("ES256 public jwk serialises");
    let jwks = json!({ "keys": [public_jwk, es256_public_jwk] });
    write_fixture(
        &fixture_dir,
        "issuer-jwks.json",
        &serde_json::to_string_pretty(&jwks).expect("jwks serialises"),
    );

    // Write fixture metadata so the harness knows constants without embedding
    // them as Rust literals.
    let meta = json!({
        "issuer": ISSUER,
        "vct": VCT,
        "iat": IAT,
        "exp": EXP,
        "holder_did": holder_did,
        "key_id": "did:web:fixture.test#key-1",
        "es256_key_id": "did:web:fixture.test#p256-key-1",
        "note": "All key material in this directory is synthetic test-only material. Do not use outside tests."
    });
    write_fixture(
        &fixture_dir,
        "meta.json",
        &serde_json::to_string_pretty(&meta).expect("meta serialises"),
    );

    // 1. Valid credential (positive fixture).
    let valid = issue(
        &issuer,
        ISSUER,
        IAT,
        EXP,
        None,
        &["claim_a", "claim_b"],
        None,
    )
    .await;
    write_fixture(&fixture_dir, "valid.sd-jwt", &valid);

    // 2. Valid holder-bound credential (positive fixture).
    let valid_holder_bound = issue(
        &issuer,
        ISSUER,
        IAT,
        EXP,
        Some((&holder_did, &holder_jwk)),
        &["claim_a"],
        None,
    )
    .await;
    write_fixture(
        &fixture_dir,
        "valid-holder-bound.sd-jwt",
        &valid_holder_bound,
    );

    // Write holder JWK (public) for the harness.
    let holder_public =
        serde_json::to_value(holder_jwk.public()).expect("holder public serialises");
    write_fixture(
        &fixture_dir,
        "holder-public-jwk.json",
        &serde_json::to_string_pretty(&holder_public).expect("holder public serialises"),
    );

    // 3. Wrong vct: issued with a different vct, harness checks vct_mismatch.
    let wrong_vct = issue(
        &issuer,
        ISSUER,
        IAT,
        EXP,
        None,
        &["claim_a"],
        Some("https://fixture.test/credentials/other-profile/v1"),
    )
    .await;
    write_fixture(&fixture_dir, "wrong-vct.sd-jwt", &wrong_vct);

    // 4. Expired credential: exp is in the past relative to iat.
    let expired = issue(
        &issuer,
        ISSUER,
        IAT - 7200,
        IAT - 3600,
        None,
        &["claim_a"],
        None,
    )
    .await;
    write_fixture(&fixture_dir, "expired.sd-jwt", &expired);

    // 5. Unsupported alg: rewrite the header alg to RS256 (breaks signature
    //    and triggers algorithm.disallowed before the sig check).
    let valid_raw = issue(&issuer, ISSUER, IAT, EXP, None, &["claim_a"], None).await;
    let bad_alg = tamper_header(&valid_raw, |h| {
        h["alg"] = json!("RS256");
    });
    write_fixture(&fixture_dir, "unsupported-alg.sd-jwt", &bad_alg);

    // 6. Wrong kid: rewrite the header kid to a key that does not exist in JWKS.
    let bad_kid = tamper_header(&valid_raw, |h| {
        h["kid"] = json!("did:web:fixture.test#missing");
    });
    write_fixture(&fixture_dir, "wrong-kid.sd-jwt", &bad_kid);

    // 7. Missing cnf: use a credential issued without holder binding, then
    //    verify with RequiredKid — harness expects holder_binding.required.
    //    The file itself is the same as valid.sd-jwt; the harness applies the
    //    policy. Write a copy so the intent is explicit.
    write_fixture(
        &fixture_dir,
        "missing-cnf-when-binding-required.sd-jwt",
        &valid,
    );

    // 8. Malformed disclosure: corrupt the last disclosure segment so that
    //    base64url decoding fails. The verifier maps this parse failure to
    //    disclosure.digest_mismatch (the hash-comparison branch is never
    //    reached because the disclosure cannot even be decoded).
    let malformed_disc = tamper_last_disclosure(&valid_raw);
    write_fixture(&fixture_dir, "malformed-disclosure.sd-jwt", &malformed_disc);

    // 9. Tampered disclosure: the disclosure is valid base64url-encoded JSON
    //    with three elements (salt, claim name, value), so it passes the parse
    //    checks, but the claim value has been altered so its SHA-256 digest is
    //    not present in the payload _sd array. This exercises the actual
    //    hash-comparison branch in the verifier, which is distinct from the
    //    parse-failure path covered by malformed-disclosure.sd-jwt.
    let tampered_disc = tamper_disclosure_value(&valid_raw);
    write_fixture(&fixture_dir, "tampered-disclosure.sd-jwt", &tampered_disc);

    // 10. Holder proof mismatch: valid holder-bound credential but the
    //     key-binding JWT is signed by the wrong key (the issuer key instead of
    //     the holder key). The harness expects holder_binding.proof_invalid.
    let bad_kb = format!(
        "{valid_holder_bound}{}",
        bad_key_binding_jwt(&issuer_jwk, IAT)
    );
    write_fixture(&fixture_dir, "holder-proof-mismatch.sd-jwt", &bad_kb);

    generate_algorithm_fixtures().await;
    println!("fixtures written to {}", fixture_dir.display());
}

/// Generate only the deterministic fixtures for the narrowed Registry Stack
/// 1.0 algorithm profile. Keeping this command separate avoids rewriting the
/// older disclosure fixtures, whose random salts are intentionally not stable.
async fn generate_algorithm_fixtures() {
    let fixture_dir = workspace_root().join("tests/fixtures/sd_jwt_vc");
    std::fs::create_dir_all(&fixture_dir).expect("fixture dir created");

    let es256_issuer_jwk = PrivateJwk::parse(ES256_ISSUER_JWK).expect("ES256 issuer jwk parses");
    let es256_issuer =
        SdJwtIssuer::from_jwk(es256_issuer_jwk.clone()).expect("ES256 issuer builds");
    let holder_jwk = PrivateJwk::parse(HOLDER_JWK).expect("holder jwk parses");
    let holder_did = did_jwk_from_public_jwk(&holder_jwk.public()).expect("holder did encodes");

    // These private keys are synthetic test material already embedded in this
    // generator. Publishing them as fixtures lets the transaction harness
    // exercise the same exact key pairs without duplicating constants.
    for (name, raw) in [
        ("issuer-eddsa-private.test.jwk.json", ISSUER_JWK),
        ("issuer-es256-private.test.jwk.json", ES256_ISSUER_JWK),
        ("holder-eddsa-private.test.jwk.json", HOLDER_JWK),
    ] {
        let key: Value = serde_json::from_str(raw).expect("private fixture JWK parses as JSON");
        write_fixture(
            &fixture_dir,
            name,
            &serde_json::to_string_pretty(&key).expect("private fixture JWK serialises"),
        );
    }

    // No selective disclosures are needed for this fixture. That keeps the
    // compact credential byte-for-byte reproducible while still exercising
    // issuer signing, cnf holder binding, and verifier algorithm dispatch.
    let valid_es256 = issue(
        &es256_issuer,
        ISSUER,
        IAT,
        EXP,
        Some((&holder_did, &holder_jwk)),
        &[],
        None,
    )
    .await;
    write_fixture(&fixture_dir, "valid-es256.sd-jwt", &valid_es256);

    let holder_proof = oid4vci_proof_jwt(&holder_jwk, "EdDSA", &holder_did);
    write_fixture(&fixture_dir, "holder-proof-eddsa.jwt", &holder_proof);

    let es256_holder_jwk =
        PrivateJwk::parse(ES256_ISSUER_JWK).expect("ES256 holder fixture key parses");
    // The platform intentionally refuses to construct an ES256 holder DID.
    // Encode the synthetic public key directly so the negative fixture proves
    // that the credential-endpoint validator rejects this out-of-profile proof.
    let es256_holder_did = format!(
        "did:jwk:{}",
        URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&es256_holder_jwk.public())
                .expect("ES256 holder public JWK serialises")
        )
    );
    let unsupported_holder_proof = oid4vci_proof_jwt(&es256_holder_jwk, "ES256", &es256_holder_did);
    write_fixture(
        &fixture_dir,
        "holder-proof-es256-unsupported.jwt",
        &unsupported_holder_proof,
    );

    let profile = json!({
        "credential_configurations": {
            "fixture_eddsa": {
                "credential_signing_alg_values_supported": ["EdDSA"],
                "proof_signing_alg_values_supported": ["EdDSA"],
                "cryptographic_binding_methods_supported": ["did:jwk"],
                "fixture": "valid-holder-bound.sd-jwt",
                "private_jwk_fixture": "issuer-eddsa-private.test.jwk.json"
            },
            "fixture_es256": {
                "credential_signing_alg_values_supported": ["ES256"],
                "proof_signing_alg_values_supported": ["EdDSA"],
                "cryptographic_binding_methods_supported": ["did:jwk"],
                "fixture": "valid-es256.sd-jwt",
                "private_jwk_fixture": "issuer-es256-private.test.jwk.json"
            }
        },
        "holder_proof": {
            "signing_alg_values_supported": ["EdDSA"],
            "cryptographic_binding_methods_supported": ["did:jwk"],
            "fixture": "holder-proof-eddsa.jwt",
            "private_jwk_fixture": "holder-eddsa-private.test.jwk.json",
            "unsupported_fixture": "holder-proof-es256-unsupported.jwt"
        },
        "proof_audience": PROOF_AUDIENCE,
        "proof_nonce": PROOF_NONCE,
        "note": "All key and token material is synthetic test-only material. Do not use outside tests."
    });
    write_fixture(
        &fixture_dir,
        "algorithm-profile.json",
        &serde_json::to_string_pretty(&profile).expect("algorithm profile serialises"),
    );

    println!("algorithm fixtures written to {}", fixture_dir.display());
}

async fn issue(
    issuer: &SdJwtIssuer,
    iss: &str,
    iat: i64,
    exp: i64,
    holder: Option<(&str, &PrivateJwk)>,
    claim_names: &[&str],
    vct_override: Option<&str>,
) -> String {
    let vct = vct_override.unwrap_or(VCT).to_string();
    let cnf = holder.map(|(kid, jwk)| HolderConfirmation {
        jwk: jwk.public(),
        kid: Some(kid.to_string()),
    });
    let input = SdJwtIssuanceInput {
        iss: iss.to_string(),
        sub_ref: holder
            .map(|(kid, _)| kid.to_string())
            .unwrap_or_else(|| "subject-ref".to_string()),
        credential_id: Some("urn:ulid:01HG0000000000000000000000".to_string()),
        iat,
        exp,
        vct,
        status: None,
        public_claims: BTreeMap::new(),
        cnf,
        disclosures: claim_names
            .iter()
            .map(|name| Disclosure {
                name: name.to_string(),
                value: json!({"satisfied": true, "value": "fixture"}),
            })
            .collect(),
    };
    issuer.issue(input).await.expect("fixture issues").jwt
}

fn tamper_header(compact: &str, mutate: impl FnOnce(&mut Value)) -> String {
    let (jwt, suffix) = compact
        .split_once('~')
        .expect("sd-jwt has disclosure separator");
    let mut parts: Vec<&str> = jwt.split('.').collect();
    let mut header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[0])
            .expect("header base64 decodes"),
    )
    .expect("header json decodes");
    mutate(&mut header);
    let new_header =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header serialises"));
    let new_header_owned = new_header.clone();
    parts[0] = &new_header_owned;
    // We need owned strings here since parts holds &str into jwt.
    let new_jwt = format!("{}.{}.{}", new_header, parts[1], parts[2]);
    format!("{new_jwt}~{suffix}")
}

fn tamper_last_disclosure(compact: &str) -> String {
    let mut parts: Vec<&str> = compact.split('~').collect();
    // Find last non-empty disclosure part (before trailing empty from trailing ~)
    let last_disc_idx = parts
        .iter()
        .enumerate()
        .filter(|(_, p)| !p.is_empty() && !p.contains('.'))
        .map(|(i, _)| i)
        .next_back()
        .expect("has disclosure");
    let mut disc = parts[last_disc_idx].to_string();
    // Flip the last character to corrupt the base64.
    let replacement = if disc.ends_with('A') { "B" } else { "A" };
    disc.pop();
    disc.push_str(replacement);
    let disc_owned = disc.clone();
    parts[last_disc_idx] = &disc_owned;
    parts.join("~")
}

/// Re-encode the first disclosure in an SD-JWT compact form with an altered
/// claim value. The resulting disclosure is valid base64url-encoded JSON with
/// three elements, so the verifier passes the parse checks and reaches the
/// hash-comparison step, where it discovers the disclosure digest is not in
/// the payload _sd array and returns disclosure.digest_mismatch.
fn tamper_disclosure_value(compact: &str) -> String {
    let parts: Vec<&str> = compact.split('~').collect();
    // parts[0] is the issuer JWT; parts[1..] are disclosures (last may be empty).
    let first_disc_raw = parts
        .iter()
        .skip(1)
        .find(|p| !p.is_empty() && !p.contains('.'))
        .expect("at least one disclosure");

    // Decode, mutate the value (third element), and re-encode.
    let decoded = URL_SAFE_NO_PAD
        .decode(first_disc_raw)
        .expect("disclosure base64 decodes");
    let mut arr: Vec<serde_json::Value> =
        serde_json::from_slice(&decoded).expect("disclosure json decodes");
    // arr[0] = salt (keep), arr[1] = claim name (keep), arr[2] = value (tamper).
    arr[2] = json!({"satisfied": false, "value": "tampered"});
    let new_bytes = serde_json::to_vec(&arr).expect("tampered disclosure serialises");
    let new_disc = URL_SAFE_NO_PAD.encode(&new_bytes);

    // Rebuild the compact form with the tampered first disclosure.
    let mut new_parts: Vec<String> = parts.iter().map(|p| p.to_string()).collect();
    for p in new_parts.iter_mut().skip(1) {
        if !p.is_empty() && !p.contains('.') {
            *p = new_disc.clone();
            break;
        }
    }
    new_parts.join("~")
}

/// Produce a key-binding JWT signed with the wrong key (issuer key instead of
/// holder key). The harness verifies this fails with holder_binding.proof_invalid.
fn bad_key_binding_jwt(wrong_key: &PrivateJwk, iat: i64) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"kb+jwt"}"#);
    let payload_json = format!(r#"{{"iat":{iat}}}"#);
    let payload = URL_SAFE_NO_PAD.encode(payload_json.as_bytes());
    let signing_input = format!("{header}.{payload}");
    let signature = sign(signing_input.as_bytes(), wrong_key).expect("bad kb jwt signs");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn oid4vci_proof_jwt(key: &PrivateJwk, alg: &str, holder_did: &str) -> String {
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": alg,
            "typ": "openid4vci-proof+jwt",
            "kid": format!("{holder_did}#0")
        }))
        .expect("proof header serialises"),
    );
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "aud": PROOF_AUDIENCE,
            "iat": IAT,
            "exp": IAT + 300,
            "nonce": PROOF_NONCE
        }))
        .expect("proof payload serialises"),
    );
    let signing_input = format!("{header}.{payload}");
    let signature = sign(signing_input.as_bytes(), key).expect("proof signs");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn write_fixture(dir: &std::path::Path, name: &str, content: &str) {
    let path = dir.join(name);
    std::fs::write(&path, content).expect("fixture write succeeds");
    println!("  wrote {}", path.display());
}

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is xtask/; workspace root is one level up.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("workspace root is parent of xtask")
        .to_path_buf()
}
