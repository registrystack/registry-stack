// SPDX-License-Identifier: Apache-2.0

use registry_payment_mifos_connector::{
    build_batch_request, legacy_batch_request_signature_digest, legacy_signature_digest,
    legacy_signature_preimage, BatchCommand, ExactMoney, LegacySignatureDigest,
    LegacySignatureError, LegacySignatureFuture, LegacySignatureHeaders, LegacyWebSignatureSigner,
    LegacyWebSignatureVerifier, PartyIdentifier, SecretHeader, LEGACY_WEB_SIGNATURE_PROFILE,
};

const JAVA_17_DIGEST: &str = "b87417754485eba4f5d1bb206f0e8358a6bc678ea75343d7baf25ecfd5187bff";
const JAVA_17_SIGNATURE: &str = "nrNse2Cxxd0nvvTqHx9jWudZrS6SoZtBQom2nK4thmguBznaq0xv1Hi+4LJyt1USy1LM7NvJ3qPf+XASfsPYx1sR6jUhqvCaoEcAjrTBantFj94T0hpopuHLyaI+lO+ALct2okH4qsgcJt6tx7si3sgrQGBPy/vVzNE4XQNLgfFSlC7CJO2sgmW09RpdHiasJfOWuTIacLDwtU+TktCM+pbOkrhwyXddbw/9v7YJITGkLHKUXW63+Osw5vymXBgjZNzUELjUzlQHBscWqFeAwD3JOq7UlQGQ1mdAoNcJwNcbhrULXhjHdHg/JrMIofuiOzwj8Ixw0PGW+gQwlncLkg==";
const JAVA_17_PUBLIC_KEY_DER_BASE64: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuN/Zn65A4aySYv8BsStT2cHbVJTuOZtyfHrplIhdtTp6jjFZ1KGsVvZpbih77yPukQS2nSdgUsyos/r/4DM28Dv6mnun1geQNySYFUwoqyUWoPxTjf1NTI/PDFGhWTxFiAydxS8GPswdLi6Hnaw+sskZFrsNh/9l/zUeUk6/7eFNZDPg0WQNLzpfQgJWm31p6yZuWq6Iv12x1EXeHaxqOL6rIZQm5lc95k2RZ0sZIlcI+8/kczx2OxdN2qYkrx4ZBa8Xt9mWvDMGIPOUGEtEVVRC32YarPZnShgFdDhRXL5eoSWC4nVUAseIuDnW1X8mLL5QkeQeFDqAWbWAVJY3swIDAQAB";

fn batch() -> BatchCommand {
    BatchCommand {
        correlation_id: "batch-request-1".into(),
        purpose: "social-transfer".into(),
        credit_party: vec![PartyIdentifier {
            key: "MSISDN".into(),
            value: "254700000002".into(),
        }],
        debit_party: vec![PartyIdentifier {
            key: "ACCOUNTID".into(),
            value: "programme-account".into(),
        }],
        sub_type: "TRANSFER".into(),
        money: ExactMoney {
            amount: "1000.00".into(),
            currency: "KES".into(),
        },
        description_text: "cycle-2026-11".into(),
        registering_institution_id: None,
        program_id: None,
        callback_url: None,
    }
}

#[test]
fn released_header_order_skips_absent_values_and_preserves_exact_body() {
    let body = br#"[{"amount":"1000.00"}]"#;
    let request = legacy_signature_preimage(
        LegacySignatureHeaders::bulk_request("batch-request-1", "pilot"),
        body,
    )
    .unwrap();
    assert_eq!(
        request.as_bytes(),
        br#"batch-request-1:pilot:[{"amount":"1000.00"}]"#
    );

    let with_batch = legacy_signature_preimage(
        LegacySignatureHeaders::response(
            Some("provider-batch-1"),
            Some("batch-request-1"),
            "pilot",
        ),
        body,
    )
    .unwrap();
    assert_eq!(
        with_batch.as_bytes(),
        br#"provider-batch-1:batch-request-1:pilot:[{"amount":"1000.00"}]"#
    );
}

#[test]
fn response_preimage_uses_only_headers_the_released_server_returned() {
    let response = legacy_signature_preimage(
        LegacySignatureHeaders::response(None, None, "pilot"),
        br#"{"batch_id":"provider-batch-1"}"#,
    )
    .unwrap();
    assert_eq!(
        response.as_bytes(),
        br#"pilot:{"batch_id":"provider-batch-1"}"#
    );
}

#[test]
fn empty_body_removes_the_last_separator_like_connector_common_v1_8_1() {
    let preimage = legacy_signature_preimage(
        LegacySignatureHeaders::bulk_request("batch-request-1", "pilot"),
        b"",
    )
    .unwrap();
    assert_eq!(preimage.as_bytes(), b"batch-request-1:pilot");
}

#[test]
fn malformed_or_unbounded_inputs_fail_closed() {
    assert!(legacy_signature_preimage(LegacySignatureHeaders::empty(), b"").is_err());
    assert!(legacy_signature_preimage(
        LegacySignatureHeaders::response(None, None, "pilot"),
        &[0xff]
    )
    .is_err());
    assert!(legacy_signature_preimage(
        LegacySignatureHeaders::response(None, None, "pilot\nforged"),
        b"{}"
    )
    .is_err());
    assert!(legacy_signature_preimage(
        LegacySignatureHeaders::response(None, None, "pilot"),
        &vec![b'x'; 65_537]
    )
    .is_err());
}

#[test]
fn exact_body_bytes_are_part_of_the_digest() {
    let headers = LegacySignatureHeaders::bulk_request("batch-request-1", "pilot");
    let compact = legacy_signature_digest(headers, br#"{"amount":"1000.00"}"#).unwrap();
    let spaced = legacy_signature_digest(headers, br#"{ "amount": "1000.00" }"#).unwrap();
    assert_ne!(compact.as_bytes(), spaced.as_bytes());
}

#[test]
fn batch_helper_refuses_bytes_other_than_the_validated_command_encoding() {
    let command = batch();
    let body = build_batch_request(&command).unwrap();
    assert!(legacy_batch_request_signature_digest(&command, "pilot", &body).is_ok());
    let changed = String::from_utf8(body)
        .unwrap()
        .replace("1000.00", "1000.01");
    assert!(legacy_batch_request_signature_digest(&command, "pilot", changed.as_bytes()).is_err());
}

/// Generated with Temurin OpenJDK 17.0.20 using the released Java sequence:
/// SHA3-256 UTF-8 input, lowercase hex, then `Cipher.getInstance("RSA")`
/// over a synthetic 2048-bit PKCS#8 key. It is an interoperability vector,
/// not a deployed key or proof of a deployed Payment Hub image.
#[tokio::test]
async fn java_17_vector_reaches_the_typed_legacy_signer_and_verifier() {
    assert_eq!(
        LEGACY_WEB_SIGNATURE_PROFILE,
        "ph-ee-connector-common/v1.8.1:rsa-cipher-sha3-256/v1"
    );
    let command = batch();
    let body = build_batch_request(&command).unwrap();
    let digest = legacy_batch_request_signature_digest(&command, "pilot", &body).unwrap();
    assert_eq!(digest.as_str(), JAVA_17_DIGEST);
    assert!(JAVA_17_PUBLIC_KEY_DER_BASE64.starts_with("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"));

    let signer = JavaVectorProvider;
    let signature = signer.sign_digest_hex(&digest).await.unwrap();
    signer
        .verify_digest_hex(&digest, signature.as_bytes())
        .await
        .unwrap();
}

struct JavaVectorProvider;

impl LegacyWebSignatureSigner for JavaVectorProvider {
    fn sign_digest_hex<'a>(
        &'a self,
        digest: &'a LegacySignatureDigest,
    ) -> LegacySignatureFuture<'a, SecretHeader> {
        Box::pin(async move {
            if digest.as_str() != JAVA_17_DIGEST {
                return Err(LegacySignatureError::Refused);
            }
            SecretHeader::new(JAVA_17_SIGNATURE).map_err(|_| LegacySignatureError::Refused)
        })
    }
}

impl LegacyWebSignatureVerifier for JavaVectorProvider {
    fn verify_digest_hex<'a>(
        &'a self,
        digest: &'a LegacySignatureDigest,
        signature: &'a [u8],
    ) -> LegacySignatureFuture<'a, ()> {
        Box::pin(async move {
            if digest.as_str() == JAVA_17_DIGEST && signature == JAVA_17_SIGNATURE.as_bytes() {
                Ok(())
            } else {
                Err(LegacySignatureError::Mismatch)
            }
        })
    }
}
