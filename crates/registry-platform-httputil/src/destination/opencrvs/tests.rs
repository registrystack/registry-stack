use std::marker::PhantomData;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use registry_platform_crypto::{sign, PrivateJwk};
use serde_json::{json, Value};

use super::*;
use crate::destination::json::{
    ClosedJsonField, ClosedJsonRecordRoot, ClosedJsonSchema, ProjectedJsonScalar,
};

const MESSAGE_ID: &str = "01JZ0000000000000000000000";
const SENDER_ID: &str = "registry-relay";
const RECEIVER_ID: &str = "opencrvs-farajaland";
const EXPECTED_UIN: &str = "1234567890";
const SIGNING_KID: &str = "opencrvs-signing-key";
const CORRELATION_ID: &str = "123e4567-e89b-42d3-a456-426614174000";

// Test-only 2048-bit RSA private JWK copied from the platform crypto RS256
// vectors. It was generated solely for deterministic offline tests.
const RSA_JWK: &str = r#"{"kty":"RSA","kid":"registry-notary-rs256-test","alg":"RS256","n":"yIgEn3IXWI3CRyUY0gvZ-kJ55EC36MRFvj-ICsitN1-50phRS4CKMBRwbHwjgeTkbMDndOCmVfIbyKhJjOMIPxAzIHeMn9oWj5i-s8nlSgjHZpvCTnRbwZhbq6mEVoHJliX36IfV_iUopcwSL5lPd2wZmJ-msUmZFs6CTRExu0JGUJScOwFO5dqxBwiKyh7yGEPXI3u4tc3_47SZYxyde7fb-o3wl2RBJ28upa2jVRP9r-WjOGjE6tbZ35HnVUY4ECdYWzsiotg_XA9QVWa-pAKXV2Flr-gocCQ9E2qrSYjEbNXuFjPtMnuL6AHi0o5PiwT1dllcl925hpKd7Xt60w","e":"AQAB","d":"ATDtMhpe_z1-GTUV7NLO3V_Z0kb8W1YXkC7JbJTAdcE-FdKJrtu84Q87WpxG0tPcutFPLqW12QAQp2fbmxhZ6VrfVYneeOlEjO14ukqM_g35Z-eRDmYhwoFYrEWGqlH9XrZysHhKFZyKHW_G0lJV-Ks8Na_RFNNIXeVedVMQiytAFXibTHvdAdIrBGtt0M4tlQOCeRwnuoAQU-a5VB7rKGpxnJtUA7F_jjeX6jQPnUhkOXs20pPRey-i-jxwBbsF4XijHgTnGwAo5uOoY9b0kOmOb3Hs5TVqZCb3a4JoYAqZBbWrkKxccJTGMqLHCe0MBgQzKqP5KyrHRgQdzlmTnQ","p":"5xhkHe5lD7tUYJAFffHiRpy4unHfKDvTEASu8RBgWvHP2Hu5XLQU5n6DvI47LsW42swTcT6Ce1pWB2LK3SjKcw9FPEEGg8m5-tmfixaRq4DBaK0hj17763HmnYR0eQC0n_5y-My8WSC1y80T-AhKHJ_3xTtLXQd5Z9bf9MEiKS8","q":"3iRoiwbnn8oRJMjZUZhqKB-GVa7AJV0SUqXiUsBAJnqtbhuIESbkJKpt5eULeUQgdNkoG65KD-jXFUipWX1zlentc1FliCaB46jntqtxUsui8LNwKw_eb3nujQO7H1He4NJ5pfaLfRcmBOLwB-u2Z1cxrRDWhIgiHtGaAdQ7F50","dp":"j4h9vn1wNbozaRpq3tPap-L1dY_-e93UdPGDuuRiBHqGjr4h3itXg-X2aqmopp9V9kekl8SshHMSVdoNiBmqzJYieY8lvbsQkXaTem8VIQGCn0JRQtxK-eyvwQwgz3sZtPn0bQW0wmLnp2KD0Z1McsUEvnLalzhqNo2mYj2Guy8","dq":"0T6ySuLCIz2PUHrwWW-b7xdizirBS3CT5c3jldcJljVQT7sXPDDKDc-LnVVWrW-Csw4qPYi6sqm8j4vWGTmWOswSouE1Jj4_c1aSjPqI0FiIrvoW2jkkaRUNoz60cBgKPPOFKtNFKRs48LljJ9LcChOT81U8-7HPkgAVdUuYLfE","qi":"PnMeCE0dvWDLp2Dn1wsxtl-a0qjpkT9cp8EkvHYjCvVqqWqrVv84CoEo-1wA9j_VDvCG6T4n0UO9K0jfBf5yvPnahSQCLJk2nw-2uZ9YzBZKwkm21wU6hTknPst5Vk5ZbYJmzqXsCqEB5T2Bn5vqeXMe3SOB5hD2CbTFFfp3TC4"}"#;

const RSA_1024_N: &str = "0XamHpbNC-FqjNCuvjTv3JlceEpQlZtsULPcCTy0CYnGxMNHNYUdcUuVXSFtIQCpHPWUwLL-GWu5PmF_svocDHHsbnlbPj3Eg9dVN2m1g-du7jK1IA3eeTmfWZAkZC9R_ITsULIr7QjrMrUm2GgejMLqnaeZpVxmCD6X6ER02Ik";

fn body(raw: impl AsRef<[u8]>) -> DataDestinationBody {
    BoundedDestinationBody {
        bytes: Zeroizing::new(raw.as_ref().to_vec()),
        slot: PhantomData,
    }
}

fn private_key() -> PrivateJwk {
    PrivateJwk::parse(RSA_JWK).expect("test RSA JWK")
}

fn public_members() -> (String, String) {
    let public = private_key().public();
    (
        public.n.expect("RSA modulus"),
        public.e.expect("RSA exponent"),
    )
}

fn jwks_value() -> Value {
    let (n, e) = public_members();
    json!({
        "keys": [
            {
                "kty": "RSA",
                "kid": SIGNING_KID,
                "use": "sig",
                "alg": "RS256",
                "n": n,
                "e": e
            },
            {
                "kty": "RSA",
                "kid": "opencrvs-encryption-key",
                "use": "enc",
                "alg": "RSA-OAEP-256",
                "n": public_members().0,
                "e": public_members().1
            }
        ]
    })
}

fn jwks_body() -> DataDestinationBody {
    body(serde_json::to_vec(&jwks_value()).expect("JWKS serializes"))
}

fn record_schema() -> ClosedJsonDecoder {
    let identifier = ClosedJsonSchema::object(
        false,
        vec![
            ClosedJsonField::new(
                "identifier_type",
                true,
                ClosedJsonSchema::string(false, 3).expect("identifier type schema"),
            )
            .expect("identifier type field"),
            ClosedJsonField::new(
                "identifier_value",
                true,
                ClosedJsonSchema::string(false, 12).expect("identifier value schema"),
            )
            .expect("identifier value field"),
        ],
    )
    .expect("identifier schema");
    let raw_record = ClosedJsonSchema::object(
        false,
        vec![
            ClosedJsonField::new(
                "identifier",
                true,
                ClosedJsonSchema::array(false, 2, identifier).expect("identifier array schema"),
            )
            .expect("identifier field"),
            ClosedJsonField::new(
                "secret",
                true,
                ClosedJsonSchema::string(false, 64).expect("string schema"),
            )
            .expect("record field"),
        ],
    )
    .expect("record schema");
    let logical = ClosedJsonSchema::object(
        false,
        vec![ClosedJsonField::new("record", true, raw_record).expect("logical field")],
    )
    .expect("logical schema");
    let records = ClosedJsonSchema::array(false, 2, logical).expect("records schema");
    ClosedJsonDecoder::new(records, ClosedJsonRecordRoot::ArrayProbeTwo, vec![])
        .expect("closed decoder")
}

fn decode_bodies_with_bounds(
    jwks: DataDestinationBody,
    response: DataDestinationBody,
    max_jwks_bytes: usize,
    max_response_bytes: usize,
) -> Result<ClosedJsonOutcome, OpenCrvsDciV190Rc1DecodeError> {
    let expectation = OpenCrvsDciV190Rc1Expectation::new(
        MESSAGE_ID,
        SENDER_ID,
        Some(RECEIVER_ID),
        EXPECTED_UIN,
        max_jwks_bytes,
        max_response_bytes,
    )
    .expect("response expectation");
    let record_decoder = record_schema();
    OpenCrvsDciV190Rc1Decoder::new(expectation, &record_decoder).decode(jwks, response)
}

fn decode_bodies(
    jwks: DataDestinationBody,
    response: DataDestinationBody,
) -> Result<ClosedJsonOutcome, OpenCrvsDciV190Rc1DecodeError> {
    decode_bodies_with_bounds(jwks, response, 32 * 1_024, 128 * 1_024)
}

fn unsigned_response(records: Vec<Value>, pagination_total_count: u64) -> Value {
    let records = records
        .into_iter()
        .map(|mut record| {
            if let Some(record) = record.as_object_mut() {
                record.entry("identifier").or_insert_with(|| {
                    json!([{
                        "identifier_type": "UIN",
                        "identifier_value": EXPECTED_UIN
                    }])
                });
            }
            record
        })
        .collect::<Vec<_>>();
    let record_count = records.len();
    json!({
        "header": {
            "version": "1.0.0",
            "message_id": MESSAGE_ID,
            "message_ts": "2026-07-12T08:30:00Z",
            "action": "on-search",
            "status": "succ",
            "total_count": record_count,
            "sender_id": SENDER_ID,
            "receiver_id": RECEIVER_ID,
            "is_msg_encrypted": false
        },
        "message": {
            "transaction_id": MESSAGE_ID,
            "correlation_id": CORRELATION_ID,
            "search_response": [{
                "reference_id": MESSAGE_ID,
                "timestamp": "2026-07-12T08:30:00Z",
                "status": "succ",
                "data": {
                    "version": "1.0.0",
                    "reg_type": "ns:org:RegistryType:Civil",
                    "reg_record_type": "spdci-extensions-dci:Person",
                    "reg_records": records
                },
                "pagination": {
                    "page_number": 1,
                    "page_size": 2,
                    "total_count": pagination_total_count
                },
                "locale": "eng"
            }]
        }
    })
}

fn compact_jws(payload: &Value) -> String {
    compact_jws_with_header(payload, br#"{"alg":"RS256","kid":"opencrvs-signing-key"}"#)
}

fn compact_jws_with_header(payload: &Value, protected: &[u8]) -> String {
    let protected = URL_SAFE_NO_PAD.encode(protected);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload).expect("payload serializes"));
    let signing_input = format!("{protected}.{payload}");
    let signature = sign(signing_input.as_bytes(), &private_key()).expect("fixture signs");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn signed_body(unsigned: &Value) -> DataDestinationBody {
    body(signed_bytes(unsigned))
}

fn signed_bytes(unsigned: &Value) -> Vec<u8> {
    let mut outer = unsigned.clone();
    outer
        .as_object_mut()
        .expect("outer object")
        .insert("signature".to_owned(), Value::String(compact_jws(unsigned)));
    serde_json::to_vec(&outer).expect("signed response serializes")
}

fn decode(unsigned: &Value) -> Result<ClosedJsonOutcome, OpenCrvsDciV190Rc1DecodeError> {
    decode_bodies(jwks_body(), signed_body(unsigned))
}

#[test]
fn verifies_before_releasing_zero_one_or_ambiguous_cardinality() {
    assert!(matches!(
        decode(&unsigned_response(vec![], 0)).expect("no match"),
        ClosedJsonOutcome::NoMatch
    ));

    let one = decode(&unsigned_response(
        vec![json!({"secret": "record-secret"})],
        1,
    ))
    .expect("one record");
    let ClosedJsonOutcome::One(record) = one else {
        panic!("expected one record");
    };
    assert!(record.is_empty());
    let diagnostic = format!("{record:?}");
    assert!(!diagnostic.contains("record-secret"));

    assert!(matches!(
        decode(&unsigned_response(
            vec![json!({"secret": "first"}), json!({"secret": "second"})],
            2,
        ))
        .expect("two records are ambiguous"),
        ClosedJsonOutcome::Ambiguous
    ));
    assert!(matches!(
        decode(&unsigned_response(
            vec![json!({"secret": "partial-page"})],
            2,
        ))
        .expect("declared ambiguity is conservative"),
        ClosedJsonOutcome::Ambiguous
    ));
}

#[test]
fn binds_every_returned_record_to_the_requested_uin() {
    let mut wrong = unsigned_response(vec![json!({"secret": "record-secret"})], 1);
    wrong["message"]["search_response"][0]["data"]["reg_records"][0]["identifier"][0]
        ["identifier_value"] = json!("0987654321");
    let error = decode(&wrong).expect_err("wrong UIN is rejected");
    assert_eq!(
        error,
        OpenCrvsDciV190Rc1DecodeError::SelectorBindingViolation
    );
    let diagnostic = format!("{error:?} {error}");
    assert!(!diagnostic.contains("record-secret"));
    assert!(!diagnostic.contains(EXPECTED_UIN));

    let mut wrong_type = unsigned_response(vec![json!({"secret": "record-secret"})], 1);
    wrong_type["message"]["search_response"][0]["data"]["reg_records"][0]["identifier"][0]
        ["identifier_type"] = json!("BRN");
    assert_eq!(
        decode(&wrong_type).err(),
        Some(OpenCrvsDciV190Rc1DecodeError::SelectorBindingViolation)
    );
}

#[test]
fn rejects_duplicate_json_jws_and_jwks_members() {
    let duplicate_outer = br#"{"header":{},"header":{},"message":{},"signature":"a.b.c"}"#;
    assert_eq!(
        decode_bodies(jwks_body(), body(duplicate_outer)).err(),
        Some(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse)
    );

    let unsigned = unsigned_response(vec![], 0);
    let duplicate_header = compact_jws_with_header(
        &unsigned,
        br#"{"alg":"RS256","alg":"RS256","kid":"opencrvs-signing-key"}"#,
    );
    let mut outer = unsigned.clone();
    outer["signature"] = Value::String(duplicate_header);
    assert_eq!(
        decode_bodies(jwks_body(), body(serde_json::to_vec(&outer).unwrap())).err(),
        Some(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse)
    );

    let (n, e) = public_members();
    let duplicate_jwk = format!(
        r#"{{"keys":[{{"kty":"RSA","kty":"RSA","kid":"{SIGNING_KID}","use":"sig","alg":"RS256","n":"{n}","e":"{e}"}}]}}"#
    );
    assert_eq!(
        decode_bodies(body(duplicate_jwk), signed_body(&unsigned)).err(),
        Some(OpenCrvsDciV190Rc1DecodeError::InvalidJwks)
    );
}

#[test]
fn rejects_private_remote_embedded_unknown_weak_duplicate_and_wrong_keys() {
    let unsigned = unsigned_response(vec![], 0);
    for field in [
        ("d", json!("private-key-material")),
        ("jku", json!("https://attacker.invalid/jwks")),
        ("x5c", json!(["embedded-certificate"])),
        ("unexpected", json!(true)),
    ] {
        let mut jwks = jwks_value();
        jwks["keys"][0][field.0] = field.1;
        assert_eq!(
            decode_bodies(
                body(serde_json::to_vec(&jwks).unwrap()),
                signed_body(&unsigned),
            )
            .err(),
            Some(OpenCrvsDciV190Rc1DecodeError::InvalidJwks)
        );
    }

    let mut weak = jwks_value();
    weak["keys"][0]["n"] = json!(RSA_1024_N);
    assert_eq!(
        decode_bodies(
            body(serde_json::to_vec(&weak).unwrap()),
            signed_body(&unsigned),
        )
        .err(),
        Some(OpenCrvsDciV190Rc1DecodeError::SigningKeyRejected)
    );

    let mut duplicate = jwks_value();
    let signing = duplicate["keys"][0].clone();
    duplicate["keys"].as_array_mut().unwrap().push(signing);
    assert_eq!(
        decode_bodies(
            body(serde_json::to_vec(&duplicate).unwrap()),
            signed_body(&unsigned),
        )
        .err(),
        Some(OpenCrvsDciV190Rc1DecodeError::InvalidJwks)
    );

    let mut wrong = jwks_value();
    wrong["keys"][0]["kid"] = json!("wrong-signing-key");
    assert_eq!(
        decode_bodies(
            body(serde_json::to_vec(&wrong).unwrap()),
            signed_body(&unsigned),
        )
        .err(),
        Some(OpenCrvsDciV190Rc1DecodeError::SigningKeyRejected)
    );

    for (key_use, alg) in [("sig", "RS512"), ("other", "RS256"), ("enc", "RSA1_5")] {
        let mut wrong_shape = jwks_value();
        wrong_shape["keys"][1]["use"] = json!(key_use);
        wrong_shape["keys"][1]["alg"] = json!(alg);
        assert_eq!(
            decode_bodies(
                body(serde_json::to_vec(&wrong_shape).unwrap()),
                signed_body(&unsigned),
            )
            .err(),
            Some(OpenCrvsDciV190Rc1DecodeError::InvalidJwks)
        );
    }
}

#[test]
fn rejects_header_extras_tampering_and_signed_sibling_mismatch() {
    let unsigned = unsigned_response(vec![json!({"secret": "record-secret"})], 1);
    let header_extra = compact_jws_with_header(
        &unsigned,
        br#"{"alg":"RS256","kid":"opencrvs-signing-key","typ":"JWT"}"#,
    );
    let mut outer = unsigned.clone();
    outer["signature"] = Value::String(header_extra);
    assert_eq!(
        decode_bodies(jwks_body(), body(serde_json::to_vec(&outer).unwrap())).err(),
        Some(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse)
    );

    let mut tampered = unsigned.clone();
    let mut compact = compact_jws(&unsigned).into_bytes();
    let payload_start = compact.iter().position(|byte| *byte == b'.').unwrap() + 1;
    compact[payload_start] = if compact[payload_start] == b'A' {
        b'B'
    } else {
        b'A'
    };
    tampered["signature"] = Value::String(String::from_utf8(compact).unwrap());
    assert_eq!(
        decode_bodies(jwks_body(), body(serde_json::to_vec(&tampered).unwrap())).err(),
        Some(OpenCrvsDciV190Rc1DecodeError::SignatureVerificationFailed)
    );

    let mut sibling = unsigned.clone();
    sibling["header"]["status"] = json!("fail");
    sibling["signature"] = Value::String(compact_jws(&unsigned));
    assert_eq!(
        decode_bodies(jwks_body(), body(serde_json::to_vec(&sibling).unwrap())).err(),
        Some(OpenCrvsDciV190Rc1DecodeError::SignedPayloadMismatch)
    );
}

#[test]
fn rejects_correlation_identity_status_and_envelope_failures_after_verification() {
    let cases = [
        (
            "/header/message_id",
            json!("01JZ0000000000000000000001"),
            OpenCrvsDciV190Rc1DecodeError::CorrelationViolation,
        ),
        (
            "/message/transaction_id",
            json!("01JZ0000000000000000000001"),
            OpenCrvsDciV190Rc1DecodeError::CorrelationViolation,
        ),
        (
            "/message/correlation_id",
            json!("123E4567-E89B-42D3-A456-426614174000"),
            OpenCrvsDciV190Rc1DecodeError::CorrelationViolation,
        ),
        (
            "/message/search_response/0/reference_id",
            json!("01JZ0000000000000000000001"),
            OpenCrvsDciV190Rc1DecodeError::CorrelationViolation,
        ),
        (
            "/header/sender_id",
            json!("wrong-sender"),
            OpenCrvsDciV190Rc1DecodeError::IdentityViolation,
        ),
        (
            "/header/receiver_id",
            json!("wrong-receiver"),
            OpenCrvsDciV190Rc1DecodeError::IdentityViolation,
        ),
        (
            "/header/status",
            json!("fail"),
            OpenCrvsDciV190Rc1DecodeError::SourceRejected,
        ),
        (
            "/message/search_response/0/status",
            json!("fail"),
            OpenCrvsDciV190Rc1DecodeError::SourceRejected,
        ),
        (
            "/header/action",
            json!("search"),
            OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation,
        ),
        (
            "/header/message_ts",
            json!("not-rfc3339"),
            OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation,
        ),
        (
            "/header/is_msg_encrypted",
            json!(true),
            OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation,
        ),
        (
            "/message/search_response/0/data/reg_type",
            json!("ns:org:RegistryType:Other"),
            OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation,
        ),
        (
            "/message/search_response/0/locale",
            json!("fra"),
            OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation,
        ),
    ];
    for (pointer, value, expected) in cases {
        let mut unsigned = unsigned_response(vec![], 0);
        *unsigned.pointer_mut(pointer).expect("fixture pointer") = value;
        assert_eq!(decode(&unsigned).err(), Some(expected), "{pointer}");
    }

    let mut unknown = unsigned_response(vec![], 0);
    unknown["header"]["unreviewed"] = json!("response-secret");
    assert_eq!(
        decode(&unknown).err(),
        Some(OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation)
    );

    let mut misplaced = unsigned_response(vec![], 0);
    let response = misplaced["message"]["search_response"][0]
        .as_object_mut()
        .expect("search response object");
    let pagination = response.remove("pagination").expect("pagination sibling");
    let locale = response.remove("locale").expect("locale sibling");
    let data = response
        .get_mut("data")
        .and_then(Value::as_object_mut)
        .expect("data object");
    data.insert("pagination".to_owned(), pagination);
    data.insert("locale".to_owned(), locale);
    assert_eq!(
        decode(&misplaced).err(),
        Some(OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation)
    );
}

#[test]
fn rejects_pagination_and_cardinality_inconsistency() {
    for (pointer, value) in [
        (
            "/message/search_response/0/pagination/page_number",
            json!(2),
        ),
        ("/message/search_response/0/pagination/page_size", json!(3)),
        (
            "/message/search_response/0/pagination/total_count",
            json!(0),
        ),
    ] {
        let mut unsigned = unsigned_response(vec![json!({"secret": "record-secret"})], 1);
        *unsigned.pointer_mut(pointer).expect("fixture pointer") = value;
        assert_eq!(
            decode(&unsigned).err(),
            Some(OpenCrvsDciV190Rc1DecodeError::PaginationViolation)
        );
    }

    let three = unsigned_response(
        vec![
            json!({"secret": "one"}),
            json!({"secret": "two"}),
            json!({"secret": "three"}),
        ],
        3,
    );
    assert_eq!(
        decode(&three).err(),
        Some(OpenCrvsDciV190Rc1DecodeError::CardinalityViolation)
    );

    let mut wrong_header_count = unsigned_response(vec![json!({"secret": "record-secret"})], 1);
    wrong_header_count["header"]["total_count"] = json!(0);
    assert_eq!(
        decode(&wrong_header_count).err(),
        Some(OpenCrvsDciV190Rc1DecodeError::CardinalityViolation)
    );

    for count in [0, 2] {
        let mut unsigned = unsigned_response(vec![], 0);
        let response = unsigned["message"]["search_response"][0].clone();
        unsigned["message"]["search_response"] = if count == 0 {
            json!([])
        } else {
            json!([response.clone(), response])
        };
        assert_eq!(
            decode(&unsigned).err(),
            Some(OpenCrvsDciV190Rc1DecodeError::CardinalityViolation)
        );
    }
}

#[test]
fn validates_every_record_against_the_complete_logical_schema() {
    for record in [
        json!({"secret": 1}),
        json!({"secret": "valid", "extra": "not-reviewed"}),
        json!({}),
    ] {
        assert_eq!(
            decode(&unsigned_response(vec![record], 1)).err(),
            Some(OpenCrvsDciV190Rc1DecodeError::RecordContractViolation)
        );
    }
    assert_eq!(
        decode(&unsigned_response(
            vec![json!({"secret": "valid"}), json!({"secret": 1}),],
            2,
        ))
        .err(),
        Some(OpenCrvsDciV190Rc1DecodeError::RecordContractViolation)
    );
}

#[test]
fn byte_bounds_expectation_debug_and_errors_never_expose_values() {
    assert!(OpenCrvsDciV190Rc1Expectation::new("", SENDER_ID, None, EXPECTED_UIN, 1, 1).is_err());
    assert!(OpenCrvsDciV190Rc1Expectation::new(MESSAGE_ID, SENDER_ID, None, "", 1, 1).is_err());
    assert!(OpenCrvsDciV190Rc1Expectation::new(
        MESSAGE_ID,
        SENDER_ID,
        None,
        "selector\nvalue",
        1,
        1,
    )
    .is_err());
    assert!(OpenCrvsDciV190Rc1Expectation::new(
        MESSAGE_ID,
        SENDER_ID,
        None,
        &"s".repeat(257),
        1,
        1,
    )
    .is_err());
    assert!(OpenCrvsDciV190Rc1Expectation::new(
        MESSAGE_ID,
        SENDER_ID,
        None,
        "country-UIN-01",
        1,
        1,
    )
    .is_ok());
    assert!(
        OpenCrvsDciV190Rc1Expectation::new(MESSAGE_ID, SENDER_ID, None, EXPECTED_UIN, 0, 1,)
            .is_err()
    );
    assert!(
        OpenCrvsDciV190Rc1Expectation::new(MESSAGE_ID, SENDER_ID, None, EXPECTED_UIN, 1, 0,)
            .is_err()
    );

    let unsigned = unsigned_response(vec![], 0);
    assert_eq!(
        decode_bodies_with_bounds(jwks_body(), signed_body(&unsigned), 1, 128 * 1_024).err(),
        Some(OpenCrvsDciV190Rc1DecodeError::JwksTooLarge)
    );
    assert_eq!(
        decode_bodies_with_bounds(jwks_body(), signed_body(&unsigned), 32 * 1_024, 1).err(),
        Some(OpenCrvsDciV190Rc1DecodeError::ResponseTooLarge)
    );

    let expectation = OpenCrvsDciV190Rc1Expectation::new(
        "message-secret",
        "sender-secret",
        Some("receiver-secret"),
        EXPECTED_UIN,
        1,
        1,
    )
    .expect("valid expectation");
    let diagnostic = format!("{expectation:?}");
    for secret in ["message-secret", "sender-secret", "receiver-secret"] {
        assert!(!diagnostic.contains(secret));
    }

    let error = decode(&unsigned_response(
        vec![json!({"secret": "record-secret", "extra": "response-secret"})],
        1,
    ))
    .expect_err("record contract fails");
    let diagnostic = format!("{error:?} {error}");
    for secret in ["record-secret", "response-secret", MESSAGE_ID, SENDER_ID] {
        assert!(!diagnostic.contains(secret));
    }

    let one = decode(&unsigned_response(
        vec![json!({"secret": "record-secret"})],
        1,
    ))
    .expect("valid record");
    assert!(!format!("{one:?}").contains("record-secret"));
    let ClosedJsonOutcome::One(record) = one else {
        panic!("one record");
    };
    assert!(record.get("record").is_none());
    assert!(record
        .fields()
        .all(|field| !matches!(field.value(), ProjectedJsonScalar::String(_))));
}
