use registry_breg_client::{decode_exact_json, BRegCreateRequest, BRegLookupRequest};

#[test]
fn exact_values_keep_types_and_wide_integer_precision() {
    let value = decode_exact_json(br#"{"wide":9007199254740992,"decimal":"12.3400","date":"2026-09-08","null":null,"fraction":0.125,"exponent":1e3}"#).unwrap();
    assert_eq!(value["wide"].as_u64(), Some(9_007_199_254_740_992));
    assert_eq!(value["decimal"], "12.3400");
    assert!(value["null"].is_null());
    assert!(value.get("absent").is_none());
    BRegCreateRequest::new(value.as_object().unwrap().clone()).unwrap();
}

#[test]
fn lossy_literals_duplicates_and_unsupported_integer_writes_are_refused() {
    for bytes in [
        br#"{"n":0.10000000000000001}"#.as_slice(),
        br#"{"n":9007199254740993.0}"#,
        br#"{"n":1e9999}"#,
        br#"{"n":1e-9999}"#,
        br#"{"outer":{"n":1,"n":2}}"#,
    ] {
        assert!(decode_exact_json(bytes).is_err());
    }
    let value = decode_exact_json(br#"{"n":9007199254740993}"#).unwrap();
    assert_eq!(value["n"].as_u64(), Some(9_007_199_254_740_993));
    assert!(BRegCreateRequest::new(value.as_object().unwrap().clone()).is_err());
}

#[test]
fn lookup_values_keep_wide_integer_and_decimal_precision() {
    let value = decode_exact_json(br#"{"wide":9007199254740992,"decimal":"12.3400"}"#).unwrap();
    assert_eq!(value["wide"].as_u64(), Some(9_007_199_254_740_992));
    assert_eq!(value["decimal"], "12.3400");
    // BRegLookupRequest::body() is crate-private, so this integration test cannot inspect
    // the serialized wire bytes directly. Accepting both decoded forms unchanged as lookup
    // values, with no truncation or coercion, is the strongest exactness proof available
    // from outside the crate.
    BRegLookupRequest::new("by-wide-value")
        .unwrap()
        .value("wide", value["wide"].clone())
        .unwrap()
        .value("decimal", value["decimal"].clone())
        .unwrap();
}
