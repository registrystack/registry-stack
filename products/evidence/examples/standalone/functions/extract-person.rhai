fn extract(response, selectors, context) {
    if response.total == 0 { return #{outcome: "no_match"}; }
    if response.total != 1 { return #{outcome: "ambiguous"}; }
    let record = required(response.record, "record_missing");
    if record.record_id != selectors.subject.values["record-id"] { throw("identity_mismatch"); }
    #{outcome: "match", facts: #{
        "birth-date": required(record.birth_date, "birth_date_missing"),
        "residence-region": required(record.residence_region, "region_missing"),
        "address-canary": required(record.address_canary, "private_canary_missing"),
    }}
}
