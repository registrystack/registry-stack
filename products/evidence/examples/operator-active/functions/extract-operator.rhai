fn extract(response, selectors, context) {
    if response.total == 0 { return #{outcome: "no_match"}; }
    if response.total != 1 { return #{outcome: "ambiguous"}; }
    let record = required(response.record, "record_missing");
    if record.operator_id != selectors.operator.values["operator-id"] { throw("operator_mismatch"); }
    #{outcome: "match", facts: #{
        active: required(record.active, "active_missing"),
        status: required(record.status, "status_missing"),
        "address-canary": required(record.address_canary, "canary_missing"),
    }}
}
