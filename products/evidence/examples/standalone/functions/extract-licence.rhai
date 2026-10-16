fn extract(response, selectors, context) {
    if response.total == 0 { return #{outcome: "no_match"}; }
    if response.total != 1 { return #{outcome: "ambiguous"}; }
    let record = required(response.record, "record_missing");
    if record.record_id != selectors.licence.values["record-id"] { throw("identity_mismatch"); }
    #{outcome: "match", facts: #{status: required(record.status, "status_missing")}}
}
