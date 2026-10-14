fn extract(response, selectors, context) {
    if response.total == 0 { return #{outcome: "no_match"}; }
    if response.total != 1 { return #{outcome: "ambiguous"}; }
    let record = required(response.record, "record_missing");
    if record.record_id != selectors.child.values["record-id"] || record.complete != true { throw("relationship_contract_mismatch"); }
    #{outcome: "match", facts: #{parents: required(record.parents, "parents_missing")}}
}
