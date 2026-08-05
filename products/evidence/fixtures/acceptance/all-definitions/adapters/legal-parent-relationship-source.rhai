fn extract(source_response, parameters) {
    let total = source_response["total"];
    let records = source_response["records"];
    if records.len > parameters["resultLimit"] { throw("source_protocol_error"); }
    if total == 0 {
        if records.len != 0 { throw("source_protocol_error"); }
        return #{outcome: "no_match"};
    }
    if total > 1 {
        if records.len < 2 { throw("source_protocol_error"); }
        return #{outcome: "ambiguous"};
    }
    if records.len != 1 { throw("source_protocol_error"); }
    let record = records[0];
    // The shape cannot require these of every record, because the ambiguous
    // page is decided before any record is read. A single matched record that
    // omits either one is a source this adapter does not understand.
    if is_missing(record["returned_child_reference"]) || is_missing(record["parent_references"]) { throw("source_protocol_error"); }
    if record["reference_namespace"] != parameters["referenceNamespace"] || record["relationship_set_contract"] != parameters["relationshipSetContract"] || record["relationship_set_complete"] != parameters["relationshipSetComplete"] { throw("source_protocol_error"); }
    #{outcome: "match", facts: #{returned_child_reference: record["returned_child_reference"], parent_references: record["parent_references"], reference_namespace: record["reference_namespace"], relationship_set_contract: record["relationship_set_contract"], relationship_set_complete: record["relationship_set_complete"]}}
}
