fn extract(source_response, parameters) {
    if len(source_response) != 2 ||
       !source_response.contains("total") ||
       !source_response.contains("records") ||
       type_of(source_response["total"]) != "i64" ||
       source_response["total"] < 0 ||
       type_of(source_response["records"]) != "array" ||
       source_response["records"].len > parameters["resultLimit"] {
        throw("source_protocol_error");
    }
    let total = source_response["total"];
    let records = source_response["records"];
    if total == 0 {
        if records.len != 0 { throw("source_protocol_error"); }
        return #{outcome: "no_match"};
    }
    if total > 1 {
        if records.len < 2 { throw("source_protocol_error"); }
        return #{outcome: "ambiguous"};
    }
    if records.len != 1 || type_of(records[0]) != "map" {
        throw("source_protocol_error");
    }
    let record = records[0];
    if len(record) != 5 ||
       !record.contains("returned_child_reference") ||
       !record.contains("parent_references") ||
       !record.contains("reference_namespace") ||
       !record.contains("relationship_set_contract") ||
       !record.contains("relationship_set_complete") ||
       type_of(record["returned_child_reference"]) != "string" ||
       type_of(record["parent_references"]) != "array" ||
       type_of(record["reference_namespace"]) != "string" ||
       type_of(record["relationship_set_contract"]) != "string" ||
       type_of(record["relationship_set_complete"]) != "bool" ||
       record["relationship_set_complete"] != parameters["relationshipSetComplete"] ||
       record["reference_namespace"] != parameters["referenceNamespace"] ||
       record["relationship_set_contract"] != parameters["relationshipSetContract"] ||
       record["parent_references"].len > 2 {
        throw("source_protocol_error");
    }
    let seen = [];
    for reference in record["parent_references"] {
        if type_of(reference) != "string" || reference == "" || list_contains(seen, reference) {
            throw("source_protocol_error");
        }
        seen.push(reference);
    }
    #{outcome: "match", facts: #{
        returned_child_reference: record["returned_child_reference"],
        parent_references: record["parent_references"],
        reference_namespace: record["reference_namespace"],
        relationship_set_contract: record["relationship_set_contract"],
        relationship_set_complete: record["relationship_set_complete"]
    }}
}
