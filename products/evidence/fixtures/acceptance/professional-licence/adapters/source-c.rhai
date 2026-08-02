fn extract(source_response, parameters) {
    if len(source_response) != 2 ||
       !source_response.contains("total") ||
       !source_response.contains("records") ||
       type_of(source_response["total"]) != "i64" ||
       source_response["total"] < 0 ||
       type_of(source_response["records"]) != "array" ||
       source_response["records"].len > parse_integer(parameters["resultLimit"]) {
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
    let facts = #{};
    if record.contains("licence_state") { facts["licence_state"] = record["licence_state"]; }
    if record.contains("valid_from") { facts["valid_from"] = record["valid_from"]; }
    if record.contains("valid_until") { facts["valid_until"] = record["valid_until"]; }
    #{
        outcome: "match",
        facts: facts
    }
}
