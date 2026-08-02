fn extract(source_response, parameters) {
    if !source_response.contains("total") ||
       type_of(source_response["total"]) != "i64" ||
       source_response["total"] < 0 {
        throw("source_protocol_error");
    }
    if source_response["total"] == 0 {
        if len(source_response) != 1 { throw("source_protocol_error"); }
        return #{outcome: "no_match"};
    }
    if source_response["total"] > 1 {
        return #{outcome: "ambiguous"};
    }
    if !source_response.contains("date_of_birth") {
        return #{outcome: "match", facts: #{}};
    }
    if type_of(source_response["date_of_birth"]) != "string" {
        throw("source_protocol_error");
    }
    #{outcome: "match", facts: #{date_of_birth: source_response["date_of_birth"]}}
}
