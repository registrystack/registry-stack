fn extract(source_response, parameters) {
    let total = source_response["total"];
    let records = source_response["records"];
    if records.len > parse_integer(parameters["resultLimit"]) { throw("source_protocol_error"); }
    if total == 0 {
        if records.len != 0 { throw("source_protocol_error"); }
        return #{outcome: "no_match"};
    }
    if total > 1 {
        if records.len < 2 { throw("source_protocol_error"); }
        return #{outcome: "ambiguous"};
    }
    if records.len != 1 { throw("source_protocol_error"); }
    let facts = #{};
    let licence_state = get_path(source_response, "/records/0/licence_state");
    if !is_missing(licence_state) { facts["licence_state"] = licence_state; }
    let valid_from = get_path(source_response, "/records/0/valid_from");
    if !is_missing(valid_from) { facts["valid_from"] = valid_from; }
    let valid_until = get_path(source_response, "/records/0/valid_until");
    if !is_missing(valid_until) { facts["valid_until"] = valid_until; }
    #{outcome: "match", facts: facts}
}
