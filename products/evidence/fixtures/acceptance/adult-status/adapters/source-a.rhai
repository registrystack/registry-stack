fn extract(source_response, parameters) {
    let total = source_response["total"];
    if total == 0 {
        if len(source_response) != 1 { throw("source_protocol_error"); }
        return #{outcome: "no_match"};
    }
    if total > 1 {
        return #{outcome: "ambiguous"};
    }
    let date_of_birth = get_path(source_response, "/date_of_birth");
    if is_missing(date_of_birth) {
        return #{outcome: "match", facts: #{}};
    }
    #{outcome: "match", facts: #{date_of_birth: date_of_birth}}
}
