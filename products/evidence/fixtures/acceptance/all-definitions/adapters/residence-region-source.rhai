fn extract(source_response, parameters) {
    let total = source_response["total"];
    if total == 0 {
        if len(source_response) != 1 { throw("source_protocol_error"); }
        return #{outcome: "no_match"};
    }
    if total > 1 { return #{outcome: "ambiguous"}; }
    let official_residence_code = get_path(source_response, "/official_residence_code");
    if is_missing(official_residence_code) { return #{outcome: "match", facts: #{}}; }
    #{outcome: "match", facts: #{official_residence_code: official_residence_code}}
}
