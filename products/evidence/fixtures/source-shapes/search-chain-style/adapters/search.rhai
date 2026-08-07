fn extract(source_response, context) {
    let parameters = context["parameters"];
    if source_response.len() != 2 ||
       !source_response.contains("total") ||
       !source_response.contains("results") ||
       type_of(source_response.total) != "i64" ||
       source_response.total < 0 ||
       source_response.results.len > parameters["resultLimit"] {
        throw("source_protocol_error");
    }

    if source_response.total == 0 {
        if source_response.results.len != 0 {
            throw("source_protocol_error");
        }
        return #{ outcome: "no_match" };
    }

    // A register that silently ignored a filter clause still reports its own
    // count. Any count above one is ambiguity, and the first result is never
    // read, so a filter field this deployment does not support cannot become a
    // match.
    if source_response.total > 1 {
        if source_response.results.len < 1 {
            throw("source_protocol_error");
        }
        return #{ outcome: "ambiguous" };
    }

    if source_response.results.len != 1 {
        throw("source_protocol_error");
    }

    // Both selected declaration keys are literally dotted names, so the dot is
    // data. subject.origin is one such key whose value is an object, and code
    // below it is a real nesting level.
    let declaration = source_response.results[0]["declaration"];
    let facts = #{};
    if declaration.contains("subject.reference") {
        facts.subject_reference = declaration["subject.reference"];
    }
    if declaration.contains("subject.origin") {
        let origin = declaration["subject.origin"];
        if origin.contains("code") {
            facts.register_origin_code = origin["code"];
        }
    }

    #{ outcome: "match", facts: facts }
}
