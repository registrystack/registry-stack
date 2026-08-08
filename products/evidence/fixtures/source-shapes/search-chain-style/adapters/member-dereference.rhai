fn extract(source_response, context) {
    let parameters = context["parameters"];
    if source_response.len() != 2 ||
       !source_response.contains("matched") ||
       !source_response.contains("record") ||
       type_of(source_response.matched) != "i64" ||
       source_response.matched < 0 ||
       source_response.matched > parameters["maximumMatched"] {
        throw("source_protocol_error");
    }

    let record = source_response.record;
    if source_response.matched == 0 {
        if record.len() != 0 {
            throw("source_protocol_error");
        }
        return #{ outcome: "no_match" };
    }

    if source_response.matched > 1 {
        return #{ outcome: "ambiguous" };
    }

    // status.setCompleteness is a literally dotted key, so the dot is data in
    // the extract exactly as it is in the acquisition projection.
    if !record.contains("status.setCompleteness") {
        return #{ outcome: "match", facts: #{} };
    }

    let completeness = record["status.setCompleteness"];
    if completeness == parameters["completenessAttested"] {
        return #{ outcome: "match", facts: #{ related_set_attested_complete: true } };
    }
    if completeness == parameters["completenessPartial"] {
        return #{ outcome: "match", facts: #{ related_set_attested_complete: false } };
    }

    throw("source_protocol_error");
}
