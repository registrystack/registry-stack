fn extract(source_response, context) {
    let parameters = context["parameters"];
    if source_response.len() != 2 ||
       !source_response.contains("total") ||
       !source_response.contains("results") ||
       source_response.results.len > parameters["resultLimit"] ||
       source_response.total < 0 {
        throw("source_protocol_error");
    }

    if source_response.total == 0 {
        if source_response.results.len != 0 {
            throw("source_protocol_error");
        }
        return #{ outcome: "no_match" };
    }

    if source_response.total > 1 {
        if source_response.results.len != 2 {
            throw("source_protocol_error");
        }
        return #{ outcome: "ambiguous" };
    }

    if source_response.results.len != 1 {
        throw("source_protocol_error");
    }

    let result = source_response.results[0];
    if !result.contains("dateOfEvent") {
        return #{ outcome: "match", facts: #{} };
    }

    #{
        outcome: "match",
        facts: #{ date_of_event: result.dateOfEvent }
    }
}
