fn extract(source_response, parameters) {
    if len(source_response) != 2 ||
       !source_response.contains("total") ||
       type_of(source_response["total"]) != "i64" ||
       source_response["total"] < 0 ||
       source_response["total"] > parameters["resultLimit"] {
        throw("source_protocol_error");
    }
    if source_response["total"] == 0 {
        if !source_response.contains("result") ||
           !is_missing(source_response["result"]) {
            throw("source_protocol_error");
        }
        return #{ outcome: "no_match" };
    }
    if source_response["total"] > 1 {
        if !source_response.contains("results") ||
           type_of(source_response["results"]) != "array" ||
           source_response["results"].len != source_response["total"] {
            throw("source_protocol_error");
        }
        return #{ outcome: "ambiguous" };
    }
    if !source_response.contains("result") ||
       type_of(source_response["result"]) != "map" {
        throw("source_protocol_error");
    }
    #{
        outcome: "match",
        facts: #{ official_residence_code: source_response["result"]["fact_code"] }
    }
}
