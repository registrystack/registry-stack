fn extract(source_response, parameters) {
    if len(source_response) != 2 ||
       !source_response.contains("total") ||
       !source_response.contains("results") ||
       type_of(source_response["total"]) != "i64" ||
       source_response["total"] < 0 ||
       type_of(source_response["results"]) != "array" ||
       source_response["results"].len > parameters["resultLimit"] {
        throw("source_protocol_error");
    }

    let total = source_response["total"];
    let results = source_response["results"];
    if total == 0 {
        if results.len != 0 { throw("source_protocol_error"); }
        return #{outcome: "no_match"};
    }
    if total > 1 {
        if results.len < 2 { throw("source_protocol_error"); }
        return #{outcome: "ambiguous"};
    }
    if results.len != 1 { throw("source_protocol_error"); }

    let result = results[0];
    if !result.contains("type") ||
       !result.contains("status") ||
       result["type"] != parameters["eventType"] ||
       result["status"] != parameters["registeredStatus"] ||
       !result.contains("trackingId") ||
       type_of(result["trackingId"]) != "string" ||
       !result.contains(parameters["dateField"]) ||
       type_of(result[parameters["dateField"]]) != "string" {
        throw("source_protocol_error");
    }

    #{
        outcome: "match",
        facts: #{
            record_tracking_id: result["trackingId"],
            date_of_birth: result[parameters["dateField"]]
        }
    }
}
