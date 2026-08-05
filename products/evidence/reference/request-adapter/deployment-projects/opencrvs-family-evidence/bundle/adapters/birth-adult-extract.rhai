// The response schema has already refused anything outside the declared shape,
// so what remains here is what a shape cannot state: how total relates to the
// records returned, and which values must agree with the adapter parameters.
fn extract(source_response, parameters) {
    let total = source_response["total"];
    let results = source_response["results"];
    if results.len > parameters["resultLimit"] { throw("source_protocol_error"); }

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
    // The shape cannot require these of every record, because the ambiguous
    // page is decided before any record is read. The date field is named by an
    // adapter parameter, so its presence is parameter-dependent besides.
    if result["type"] != parameters["eventType"] ||
       result["status"] != parameters["registeredStatus"] ||
       is_missing(result["trackingId"]) ||
       !result.contains(parameters["dateField"]) {
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
