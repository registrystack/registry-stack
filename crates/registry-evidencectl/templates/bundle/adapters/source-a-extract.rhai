// Fact extraction. Decides whether the projected source response resolved to
// exactly one record, and emits only the narrow facts the derivation needs.
// A response the adapter does not understand is a protocol error rather than a
// silent no_match, so a source change cannot be mistaken for an answer.
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
    if !source_response.contains("event_date") {
        return #{outcome: "match", facts: #{}};
    }
    if type_of(source_response["event_date"]) != "string" {
        throw("source_protocol_error");
    }
    #{outcome: "match", facts: #{event_date: source_response["event_date"]}}
}
