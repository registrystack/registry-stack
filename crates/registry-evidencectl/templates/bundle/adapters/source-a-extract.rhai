// Fact extraction. Decides whether the projected source response resolved to
// exactly one record, and emits only the narrow facts the derivation needs.
// A response the adapter does not understand is a protocol error rather than a
// silent no_match, so a source change cannot be mistaken for an answer.
//
// The response schema has already rejected anything outside the declared shape,
// so this script carries no presence or type checks. What is left is the part a
// shape cannot state: how the fields relate, and what an absent optional leaf
// means for this requirement.
fn extract(source_response, parameters) {
    let total = source_response["total"];
    if total == 0 {
        // The source says it found nothing, so it must not also return a record.
        if len(source_response) != 1 { throw("source_protocol_error"); }
        return #{outcome: "no_match"};
    }
    if total > 1 {
        return #{outcome: "ambiguous"};
    }
    // get_path reads one RFC 6901 pointer and reports an absent leaf as missing,
    // which composes with is_missing here and with required(...) elsewhere.
    let event_date = get_path(source_response, "/event_date");
    if is_missing(event_date) {
        return #{outcome: "match", facts: #{}};
    }
    #{outcome: "match", facts: #{event_date: event_date}}
}
