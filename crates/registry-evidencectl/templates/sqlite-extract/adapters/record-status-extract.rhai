// Bounded extraction: it reduces one statement result to the facts a question
// may reason over. It reads the projection the source declared and nothing
// else, and it decides which of the three outcomes this request had.
fn extract(source_response, context) {
    let rows = source_response["rows"];

    // No row and more than one row are separate answers, not errors: the
    // runtime reports both as unavailable without saying which, so a caller
    // cannot learn whether a reference exists.
    if rows.len == 0 {
        return #{outcome: "no_match"};
    }
    if rows.len > 1 {
        return #{outcome: "ambiguous"};
    }

    // One row: hand on the single fact the fact schema declares.
    #{
        outcome: "match",
        facts: #{qualifying_record_count: rows[0]["qualifying_record_count"]}
    }
}
