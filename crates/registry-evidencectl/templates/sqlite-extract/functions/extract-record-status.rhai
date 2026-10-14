// Reduce the bounded statement result to the one private fact the assertion uses.
fn extract(source_response, context) {
    let rows = source_response["rows"];
    if rows.len == 0 {
        return #{outcome: "no_match"};
    }
    if rows.len > 1 {
        return #{outcome: "ambiguous"};
    }
    #{
        outcome: "match",
        facts: #{"record-count": rows[0]["qualifying_record_count"]}
    }
}
