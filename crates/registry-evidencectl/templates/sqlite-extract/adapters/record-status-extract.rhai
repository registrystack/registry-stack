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
        facts: #{qualifying_record_count: rows[0]["qualifying_record_count"]}
    }
}
