// The statement returns one row per registrant carrying the requested
// reference. Only the aggregate crosses the source boundary.
fn extract(exchange) {
    let rows = exchange.body.rows;
    if rows.len() == 0 {
        return #{lookup: "no-match"};
    }
    if rows.len() > 1 {
        return #{lookup: "ambiguous"};
    }
    #{
        lookup: "matched",
        facts: #{active_licence_count: rows[0].active_licence_count}
    }
}
