// Reduce the bounded statement result to the one reviewed fact. The lookup
// outcome remains distinct from dependency and protocol failures.
fn extract(exchange) {
    let rows = exchange.body.rows;
    if rows.len() == 0 {
        return #{lookup: "no-match"};
    }
    if rows.len() > 1 {
        return #{lookup: "ambiguous"};
    }
    #{lookup: "matched", facts: #{status: rows[0].status}}
}
