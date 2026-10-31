// The upstream Relay cursor for the next page, or () on the last page.
// Reads the raw GraphQL response body (`data.cases.pageInfo`); whether the
// graphql component unwraps `data` is undefined, so both are tried.
fn next_cursor(exchange) {
    let connection = cases_connection(exchange.body);
    let info = connection.pageInfo;
    if info == () || info.hasNextPage != true {
        return ();
    }
    if info.endCursor == () || info.endCursor == "" {
        throw "hasNextPage without an endCursor";
    }
    info.endCursor
}

fn cases_connection(body) {
    if body.data != () {
        return body.data.cases;
    }
    body.cases
}
