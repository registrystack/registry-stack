// GraphQL variables for FindCases, one page per facade call.
//
// The engine is assumed to call `find_variables` with the exchange map, and
// the case-api `rest` consumer to place the facade cursor and page size on
// the exchange as headers under the profile's names (`pageStateToken`,
// `maxResults`) and the request envelope's `query` record as the body. No
// document fixes either; the README records the gap.
//
// The facade cursor is passed through as the upstream Relay cursor. The
// engine is said to own cursor encoding (CONCEPT section 7), so the caller
// is assumed never to see the raw upstream cursor.
fn find_variables(exchange) {
    let variables = #{
        caseType: exchange.properties.caseType,
        first: 50
    };
    let size = exchange.headers.maxResults;
    if size != () {
        variables.first = parse_int(size);
    }
    let cursor = exchange.headers.pageStateToken;
    if cursor != () && cursor != "" {
        variables.after = cursor;
    }
    let filter = exchange.body;
    if filter != () && filter.status != () {
        variables.status = status_enum(filter.status);
    }
    variables
}

fn status_enum(status) {
    switch status {
        "open" => "OPEN",
        "closed" => "CLOSED",
        "suspended" => "SUSPENDED",
        _ => throw "unknown case status filter"
    }
}
