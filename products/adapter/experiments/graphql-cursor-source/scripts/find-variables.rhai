// GraphQL variables for FindCases, one page per facade call.
//
// The engine places the typed facade filters under `AdapterFilters`, the
// decoded upstream continuation under `AdapterContinuation`, and the bounded
// page size in the `pageSize` header. The facade cursor remains opaque to the
// caller; only its decoded continuation reaches this reviewed source query.
fn find_variables(exchange) {
    let variables = #{
        caseType: exchange.properties.caseType,
        first: 50
    };
    let size = exchange.headers.pageSize;
    if size != () {
        variables.first = size;
    }
    let cursor = exchange.properties.AdapterContinuation;
    if cursor != () && cursor != "" {
        variables.after = cursor;
    }
    let filter = exchange.properties.AdapterFilters;
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
