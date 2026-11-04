// Exact native registered-event acquisition. Public fields and schemas are
// selected by the consuming project, independently of this source pack.
fn source_query(exchange) {
    #{query: #{type: "and", clauses: [#{
        eventType: exchange.properties.opencrvsEventType,
        status: #{type: "exact", term: "REGISTERED"},
        trackingId: #{type: "exact", term: exchange.body.recordId}
    }]}, limit: 2, offset: 0}
}

fn valid_page(body) {
    if type_of(body) != "map" { return false; }
    type_of(body.total) == "i64" && type_of(body.results) == "array"
}

fn is_missing(exchange) {
    let body = exchange.body;
    valid_page(body) && body.total == 0 && body.results.len() == 0
}

fn is_unique(exchange) {
    let body = exchange.body;
    if !valid_page(body) || body.total != 1 || body.results.len() != 1 { return false; }
    let event = body.results[0];
    type_of(event) == "map" && type_of(event.trackingId) == "string"
        && event.trackingId == exchange.properties.opencrvsRecordId
        && event["type"] == exchange.properties.opencrvsEventType
        && event.status == "REGISTERED" && type_of(event.id) == "string"
        && event.id.len() > 0
}

fn source_page(exchange) {
    let event = exchange.body.results[0];
    #{items: [#{key: event.trackingId, value: event}]}
}
