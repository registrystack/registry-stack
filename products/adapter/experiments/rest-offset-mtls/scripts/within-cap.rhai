// The hard total cap: true while the upstream's reported total stays within
// the deployment's reviewed maximum. A larger result is refused whole
// (the validate step raises `validation`), never truncated, so a caller
// never mistakes the first N records for the full answer.
//
// Template instantiation preserves the integer parameter type.
fn within_cap(exchange) {
    let total = exchange.properties.upstreamTotal;
    if type_of(total) != "i64" {
        throw "meta.total is not an integer";
    }
    total <= exchange.properties.maximumTotal
}
