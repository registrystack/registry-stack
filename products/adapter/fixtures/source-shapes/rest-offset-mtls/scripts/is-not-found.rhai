// True when the failed send answered 404. The inline languages have no
// comparison, so the status test is a script.
fn is_not_found(exchange) {
    exchange.headers.CamelHttpResponseCode == 404
}
