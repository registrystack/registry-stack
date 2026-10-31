// Whether the upstream refused the conditional create because more than
// one Patient matched (HTTP 412 Precondition Failed,
// https://hl7.org/fhir/R4/http.html#ccreate).
//
// The engine is assumed to call `is_multiple_match` with the exchange map
// whose `headers.CamelHttpResponseCode` the http component set on
// failure. Inline languages carry no comparison, so the status test
// needs a script. Pure and deterministic; no I/O.
fn is_multiple_match(exchange) {
    exchange.headers.CamelHttpResponseCode == 412
}
