// True unless the read's doCatch recorded an upstream 404. A false answer
// fails the `validate` step, and the template's `validation` clause turns it
// into the profile's not-found problem. This stands in for Camel's
// throwException, which is not ported: a plain step cannot end the exchange
// with a problem response (CONCEPT section 7 validates every final body
// against the success schema), so the only road to a problem is a raised
// error class that a handled clause catches.
fn is_present(exchange) {
    exchange.properties.householdMissing != true
}
