// Relay `node(id:)` answers `{"data": {"node": null}}` for an unknown id:
// a 200 with no GraphQL error, so no error class fires. True when the node
// is null.
fn is_missing(exchange) {
    let body = exchange.body;
    if body.data != () {
        return body.data.node == ();
    }
    body.node == ()
}
