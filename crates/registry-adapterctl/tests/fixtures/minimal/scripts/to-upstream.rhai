// Convert the facade record into the source's synchronous create body.
fn to_upstream(exchange) {
    #{ id: exchange.body.national_id }
}
