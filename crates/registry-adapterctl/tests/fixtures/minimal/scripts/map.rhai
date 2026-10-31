// Map the actual upstream response into the project's one declared field.
fn map(exchange) {
    #{ national_id: exchange.body.id }
}
