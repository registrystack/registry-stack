// GraphQL variables for GetCase. The facade path parameter `case_id` is
// assumed to arrive as the `recordId` header, as the dhis2 pack and the
// corpus base pack assume.
fn get_variables(exchange) {
    let id = exchange.headers.recordId;
    if id == () || id == "" {
        throw "no case id on the exchange";
    }
    #{ id: id }
}
