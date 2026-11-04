// Match only BReg's closed problem codes and their corresponding native
// statuses. No source detail or caller-controlled text selects an outcome.
fn is_not_found(exchange) {
    let body = exchange.body;
    exchange.headers.camelhttpresponsecode == 404
        && type_of(body) == "map"
        && body.status == 404
        && body.code == "resource.not_found"
}

fn is_invalid_request(exchange) {
    let body = exchange.body;
    exchange.headers.camelhttpresponsecode == 422
        && type_of(body) == "map"
        && body.status == 422
        && body.code == "action.refused"
}

fn is_rejected_request_shape(exchange) {
    let body = exchange.body;
    exchange.headers.camelhttpresponsecode == 400
        && type_of(body) == "map"
        && body.status == 400
        && body.code == "request.invalid"
}
