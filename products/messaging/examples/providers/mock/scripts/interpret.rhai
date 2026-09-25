// A 2xx names the gateway's message id, unless the body reports an error.
fn interpret(response) {
    let body = response.body;
    let is_map = type_of(body) == "map";
    if response.status >= 200 && response.status < 300 {
        if is_map && body.error != () {
            return #{ outcome: "permanent", code: "gateway.rejected" };
        }
        if is_map && type_of(body.id) == "string" {
            return #{ outcome: "accepted", providerReference: body.id };
        }
        return #{ outcome: "maybe-sent" };
    }
    if response.status == 408 || response.status == 429 || response.status >= 500 {
        return #{ outcome: "transient" };
    }
    #{ outcome: "permanent", code: "http." + response.status }
}
