// Classify the provider's answer. A 2xx names the message sid; an error body
// carries a numeric provider code, kept as the failure code.
fn interpret(response) {
    let body = response.body;
    let is_map = type_of(body) == "map";
    if response.status >= 200 && response.status < 300 {
        if is_map && type_of(body.sid) == "string" && body.error_code == () {
            return #{ outcome: "accepted", providerReference: body.sid };
        }
        return #{ outcome: "maybe-sent" };
    }
    if response.status == 429 || response.status >= 500 {
        return #{ outcome: "transient" };
    }
    if is_map && type_of(body.code) == "i64" {
        return #{ outcome: "permanent", code: "twilio." + body.code };
    }
    #{ outcome: "permanent", code: "http." + response.status }
}
