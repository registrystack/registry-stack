// Normalize one successful BReg batch result into SourceWriteReceipt.

fn valid_breg_etag(value) {
    if type_of(value) != "string" || value.len() <= 7 || value.len() > 256
            || !value.starts_with("\"breg-") || !value.ends_with("\"") {
        return false;
    }
    let allowed = "!#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~";
    for character in value.sub_string(1, value.len() - 2).chars() {
        if !allowed.contains(character) {
            return false;
        }
    }
    true
}

fn receipt(exchange, expected_operation) {
    let body = exchange.body;
    if type_of(body) != "map" || type_of(body.results) != "array"
            || body.results.len() != 1 {
        throw "the batch response is not one result";
    }
    let result = body.results[0];
    if type_of(result) != "map" || result.operation != expected_operation
            || type_of(result.recordIdentifier) != "string"
            || !valid_breg_etag(result.etag)
            || type_of(result.domainData) != "map" {
        throw "the batch result is malformed";
    }
    #{
        key: result.recordIdentifier,
        nativeValidator: result.etag,
        data: result.domainData
    }
}

fn create_receipt(exchange) {
    receipt(exchange, "create")
}

fn update_receipt(exchange) {
    receipt(exchange, "patch")
}
