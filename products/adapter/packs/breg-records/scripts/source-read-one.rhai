// Normalize one BReg Registry Record response. The native ETag response
// header is the revision used for the companion read and later conditional
// write; it is the same validator returned in a batch result.
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

fn source_read_one(exchange) {
    let envelope = exchange.body;
    let etag = exchange.headers.etag;
    if type_of(envelope) != "map" || type_of(envelope.data) != "map"
            || type_of(envelope.data.recordIdentifier) != "string"
            || type_of(envelope.data.domainData) != "map"
            || !valid_breg_etag(etag) {
        throw "the record response is malformed";
    }
    if envelope.data.recordIdentifier != exchange.properties.bregRecordId {
        throw "the record response carries another identifier";
    }
    #{items: [#{
        key: envelope.data.recordIdentifier,
        revision: etag,
        value: envelope.data.domainData
    }]}
}
