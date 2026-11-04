// Build one BReg native batch item from already validated and transformed
// domain data. The Adapter engine supplies the upstream idempotency header.

fn pointer_member(name) {
    let escaped = name;
    escaped.replace("~", "~0");
    escaped.replace("/", "~1");
    escaped
}

fn create_batch(exchange) {
    if type_of(exchange.body) != "map" {
        throw "create data is not an object";
    }
    #{items: [#{operation: "create", data: exchange.body}]}
}

fn update_batch(exchange) {
    if type_of(exchange.body) != "map" || exchange.body.keys().len == 0 {
        throw "update data is not a nonempty object";
    }
    let record_id = exchange.headers.recordid;
    let condition = exchange.properties["AdapterSourceCondition"];
    if type_of(record_id) != "string" || record_id == "" {
        throw "the exchange carries no record identifier";
    }
    if type_of(condition) != "string" || condition == "" {
        throw "the exchange carries no source condition";
    }
    let patch = [];
    for name in exchange.body.keys() {
        let path = "/data/" + pointer_member(name);
        let value = exchange.body[name];
        if value == () {
            patch.push(#{op: "remove", path: path});
        } else {
            patch.push(#{op: "add", path: path, value: value});
        }
    }
    #{items: [#{
        operation: "patch",
        recordIdentifier: record_id,
        ifMatch: condition,
        patch: patch
    }]}
}
