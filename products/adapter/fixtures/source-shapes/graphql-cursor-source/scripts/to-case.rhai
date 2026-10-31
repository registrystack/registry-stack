// The GetCase node, mapped to one case-api record slot object. Shares the
// mapping with to-cases.rhai by duplication: each file is compiled alone,
// so a helper defined in another file is not reachable.
fn to_case(exchange) {
    let body = exchange.body;
    let node = ();
    if body.data != () {
        node = body.data.node;
    } else {
        node = body.node;
    }
    if node == () || node.id == () {
        throw "the response carries no case node";
    }
    let national_id = ();
    if node.applicant != () {
        national_id = node.applicant.nationalId;
    }
    #{
        recordIdentifier: node.id,
        revisionIdentifier: node.version,
        domainData: #{
            status: lower_status(node.status),
            opened_on: node.openedOn,
            programme: node.programme,
            applicant_national_id: national_id
        }
    }
}

fn lower_status(status) {
    switch status {
        "OPEN" => "open",
        "CLOSED" => "closed",
        "SUSPENDED" => "suspended",
        _ => throw "unknown upstream case status"
    }
}
