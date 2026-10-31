// The FindCases edges, mapped to case-api record slot objects.
fn to_cases(exchange) {
    let body = exchange.body;
    let connection = ();
    if body.data != () {
        connection = body.data.cases;
    } else {
        connection = body.cases;
    }
    if connection == () {
        throw "the response carries no cases connection";
    }
    let records = [];
    for edge in connection.edges {
        records.push(case_record(edge.node));
    }
    records
}

fn case_record(node) {
    if node == () || node.id == () {
        throw "a case node carries no id";
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
