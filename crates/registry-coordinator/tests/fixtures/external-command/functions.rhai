// Pure Function ABI: one typed object of named inputs, one typed output.
fn bill_request(args) {
    #{reference: args.request.applicationId, amount: args.request.amount}
}

// Only a recognised answer settles the command. Anything else is uncertain,
// so the run holds for same-command recovery instead of guessing.
fn bill_outcome(args) {
    let status = args.response.status;
    let body = args.response.body;
    if (status == 200 || status == 201) && "billId" in body {
        return #{state: "accepted", result: #{billId: body.billId}};
    }
    if status == 422 && "reason" in body && body.reason == "account-closed" {
        return #{state: "refused", code: "account-closed"};
    }
    #{state: "uncertain"}
}
