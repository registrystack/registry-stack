// Synthetic business mapping. BReg owns the reviewed action, current authority,
// target preconditions and exact same-command recovery; this file stays pure.
fn information_route(args) {
    let record = args["record"];

    if record.data.domainData.complete { "skip" } else { "request" }
}

fn action_request(args) {
    let input = args["input"];
    let record = args["record"];

    #{
        input: #{
            applicationId: input.applicationId,
            reason: "Please provide " + record.data.domainData.missingField
        }
    }
}

fn notice_request(args) {
    let record = args["record"];
    let action = args["action"];

    #{
        senderProfile: "transactional",
        to: #{ email: record.data.domainData.email },
        template: #{ id: "information-requested", version: "1" },
        locale: "en",
        data: #{ actionApplicationId: action.applicationId }
    }
}
