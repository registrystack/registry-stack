// Synthetic business mapping. BReg owns the reviewed action, current authority,
// target preconditions and exact same-command recovery; this file stays pure.
fn read_request(input) {
    #{ collection: "applications", recordId: input.applicationId }
}

fn information_route(record) {
    if record.data.domainData.complete { "skip" } else { "request" }
}

fn action_request(input, record) {
    #{
        action: "request-information",
        input: #{
            applicationId: input.applicationId,
            reason: "Please provide " + record.data.domainData.missingField
        }
    }
}

fn notice_request(record, action) {
    #{
        senderProfile: "transactional",
        to: #{ email: record.data.domainData.email },
        template: #{ id: "information-requested", version: "1" },
        locale: "en",
        data: #{ actionApplicationId: action.applicationId }
    }
}

fn accepted_result(action, message) {
    #{ actionApplicationId: action.applicationId, messageId: message.id }
}
