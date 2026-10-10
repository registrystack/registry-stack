// Pure mappings for the synthetic follow-up fixture. The source owns current
// notice permission and contact data; the Coordinator reads both after waiting.
fn send_after(input) {
    input.sendAfter
}

fn read_request(input) {
    #{ collection: "applications", recordId: input.applicationId }
}

fn notice_route(record) {
    if record.data.domainData.noticeAllowed { "send" } else { "skip" }
}

fn notice_request(input, record) {
    #{
        senderProfile: "transactional",
        to: #{ email: record.data.domainData.email },
        template: #{ id: "application-follow-up", version: "1" },
        locale: "en",
        data: #{ applicationReference: input.applicationId }
    }
}

fn receipt_result(receipt) {
    #{ messageId: receipt.id }
}
