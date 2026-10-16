// Pure mappings for the synthetic follow-up fixture. The source owns current
// notice permission and contact data; the Coordinator reads both after waiting.
fn notice_route(args) {
    let record = args["record"];

    if record.data.domainData.noticeAllowed { "send" } else { "skip" }
}

fn notice_request(args) {
    let input = args["input"];
    let record = args["record"];

    #{
        senderProfile: "transactional",
        to: #{ email: record.data.domainData.email },
        template: #{ id: "application-follow-up", version: "1" },
        locale: "en",
        data: #{ applicationReference: input.applicationId }
    }
}
