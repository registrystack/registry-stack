// Casework decides who reviews and what a reviewer sees. The request names the
// application version under review and submits the only context a reviewer is
// shown, so Casework needs no source adapter for it. The notice cites the
// review result by id and repeats none of its content.
fn review_request(args) {
    let input = args["input"];

    #{
        policy: #{id: "application-review", version: "1", digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        subject: #{
            source: "applications",
            type: "application",
            id: input.applicationId,
            version: input.applicationVersion,
            digest: input.applicationDigest
        },
        requesterReference: input.applicationId,
        context: #{
            mode: "submitted",
            snapshot: #{
                applicationId: input.applicationId,
                applicationVersion: input.applicationVersion
            }
        }
    }
}

fn notice_request(args) {
    let input = args["input"];
    let result = args["result"];

    #{
        senderProfile: "transactional",
        to: #{ email: input.email },
        template: #{ id: "application-approved", version: "1" },
        locale: "en",
        data: #{ applicationReference: input.applicationId, reviewResult: result.resultId }
    }
}
