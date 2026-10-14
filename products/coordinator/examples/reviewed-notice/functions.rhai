// A trusted starter computes applicationDigest over this exact bounded
// projection before it starts the run. The Coordinator reads the application
// and verifies that its revision is still the starter's reviewed revision.
fn review_subject_route(args) {
    let input = args["input"];
    let record = args["record"];

    if record.data.recordIdentifier == input.applicationId
        && record.data.revisionIdentifier == input.applicationRevision {
        "current"
    } else {
        "changed"
    }
}

fn review_request(args) {
    let input = args["input"];
    let record = args["record"];

    #{
        policy: #{id: "application-review", version: "1", digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        subject: #{
            source: "applications",
            type: "application",
            id: input.applicationId,
            version: input.applicationRevision,
            digest: input.applicationDigest
        },
        requesterReference: input.applicationId,
        context: #{
            mode: "submitted",
            snapshot: #{
                applicantName: record.data.domainData.applicantName,
                benefitProgram: record.data.domainData.benefitProgram,
                requestedAmount: record.data.domainData.requestedAmount
            }
        }
    }
}

// Revoked consent is reported explicitly even though changing that field also
// advances the record revision. Every other revision change takes the changed
// outcome. A notice requires both the reviewed revision and current consent.
fn notice_route(args) {
    let input = args["input"];
    let record = args["record"];

    if !record.data.domainData.noticeAllowed {
        "permission-gone"
    } else if record.data.recordIdentifier != input.applicationId
        || record.data.revisionIdentifier != input.applicationRevision {
        "changed"
    } else {
        "send"
    }
}

fn notice_request(args) {
    let input = args["input"];
    let result = args["result"];
    let record = args["record"];

    #{
        senderProfile: "transactional",
        to: #{ email: record.data.domainData.email },
        template: #{ id: "application-approved", version: "1" },
        locale: "en",
        data: #{ applicationReference: input.applicationId, reviewResult: result.resultId }
    }
}
