// Pure mapping for the maintained Kobo ingestion workflow. Trigger mappings
// stay total; all optional-field handling happens inside the Run.

fn source_submission_id(value) {
    if value.type_of() == "string" {
        value
    } else if value.type_of() == "i64" {
        value.to_string()
    } else {
        throw "source submission id has an unsupported type";
    }
}

fn household_size(value) {
    if value.type_of() == "i64" {
        value
    } else if value.type_of() == "string" {
        parse_int(value)
    } else {
        throw "household size has an unsupported type";
    }
}

fn proposal_request(args) {
    let event = args["event"];
    #{ input: #{
        sourceSubmissionId: source_submission_id(event.item["_id"]),
        respondentName: event.item.respondent_name,
        householdSize: household_size(event.item["household.household_size"])
    }}
}

fn lookup_request(args) {
    let event = args["event"];
    #{
        entity: "households",
        selector: "by-source-submission",
        values: #{ sourceSubmissionId: source_submission_id(event.item["_id"]) }
    }
}

fn review_context(event, resolution, record_id) {
    let snapshot = #{
        resolution: resolution,
        sourceSubmissionId: source_submission_id(event.item["_id"]),
        respondentName: event.item.respondent_name,
        householdSize: household_size(event.item["household.household_size"])
    };
    if event.contains("priorRunId") {
        snapshot.priorRunId = event.priorRunId;
    }
    if record_id != "" {
        snapshot.recordId = record_id;
    }
    #{
        policy: #{
            id: "household-ingestion-review",
            version: "1",
            digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        subject: #{
            source: "adapter-ingestion",
            type: event.job.id,
            id: event.key,
            version: event.sequence.to_string(),
            digest: event.digest
        },
        requesterReference: event.key,
        context: #{ mode: "submitted", snapshot: snapshot }
    }
}

fn resolved_review_request(args) {
    review_context(args["event"], "resolved", args["lookup"].recordIdentifier)
}

fn unresolved_review_request(args) {
    review_context(args["event"], "unresolved", "")
}

fn returned_review_request(args) {
    review_context(args["event"], "proposal-returned", "")
}
