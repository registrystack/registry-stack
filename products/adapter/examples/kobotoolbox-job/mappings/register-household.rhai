// Example-only programme mapping. The Kobo provider pack stays reusable:
// this job-owned file maps its declared projection into one synthetic BReg
// Proposal Action input and is pinned by the job document.
fn source_submission_id(value) {
    if value.type_of() == "string" {
        return value;
    }
    if value.type_of() == "i64" {
        return value.to_string();
    }
    throw "source submission id is not a string or integer";
}

fn household_size(value) {
    if value.type_of() == "i64" {
        return value;
    }
    if value.type_of() == "string" {
        return parse_int(value);
    }
    throw "household size is not an integer or integer string";
}

fn map_submission(exchange) {
    #{
        startInput: #{
            input: #{
                sourceSubmissionId: source_submission_id(exchange.body["_id"]),
                respondentName: exchange.body.respondent_name,
                householdSize: household_size(exchange.body["household.household_size"])
            }
        },
        submitBody: #{}
    }
}
