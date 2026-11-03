// Example-only programme mapping. It turns one projected view row into the
// inputs of the BReg `register-household` Action in ../../kobotoolbox-breg.
// The Action's `sourceSubmissionId` input carries the view's `id`. The job
// document pins this file by digest.
fn map_household(exchange) {
    #{
        startInput: #{
            input: #{
                sourceSubmissionId: exchange.body.id,
                respondentName: exchange.body.respondent_name,
                householdSize: exchange.body.household_size
            }
        },
        submitBody: #{}
    }
}
