// Creates the household from the Action inputs. `owner` must equal the
// `sub` claim of the ingestion client's token: the access profile's row
// boundary matches on it. Replace the literal with your client's subject.
fn plan(ctx) {
    #{effects: [#{
        id: "household",
        operation: "create",
        set: #{
            owner: "adapter-kobo-ingestion",
            "source-submission-id": ctx.inputs["source-submission-id"],
            "respondent-name": ctx.inputs["respondent-name"],
            "household-size": ctx.inputs["household-size"]
        }
    }]}
}
