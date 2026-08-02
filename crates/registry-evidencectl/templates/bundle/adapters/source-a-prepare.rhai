// Request preparation. Turns the already validated selector values and the
// reviewed adapter parameters into the request body the source expects.
// Preparation may not invent fields: everything it emits comes from a selector
// value or from a closed adapter parameter.
fn prepare(selectors, parameters) {
    let subject = selectors["subject"];
    #{
        query: [],
        body: #{
            lookup: #{
                record_reference: subject["values"]["record_reference"],
                registry_code: subject["values"]["registry_code"]
            },
            fields: parameters["requestedFields"],
            limit: parameters["resultLimit"]
        }
    }
}
