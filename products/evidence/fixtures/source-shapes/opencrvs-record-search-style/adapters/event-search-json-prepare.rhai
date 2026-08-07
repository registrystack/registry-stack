fn prepare(selectors, context) {
    let parameters = context["parameters"];
    let subject = selectors["subject"];
    #{
        query: [],
        body: #{
            query: #{
                type: "and",
                clauses: [#{
                    eventType: parameters["eventType"],
                    status: #{type: "exact", term: parameters["registeredStatus"]},
                    trackingId: #{type: "exact", term: subject["values"]["record_reference"]}
                }]
            },
            limit: parameters["resultLimit"],
            offset: parameters["resultOffset"]
        }
    }
}
