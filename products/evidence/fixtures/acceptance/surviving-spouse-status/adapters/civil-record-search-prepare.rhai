fn prepare(selectors, context) {
    let parameters = context["parameters"];
    let subject = selectors["subject"];
    #{
        query: [],
        body: #{
            lookup: #{
                family_name: subject["values"]["family_name"],
                given_name: subject["values"]["given_name"],
                date_of_birth: subject["values"]["date_of_birth"]
            },
            fields: parameters["requestedFields"],
            limit: parameters["resultLimit"]
        }
    }
}
