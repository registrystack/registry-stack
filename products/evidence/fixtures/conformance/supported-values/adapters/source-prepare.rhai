fn prepare(selectors, parameters) {
    let subject = selectors["subject"];
    #{
        query: [],
        body: #{
            lookup: #{opaque_id: subject["values"]["opaque_id"]},
            fields: parameters["requestedFields"],
            limit: parameters["resultLimit"]
        }
    }
}
