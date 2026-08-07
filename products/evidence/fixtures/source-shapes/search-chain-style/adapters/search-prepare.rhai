fn prepare(selectors, context) {
    let parameters = context["parameters"];
    let subject = selectors["subject"];
    #{
        query: [],
        body: #{
            filter: #{
                registerScope: parameters["registerScope"],
                recordStatus: parameters["recordStatus"],
                subjectReference: #{operator: "exact", value: subject["values"]["record_reference"]}
            },
            limit: parameters["resultLimit"],
            offset: parameters["resultOffset"]
        }
    }
}
