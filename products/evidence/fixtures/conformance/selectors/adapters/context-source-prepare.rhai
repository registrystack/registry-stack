fn prepare(selectors, context) {
    let parameters = context["parameters"];
    let subject = selectors["subject"]["values"];
    #{
        query: [],
        body: #{
            selector: #{
                context_given_name: subject["given_name"],
                context_family_name: subject["family_name"],
                context_birth_date: subject["birth_date"]
            },
            requested_fields: parameters["requestedFields"]
        }
    }
}
