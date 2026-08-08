fn prepare(selectors, context) {
    let parameters = context["parameters"];
    let prior_facts = context["prior_facts"];
    // This member takes its input through the JSON body it builds here. Only
    // the allowlisted search fact is readable: every other search fact was
    // removed before this script ran.
    #{
        query: [],
        body: #{
            filter: #{
                registerScope: parameters["registerScope"],
                relationRole: parameters["relationRole"],
                holderReference: #{operator: "exact", value: prior_facts["subject_reference"]}
            },
            limit: parameters["resultLimit"],
            offset: parameters["resultOffset"]
        }
    }
}
