fn prepare(selectors, context) {
    let parameters = context["parameters"];
    let subject = selectors["subject"];
    #{
        query: [
            #{name: "program", value: parameters["program"]},
            #{name: "orgUnits", value: parameters["organisationUnit"]},
            #{name: "trackedEntities", value: subject["values"]["record_reference"]},
            #{name: "fields", value: parameters["providerFields"]},
            #{name: "pageSize", value: parameters["pageSize"]},
            #{name: "page", value: parameters["page"]},
            #{name: "totalPages", value: parameters["totalPages"]}
        ],
        body: ()
    }
}
