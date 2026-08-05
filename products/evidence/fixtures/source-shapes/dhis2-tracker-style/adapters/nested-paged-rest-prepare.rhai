fn prepare(selectors, parameters) {
    let subject = selectors["subject"];
    #{
        query: [
            #{name: "program", value: parameters["program"]},
            #{name: "orgUnits", value: parameters["organisationUnits"]},
            #{name: "trackedEntities", value: subject["values"]["record_reference"]},
            #{name: "fields", value: parameters["fields"]},
            #{name: "pageSize", value: parameters["pageSize"]},
            #{name: "page", value: parameters["page"]},
            #{name: "totalPages", value: parameters["totalPages"]}
        ],
        body: ()
    }
}
