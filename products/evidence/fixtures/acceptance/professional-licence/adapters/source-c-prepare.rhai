fn prepare(selectors, parameters) {
    let subject = selectors["subject"];
    #{
        query: [
            #{name: "licence_reference", value: subject["values"]["licence_reference"]},
            #{name: "registry_region", value: subject["values"]["registry_region"]},
            #{name: "fields", value: parameters["requestedFields"]},
            #{name: "limit", value: parameters["resultLimit"]}
        ],
        body: ()
    }
}
