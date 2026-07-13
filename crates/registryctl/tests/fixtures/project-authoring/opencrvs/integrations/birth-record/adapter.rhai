fn consult(ctx) {
    let verified = protocol.dci.search(#{
        selectors: #{ uin: ctx.input.uin },
        parameters: #{}
    });
    let records = verified.message.search_response[0].data.reg_records;
    if records.len == 0 {
        return result.no_match();
    }
    if records.len > 1 {
        return result.ambiguous();
    }
    let record = records[0];
    result.match(#{
        date_of_birth: record.child.date_of_birth,
        sex: record.child.sex,
        child_given_name: record.child.given_name,
        child_family_name: record.child.family_name,
        place_of_birth: record.place_of_birth
    })
}
