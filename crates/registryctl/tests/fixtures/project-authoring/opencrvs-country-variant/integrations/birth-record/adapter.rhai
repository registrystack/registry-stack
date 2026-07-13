fn consult(ctx) {
    let verified = protocol.dci.search(#{
        selectors: #{ registration_number: ctx.input.registration_number },
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
        date_of_birth: record.person.birth.date,
        sex: record.person.birth.sex_code,
        child_given_name: record.person.names.primary_given,
        child_family_name: record.person.names.primary_family,
        place_of_birth: record.person.birth.locality
    })
}
