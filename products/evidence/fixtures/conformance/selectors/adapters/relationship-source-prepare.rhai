fn prepare(selectors, parameters) {
    let role_a = selectors["subject-a"];
    let role_b = selectors["subject-b"];
    let selector = #{};

    if role_a["profile"] == "opaque-record-v1" {
        selector["role_a_record_reference"] = role_a["values"]["record_reference"];
    } else {
        selector["role_a_alpha"] = role_a["values"]["alpha"];
        selector["role_a_delta"] = role_a["values"]["delta"];
        selector["role_a_kappa"] = role_a["values"]["kappa"];
    }

    if role_b["profile"] == "demographics-v1" {
        selector["role_b_given_name"] = role_b["values"]["given_name"];
        selector["role_b_family_name"] = role_b["values"]["family_name"];
        selector["role_b_birth_date"] = role_b["values"]["birth_date"];
    } else {
        selector["role_b_event_given_name"] = role_b["values"]["given_name"];
        selector["role_b_event_family_name"] = role_b["values"]["family_name"];
        selector["role_b_event_birth_date"] = role_b["values"]["birth_date"];
        selector["role_b_event_reference"] = role_b["values"]["event_reference"];
    }

    #{
        query: [],
        body: #{selector: selector, requested_fields: parameters["requestedFields"]}
    }
}
