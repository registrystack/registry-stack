fn patient_matches_selectors(patient, input) {
    if patient.birthDate != input.birthdate {
        return false;
    }
    for name in patient.name {
        if name.family == input.family {
            for given in name.given {
                if given == input.given {
                    return true;
                }
            }
        }
    }
    false
}

fn consult(ctx) {
    let patient_response = source.get("/fhir/Patient", #{
        query: #{
            _count: 2,
            birthdate: ctx.input.birthdate,
            family: ctx.input.family,
            given: ctx.input.given
        }
    });
    if patient_response.status != 200 {
        return result.fail(failure.source_rejected);
    }
    let page = protocol.fhir.parse_searchset(patient_response, "Patient");
    let patients = page.matches;
    if patients.len < 2 && page.next != () {
        let continuation_response = source.get(page.next);
        if continuation_response.status != 200 {
            return result.fail(failure.source_rejected);
        }
        let continuation = protocol.fhir.parse_searchset(continuation_response, "Patient");
        for patient in continuation.matches {
            patients.push(patient);
        }
        if continuation.next != () {
            return result.ambiguous();
        }
    }
    if patients.len == 0 {
        return result.no_match();
    }
    if patients.len > 1 {
        return result.ambiguous();
    }
    let patient = patients[0];
    if !patient_matches_selectors(patient, ctx.input) {
        return result.fail(failure.subject_mismatch);
    }

    let coverage_response = source.get("/fhir/Coverage", #{
        query: #{ _count: 2, beneficiary: "Patient/" + patient.id }
    });
    if coverage_response.status != 200 {
        return result.fail(failure.source_rejected);
    }
    let coverage_search = protocol.fhir.parse_searchset(coverage_response, "Coverage");
    if coverage_search.matches.len == 0 {
        return result.no_match();
    }
    if coverage_search.matches.len > 1 || coverage_search.next != () {
        return result.ambiguous();
    }
    let coverage = coverage_search.matches[0];
    let payor_reference = coverage.payor[0].reference;
    let reference_parts = payor_reference.split("/");
    if reference_parts.len != 2 || reference_parts[0] != "Organization" {
        return result.fail(failure.source_rejected);
    }

    let organization_target = source.path(
        "/fhir/Organization/{organization_id}",
        #{ organization_id: reference_parts[1] }
    );
    let organization_response = source.get(organization_target);
    if organization_response.status != 200 || organization_response.body.resourceType != "Organization" {
        return result.fail(failure.source_rejected);
    }
    result.match(#{
        coverage_status: coverage.status,
        insurer_name: organization_response.body.name
    })
}
