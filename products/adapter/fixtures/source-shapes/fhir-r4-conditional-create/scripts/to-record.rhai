// The Patient as read back after the create, mapped to the record slot
// object the breg-records single-record envelope wraps.
//
// The engine is assumed to call `to_record` with the exchange map: the
// body is the Patient the follow-up read returned, and
// `properties.fhirIdentifierSystem` the template's identifier system.
// Pure and deterministic; no I/O.
fn to_record(exchange) {
    let patient = exchange.body;
    if patient.resourceType != "Patient" || patient.id == () {
        throw "the read-back is not a Patient";
    }
    let national_id = ();
    for identifier in patient.identifier {
        if identifier.system == exchange.properties.fhirIdentifierSystem {
            national_id = identifier.value;
        }
    }
    let given = ();
    let family = ();
    if patient.name != () && patient.name.len() > 0 {
        family = patient.name[0].family;
        for part in patient.name[0].given {
            if given == () { given = part; } else { given = given + " " + part; }
        }
    }
    #{
        recordIdentifier: patient.id,
        revisionIdentifier: patient.meta.versionId,
        domainData: #{
            national_id: national_id,
            family_name: family,
            given_names: given,
            birth_date: patient.birthDate,
            gender: patient.gender
        }
    }
}
