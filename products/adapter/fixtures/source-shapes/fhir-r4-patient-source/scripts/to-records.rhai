// FHIR R4 Patient resources, mapped to the record slot objects the
// breg-records collection envelope wraps.
//
// The engine is assumed to call `to_records` with the exchange map: the
// body's `records` member holds the Patient resources the loop appended,
// and `properties.fhirIdentifierSystem` the template's identifier system.
// No document says what a setBody `rhai` expression receives; the README
// records the gap. Mapping (https://hl7.org/fhir/R4/patient.html):
//   recordIdentifier   Patient.id
//   revisionIdentifier Patient.meta.versionId
//   family_name        Patient.name[use=official].family, else name[0]
//   given_names        the same name's given[], space-joined
//   birth_date         Patient.birthDate
//   gender             Patient.gender
//   national_id        Patient.identifier[system=<identifierSystem>].value
// Pure and deterministic; no I/O.
fn to_records(exchange) {
    let patients = exchange.body.records;
    let identifier_system = exchange.properties.fhirIdentifierSystem;
    let records = [];
    for patient in patients {
        if patient.resourceType != "Patient" {
            throw "a searchset match is not a Patient";
        }
        if patient.id == () {
            throw "a Patient carries no id";
        }
        let name = official_name(patient.name);
        let national_id = ();
        if patient.identifier != () {
            for identifier in patient.identifier {
                if identifier.system == identifier_system {
                    national_id = identifier.value;
                }
            }
        }
        let version = ();
        if patient.meta != () {
            version = patient.meta.versionId;
        }
        records.push(#{
            recordIdentifier: patient.id,
            revisionIdentifier: version,
            domainData: #{
                family_name: name.family,
                given_names: name.given,
                birth_date: patient.birthDate,
                gender: patient.gender,
                national_id: national_id
            }
        });
    }
    records
}

fn official_name(names) {
    if names == () || names.len() == 0 {
        return #{ family: (), given: () };
    }
    let chosen = names[0];
    for name in names {
        // `use` is a reserved Rhai keyword, so FHIR's HumanName.use is read
        // by index, not by property access.
        if name["use"] == "official" {
            chosen = name;
        }
    }
    let given = ();
    if chosen.given != () {
        for part in chosen.given {
            if given == () {
                given = part;
            } else {
                given = given + " " + part;
            }
        }
    }
    #{ family: chosen.family, given: given }
}
