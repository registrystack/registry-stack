// The validated facade record, as a FHIR R4 transaction Bundle carrying
// one conditional create.
//
// The direct form of a FHIR conditional create is
// `POST [base]/Patient` with the header `If-None-Exist: identifier=...`
// (https://hl7.org/fhir/R4/http.html#ccreate). The `to` step declares no
// request headers, so that form cannot be authored. The transaction form
// carries the same condition in the body as `entry.request.ifNoneExist`
// (https://hl7.org/fhir/R4/bundle-definitions.html#Bundle.entry.request.ifNoneExist),
// which servers process with the conditional-create rules: no match
// creates (201), one match returns the existing resource (200) without a
// second create, more than one match fails (412).
//
// The engine is assumed to call `to_transaction` with the exchange map:
// `body` is the validated facade record and `properties.fhirIdentifierSystem`
// the template's identifier system. A record without a national_id has
// no condition to guard the create: the script throws, because an
// unconditioned POST is not idempotent and the endpoint operation's
// idempotentUpstream claim would be false. Pure and deterministic; no I/O.
fn to_transaction(exchange) {
    let record = exchange.body;
    let national_id = record.national_id;
    if national_id == () || national_id == "" {
        throw "the record carries no national_id to condition the create on";
    }
    let system = exchange.properties.fhirIdentifierSystem;
    let given = [];
    if record.given_names != () {
        given = record.given_names.split(" ");
    }
    #{
        resourceType: "Bundle",
        type: "transaction",
        entry: [
            #{
                resource: #{
                    resourceType: "Patient",
                    identifier: [ #{ system: system, value: national_id } ],
                    name: [ #{ family: record.family_name, given: given } ],
                    birthDate: record.birth_date,
                    gender: record.gender
                },
                request: #{
                    method: "POST",
                    url: "Patient",
                    ifNoneExist: "identifier=" + system + "|" + national_id
                }
            }
        ]
    }
}
