fn review_request(args) {
    let input = args["input"];
    let record = args["reservation"];
    #{
        policy: #{id: "reservation-review", version: "1", digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
        subject: #{source: "reservations", type: "reservation-request", id: input.reservationId,
                   version: input.sourceVersion, digest: input.sourceDigest},
        requesterReference: input.reservationId,
        context: #{mode: "submitted", snapshot: #{
            reservationId: input.reservationId,
            offering: record.data.domainData.offering,
            start: record.data.domainData.start,
            durationMinutes: record.data.domainData.durationMinutes,
            attendees: record.data.domainData.attendees
        }}
    }
}

fn source_decision_request(args) {
    #{ input: #{
        reservationId: args["input"].reservationId,
        reviewResultId: args["result"].resultId
    } }
}

fn agreement_request(args) {
    #{ input: #{
        reservationId: args["input"].reservationId,
        callbackId: args["input"].agreementCallbackId
    } }
}

fn withdrawal_request(args) {
    #{ input: #{reservationId: args["input"].reservationId} }
}

fn booking_request(args) {
    let input = args["input"];
    let record = args["reservation"].data.domainData;
    #{ grant: input.grant, appointment: #{ hold: (), admission: #{
        offering: record.offering,
        start: record.start,
        durationMinutes: record.durationMinutes,
        resource: record.resourceId,
        resourceUnits: 1,
        party: #{recipients: 1, attendees: record.attendees},
        manager: "schedulingManager",
        partyReferences: [#{role: "organization", reference: #{
            product: "breg", recordType: "reservation-request", identifier: input.reservationId
        }}],
        channel: (), duplicateKey: record.requestKey,
        policyRevision: args["metadata"].policyRevision, windowRevision: (),
        capabilities: [], prerequisites: [], externalReferences: [#{
            product: "breg", recordType: "reservation-request", identifier: input.reservationId
        }]
    } } }
}

fn record_confirmation_request(args) {
    #{ input: #{
        reservationId: args["input"].reservationId,
        appointmentId: args["appointment"].appointmentId
    } }
}

fn notice_request(args) {
    let record = args["reservation"].data.domainData;
    #{ senderProfile: "transactional", to: #{email: record.notificationDestination},
       template: #{id: "reservation-confirmed", version: "1"}, locale: "en",
       data: #{reservationReference: args["input"].reservationId,
               appointmentReference: args["appointment"].appointmentId} }
}
