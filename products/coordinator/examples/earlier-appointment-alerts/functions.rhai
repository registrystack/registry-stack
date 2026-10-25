fn source_route(args) {
    let source = args["subscription"].data.domainData;
    if source.scope != "appointment" { return "suppressed"; }
    if source.state == "notified" { return "already-notified"; }
    if source.state == "dispatching" { return "dispatch-owned"; }
    if !source.consent || source.state == "withdrawn" { return "suppressed"; }
    if source.state == "active" || source.state == "claimed" { return "inspect"; }
    "suppressed"
}

fn appointment_request(args) {
    #{
        appointmentId: args["subscription"].data.domainData.appointmentId,
        grant: args["input"].detailGrant
    }
}

fn appointment_matches(subscription, appointment) {
    let source = subscription.data.domainData;
    appointment.appointmentId == source.appointmentId
        && appointment.manager == "schedulingManager"
        && appointment.state == "confirmed"
        && appointment.revision == source.appointmentRevision
}

fn appointment_route(args) {
    if appointment_matches(args["subscription"], args["appointment"]) {
        "match"
    } else {
        "changed"
    }
}

fn preview_request(args) {
    let source = args["subscription"].data.domainData;
    #{ preview: #{
        offering: source.offering,
        start: source.desiredStart,
        durationMinutes: source.durationMinutes,
        resource: source.resource,
        resourceUnits: source.resourceUnits,
        party: #{ recipients: source.partyRecipients, attendees: source.partyAttendees },
        additionalAllocations: [#{
            offering: source.additionalOffering,
            resource: source.additionalResource,
            units: source.additionalUnits
        }]
    } }
}

fn capacity_route(args) {
    if args["preview"].capacityAvailable { "available" } else { "unavailable" }
}

fn claim_route(args) {
    if args["subscription"].data.domainData.state == "active" { "claim" } else { "resume" }
}

fn claim_request(args) {
    let subscription = args["subscription"];
    #{ input: #{
        subscriptionId: subscription.data.recordIdentifier,
        conditionId: subscription.data.domainData.conditionId
    } }
}

fn final_route(args) {
    let source = args["subscription"].data.domainData;
    if source.scope == "appointment"
        && source.state == "claimed"
        && source.consent
        && appointment_matches(args["subscription"], args["appointment"]) {
        "dispatch"
    } else {
        "suppressed"
    }
}

fn authorize_request(args) {
    let subscription = args["subscription"];
    #{ input: #{
        subscriptionId: subscription.data.recordIdentifier,
        conditionId: subscription.data.domainData.conditionId
    } }
}

fn dispatch_route(args) {
    let source = args["subscription"].data.domainData;
    if source.state == "dispatching"
        && source.consent
        && appointment_matches(args["subscription"], args["appointment"]) {
        "send"
    } else {
        "suppressed"
    }
}

fn notice_request(args) {
    let source = args["subscription"].data.domainData;
    #{
        senderProfile: "transactional",
        to: #{ email: source.destination },
        template: #{ id: "earlier-appointment", version: "1" },
        locale: "en",
        data: #{
            appointmentReference: source.appointmentId,
            availableStart: source.desiredStart
        }
    }
}

fn completion_request(args) {
    let subscription = args["subscription"];
    #{ input: #{
        subscriptionId: subscription.data.recordIdentifier,
        conditionId: subscription.data.domainData.conditionId,
        messageId: args["message"].id
    } }
}
