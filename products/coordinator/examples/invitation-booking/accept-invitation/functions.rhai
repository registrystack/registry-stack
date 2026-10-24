fn invitation_route(args) {
    let invitation = args["invitation"].data.domainData;
    if invitation.state == "expired" { return "expired"; }
    if invitation.state == "revoked" { return "revoked"; }
    if invitation.state == "booked" { return "booked"; }
    if invitation.state == "accepting" { return "accepting"; }
    if invitation.state == "no-capacity" { return "no-capacity"; }
    if !invitation.acceptanceAuthorized { return "ineligible"; }
    "claim"
}

fn claim_request(args) {
    #{ input: #{ invitationId: args["input"].invitationId } }
}

fn availability_request(args) {
    let invitation = args["invitation"].data.domainData;
    let resource = if invitation.resourceRequired { invitation.resourceId } else { () };
    #{
        offering: invitation.offering,
        start: invitation.searchStart,
        end: invitation.searchEnd,
        durationMinutes: invitation.durationMinutes,
        resource: resource,
        limit: 20
    }
}

fn capacity_route(args) {
    for slot in args["availability"].items {
        if slot.kind == "slot" && slot.free > 0 { return "available"; }
    }
    "unavailable"
}

fn booking_request(args) {
    let input = args["input"];
    let invitation = args["invitation"].data.domainData;
    let metadata = args["metadata"];
    let selected = "";
    for slot in args["availability"].items {
        if slot.kind == "slot" && slot.free > 0 { selected = slot.start; break; }
    }
    let resource = if invitation.resourceRequired { invitation.resourceId } else { () };

    #{
        grant: input.grant,
        appointment: #{
            hold: (),
            admission: #{
                offering: invitation.offering,
                start: selected,
                durationMinutes: invitation.durationMinutes,
                resource: resource,
                party: #{ recipients: 1, attendees: 1 },
                manager: "schedulingManager",
                partyReferences: [#{
                    role: "beneficiary",
                    reference: #{
                        product: "breg",
                        recordType: "beneficiary",
                        identifier: invitation.beneficiaryReference
                    }
                }],
                channel: (),
                duplicateKey: invitation.acceptanceId,
                policyRevision: metadata.policyRevision,
                windowRevision: (),
                capabilities: [],
                prerequisites: [],
                externalReferences: [#{
                    product: "breg",
                    recordType: "invitation",
                    identifier: args["invitation"].data.recordIdentifier
                }]
            }
        }
    }
}

fn record_result_request(args) {
    let invitation = args["invitation"];
    #{ input: #{
        invitationId: invitation.data.recordIdentifier,
        acceptanceId: invitation.data.domainData.acceptanceId,
        appointmentId: args["appointment"].appointmentId
    } }
}

fn record_no_capacity_request(args) {
    let invitation = args["invitation"];
    #{ input: #{
        invitationId: invitation.data.recordIdentifier,
        acceptanceId: invitation.data.domainData.acceptanceId
    } }
}

fn notice_request(args) {
    let invitation = args["invitation"].data.domainData;
    let appointment = args["appointment"];
    #{
        senderProfile: "transactional",
        to: #{ email: invitation.notificationDestination },
        template: #{ id: "booking-confirmed", version: "1" },
        locale: "en",
        data: #{
            appointmentReference: appointment.appointmentId,
            appointmentStart: appointment.start
        }
    }
}
