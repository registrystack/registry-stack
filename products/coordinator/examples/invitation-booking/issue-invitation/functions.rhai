fn issue_request(args) {
    #{ input: args["input"] }
}

fn notice_request(args) {
    let invitation = args["invitation"].data.domainData;
    let record_id = args["invitation"].data.recordIdentifier;

    #{
        senderProfile: "transactional",
        to: #{ email: invitation.notificationDestination },
        template: #{ id: "booking-invitation", version: "1" },
        locale: "en",
        data: #{
            invitationReference: record_id,
            bookingUrl: "https://booking.example.invalid/invitations/" + record_id,
            expiresOn: invitation.expiresOn
        }
    }
}
