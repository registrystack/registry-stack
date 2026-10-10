// The grant is an approval reference with its original deadline, never a token.
// Casework checks current source authority; Scheduling owns every capacity commitment.
fn read_request(input) {
    #{ collection: "applications", recordId: input.applicationId }
}
fn appointment_route(record) {
    if record.data.domainData.appointmentAllowed { "book" } else { "skip" }
}
fn book_after(input) { input.bookAfter }
fn metadata_request() { #{} }
fn availability_request(input) {
    #{ offering: "application-review", start: input.searchStart, end: input.searchEnd, limit: 20 }
}
fn capacity_route(availability) {
    for slot in availability.items {
        if slot.kind == "slot" && slot.free > 0 { return "available"; }
    }
    "unavailable"
}
fn booking_request(input, metadata, availability) {
    let selected = "";
    for slot in availability.items {
        if slot.kind == "slot" && slot.free > 0 { selected = slot.start; break; }
    }
    #{ grant: input.grant, appointment: #{ hold: (), admission: #{
        offering: "application-review", start: selected,
        party: #{ recipients: 1, attendees: 1 }, channel: (),
        duplicateKey: input.applicationId, policyRevision: metadata.policyRevision,
        windowRevision: (), capabilities: [], prerequisites: [],
        externalReferences: [#{ product: "breg", recordType: "applications", identifier: input.applicationId }]
    } } }
}
fn notice_request(input, record, appointment) {
    #{ senderProfile: "transactional", to: #{ email: record.data.domainData.email },
       template: #{ id: "appointment-confirmed", version: "1" }, locale: "en",
       data: #{ applicationReference: input.applicationId, appointmentReference: appointment.appointmentId,
                appointmentStart: appointment.start } }
}
fn accepted_result(appointment, receipt) {
    #{ appointmentId: appointment.appointmentId, messageId: receipt.id }
}
