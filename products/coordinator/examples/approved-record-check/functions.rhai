// Copy only the UUID and original Unix expiry returned by Casework approval.
// The adapter acquires a fresh assertion and bearer at the time of each read.
fn not_before(input) { input.notBefore }
fn read_request(input) {
    #{ collection: input.collection, recordId: input.recordId, grant: input.grant }
}
fn minimal_result(record) { #{ recordId: record.data.recordIdentifier } }
