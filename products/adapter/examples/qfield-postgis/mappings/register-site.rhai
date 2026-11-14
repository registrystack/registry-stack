// The source view returns one complete site. Both jobs bind the same
// typed values to their separately authorized BReg Actions.
fn site_input(row) {
    #{
        sourceSubmissionId: row.id,
        siteName: row.site_name,
        position: row.position,
        boundary: row.boundary,
        contacts: row.contacts
    }
}

fn map_immediate(exchange) {
    #{input: site_input(exchange.body)}
}

fn map_proposal(exchange) {
    #{startInput: #{input: site_input(exchange.body)}, submitBody: #{}}
}
