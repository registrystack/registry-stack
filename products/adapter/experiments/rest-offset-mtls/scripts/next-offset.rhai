// The next JSON:API `page[offset]`: the current offset plus the page limit.
fn next_offset(exchange) {
    exchange.properties.pageOffset + parse_int(exchange.properties.pageLimit)
}
