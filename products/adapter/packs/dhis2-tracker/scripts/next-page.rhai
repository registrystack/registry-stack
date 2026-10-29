// The page number the tracker search loop asks for next.
//
// The engine calls `next_page` with the loop's paging map (see
// scripts/has-more-pages.rhai) and returns the page number one past the
// last fetched page. Pure and deterministic; no I/O.
fn next_page(paging) {
    paging.page + 1
}
