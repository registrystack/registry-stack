// Whether the tracker search loop fetches another page.
//
// The engine calls `has_more_pages` after each fetched page, with the
// loop's paging map:
//
//   page          the last fetched DHIS2 page number (integer)
//   totalPages    the total page count the last fetch reported (integer;
//                 DHIS2 fills it only when the request carries
//                 totalPages=true, which this pack always sends)
//   maximumPages  the pack's reviewed page bound (integer)
//
// Returns true while another page stays within both the source's total
// and the reviewed bound. A fetch that reports no usable total ends the
// loop rather than paging blind. Pure and deterministic; no I/O.
fn has_more_pages(paging) {
    if paging.page >= paging.maximumPages {
        return false;
    }
    if paging.totalPages <= 0 {
        return false;
    }
    paging.page < paging.totalPages
}
