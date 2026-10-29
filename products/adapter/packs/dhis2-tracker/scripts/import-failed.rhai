// Whether a tracker import that answered HTTP 200 still failed.
//
// The tracker importer reports its outcome in the summary body, not the
// status line: a synchronous import (async=false) answers with an import
// summary whose `status` is OK, WARNING, or ERROR, and DHIS2 has been
// observed answering 200 with error reports in the body (DHIS2
// documentation, "Tracker"; the community thread "Unexpected 409 /
// Exception:null with api/tracker"). Detecting that answer is this
// pack's concern: the engine calls `import_failed` with the import
// summary and returns true exactly when the summary reports ERROR.
// WARNING stays an acceptance: DHIS2 applied the payload. Pure and
// deterministic; no I/O.
fn import_failed(summary) {
    summary.status == "ERROR"
}
