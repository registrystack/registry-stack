# DHIS2 2.41.9 enrollment-status consultation profile

This directory contains a Registry Stack-maintained, unofficial consultation
profile for one bounded journey: read the enrollment status for one exact DHIS2
tracked-entity UID in one fixed program.

The fixed `registry-notary` workload selects the exact tracked-entity UID under
the profile's public-task legal basis. This profile does not claim an
individual subject-binding assertion or individual consent, and its public
contract explicitly declares consent is not required.

The reviewed operation is one Basic-authenticated `GET` to
`/api/tracker/enrollments`. Its query is closed to:

- the canonical consultation input in `trackedEntity`;
- one pack-owned `program` UID;
- `orgUnitMode=ALL`;
- `fields=status`;
- `pageSize=2`, which allows Relay to distinguish no match, one match, and an
  ambiguous result without following pagination.

The response contract is the exact DHIS2 2.41.9 envelope observed by the
redacted interoperability probe: `enrollments`, `page`, `pageSize`, and
`pager`, where `pager` contains `page` and `pageSize`. Only `status` is acquired
from an enrollment and released. Unknown envelope or record members are
rejected.

The fixed program UID is deliberately part of the integration-pack hash. A
country using another DHIS2 program must review and mint a new pack rather than
turning the program into caller-selected runtime configuration. The example
private binding uses a pure root-origin placeholder, an exact
`/stable-2-41-9` application base path, and an environment-backed Basic
credential reference. The compiler concatenates that hash-covered base path
with the pack-owned `/api/tracker/enrollments` path without normalization or
caller input. The destination policy still owns only the HTTPS origin for DNS
and TLS enforcement. The example contains no credential value or live host.

Compilation and synthetic response fixtures earn only repository conformance
evidence. They do not claim DHIS2 maintainer endorsement, a country deployment,
or a successful Relay end-to-end execution. A root-mounted deployment may omit
`application_base_path`; omission and an explicit `/` compile to the same
canonical root binding.
