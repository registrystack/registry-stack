# Household History Acceptance Fixture

This fixture exercises Registry Server correction and historical snapshot behavior
with a small effective-membership model. The runtime entity is intentionally
generic: `membership-record` stores a subject, a group, and a validity interval.

The executable workflow lives in
`products/registry-server/scripts/test-historical-workflow.sh`. It builds and
applies signed packages, writes records only through the authenticated HTTP API,
captures snapshot references returned by the server, and verifies that a
downstream consumer decision can retain its original snapshot, effective date,
input revision, rule package, and decision identifier until a distinct
reconsideration is made.

Run from the repository root with Cargo, Python 3, OpenSSL and `psql` available.
Use a disposable PostgreSQL server with TLS and permission to create temporary
databases and roles. Do not point this acceptance workflow at production.

Supply these environment variables through a trusted, owner-only local file:

- `REGISTRY_SERVER_TEST_DATABASE_URL`: the disposable administrator connection.
- `REGISTRY_SERVER_TEST_TLS_CA_PEM_PATH`: the absolute path to its PEM CA
  certificate. The connection hostname must match the certificate.

After loading that private test environment, run:

```bash
products/registry-server/scripts/test-historical-workflow.sh
```

The script builds the two binaries, creates its own databases and credentials,
then tests correction, exact replay, stale-edit refusal, snapshot reads, restart,
additive upgrade, a post-upgrade write and access revocation. It prints
`historical workflow:` checkpoints before each major phase so a failing transcript
shows whether v1 correction and restart, v2 additive upgrade and post-upgrade
write, or v3 snapshot revocation was reached. Access-profile review notices from
package checking are informational for this fixture unless the command exits
nonzero. An assertion failure exits nonzero. Normal exit and failures clean up the
resources created by this run. The existing adopter workflow invokes the same test
automatically.

For the API and operator semantics behind the assertions, see
[Corrections and historical queries](../../HISTORY.md).
