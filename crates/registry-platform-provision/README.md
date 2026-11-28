# Registry Platform Provision

`registry-platform-provision` turns what a product needs from an empty
PostgreSQL server into an ordered plan of statements: the migration and runtime
login roles, an isolated database that is closed to `PUBLIC`, the schema layout
the product's migrations expect, and the optional `btree_gist` and PostGIS
extensions.

A product describes itself as data (`ProductDatabase`) and names its roles and
database (`ProvisionTarget`). The crate carries no product, schema or role
name.

- `plan` builds the statements. A statement with a `Probe` runs only when its
  object is absent. A grant, revoke or connection switch has no probe and is
  safe to run again. A single-role target (one name for both roles) plans one
  role.
- `render_script` prints the plan for an administrator to review and run with
  `psql`. The script holds no password and no password verifier: each login
  role is followed by a `\password` line, and a statement that needs a
  superuser is marked.
- `verify_server_version` refuses a server below the shared PostgreSQL floor,
  `registry_platform_activation::MINIMUM_SERVER_VERSION_NUM`.
- `sql` holds the statement builders and the identifier and literal quoting.

Passwords enter only through `RoleCredential`, whose `Debug` prints the name.
The executable text of a role statement carries a SCRAM-SHA-256 verifier
computed in the client, never the password. No API in this crate prints,
formats or logs a secret.

This crate builds plans only. It opens no connection.

The `test-support` feature adds `test_support`, a verified-TLS superuser
session and the two `PROVISION_TEST_DATABASE_*` variables, for the provision
tests of `registry-caseworkctl`, `registry-coordinator` and
`registry-documentsctl`. Only their dev-dependencies enable it.
