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
  role is followed by a `\password` line, a statement that needs a superuser
  is marked, and the script stops at the first error. A role or database name
  with a control character or a backslash, a database name with `=`, the
  role names `public`, `none` and `pg_*`, and the databases `postgres`,
  `template0` and `template1` are refused when the plan is built, so no name
  can start a `psql` meta-command or reach another database.
- `verify_server_version` refuses a server below the shared PostgreSQL floor,
  `registry_platform_activation::MINIMUM_SERVER_VERSION_NUM`.
- `sql` holds the statement builders and the identifier and literal quoting.
- `execute` and `execute_recording` run a plan against a server as an
  administrator, and `verify_logins` opens a session as each product role.
  They open network connections. `admin_config` accepts only a `postgres://`
  URL naming one TCP host, and every connection uses TLS verified against
  `caBundleRef` or the platform roots (`sslmode=verify-ca` is checked as
  `verify-full`). In `Mode::Converge` the server version is checked before the
  first statement, and an existing role, database, schema or extension in
  another shape is refused and never altered: a role with other attributes,
  role-level settings or a membership the plan did not grant, a template
  database, a PostGIS installed outside the plan's schema or without the bbox
  membership. `execute_recording` keeps the outcomes of the statements that
  ran before a failure.

Passwords enter only through `RoleCredential`, whose `Debug` prints the name.
The executable text of a role statement carries a SCRAM-SHA-256 verifier
computed in the client, never the password. No API in this crate prints,
formats or logs a secret.

## Features

- `cli` adds the shared `provision` command (`cli::run_provision`): its clap
  arguments, the runner and the report. A product supplies a loader that turns
  its runtime file into a `ProvisionInput`. The runner reads role and database
  names and passwords from the two product URLs, opens a connection only
  outside `--print-sql`, and never prints a password, a verifier or a URL.
- `schema` renders the report's JSON Schema from its Rust type.
- `test-support` adds `test_support`, a verified-TLS superuser session and the
  two `PROVISION_TEST_DATABASE_*` variables, for the provision tests of the
  products that use this crate. Only their dev-dependencies enable it.
- `postgres-test` runs `tests/postgres.rs` against a disposable server. Its
  header names the three variables it needs.
