# Run a project for development

Use `rstack dev` to start a checkout's BReg and Casework projects together.
Install matching BReg and Casework components and supply a dedicated development
PostgreSQL server over TLS. The database administrator needs to create and
remove roles and databases and install `btree_gist`. Use the platform's trusted
roots or set `RSTACK_DEV_DATABASE_CA` to your server's CA bundle in PEM format.

```sh
rstack install breg casework
# Set RSTACK_DEV_DATABASE_URL through your shell's secret provider.
rstack dev start ./licensing --ttl 30m --json
rstack dev status RUN_ID
rstack dev token RUN_ID --as applicant --json
rstack dev stop RUN_ID
```

You can also pass `--database-url`. Use the environment variable when the URL
includes a password. Start reports the product URLs and the journey result.
A failed journey exits 1 and includes the live run ID so you can inspect the
result and stop the run. Startup failures clean up or report the run ID if
cleanup is pending. The TTL starts at readiness and defaults to 30 minutes.
Supply one whole-number value from `1s` to `24h` with an `s`, `m`, or `h` suffix.

The [licensing example](examples/licensing/dev.yaml) creates an application in
BReg, requests approval of the captured application in Casework, and checks the
reviewer's decision. Point `start` at the directory containing `dev.yaml`.
Product files remain byte-for-byte unchanged. Generated runtime settings, keys,
and packages live in the run's owner-only scratch directory.

## Write the development plan

Use the [versioned plan schema](../breg/generated/tools/project-dev.v1alpha1.schema.json).
List the project's issuer, product directories and audiences in startup order,
and test people with synthetic subjects and exact product grants. A grant selects
the access profile, scopes, and additional claims. Each selected profile gets
the test person's subject in its principal claim. The products enforce their
ordinary permissions. If several people match a BReg schema-test step, select
its alias under `schemaTestPeople.<journey-id>.<step-id>`. The run obtains the
normal schema-test receipt before packaging.

For a native review handoff, `bindings.bregReviewAuthority` identifies the
Casework producer, and `bindings.caseworkContextProvider` identifies the BReg
context provider and action. The run pairs the provider on a private copy
before packaging. A reviewer whose Casework context call forwards the bearer
to BReg declares both grants, one shared client, and `caseworkContext: true`.
Both grants declare the same scopes and additional claims. Casework reads the
token subject or the BReg principal claim. The token carries both audiences
and the authority explicitly shared by both grants.
See the [native review example](../breg/acceptance/reviewed-evidence-journey/dev.yaml).

Journey steps call relative product API paths and assert the HTTP status and
optional JSON-pointer values. Capture a string or number by JSON pointer and
refer to it as `{{capture-name}}` in a later path, request body, header, or
expected value. Use URI-safe characters for values in a path. Each step names
the test person it runs as.

Use a bounded GET poll for asynchronous delivery or result retrieval. Each
poll can wait up to 60 seconds. A journey can make at most 512 requests and
transfer at most 8 MiB of request and response bodies in total.

`token` writes a short-lived bearer header file for each grant. Its JSON report
gives the file path and the selected profile. Pass the file to curl with
`--header @HEADER_FILE`. With BReg, include the selected profile as the
`accessProfile` query parameter. With Casework, the header file carries the profile.

## Run isolation

Each run listens on loopback, creates separate databases and migration and
runtime logins, and pins its own public signing key in the runtime files. The
local issuer signs under the project's issuer name with a key unique to the run.
Use synthetic test people and keep the issuer's private directory under your
user account.

Stop and TTL expiry terminate the services and remove the databases, roles,
keys, and run files. If PostgreSQL temporarily becomes unavailable, the
supervisor retries cleanup and `stop` reports pending work. Keep the supervisor
alive to finish cleanup when PostgreSQL returns. After an uncatchable
supervisor exit or machine failure, identify the exact databases and roles by
run ID before removing them.
