# Registry Stack CLI API tooling

`registry-cli-api` owns the shared implementation behind each product CLI's raw
`api` and saved `connection` commands. It provides bounded HTTP requests,
strict saved-connection parsing, secret references, renewable
`private_key_jwt` credentials, private CA trust, and project-scoped connection
selection.

Product adapters retain product semantics. They resolve named local clients,
declare any access-profile header names, and decide where these commands appear
in their CLI. This crate does not interpret API resources, grants, revisions,
or product-specific request bodies.

Saved connections use the one registered `PlatformCliConnections` YAML format.
Credentials remain in file or environment secret providers; the YAML stores
references only. `rstack <product> connection check --file FILE` checks a
document without resolving credentials or contacting an endpoint. The checked-in
schema is [schema/connections.schema.json](schema/connections.schema.json), and
an example is [example/connections.yaml](example/connections.yaml). Structured
check output uses the shared `PlatformCliConnectionCheckReport` contract in
[schema/connection-check-report.schema.json](schema/connection-check-report.schema.json),
with [example/connection-check-report.json](example/connection-check-report.json)
as its maintained example.

## Security boundary

Connection selection does not create product authority. `--client` delegates
to the product adapter, which owns any retained local endpoint, credential,
profile headers, and readiness checks. `--connection` materializes one saved
connection for that product. `--url` is an advanced one-off destination with
no automatic credential unless `--token-file` is supplied. A saved
connection's automatic authentication mode is one of anonymous, a referenced
bearer, or `private_key_jwt`. Anonymous means that the connection supplies no
automatic credential; when no automatic provider is selected, the raw command
may still supply one explicit `Authorization` header. The receiving product
still authenticates and authorizes every protected request.

The direct `--token-file` input must fit within 8 KiB, including its optional
line ending. That ending is removed and the bearer remains opaque; it need not
be a compact JWT. Direct token,
CA, request-body, and header files use the shared bounded regular-file reader;
on Unix it opens nonblocking, so a FIFO is refused instead of hanging. A
symlink whose target is a regular file remains accepted. Only `--input -`
reads a request body from standard input. The saved-connections document uses
the same reader under its own document bound. Saved bearer and private-key
references instead use the platform secret resolver, retaining that resolver's
separate root, permission, size, and symlink policy.

An explicit header may be inline, read as one value with `NAME: @FILE`, or
read as complete `NAME: VALUE` lines with `@FILE`. Each header file is bounded
to 64 KiB. These explicit headers are raw request material held as ordinary
strings; they do not inherit the 8 KiB `--token-file` credential contract or
the saved secret resolver's custody policy. In particular, an inline
credential may be visible to process-argument inspection.

Every service base URL uses the shared checked HTTP(S) type, which permits
plain HTTP only for loopback. A request path stays under the selected origin
and deployment prefix. The selected connection owns `Host`, automatic
`Authorization`, and any product profile header it sets, so command-line
headers cannot replace them. Without an automatic provider, exactly one
explicit `Authorization` header is accepted through any of the raw header
forms; another explicit source is refused. The client ignores ambient proxies,
follows no redirect, retries no request, applies fixed connect and overall
deadlines, and bounds both request and response bodies. `ApiArgs` debug output
records header counts and option presence rather than raw request values, and
the automatic bearer connection's tested debug and failure paths do not expose
that bearer. Those focused properties are not a general secret-custody
guarantee for explicit raw headers.

The maintained proofs are:

- `crates/registry-cli-api/tests/api_http.rs`, including
  `anonymous_requests_accept_one_explicit_authorization_header_from_each_supported_input`,
  `automatic_credentials_cannot_be_replaced_by_a_repeated_header`,
  `api_args_debug_redacts_request_values`,
  `paths_and_host_headers_cannot_escape_the_selected_endpoint`,
  `redirect_answers_are_returned_without_following_them`,
  `response_bodies_are_bounded`, and
  `bearer_connection_debug_and_failures_do_not_disclose_the_token`;
- `crates/registry-cli-api/tests/connection_store.rs`,
  `saved_connections_add_show_use_reread_credentials_and_acquire_private_key_jwt`;
- `crates/registry-bregctl/tests/api_cli.rs`,
  `raw_api_refuses_fifo_file_inputs_without_blocking`,
  `connection_commands_refuse_fifo_stores_without_blocking`, and
  `raw_api_accepts_a_regular_token_file_and_request_body_from_standard_input`.

These references identify the maintained contract; this README does not claim
that they ran in a particular review.

Run the focused checks from the workspace root:

```console
cargo test --locked -p registry-cli-api
cargo test --locked -p registry-cli-api --features schema
```

Regenerate the schema after an intentional format change:

```console
cargo run --locked -p registry-cli-api --features schema --example connections-schema -- --output crates/registry-cli-api/schema/connections.schema.json --report-output crates/registry-cli-api/schema/connection-check-report.schema.json
```

The schema-feature test compares the generated bytes with the checked-in file,
so drift fails before publication.
