# Base Registry Engine MCP gateway

`registry-breg-mcp` builds the `breg-mcp` binary: a Model Context Protocol
server that lets a chat host act for one verified citizen against one Base
Registry Engine deployment. The citizen reads their own record, drafts and
edits an application to change it, and gets a link to the registry's own review
page, where the application is reviewed and submitted. The chat host never
submits anything.

It is a supporting service beside the Base Registry Engine, not a runtime
product of its own, in the same way `registry-evidence-oid4vci` sits beside
Evidence. It adds no registry semantics: every decision about what the citizen
may see or change is the registry's, made under the registry's agent access
profile. No product crate depends on it, and it depends on the engine only
through `registry-breg-client`. `registry-breg` is a dev-dependency, used to run
the gateway against a real engine on PostgreSQL.

## Two halves that share nothing

The inbound half is an OAuth 2.0 protected resource. It verifies the chat
host's access token with `registry-platform-oidc` (strict `at+jwt`, exact
audience equal to the gateway's resource identifier, allowed clients, required
scopes, bounded lifetime) and publishes RFC 9728 metadata at
`/.well-known/oauth-protected-resource`. A request without a valid token gets
`401` with `WWW-Authenticate: Bearer resource_metadata="..."`. The gateway is
not an authorization server and serves no authorization, token, or
registration endpoint.

The outbound half acts at the registry. For every tool call it exchanges the
verified inbound token (RFC 8693) for a delegated registry token, with the
inbound token as the subject and the gateway's own `private_key_jwt` client as
the actor, and calls the registry with that token only. The chat host's token
is never sent to the registry, and the `Authorization` header is removed from
the request once verified so no later layer can forward it.

The gateway's actor token comes from its own `client_credentials` grant, which
names the gateway's resource identifier (`resourceServer.resource`) as its
RFC 8707 `resource` and asks for no scopes. The authorization server must let
the gateway's client request that resource, and must never issue the actor
token with the registry's audience: an actor token the registry would accept
is a standing registry credential the gateway holds without a citizen behind
it. A server that ignores `resource` on this grant must not fall back to the
registry's audience for this client either. The inbound half refuses the actor
token even so, because the configuration keeps the gateway's own client out of
`resourceServer.allowedClients`.

The halves share no code path and no configuration section:
`resourceServer` configures the first, `registry` and `exchange` the second.

## Tools

| Tool | What it does | Registry calls |
|---|---|---|
| `describe_service` | The operator-authored service name, description, and disclosure | none |
| `get_my_details` | The citizen's own record as labelled fields | metadata, linked list lookup |
| `start_application` | Creates a draft application for the citizen's own record | metadata, linked list lookup, create |
| `update_application` | Edits a draft the citizen owns, under its revision | metadata, linked list lookup, read, patch |
| `prepare_review` | Returns `<reviewBaseUrl>/requests/<id>` for the citizen to review and submit | metadata, linked list lookup, read |
| `get_application_status` | `prepared`, `submitted`, `under_review`, `approved`, `rejected`, `applied`, or `cancelled`, as the registry reports it | metadata, linked list lookup, read |

`cancelled` is the request's own state. A review that was cancelled, answered,
or superseded, or that asked for changes, leaves the request submitted and open,
so its status is `under_review`. Only `rejected`, `applied`, and `cancelled` are
closed, and an identical `start_application` returns an identical application
that is still open instead of creating another.

Tool input schemas come from the registry's caller-filtered metadata for the
configured agent access profile, so a field the profile cannot write is never
offered.

The citizen is only ever the token subject. No tool accepts an identifier for
the citizen, and none accepts the record an application targets or the field
that records its owner: the gateway resolves the citizen's own record through
the agent profile's linked lookup, under the delegated token, and writes both
fields itself. A lookup that finds no record, or more than one, refuses the call
and creates nothing. An argument or patch path naming either field is refused
before the gateway reads or writes any record. An application that no longer
names the citizen's own record is reported exactly as one that does not exist.

Registry text is returned as labelled structured data with a notice that it is
data, never instructions.

Writes carry an idempotency key derived with a keyed hash over the citizen's
pseudonym, the tool, and the canonical arguments, so a retried call replays
rather than duplicates. The registry keeps every key it has answered spent,
and replays its answer within the receipt horizon
(`idempotency.receiptRetentionDays`, 7 days by default), so a start walks a
chain of keys derived from the same values and stops at the first application
that is still open: a retried start returns the draft its first attempt made,
while a citizen whose last identical application was cancelled, rejected, or
applied gets a new draft. The registry binds each key to the package revision
active when it first answered it, and refuses a key bound under an earlier
revision, one whose closed application request retention erased, or one past
its receipt horizon, without creating anything; the start steps past such a key
the same way. A start after a package activation, or an identical start past
the receipt horizon, therefore gets a new draft, even while the earlier
identical draft is still open. A start that would walk past more than 32 closed
or refused identical keys is refused with `not-permitted`. An identical
`update_application` repeated past the receipt horizon answers
`stale-application`. Registry problems map to a fixed set of tool error
codes, each with fixed text: `invalid-arguments`, `record-not-resolved`,
`not-found`, `application-not-editable`, `stale-application`,
`idempotency-conflict`, `not-permitted`, `authorization-failed`,
`registry-unavailable`, `service-unavailable`, and `unexpected-response`.

## Run it

```bash
breg-mcp --runtime-config /etc/breg-mcp/runtime.yaml check
breg-mcp --runtime-config /etc/breg-mcp/runtime.yaml serve
```

`check` reads the document offline, as `serve` reads it, and reports its
findings in the shared diagnostic shape: human lines by default, or one
`BRegMcpCtlReport` JSON document with `--format json`. It resolves no secret,
opens no socket, and writes no audit file. It exits 0 when the file is
accepted, 1 when something is refused (or a warning is reported under
`--deny-warnings`), 2 on a usage error, and 3 when the file cannot be read. A
`${NAME}` expression is checked by syntax and position only, unless
`--environment` substitutes it from the environment first.

`serve` refuses a file `check` would refuse, with the same lines on standard
error, then resolves every secret before it listens, and answers until
`SIGINT` or `SIGTERM`. Logs are JSON lines on standard output from the gateway
alone, at the level `BREG_MCP_LOG` names: `error`, `warn`, or `info` (the
default). Any other value, including a filter directive, is refused on
standard error with exit status 2 before any work.

The runtime file below is
[`products/breg/examples/mcp-runtime/runtime.yaml`](../../products/breg/examples/mcp-runtime/runtime.yaml);
its JSON Schema is
[`products/breg/generated/mcp-runtime/mcp-runtime.schema.json`](../../products/breg/generated/mcp-runtime/mcp-runtime.schema.json).

```yaml
apiVersion: id.registrystack.org/formats/breg/mcp-runtime/v1alpha1
kind: BRegMcpRuntimeConfig
listener:
  bind: 127.0.0.1:8110
  tlsTermination: operator-controlled-upstream
secretProviders:
  file:
    root: /run/secrets/breg-mcp
resourceServer:
  resource: https://gateway.example.test/mcp
  issuer: https://login.example.test
  jwksSource:
    kind: uri
    uri: https://login.example.test/jwks.json
  algorithms: [EdDSA, ES256]
  allowedClients: [chat-host]
  requiredScopes: [address-correction:self]
  maximumTokenLifetimeSeconds: 3600
registry:
  baseUrl: https://registry.example.test/
  accessProfile: citizen-agent
  audience: urn:breg:citizen-address-correction
  scopes: [address-correction:self]
exchange:
  tokenEndpoint: https://login.example.test/token
  clientId: citizen-gateway
  privateKeyRef: secret:file/gateway-key
  assertionAudience: https://login.example.test
service:
  name: Address correction
  description: Correct the postal address the registry holds for you.
  disclosure: The assistant you use will see your current address and the correction you request.
  details:
    entity: person-address
  application:
    entity: address-correction-request
    targetField: address
    ownerField: owner
  reviewBaseUrl: https://review.example.test
audit:
  hashKeyRef: secret:file/audit-key
  destination: file
  path: /var/lib/breg-mcp/audit/audit.jsonl
rateLimits:
  perCitizen:
    requestsPerMinute: 30
    burst: 10
  perClient:
    requestsPerMinute: 600
    burst: 100
limits:
  maximumRequestBytes: 65536
```

Secrets are references (`secret:file/<name>` or `secret:env/<name>`), never
inline values; `serve` refuses a secret file others can read. The gateway's
private key is a private JWK. Every list (`algorithms`, `allowedClients`,
`requiredScopes`, `registry.scopes`) holds 1 to 128 distinct items, and every
number has the bound its schema states: `maximumTokenLifetimeSeconds` 1 to
86400 (default 3600), `attemptTimeoutMilliseconds` 100 to 120000 (default
10000), `requestsPerMinute` and `burst` 1 to 1000000, and `limits.maximumRequestBytes` 1 to 1048576
(default 65536). Plain HTTP is accepted only with
`tlsTermination: development-loopback` on a loopback address. `jwksSource`
defaults to OIDC discovery; `kind: uri` fetches the configured key set and
`kind: static` resolves a `documentRef` secret. Network key sources use the
platform's strict URL policy, which refuses a
loopback, private, or cloud-metadata address before connecting; only under
`development-loopback` does the development policy also admit plain HTTP to
loopback.

The endpoint is served at `/mcp` over streamable HTTP, stateless, with JSON
responses. Requests whose `Host` is not the resource's authority, and any
request carrying an `Origin` header, are refused with `403` before the token
is verified or a rate limit is charged. A `Host` that omits the port names the
scheme's default one, so for `https://gateway.example.test/mcp` both
`gateway.example.test` and `gateway.example.test:443` are accepted, and the
same host on another port is not. `/health` answers
`{"status":"alive"}` while the process is up; `/ready` reports whether the
audit log is writable.

A request refused outside MCP gets an RFC 9457 problem document
(`application/problem+json`, type `about:blank`) with fixed text and a stable
`code`: `unauthorized` or `invalid-token` with `401`, `insufficient-scope` or
`forbidden` with `403`, `not-found` with `404`, `rate-limited` with `429`, and
`temporarily-unavailable` with `503`. A `401` and an `insufficient-scope`
refusal keep their RFC 6750 `WWW-Authenticate` challenge, whose `error`
values are the RFC's own `invalid_token` and `insufficient_scope`.

Each tool call is audited twice, before any token exchange or registry call
and before its result is released. The shared writer emits `request` and
`response` JSON Lines entries with one `correlation`, the tool,
keyed pseudonyms of the citizen (`principalPseudonym`) and the chat-host client
(`clientPseudonym`), and the outcome: `ok`, `refused` for a failure that had
no registry effect, or `unfinished` when a create or patch was sent and its
effect is unknown, as after a transport failure, a server error, or a response
the gateway cannot use. A failed call also records its tool error code as
`reason`. A cancelled call emits an `unfinished` response. The pseudonyms
are the shared audit reference hashes of `[issuer, subject]` and `[issuer, client_id]` under the
classes `breg-mcp-principal-v1` and `breg-mcp-client-v1`: named as BReg's
authorization audit names them, and derived as the citizen review page derives
its own. A call whose request entry cannot be accepted performs no protected
I/O, and a result whose response entry cannot be accepted is withheld. Argument values,
prompts, and tokens are never logged or audited.

Rate limits apply per citizen and per chat-host client; a request over either
gets `429` with `Retry-After`.

## Boundary

`clippy.toml` in this crate disallows the client methods the gateway must never
reach: building a bearer or static token from text, swapping one onto a client,
writing a bearer header out of a token, building an HTTP client beside the
registry client, lifecycle actions, tombstones, batch writes, governed actions
and their target conditions, attachments, ingestion, and statistical release
publication and withdrawal. It also disallows
`BaseRegistryClientConfig::with_token_provider` everywhere but one wrapper,
`outbound::delegated`, which takes nothing but the per-call exchange.
`products/breg/scripts/check-mcp-gateway-boundary.sh` runs the lints, fails when
an entry stops resolving, and probes the configuration against the real client
with one probe per shape to prove it still refuses each and still allows a read.

## Verify

```bash
cargo test --locked -p registry-breg-mcp
cargo clippy --locked -p registry-breg-mcp --all-targets --all-features -- -D warnings
products/breg/scripts/check-mcp-gateway-boundary.sh
```

The end-to-end suite runs the gateway against a real engine serving the
`citizen-address-correction` acceptance project and needs a disposable
PostgreSQL database:

```bash
BREG_TEST_DATABASE_URL=<disposable database> cargo test --locked \
  -p registry-breg-mcp --features postgres-test --test postgres_gateway
```
