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

Tool input schemas come from the registry's caller-filtered metadata for the
configured agent access profile, so a field the profile cannot write is never
offered.

The citizen is only ever the token subject. No tool accepts an identifier for
the citizen, and none accepts the record an application targets or the field
that records its owner: the gateway resolves the citizen's own record through
the agent profile's linked lookup, under the delegated token, and writes both
fields itself. A lookup that finds no record, or more than one, refuses the call
and creates nothing. An argument or patch path naming either field is refused
before any registry call. An application that no longer names the citizen's own
record is reported exactly as one that does not exist.

Registry text is returned as labelled structured data with a notice that it is
data, never instructions.

Writes carry an idempotency key derived with a keyed hash over the citizen's
pseudonym, the tool, and the canonical arguments, so a retried call replays
rather than duplicates. The registry keeps every key it has answered, so a
start walks a chain of keys derived from the same values and stops at the first
application that is still open: a retried start returns the draft its first
attempt made, while a citizen whose last identical application was cancelled,
rejected, or applied gets a new draft. A start that would walk past more than 32
closed identical applications is refused with `not_permitted`. Once request
retention erases a closed application, the chain meets a key the registry will
never replay and the start answers `idempotency_conflict`; the citizen can start
again with any different value. Registry problems map to a fixed set of tool error
codes, each with fixed text: `invalid_arguments`, `record_not_resolved`,
`not_found`, `application_not_editable`, `stale_application`,
`idempotency_conflict`, `not_permitted`, `authorization_failed`,
`registry_unavailable`, `service_unavailable`, and `unexpected_response`.

## Run it

```bash
breg-mcp --runtime-config /etc/breg-mcp/runtime.yaml check
breg-mcp --runtime-config /etc/breg-mcp/runtime.yaml serve
```

`check` validates the document and resolves every secret without opening a
socket or the audit log. `serve` answers until `SIGINT` or `SIGTERM`. Logs are
JSON on standard output, filtered by `BREG_MCP_LOG` (default `info`).

```yaml
apiVersion: registry.registrystack.org/breg-mcp-runtime/v1alpha1
kind: BRegMcpRuntimeConfig
listener:
  bind: 0.0.0.0:8110
  tlsTermination: operator-controlled-upstream
secretProviders:
  file:
    root: /run/secrets/breg-mcp
resourceServer:
  resource: https://gateway.example/mcp
  issuer: https://login.example
  jwks:
    kind: uri
    uri: https://login.example/jwks.json
  algorithms: [ES256]
  allowedClients: [chat-host]
  requiredScopes: [address-correction:self]
registry:
  baseUrl: https://registry.example/
  accessProfile: citizen-agent
  audience: urn:registry:address-correction
  scopes: [address-correction:self]
  requestTimeoutMilliseconds: 5000
exchange:
  tokenEndpoint: https://login.example/token
  clientId: citizen-gateway
  privateKeyRef: secret:file/gateway-key
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
  reviewBaseUrl: https://registry.example/citizen/
audit:
  path: /var/lib/breg-mcp/audit.jsonl
  hashKeyRef: secret:file/audit-key
rateLimits:
  perCitizen:
    requestsPerMinute: 30
    burst: 10
  perClient:
    requestsPerMinute: 600
    burst: 100
```

Secrets are references (`secret:file/<name>` or `secret:env/<name>`), never
inline values; a secret file others can read is refused. The gateway's private
key is a private JWK. Plain HTTP is accepted only with
`tlsTermination: development-loopback` on a loopback address.

The endpoint is served at `/mcp` over streamable HTTP, stateless, with JSON
responses. Requests whose `Host` is not the resource's authority, and any
request carrying an `Origin` header, are refused with `403` before the token
is verified or a rate limit is charged. A `Host` that omits the port names the
scheme's default one, so for `https://gateway.example.test/mcp` both
`gateway.example.test` and `gateway.example.test:443` are accepted, and the
same host on another port is not. `/health` reports the process
is up; `/ready` reports whether the audit log is writable.

Each tool call is audited twice, before any registry call and after it, to a
hash-chained JSON Lines log: the request identifier (`requestId`), the tool,
keyed pseudonyms of the citizen (`principalPseudonym`) and the chat-host client
(`clientPseudonym`), and the outcome code. The pseudonyms are the shared audit
reference hashes of `[issuer, subject]` and `[issuer, client_id]` under the
classes `breg-mcp-principal-v1` and `breg-mcp-client-v1`: named as BReg's
authorization audit names them, and derived as the citizen review page derives
its own. A call whose audit record
cannot be written fails closed. Argument values,
prompts, and tokens are never logged or audited.

Rate limits apply per citizen and per chat-host client; a request over either
gets `429` with `Retry-After`.

## Boundary

`clippy.toml` in this crate disallows the client methods the gateway must never
reach: building a bearer or static token from text, swapping one onto a client,
writing a bearer header out of a token, building an HTTP client beside the
registry client, lifecycle actions, tombstones, batch writes, governed actions
and their target conditions, attachments, and ingestion. It also disallows
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
