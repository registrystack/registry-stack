# registry-thunderid-tooling

Private, non-published tooling support for adopter CLIs and integration tests
that need a pinned, unmodified upstream ThunderID issuer. It is not a runtime
product: it opens no listener, ships no binary, and no BREG, Evidence, Relay,
or OID4VCI runtime crate may depend on it.

## What it does

1. Loads the single upstream pin from `thunderid-version.json`.
2. Validates a product-neutral internal description
   (`description::IssuerDescription`) supplied by the owning CLI, which keeps
   every authority decision on its side.
3. Renders the pinned release's native declarative resources (`render`),
   including the `default` agent-schema update derived additively from the
   pinned bundle, preserving every upstream field.
4. Performs the explicit upstream bootstrap one-shot
   (`bootstrap::Bootstrap::apply_agent_schema`) with `--defaults` and a
   file-injected throwaway `ADMIN_PASSWORD`.
5. Owns one development session's container lifecycle
   (`container::Session`): one-time setup, start/stop with retained state,
   ownership labels, and an explicitly requested destructive reset.
6. Reads back the public endpoints and registration information
   (`issuer::IssuerEndpoints`). No secret, key, or token is ever returned,
   logged, or placed in an argv element.

## Regenerating the stored fixture

```bash
cargo run -p registry-thunderid-tooling --example render-fixture -- \
  products/identity/thunderid/fixtures/synthetic-session
```

The committed fixture under `products/identity/thunderid/fixtures/` must come
from this command, never from hand editing.

## Institutional token exchange

`IssuerDescription.exchange_issuers` registers external grant authorities as
native `connection` resources. The connection fixes user-type resolution to an
internal mapping label and copies the verified subject-token `iss` into
`registry_grant_source_issuer`. Incoming claims cannot select a different
mapping or replace that derived value. The development container loads identity
providers only from declarative resources.

A machine client's `token_exchange: Some(TokenExchangeClient { ... })` enables
`client_credentials` and RFC 8693 token exchange on the same registered key.
Every role assigned to that client must contain only its configured authority
assertion lookup permission. Client credentials uses `clientConfig`; exchange
uses `userConfig`, whose closed allowlist carries the signed task fields,
including JSON identity selectors, product-specific bounds and numeric expiry.
Static schemas and client attributes cannot contain `registry_grant_*`,
`identity`, or `registry_approver`. Ordinary actor-kind and purpose attributes
remain available for non-grant service profiles.

These declarations transport authority; each resource server still compares
its authenticated client and configured resource against the immutable grant
client and destination, binds the source issuer to its permitted authority,
checks its native permissions and selectors, and refuses the earlier of token
expiry and grant deadline. Re-exchange preserves the original deadline. A
bootstrap access token contains no task grant and cannot acquire one by
exchanging itself.

The reproducible real-container proof is:

```bash
products/identity/scripts/test-contextual-exchange.py
```

It builds the `contextual-exchange` example with locked dependencies, selects the
immutable upstream image pin, allocates a fresh owner-only state directory and
uniquely labelled container, and serves generated public authority JWKS from the
host. It retains its state and stops only its own container. A prebuilt driver
can be supplied with `--driver`; `--state` must name an absent absolute path.
The current host-network proof uses Docker Desktop/OrbStack's
`host.docker.internal` resolution.

The cases verify the shared private-key-JWT provider, nested Evidence and BREG
bounds, an unregistered assertion subject, signed issuer provenance, unavailable
or unknown issuers, missing grant fields, scope narrowing, token type and
assertion audience, immutable client/resource bounds, original deadline through
re-exchange, and bootstrap isolation. Cross-client and cross-resource exchanges
can issue tokens carrying the original bounds; the driver explicitly distinguishes
that transport proof from resource-server enforcement. Resource-server tests
remain owned by their products. No key, assertion, bearer token or protected
response body is printed or passed in process arguments.

## Shared local-session construction

`local::local_description` constructs one resource audience, exact colon-delimited
scope trees, per-client roles and public-key registrations for adopter CLI dev
sessions. `local::agent_id` returns the stable native principal used to seed a
local directory and identify the resulting token's subject. The helper refuses
unrepresentable or ambiguous scope trees rather than rewriting permissions.

`LocalClient.allow_human_fixture` must be explicit when teaching fixtures need a
human marker on a local machine token. This option neither creates production
human sessions nor relaxes a consuming runtime's human-session checks. Task
attributes remain forbidden even for these fixtures.

`local::start(&Session, docker_path, cancellation_callback)` bootstraps already
rendered state, waits for the exact loopback issuer, and returns a bounded public
RS256 JWKS snapshot. `local::stop` selects only the exact session-owned container.
The shared runner bounds commands and HTTP responses, reads owner-only secret
files into the child environment, and discards command output other than owned
container IDs. Product CLIs retain their own policy, status UI, and cancellation
flag. Neither operation removes retained files.

### Citizen delegation


## Acquire an approved task

`bregctl`, `caseworkctl`, and `evidencectl` expose the same bounded command:

```sh
bregctl dev grant task-agent --grant APPROVED-GRANT-UUID \
  --connection /absolute/private/task-connection.yaml ./project
```

The grant must already have been approved through the configured Casework API
or UI from a governed task template and current source-backed work item. This
command neither approves a task nor accepts purpose, selectors, operations or
other grant bounds. It does not start services or change runtime trust. Configure
Casework and the consuming resource with the intended shared issuer first;
independent default local-development issuer sessions do not automatically share
trust.

Keep the connection file and existing registered agent key owner-only (0600).
Its closed v1 format is:

```yaml
version: 1
caseworkUrl: https://casework.example
# Stock ThunderID 1.0.1 expects its issuer URL as the client assertion audience.
tokenEndpoint: https://issuer.example/oauth2/token
clientAssertionAudience: https://issuer.example
bootstrapResource: urn:casework:example
clients:
  task-agent:
    assertionKeyFile: /absolute/private/task-agent.jwk
    resource: urn:breg:example
    scopes: [records:get]
```

The OAuth client must already be registered with that key and permitted to
exchange assertions from the configured Casework authority. Before approval,
its client-credentials permission is only `casework:grants:assert` at the
bootstrap resource. The requested resource and scopes above are fixed ceilings;
the real Casework assertion supplies immutable authority, subjects and task
bounds, and the issuer enforces the scope subset.

Each invocation acquires a fresh bootstrap token, requests a short-lived signed
Casework assertion, and performs uncached RFC 8693 exchange. Only the final bearer
is written to `.breg/grants/<client>-<grant>.header` (or `.casework/grants/` or
`.evidence/grants/`). The response reports that path and the original grant
expiry, never a token. A refusal leaves an existing header unchanged; the
resource's current authority checks still govern any attempted use. Run the
command again using the same connection after restarting configured services.
