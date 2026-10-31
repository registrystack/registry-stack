# Configurable MCP gateway

`registry-mcp` serves one protected MCP resource over explicit provider bindings.
Each binding has its own downstream authorization factory and a fixed public tool ceiling.
The shared edge authenticates the caller and brackets invocation with durable audit; each product authorizes the operation and the data it returns.

This is a supporting service, with no registry, assignment, legal-policy or workflow authority of its own.
Deploy citizen and staff endpoints separately with distinct resources, admitted clients, scopes and credentials.
The gateway never forwards its inbound bearer token to a provider.
There is no generic URL, SQL, connector-authoring or arbitrary product-action tool.

## Available providers

| Provider | Executable scope |
|---|---|
| BReg | The seven existing citizen tools, with the same caller-derived targets, Proposal drafts, revisions, retry identity and browser review boundary |
| Adapter | Explicitly served GET and read-only POST operations from a pinned effective contract, under a configured non-personal machine connection |
| Casework | Two assigned-work reads through the dedicated delegated-reader API; the backend must explicitly admit the configured gateway and staff subject |

A tool catalog is the intersection of configured bindings and the provider's executable catalog.
It grants no authority.
A direct call to an unconfigured name is refused before provider execution.
Public names must be unique across the deployment.

The Casework binding requires `authority: delegated-staff-read` and `readerPolicy`,
which names one Casework `delegatedStaffReaders` policy. It does not select a human
access profile. Each call exchanges the inbound credential for the Casework
resource. Casework independently checks the trusted gateway, represented staff
member, exact read scopes, credential lifetime and current assignment. It admits
only assigned-task listing and context reads through separate read-only routes.
Human claim, assignment, decision and administrative routes keep their existing
authentication. Current-source context also requires an independently authorized
source exchange and source disclosure profile.

## Check and serve

When running from sources, check the [example and golden workspace](../../products/platform/examples/mcp-runtime/README.md).
A packaged binary uses an absolute runtime configuration path:

```sh
registry-mcp --runtime-config /srv/mcp/runtime.yaml check
registry-mcp --runtime-config /srv/mcp/runtime.yaml check --format json
registry-mcp --runtime-config /srv/mcp/runtime.yaml serve
```

The operator document is `PlatformMcpRuntimeConfig`, version
`id.registrystack.org/formats/platform/mcp-runtime/v1alpha1`.
`check` uses the same bounded configuration reader and semantic validation as startup.
It reads pinned contract files but does not resolve secrets, fetch a catalog, contact an issuer or open a listener/audit destination.
Use `--environment` to evaluate configured environment expressions; otherwise diagnostics identify deferred values.
Secret references remain explicit `secret:file/` or `secret:env/` references under declared providers.

An offline pass does not prove that credentials resolve, the issuer accepts an exchange, the audit directory is writable, or the adapter journal is ready.
Startup and the actual call establish those conditions.

## BReg migration

Existing `breg-mcp` configuration and CLI remain supported by their compatibility wrapper.
It uses the shared edge and the same BReg provider.
Its audit identity, subject hashing, seven tools and product behavior remain unchanged.

To compose a generic deployment, retain `resourceServer`, listener, secrets, audit and limits; give the deployment a `name`.
Move the existing `registry`, `exchange` and `service` blocks under a binding's `provider` with `type: breg`.
Name the binding and list the intended tools explicitly.
Rename the generic rate bucket from `perCitizen` to `perPrincipal`; the BReg compatibility file still uses `perCitizen`.
Use a downstream audience distinct from the gateway resource and an exchange client distinct from every admitted inbound client.

Keep the review service as the origin serving the citizen's browser review and submission.
The MCP tools prepare drafts and never submit them.
Retain the institution's issuer and exact task-authority provisioning/status requirements.
Token exchange does not supply missing task grants.

## Adapter binding

Export the effective contract from the matching adapter runtime and reviewed artifact:

```sh
adapter effective-contract --runtime-config /srv/adapter/runtime.yaml --project /srv/adapter/project > /srv/mcp/adapter-contract.json
```

Configure the reviewed contract file, its exact digest, expected adapter audience,
`dataClass: non-personal`, one machine credential reference and an explicit public-tool-to-operation map.
The file must describe served reads with complete embedded closed schemas.
The gateway refuses schema references, unsupported writes, unknown operations, duplicate names, wrong audiences and digest mismatches.

Every catalog read checks the authenticated adapter contract and journal readiness.
Every operation checks readiness again and sends `x-registry-adapter-contract` so the adapter refuses a deployment change before source access.
The tool arguments contain only the exported `path`, `query` and, for a read-only POST, `body` objects.
They cannot choose an origin, credential, profile or operation.
The response must match the pinned output schema and carry an adapter-minted request identifier.
Redirects, automatic pagination and automatic retries are disabled.

The non-personal declaration is an operator constraint, not a data classifier or a personal-data grant.
Personal access and external writes require their own downstream authority and recovery contracts.

## Verification

Run focused provider and configuration tests, then the edge and BReg regressions:

```sh
cargo test --locked -p registry-mcp
cargo test --locked -p registry-mcp-edge -p registry-breg-mcp
cargo clippy --locked -p registry-mcp -p registry-mcp-edge -p registry-breg-mcp --all-targets -- -D warnings
python3 products/platform/scripts/check-mcp-dependencies.py
python3 products/casework/scripts/check_dependency_direction.py
```

The ignored `native_adapter` proof requires a matching native adapter binary, fixture directory and an explicitly disposable PostgreSQL URL.
It uses the adapter's actual effective-contract export and a real MCP client/router.
The external source and issuer remain synthetic.
The maintained BReg `native_citizen` proof separately requires matching BReg, tooling and review binaries and disposable PostgreSQL.
Neither fixture proves a production issuer or an external institution's live access policy.
