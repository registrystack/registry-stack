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
| Adapter (experimental) | Configured GET and read-only POST operations from a pinned effective contract, using a machine connection and an unchecked operator data classification |
| Casework | Two assigned-work reads through the dedicated delegated-reader API; the backend must explicitly admit the configured gateway and staff subject |

A tool catalog is the intersection of configured bindings and the provider's executable catalog.
It grants no authority.
A direct call to an unconfigured name is refused before provider execution.
Public names must be unique across the deployment.

The Casework binding requires the explicit contract selector
`authority: delegated-staff-read` and `readerPolicy`,
which names one Casework `delegatedStaffReaders` policy. It does not select a human
access profile. Each call exchanges the inbound credential for the Casework
resource. Casework independently checks the trusted gateway, represented staff
member, required read scopes, credential lifetime and current assignment. It admits
only assigned-task listing and context reads through separate read-only routes.
Human claim, assignment, decision and administrative routes keep their existing
authentication. Current-source context also requires an independently authorized
source exchange and source disclosure profile.

## Check and serve

This foundation increment is source-build-only. `registry-mcp` has no numbered-release
asset, installer, `rstack` component or container image, and stays held out of the
release roster until that packaging work is approved and implemented. Build it from
the exact Registry Stack source revision you intend to operate.

Check the [example and golden workspace](../../products/platform/examples/mcp-runtime/README.md)
before serving. An operator-built binary uses an absolute runtime configuration path:

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

## Operator choice and optional BReg configuration conversion

Keep `breg-mcp` for existing BReg citizen deployments. It is the released path;
`registry-mcp` requires building from source and is useful when its explicit
provider bindings are needed. See [the design record](../../products/platform/MCP-GATEWAY.md).

Existing `breg-mcp` configuration and CLI remain supported by their compatibility wrapper.
It uses the shared edge and the same BReg provider.
Its audit identity, subject hashing, seven tools and product behavior remain unchanged.

To opt into the source-built service, change `apiVersion` to
`id.registrystack.org/formats/platform/mcp-runtime/v1alpha1` and `kind` to
`PlatformMcpRuntimeConfig`. Retain `resourceServer`, listener, secrets, audit and
limits, then give the deployment a `name`.
Move the existing `registry`, `exchange` and `service` blocks under a binding's `provider` with `type: breg`.
Name the binding and list the intended tools explicitly.
Rename the generic rate bucket from `perCitizen` to `perPrincipal`; the BReg compatibility file still uses `perCitizen`.
Use a downstream audience distinct from the gateway resource and an exchange client distinct from every admitted inbound client.

The generic service uses audit schema `registry-mcp.tool-call/v1`, event
`mcp.tool_call` and pseudonym namespaces `mcp.principal` and `mcp.client`.
Audit searches spanning the conversion must account for both namespaces. Keep
the same audit hash key and BReg service/provider identities to preserve retry
correlation. `BREG_MCP_LOG` applies only to the compatibility binary; use
`logLevel` here. Generic gateway instructions replace the citizen wrapper's
instructions; the BReg tools still enforce browser submission.

Keep the review service as the origin serving the citizen's browser review and submission.
The MCP tools prepare drafts and never submit them.
Retain the institution's issuer and exact task-authority provisioning/status requirements.
Token exchange does not supply missing task grants.

## Experimental Adapter binding

This provider awaits a compatible Live Adapter producer. The producer is a
separate source dependency; the command below requires that matching source
and is not available from this gateway tree alone. Its committed golden contract
is tested without a running producer. See the example README for the explicit
native-drill prerequisites.

Export the effective contract from the matching adapter runtime and reviewed artifact:

```sh
adapter effective-contract \
  --runtime-config /srv/adapter/runtime.yaml \
  --project /srv/adapter/project \
  --profile /srv/adapter/profiles/govstack-consultation/profile.yaml \
  --pack /srv/adapter/packs/dhis2-tracker/pack.yaml \
  > /srv/mcp/adapter-contract.json
```

Select the exact profile and pack files used by the reviewed deployment; their
pins must match the project. The CLI sibling-file defaults apply only when the
project directory actually contains `profile.yaml` and `pack.yaml`.

Configure the reviewed contract file, its exact digest, expected adapter audience,
`dataClass: non-personal`, one machine credential reference and an explicit
public-tool-to-operation map with a reviewed `description` for every tool.
The classification is an unchecked operator attestation, not a data classifier
or disclosure grant. The supported synthetic journeys use facility data;
external person-level delegation remains outside this increment.

Use the export's `digest` member, for example `jq -r .digest adapter-contract.json`.
A file checksum is different and is not the contract pin.
Copy the audience exactly from the export, including an opaque name such as
`adapter-example`; matching preserves its case and characters.
The file must declare the JSON Schema 2020-12 dialect, trusted-machine authority,
and served reads with complete embedded closed schemas and declared success statuses.
The versioned digest covers the format identity and complete contract.
Re-export, review and update the pin when upgrading the effective-contract format.
The gateway refuses schema references, unsupported writes, unknown operations, duplicate names, wrong audiences and digest mismatches.

Every catalog read checks the authenticated adapter contract and journal readiness.
Every invocation sends `x-registry-adapter-contract`; the Adapter checks that pin
and journal admission atomically before source access. Invocation does not
re-fetch and recompile the catalog.
The tool arguments contain only the exported `path`, `query` and, for a read-only POST, `body` objects.
They cannot choose an origin, credential, profile or operation.
The response must use the declared success status, match the pinned output schema,
and carry the Adapter's 32-character lowercase hexadecimal request identifier.
Profile problems and the protocol's typed 412/503 problems retain their separate schemas.
Each service keeps its own request identity: the gateway retains its audit correlation
locally, and returns the Adapter's request identifier as `traceId`.
Redirects, automatic pagination and automatic retries are disabled.

The non-personal declaration is an operator constraint, not a data classifier or a personal-data grant.
Personal access and external writes require their own downstream authority and recovery contracts.

The source-built Adapter binding reads its machine token once at startup. On
expiry, replace the referenced token and restart; automatic acquisition and
renewal are not implemented. Do not extend token lifetime as a workaround.
A maintained short-lived client-credentials option remains readiness work.
Outbound TLS uses the system trust roots, including an institution's installed
private CA; there is no binding-specific CA bundle option.

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
