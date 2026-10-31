# Citizen MCP gateway

`breg-mcp` lets a chat host acting for one verified citizen read permitted own
records and prepare a native Proposal draft. `breg-review` separately signs that
citizen in, shows the canonical draft and target, and submits under the citizen's
own authority. They are independent supporting processes with separate clients
and credentials; neither adds registry semantics.

The gateway verifies the host token, exchanges it for a delegated registry token,
and never forwards the inbound token to BReg. The delegated subject remains the
citizen and the actor identifies the trusted gateway. Its standing-agent profile
can Start and edit an authorized caller-owned draft, but cannot submit, apply,
invoke immediate effects, or write records directly. BReg enforces that ceiling;
the gateway's client-method boundary supplies an additional code constraint.

The gateway resolves exactly one permitted own record and supplies the Action's
controlled reference input. Tool arguments cannot replace that target. Proposal
ownership comes from the verified BReg caller. Every editable input uses the
compiler-emitted JSON Schema exactly. The review page rechecks target disclosure
under the person's token before offering or performing submission.

External policy decides review where the Action requires it. BReg retains and
applies the exact frozen plan, automatically by default under its restricted
system grant or manually when explicitly configured. Current Proposal state and
application evidence remain BReg's; the gateway and review page keep no parallel
workflow or application authority. A later Get cannot reconcile an uncertain
command or silently follow a successor submission.

Configure the gateway with `service.details.recordType`,
`service.application.action`, and `service.application.targetInput`. Configure
the review page with `registry.action`, `registry.targetInput`, and its independent
`registry.accessProfile`. Boundaries, linked reads, target scope, and Proposal
permissions belong in the registry project. Deployment supplies issuer/exchange
credentials through secret references.

The product-neutral `registry-mcp-edge` supplies protected transport and durable
audit. The configurable, source-built `registry-mcp` supporting service can bind
this same citizen provider, or a separate Casework delegated staff reader.
Keep `breg-mcp` for existing citizen deployments. The configurable service's
ownership, protocol and source disclosure contract are recorded in
[the composition design](../platform/MCP-GATEWAY.md).

Use the maintained site guides:

- [Citizen chat assistant](../../docs/site/src/content/docs/configure/breg-mcp.mdx)

The native source is `crates/registry-breg-mcp/` and
`crates/registry-breg-review/`. Their public config checks validate documents
offline; successful checking does not prove an issuer exchange or registry grant.
The focused PostgreSQL and gateway boundary tests own runtime verification.
