# Registry MCP edge

`registry-mcp-edge` is the product-neutral authenticated MCP edge shared by
Registry Stack supporting services. It owns streamable HTTP transport, RFC 9728
protected-resource authentication, strict JWT verification inputs, keyed caller
pseudonyms, caller and client rate limits, fail-closed tool-call audit, and
dispatch to statically configured provider bindings.

Each provider binding owns an independent authorization factory and configured
public-tool allowlist. Selecting a tool cannot select another connection,
audience, scope set, profile, or credential. An exchange-backed binding creates
one opaque downstream authorization from the verified inbound caller for each
catalog or invocation. A trusted-machine binding can use a separately configured
token provider for an explicitly non-personal operation. Providers never receive
the inbound bearer. They can read the verified issuer and subject through a
redacted identity handle where product semantics require owner or idempotency
binding. Those claims must not be logged or returned.

Providers own product contracts, target binding, schemas, revisions,
idempotency, effect interpretation, and recovery. The edge distinguishes no
effect, confirmed effects, accepted-pending work, and unknown outcomes for audit
release. Tool listing is private with a zero TTL, and every provider catalog is
intersected with the binding's static allowlist.

Product wrappers own runtime configuration, secret resolution, key-source
network policy, provider construction, audit schema identity, and public
errors. The existing BReg wrapper can retain its configuration and audit names
while using this edge; the configurable cross-product runtime can register its
own format and bind several independently authorized providers.
