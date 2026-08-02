# Registry Mint

Mint issues short-lived access tokens to registered machine clients. It exists
so that a resource server such as Evidence can require signed, expiring,
audience-bound tokens without the deployment first having to stand up a general
purpose identity provider.

Mint is not a product line. It is a small supporting service for deployments
that have many callers and no IdP.

## Why a server, and not just a shared JWKS

A resource server configured with a pooled JWK set can answer only one
question: *was this token signed by one of the trusted keys?* It cannot answer
the question that authorization actually depends on: *which caller signed it,
and what is that caller permitted to assert?*

Key selection inside a JWK set is by `kid`, and `kid` is chosen by whoever
built the token. So in a pooled set every key is equally authoritative for
every claim. Any client holding any trusted key can mint a token naming any
principal, any requester tags, and any evidence audience.

Mint closes that by splitting the two questions across two places:

- The **client registry** (`clients/*.yaml`) binds a client id to *that
  client's* public keys and to the authority Mint will assert for it.
- The **token endpoint** verifies an incoming client assertion against the
  keys of the client it claims to be, selected *before* signature
  verification, and then writes the authority from the registry, never from
  the assertion payload.

A client therefore holds its own key and signs for itself, but possession of a
key no longer decides what may be said.

## Protocol

Mint speaks the `client_credentials` grant with `private_key_jwt` client
authentication (RFC 7523). A client builds a short-lived JWT assertion signed
with its own private key, and posts it to the token endpoint:

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer
&client_assertion=<compact JWS>
```

The assertion must carry `iss` and `sub` equal to the client id, `aud` equal to
the configured `clientAssertion.audience`, a `jti`, and `iat`/`exp` inside the
configured maximum lifetime. Every `jti` is single use: presenting the same
assertion twice is refused.

The response is a signed `at+jwt` access token. Errors collapse to
`invalid_client` so that the endpoint cannot be used to probe which client ids
are registered.

Endpoints:

| Path | Purpose |
|---|---|
| `POST /token` | Issue an access token |
| `GET /.well-known/jwks.json` | Public keys for verifying minted tokens (path is configurable) |
| `GET /.well-known/oauth-authorization-server` | Metadata pointing at the above |
| `GET /health`, `GET /ready` | Liveness, and readiness (503 while no client is registered) |

## Configuration

One YAML document. Every path in it resolves relative to the document's own
directory. Everything here is startup-only: issuer identity, signing keys,
listener, and token policy are fixed for the life of the process.

```yaml
version: 1
issuer: https://mint.example.org
listener:
  address: 127.0.0.1
  port: 8081
signing:
  algorithm: EdDSA
  activeKeyId: mint-2026-01
  activeKeyFile: secrets/signing.jwk
  # Public JWKs of keys that no longer sign but may still have live tokens.
  retiredPublicJwkFiles: []
accessTokens:
  audiences: [evidence]
  lifetimeSeconds: 300
  claims:
    principal: sub
    requesterTags: evidence_tags
    evidenceAudience: evidence_audience
    grantId: evidence_grant_id
    grantAuthority: evidence_authority
clientAssertion:
  audience: https://mint.example.org/token
  maximumLifetimeSeconds: 300
  algorithms: [EdDSA]
clients:
  directory: clients
```

The `accessTokens.claims` names must match the resource server's
`authentication` block, because the resource server reads its principal,
requester tags, evidence audience, and grant pair from configurable claim
names. Access token lifetime is bounded to 60..=3600 seconds; a long-lived
bearer token is the thing Mint exists to avoid.

The signing key file must be a private JWK and must be readable only by its
owner. Never commit it, print it, or pass it on a command line.

## Registering a client

One `*.yaml` file per client in `clients.directory`:

```yaml
clientId: health-desk
principal: service:health-desk
evidenceAudience: https://evidence.example.org
requesterTags: [health-desk, region-north]
# Optional. Minted only for callers acting under a recorded authority.
grant:
  id: grant-2026-014
  authority: ministry-of-health
keys:
  - kty: OKP
    crv: Ed25519
    kid: health-desk-2026-01
    x: "..."
```

Only public JWKs are accepted; a document carrying a private member is
rejected. The load is all-or-nothing, so one malformed registration fails the
whole load and a partially applied registry can never serve.

The registry is the one reloadable part of Mint. `SIGHUP` reloads it in place,
keeping the previous registry if the new one does not load. Onboarding,
offboarding, and caller key rotation therefore never restart the resource
server.

## Running

```bash
mint check --config /etc/mint/mint.yaml
```

```bash
mint serve --config /etc/mint/mint.yaml
```

Both accept `MINT_CONFIG` in place of `--config`. `check` loads the
configuration, signing key, and client registry, then exits without opening a
socket.

Mint serves plain HTTP and expects to sit behind TLS termination it does not
manage.

## Verify a change

```bash
cargo test --locked -p registry-mint
```

`tests/evidence_compatibility.rs` is the test that justifies the crate: it
drives the real router over a real on-disk deployment and feeds the minted
token to Evidence's own authenticator. The dependency runs one way only.
Evidence does not depend on Mint.
