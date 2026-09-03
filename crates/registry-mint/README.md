# Registry Mint

Mint issues short-lived access tokens to registered machine clients. It exists
so that a resource server such as Evidence Gateway or Registry Relay can
require signed, expiring, audience-bound tokens without the deployment first
having to stand up a general purpose identity provider.

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
principal or authorization claim.

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

Mint speaks the `client_credentials` grant. `private_key_jwt` client
authentication (RFC 7523) remains the default. A client builds a short-lived
JWT assertion signed with its own private key, and posts it to the token
endpoint:

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

A managed client that cannot sign assertions may use the explicitly selected
client-secret compatibility profile. Mint accepts both `client_secret_basic`
and `client_secret_post`. The registration stores one or two canonical SHA-256
fingerprints, never the raw secret:

```
POST /token
Authorization: Basic <base64(form-encode(client-id):form-encode(client-secret))>
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
```

Form-encode the client id and secret separately before joining them with the
colon delimiter and Base64-encoding the result. The same request may carry
`client_id` and `client_secret` in the form body for clients that implement
`client_secret_post`. One request may use only one authentication method.
Client-secret registrations are standard-authorization clients only; they
cannot issue Evidence or delegated authority.

The response is a signed `at+jwt` access token. Errors collapse to
`invalid_client` so that the endpoint cannot be used to probe which client ids
are registered.

Each client registration selects one authority profile. An Evidence profile
writes configurable Evidence claims. A standard authorization profile writes
one space-delimited OAuth `scope` claim plus bounded direct string or
string-list claims.
The two profiles cannot be combined in one registration, and neither profile
accepts authority from the token request.

Endpoints:

| Path | Purpose |
|---|---|
| `POST /token` | Issue an access token |
| `GET /.well-known/jwks.json` | Public keys for verifying minted tokens (path is configurable) |
| `GET /.well-known/oauth-authorization-server` | Metadata pointing at the above |
| `GET /.well-known/openid-configuration` | Equivalent discovery metadata for OIDC-compatible resource servers |
| `GET /health`, `GET /ready` | Liveness, and readiness (503 without clients, a ready signer, or a writable audit chain) |

## Configuration

One YAML document. Governed public-key, audit, and client-registry paths resolve
relative to the document's own directory. The secret root and Transit socket
are absolute. Everything here is startup-only: issuer identity, signing and
audit keys, listener, and token policy are fixed for the life of the process.

```yaml
version: 1
issuer: https://mint.example.org
listener:
  address: 127.0.0.1
  port: 8081
signing:
  algorithm: ES256
  activePublicJwkFile: public-keys/<thumbprint>.jwk.json
  publishedPublicJwkFiles: []
  revokedKeyIds: []
signer:
  kind: transit
  unixSocketPath: /run/registry-mint/transit-proxy.sock
  mount: transit
  keyName: mint-signing
  keyVersion: 7
  timeoutMilliseconds: 2000
secretProviders:
  file:
    root: /run/registry-mint/secrets
audit:
  path: audit/mint.jsonl
  maximumFileBytes: 1073741824
  hashKeyRef: secret:file/audit-hmac-key
  hashKeyVersion: 1
accessTokens:
  audiences: [evidence]
  lifetimeSeconds: 300
  claims:
    principal: sub
    requesterTags: evidence_tags
    evidenceAudience: evidence_audience
    grantId: evidence_grant_id
    grantAuthority: evidence_authority
    # Optional. Required only to issue delegated tokens; see below.
    actor: evidence_actor
clientAssertion:
  audience: https://mint.example.org/token
  maximumLifetimeSeconds: 300
  algorithms: [EdDSA]
clients:
  directory: clients
```

The `accessTokens.claims` names must match Evidence Gateway's `authentication`
block because Evidence Gateway reads its principal, requester tags, evidence
audience, and grant pair from configurable claim names. A scoped-only
deployment may omit `accessTokens.claims`. Access token lifetime is bounded to
60..=3600 seconds; a long-lived bearer token is the thing Mint exists to avoid.

Mint's service key is always P-256/ES256. Each governed public JWK carries a
`kid` equal to its 43-character RFC 7638 thumbprint and is stored as
`<thumbprint>.jwk.json`. Strict deployments use a non-exportable Vault/OpenBao
Transit key through the configured workload-local Unix socket. Mint receives
no provider token.

Supervised local development may replace the `signer` block with:

```yaml
signer:
  kind: local-jwk
  privateKeyRef: secret:file/mint-signing
```

The referenced private JWK must exactly match `activePublicJwkFile`. Secret
files are resolved beneath `secretProviders.file.root` and must be regular,
single-link, owner-only files. Never commit, print, or pass them on a command
line. Client assertion keys remain independently owned and may use EdDSA,
ES256, or RS256 with their own identifiers.

Generate every compatibility-profile secret with Mint itself:

```bash
mint client-secret generate --out /run/registry-mint/secrets/qgis-west.secret
```

The command creates a new owner-only file, refuses to replace an existing
file, and prints only its `sha256:...` fingerprint. The raw secret never
appears on stdout or in the registration. Copy the file to the one managed
client installation that will use it, through the deployment's secret-delivery
channel. Do not share one secret across people or installations.

The audit key file is also owner-only and must contain at least 32 bytes. The
audit directory, chain, and lock file must be owned by the Mint process user and
unavailable to group and other users. For a new deployment, `openssl rand -hex
32 > /run/registry-mint/secrets/audit-hmac-key` followed by `chmod 600
/run/registry-mint/secrets/audit-hmac-key` is sufficient. Mint derives separate
HKDF subkeys for chain integrity and identifier pseudonyms. It verifies the
keyed chain at startup and holds a single-writer lock for the process lifetime. It writes a durable
release record before returning every access token; if that write fails, the
request returns `server_error` and readiness fails. Denials are recorded with
value-free error categories. Raw assertions, tokens, client ids, actors,
principals, and subject values never enter the chain; successful records use
keyed pseudonyms where correlation is needed.

`audit.maximumFileBytes` is a per-segment threshold, not a total capacity limit.
When an append would exceed the threshold, Mint seals the active segment as
`<audit.path>.<eight-digit-sequence>` and opens a new active segment online. The
keyed chain continues across the seam. Mint never deletes or compacts sealed
segments, so monitor total capacity and archive sealed history under the
deployment's retention policy while retaining the matching audit key. Never
rename or archive the active segment while Mint is running.

Audit master rotation starts a new epoch. Stop Mint, record and archive the old
chain head, runtime, key, and segments, then increment `hashKeyVersion`, select
a fresh audit path, install the new key, run `mint check`, and restart. Never
append a replacement audit master to an existing chain.

For planned service-key rotation, create the next Transit version, publish its
public JWK first, and deploy and restart every replica with that overlap set.
Only after every replica publishes both keys, switch `activePublicJwkFile` and
the pinned `keyVersion` together while leaving the old key published, then
deploy and restart every replica again. Remove the old public key and raise the
Transit key's `min_encryption_version` only after the maximum access-token
lifetime plus consumer clock skew. For compromise, disable provider signing
authority immediately, remove its JWK, add its thumbprint to `revokedKeyIds`,
and activate a replacement or leave Mint unavailable. Add the compromised Mint
thumbprint to each Evidence consumer's `authentication.revokedKeyIds` in the
same incident rollout. Configuration is startup-only, so every rotation step
takes effect through a restart.

Mint client-key rotation is independent of the service key. Add the new public
client key, reload, move the client, and retain the old public key for the
configured maximum client-assertion lifetime plus 30 seconds before removing
and reloading again. Remove a compromised client key immediately and reload;
do not provide an overlap window during an incident.

Client-secret rotation uses the same registry reload boundary. Generate a new
secret, add its fingerprint beside the old fingerprint, reload, update the
managed client, then remove the old fingerprint and reload again. A
registration accepts at most two fingerprints so this overlap cannot become an
unbounded secret set. Remove a revoked fingerprint only while another valid
fingerprint remains. To revoke the last or only secret, remove the complete
registration and reload. An empty fingerprint list is invalid and leaves the
previous registry active after the failed reload. Access tokens already released
remain valid until their short configured expiry.

## Registering clients

### Evidence authority

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

### Standard scoped authority

Use `authorization` for a Registry Relay client or another OAuth resource
server that reads the standard `scope` claim:

```yaml
clientId: registry-consumer
principal: urn:example:consumer
authorization:
  scopes:
    - registry:business:read
  claims:
    purpose: statutory-consultation
    authority: district-17
keys:
  - kty: OKP
    crv: Ed25519
    kid: registry-consumer-2026-01
    x: "..."
```

Mint joins the registered scopes with one ASCII space, writes the result as
the token's `scope` claim, and returns the same string in the token response's
optional `scope` member. The direct claims are server-governed. A claim value
is either one string, minted as a JSON string, or a list of strings such as
`authority: [district-17, district-18]`, minted as a JSON array for a resource
server boundary that matches a row against a set of permitted values. The
client assertion and token request cannot add, narrow, or replace them.

A scoped registration has 1 to 64 unique RFC 6749 scope-tokens and at most 32
direct claims, and a listed claim carries 1 to 64 unique values. It cannot use
`evidenceAudience`, `requesterTags`, `grant`, or `delegation`. Direct claim
names cannot shadow `iss`, `aud`, `exp`, `iat`, `nbf`, `jti`, `client_id`,
`sub`, or `scope`.
When the deployment also configures Evidence claim names, a scoped client's
direct claims cannot reuse any of those names.

Standard-profile tokens have a maximum configured lifetime of 900 seconds.
Mint also projects the complete signed token response at startup and reload and
refuses a registration that would exceed the shared client's 16 KiB response
ceiling. Evidence-profile deployments retain the general 60 to 3600 second
range.

For Registry Relay, configure `accessTokens.audiences` with the one exact
audience from the Relay runtime. Register only scopes and direct claims that
the Relay contract uses for the intended operation and access profile. Mint
remains an ordinary conforming issuer; Relay has no Mint-specific runtime
branch.

For a managed client such as one QGIS installation, explicitly select the
client-secret compatibility profile and replace `keys` with one or two
fingerprints:

```yaml
clientId: qgis-west
principal: urn:example:qgis-installation:west
authorization:
  scopes:
    - registry:business:read
clientAuthentication:
  method: client-secret
  secretFingerprints:
    - sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

Omitting `clientAuthentication` keeps the stronger `private-key-jwt` default.
A secret authenticates that installation, not the person using it, and must
therefore receive only the least authority that installation needs. Use one
registration and secret per managed installation when independent rotation,
revocation, or audit attribution matters.

## Delegation: a token bound to one subject

A caller can be issued a token that is valid only for evidence *about one named
person*. The point is containment rather than labelling: a client that loops
over the wrong list or reuses a request object cannot cross from one person to
another, because the subject is not a request parameter it controls.

Three things have to line up.

**The registration** says which agents this client may act as, and which
selector fields it may bind, at which claim paths:

```yaml
clientId: appointment-scheduler
principal: service:appointment-scheduler
evidenceAudience: https://scheduler.example.org
requesterTags: [scheduling-agent]
delegation:
  # Optional. Omitted means the client names its own actor.
  actors: [urn:example:agent:appointment-scheduler]
  subjectClaims:
    given_name: identity.given_name
    family_name: identity.family_name
    birth_date: identity.birth_date
keys: [...]
```

A client with no `delegation` block cannot obtain a delegated token at all.

**The request** names the actor and the subject inside the client's own signed
assertion, in an `on_behalf_of` member:

```json
{
  "iss": "appointment-scheduler",
  "sub": "appointment-scheduler",
  "aud": "https://mint.example.org/token",
  "iat": 1785671511, "exp": 1785671631, "jti": "...",
  "on_behalf_of": {
    "actor": "urn:example:agent:appointment-scheduler",
    "subject": {"given_name": "...", "family_name": "...", "birth_date": "..."}
  }
}
```

Placing it inside the assertion is deliberate: the actor and the subject are
covered by the client's signature, so nothing between the client and Mint can
alter who the token is for. `on_behalf_of` is Mint's own member rather than RFC
8693 `act`, because token exchange presents a subject's own credential, which is
exactly what a deployment without an identity provider does not have.

The subject must carry the registration's subject fields exactly: a missing
field or an extra one is refused, like every other delegation failure, as
`invalid_client`.

**The resource server bundle** declares that subject role's `valueOrigin` as
`authenticated-context`, with `valueClaims` mirroring `subjectClaims` above.
That is what makes the property hold: Evidence reads the selector from the token
and rejects any request that carries selector values of its own. A request
naming a different person is refused for carrying values at all, not for
carrying the wrong ones.

Two limits worth stating plainly. This defends against a *buggy* client, not a
*compromised* one: a client holding its own signing key can ask Mint for a token
naming a different subject, within the fields its registration permits. And
Evidence confines an actor-bearing token to `kind: delegated` authority profiles
but does not conversely require an actor to reach one, so an undelegated token
matches such a grant and is stopped when the subject cannot be resolved.

[`demo/`](demo/) runs all of this end to end against the real binaries, with
every request printed before it is sent.

The registry is the one reloadable part of Mint. `SIGHUP` reloads it in place,
keeping the previous registry if the new one does not load. Onboarding,
offboarding, and caller key rotation therefore never restart the resource
server.

## Running

```bash
mint check --config /etc/mint/mint.yaml
```

The ordinary check can run while Mint is serving because it does not claim the
audit writer. Before first startup or a replacement deployment, add
`--require-runtime-dependencies` to prove the signer and writable audit chain
through the same initialization path as `mint serve`.

`mint healthcheck` probes a numeric loopback or private-address `/ready`
endpoint with a bounded, proxy-free HTTP client and accepts only Mint's exact
minimal ready response. Set `MINT_HEALTHCHECK_URL` when the container binds a
private address instead of the loopback default. The command is for container
and process supervision; it prints no response body.

```bash
mint serve --config /etc/mint/mint.yaml
```

Verify the retained chain with the same configuration and audit key:

```bash
mint verify-audit --config /etc/mint/mint.yaml
```

The command verifies every sealed segment. It also verifies the active segment
when no Mint process owns the writer lock; otherwise it reports
`active-segment: not verified`.

All three operator commands accept `MINT_CONFIG` in place of `--config`.
`check` loads the configuration, signing key, audit chain, and client registry,
then exits without opening a socket.

Mint serves plain HTTP and expects to sit behind TLS termination it does not
manage.

## Getting a token in development

```bash
mint token --url https://mint.example.org/token \
  --client-id scheduler --key ./dev/scheduler.jwk
```

It prints the access token on stdout and nothing else, so `TOKEN=$(mint token
...)` is the whole usage. Diagnostics go to stderr; `--verbose` prints the
endpoint's full response instead.

This is a *client* tool. It signs a client assertion with the caller's own key
and presents it to a running endpoint, exactly as an adopter's client library
would. It reads no server configuration and never touches Mint's signing key.
There is deliberately no subcommand that signs an access token directly: that
would be a way to obtain authority without authenticating, inside the binary
whose purpose is to make authority depend on authentication. Anything `mint
token` can obtain, the same client could have obtained over the wire.

The key file gets the same treatment as Mint's own signing key: a regular file,
owned by you, unreadable by group and other, reached without traversing a
symlink.

`mint token` intentionally exercises the preferred private-key method. For a
standard OAuth client that needs a secret, use `mint client-secret generate`
to provision it and let the client call `/token` with
`client_secret_basic` or `client_secret_post`.

For a delegated token:

```bash
mint token --url https://mint.example.org/token \
  --client-id scheduler --key ./dev/scheduler.jwk \
  --actor urn:example:agent:appointment-scheduler \
  --subject-file ./dev/subject.json
```

`--subject-file` holds a flat JSON object of selector fields
(`{"given_name": "Amara", "birth_date": "1998-04-02"}`). It is a file rather
than repeated flags because those are a real person's identifying details, and
command lines are visible to every process on the host and land in shell
history.

Two more flags matter in development. `--audience` overrides the assertion
audience, which defaults to `--url`; they differ when the endpoint is reached
over loopback but configured with its public URL. `--ca-certificate` trusts a
PEM bundle in addition to the system roots, for a deployment behind a private
CA.

## Verify a change

```bash
cargo test --locked -p registry-mint
```

`tests/evidence_compatibility.rs` is the test that justifies the crate: it
drives the real router over a real on-disk deployment and feeds the minted
token to Evidence's own authenticator. `tests/delegated_subject_binding.rs`
does the same for delegation, running Evidence's own entitlement match and
selector resolution over a token from the real Mint router. The dependency runs
one way only. Evidence does not depend on Mint.

`registry-relay-v2`'s `tests/acceptance_http.rs` also starts the real Mint and
Relay routers. The Relay client obtains a token through its shared
private-key-JWT provider, then uses Mint's registered scope, purpose, and row
authority for a protected lookup. Relay's production crates do not depend on
Mint.

`tests/token_cli.rs` runs `mint token` against a real `mint serve` as two
processes, which is the only place the stdout contract can be observed.
`tests/client_secret_compatibility.rs` drives both standard secret methods
through the real router, verifies the released token with the shared OIDC
verifier, and covers renewal, rotation, revocation, authority containment, and
audit redaction. `tests/client_secret_cli.rs` proves the provisioning command's
owner-only file and stdout contracts as a real process.
