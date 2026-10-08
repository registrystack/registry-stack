# Native local BReg lifecycle

`bregctl dev` starts an existing, explicitly authored local registry using the
installed `breg` binary, a source-pinned ThunderID image, and Docker PostgreSQL.
It needs no checkout, Python launcher, shell script or OpenSSL installation.
ThunderID is a local issuer chosen by this development tool; an operated BReg
runtime remains an independent OAuth resource server.

Prepare the project with `bregctl init ./registry`. The generated
`dev-clients.yaml` binds three distinct local clients to `operator`,
`record-reader`, and `evidence-source`, so the project starts unchanged. Review the model,
access profiles, journey fixtures and local clients before the first start.
A later dedicated Evidence source can be prepared explicitly on a stopped session.

```sh
bregctl dev ./registry
bregctl dev stop ./registry
bregctl dev start ./registry
```

The project path defaults to the current directory, as it does for every other
`bregctl` command. A first start reads `dev-clients.yaml` inside the project;
`--clients-file` names another clients file instead. `dev` and `dev start` both
detach a resident supervisor. They return only after
PostgreSQL, ThunderID, schema-test rehearsal, package activation, BReg readiness and
explicit seed creation succeed. Default loopback ports are BReg `8090`, issuer
`8091` and PostgreSQL `15432`. Override them on the first start with
`--breg-port`, `--issuer-port` and `--database-port`. A restart retains the
original ports and clients-file location. Conflicting ports are refused.

The database runs the pinned image
`postgres:17.11@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675`,
or `postgis/postgis@sha256:01a6a70e41e6c4467c8f55f6063555ed72db2d6662cd0d571040d42eadaeb6f6`
when the compiled schema requires PostGIS. The selection is retained with the
owned database. Spatial setup grants the migration role permission to SET the
no-login bbox owner; the runtime role never receives that membership.
Each supervised
prerequisite command may run for 120 seconds. The owned database and BReg have
45 seconds each to answer readiness, and ThunderID discovery has a 120-second wait. A start
that passes a deadline fails, stops what it acquired and keeps its owner-only
diagnostics.

Before it inspects the owned container or launches the supervisor, a start runs
each resolved `breg` and `docker` with `--version` and records what they
answer. `breg` ships in the same release as `bregctl`, so a `breg` reporting
another version is refused by name: the refusal gives the file that answered,
the version it reported and the version `bregctl` reports.
Without that comparison the mismatch surfaces much later as a refused package or
an unready database, which reads as a fault in the authored project. Docker
belongs to no release of this stack and is never compared, and a prerequisite
that reports no version at all still serves the session. No flag skips the
comparison: install `breg` and `bregctl` from the same release, or put the
matching build first on `PATH`. `--breg-bin` chooses which file is resolved,
and that file is compared.

`dev stop` keeps everything it created: the owned container, its named data
volume, records, the audit files under `.breg/dev/audit`, keys, credentials and
the built package. Add `--remove` to reclaim the storage as well; it removes the
owned container and its `breg-dev-<owner>` data volume, discarding records,
event receipts and seed checkpoints. The audit files are kept. For an initial package at sequence 1, the next start builds an empty
database from the same authored project, ports, credentials and package. It also
lets the next start take edited
inputs: once no records are retained, a changed package, clients file or port
([what counts as changed](#retained-state-and-recovery))
replaces the session with a fresh one that keeps the previous ports and clients
file and generates new keys. A successor package prepared for retained records
cannot initialize an empty database after removal: start refuses before Docker.
Create a fresh project at package sequence 1 for a separate empty experiment.

Use `--format json` to consume the status, URLs, audience, package digest,
runtime configuration and private credential file references. Keys and access
tokens never appear in these reports. Use `bregctl dev export-client` to obtain
the client ID, assertion key, issuer and token endpoint handoff; an OAuth client
can obtain a fresh token with those fixed values. Keep token output owner-only.

## Observe local events

Declare an event with a webhook destination in the authored project before
the first start. By default, `dev` binds every compiled destination to its own
HMAC-verifying receiver on a free numeric loopback port. The receiver port,
signing key, and bindings are retained across restarts; a conflicting receiver
port is refused. To deliver to an external local receiver instead, bind every
compiled destination ID in `dev-clients.yaml`:

```yaml
secretProviders:
  file: {root: /absolute/owner-only/dev-secrets}
eventDestinations:
  openfn:
    origin: http://127.0.0.1:8088
    path: /webhooks/registry
    hmacSha256KeyRef: secret:file/openfn-webhook-key
```

The key is a [secret reference](#secret-references). The session copies it
into its private state and uses the same bounded outbox delivery and replay
rules.
The origin must be numeric loopback HTTP with an explicit port. An explicit
destination map starts no built-in receiver, so `dev events` has no inbox
receipts; inspect the receiving service and `bregctl webhook list` instead.

For a governed action package that declares Evidence providers, bind every
required provider in the project's `dev-clients.yaml` before its first start:

```yaml
evidenceProviders:
  qualification:
    baseUrl: http://127.0.0.1:8093
    trustBindingId: exact-local-trust-v1
    tokenRef: secret:file/evidence-token
    trustedJwksRef: secret:file/evidence-jwks.json
    revokedKeyIds: []
```

The dev command accepts exact numeric loopback origins and
[secret references](#secret-references), copies the token, trusted keys and
optional CA bundle (`caBundleRef`) into its
private state, and generates the corresponding `evidenceProviders` runtime
bindings. It does not relax package activation: provider IDs must match the
compiled action requirements, and the runtime still resolves and validates
every configured trust input before serving. Obtain the token after the shared
issuer is ready, then start the action-bearing BREG borrower with this binding.

For a change request whose `review.authority` names Casework, add one logical
authority binding and one dedicated machine client before the first start:

```yaml
clients:
  - id: casework-producer
    accessProfiles: []
    scopes: [casework:reviews:request]
    claims: {}
reviewAuthorities:
  casework-a:
    endpoint: http://127.0.0.1:8096/
    profile: integration-requester
    producerId: registry-producer
    recoveryDays: 7
    client: casework-producer
```

The authority ID must exactly match the compiled requirement. `profile`
selects the Casework requester access profile on every authority exchange.
`producerId`
must match the Casework producer connection, whose admitted source namespaces
include this Registry ID and whose admitted kinds include the authored review
policy ID. The client has no BReg profile. Its scope and token identity must
instead match Casework's requester profile and producer subject.

The dev issuer generates the client's assertion key. `bregctl` copies its
client ID and key into owner-only runtime secret files and emits a
`privateKeyJwt` authority credential with the dev issuer token endpoint,
assertion audience, resource, and declared scopes. BReg acquires and refreshes
short-lived Casework tokens for each outbound exchange. No token or private key
appears in `dev-clients.yaml`, runtime YAML, reports, or logs. An unmapped client
uses the session's generated default BReg audience, which supports an App Kit
composition where Casework and BReg deliberately share that resource audience.
If `issuer.clientResources` maps the client, the generated credential uses that
declared resource instead.

For a request that selects `onApproved: {mode: automatic, executor:
automatic-applier}`, bind that exact executor to one service-only BReg profile
and an existing local issuer client:

```yaml
clients:
  - id: automatic-applier
    accessProfiles: [automatic-applier]
    scopes: [registry:generic:apply]
    claims:
      registry_principal: automatic-applier
      registry_purpose: registry-application
reviewExecutors:
  automatic-applier:
    accessProfile: automatic-applier
    client: automatic-applier
```

The profile must grant `apply_request` for every request entity that selects
the executor, declare `actorKind: service`, and admit the client's exact ID,
scopes, purpose, and principal claim. Dev derives the endpoint and registry ID
from this BReg session. It copies the selected client's retained ID and
assertion key into owner-only runtime secrets and emits a renewable
`privateKeyJwt` executor credential for the local BReg audience. The executor
map is required authoring: dev does not infer an executor from a profile and
does not create a review-authority binding for it.

Polling needs no callback credential. To test authenticated completion delivery,
add both optional fields; declaring only one is refused:

```yaml
    completionTokenRef: secret:file/casework-completion-token
    completionRecipient: registry-breg
```

The completion token is an independent sender credential, named by a
[secret reference](#secret-references) and copied into private state. It is never used for review requests or source application. Operated
runtime configuration also supports an explicit static `tokenRef` for an
opaque renewable credential supplied by the deployment, but `bregctl dev`
always generates the refreshing `privateKeyJwt` branch.

After a seed, example scenario, or API write triggers an event, inspect receipts:

```sh
bregctl dev events ./registry
bregctl --format json dev events ./registry
bregctl dev events ./registry --include-payload
```

The default report shows the event UUID, authored event, entity, trigger,
compiled delivery and destination IDs, generation, attempt and `received`
status. Record IDs and projected values are omitted. `--include-payload`
explicitly displays the projected values from the development receiver.
Receipts remain available while the session is stopped. `dev stop --remove`
erases the receipt journal along with the records, including captured payloads.

The receiver keeps these development values in the owner-only
`.breg/dev/events.jsonl` journal, outside version control. Its 16 MiB bound
prevents unbounded storage; when full, it refuses further receipts and the
runtime follows its normal retry/dead-letter policy. While stopped, move the
journal to an owner-only location if it needs to be preserved, then start again
to create an empty inbox. Treat captured values as private development data.

A receipt means the receiver accepted that attempt. The runtime's pending and
dead-letter queue is inspected separately. Supply the local PostgreSQL CA and
the absolute runtime configuration path:

```sh
SSL_CERT_FILE="$PWD/registry/.breg/dev/tls/ca.pem" \
  bregctl webhook list --runtime-config "$PWD/registry/.breg/dev/runtime.yaml"
```

Delivered rows leave that queue. Automatic retries keep the event UUID and
idempotency key; an eligible operator replay increments the generation. Use
the identifiers and generation from `webhook list` with `bregctl webhook replay
--help`. Supply the same `SSL_CERT_FILE` and absolute runtime path for replay.
The normal event delivery, dead-letter and replay rules also apply to
this generated runtime. See [Events and webhooks](EVENTS-AND-WEBHOOKS.md).

The supervisor starts the receiver before BReg and stops it after BReg during
normal shutdown or failed startup. It captures runtime deliveries, including
seed writes; the disposable schema-test rehearsal does not dispatch webhooks.
Projects declaring no webhook destinations start without a receiver and report
an empty inbox. These bindings are local development configuration; operated
deployments must bind their own destinations and signing keys.

## Explicit teaching clients

The clients file is ordinary YAML with a closed format. It starts with
`apiVersion: id.registrystack.org/formats/breg/dev-clients/v1alpha1` and
`kind: BRegDevClients`, and `bregctl dev start` reports every unknown or
removed member at its line and column before any service starts. It declares
local issuer registrations; it does not add or infer BReg access profiles.
Every protected journey step without an exact binding needs one default client
for its profile whose scopes and claims match the ordinary step. A maintained refusal step may
use another client for the same profile by naming that exact step with
`testBindings`. The closed binding contains both `journeyId` and `stepId`; stale,
profile-mismatched, duplicate, or ambiguous bindings are refused before any
service starts.

Set `accessProfiles: []` for a machine client that carries only scopes or
claims for another product, such as Casework. The empty list gives that client
no BReg access-profile binding. It is registered with the local issuer but omitted
from the BReg runtime's `allowedClients`, so it cannot call BReg.

An integration client that must call BReg without becoming a journey or seed
binding must opt in with `allowBregAccess: true`. Use that flag only when its
scopes and authority claims are intentionally sufficient for the BReg profiles
it will select. `caseworkctl source add` sets it only for exported Staff and
Supervisor reviewers; other profile-free Casework clients remain excluded.

```yaml
apiVersion: id.registrystack.org/formats/breg/dev-clients/v1alpha1
kind: BRegDevClients
clients:
  - id: operator
    accessProfiles: [operator, reference-loader]
    scopes: [registry:generic:operate, registry:generic:read]
    claims:
      registry_principal: generic-registry-operator
      registry_purpose: [registry-operations, registry-reporting]
  - id: reader
    accessProfiles: [record-reader]
    scopes: [registry:generic:read]
    claims:
      registry_principal: generic-registry-reader
      registry_purpose: registry-reporting
      registry_record_status: active
  - id: reader-for-lifecycle-test
    accessProfiles: [record-reader]
    scopes: [registry:generic:read]
    claims:
      registry_principal: generic-registry-reader
      registry_purpose: registry-reporting
      registry_record_status: active
    testBindings:
      - journeyId: record-lifecycle
        stepId: read-record-within-the-claim
  - id: source
    accessProfiles: [evidence-source]
    scopes: [registry:evidence:lookup]
    claims:
      registry_principal: generic-registry-source
      registry_purpose: evidence-source-read
seed:
  - id: first-record
    client: operator
    entity: record
    accessProfile: operator
    data:
      code: synthetic-dev-record
      label: Synthetic local record
      status: active
  - id: reference-record
    client: operator
    entity: reference-record
    accessProfile: reference-loader
    operation: import
    data:
      code: synthetic-reference-record
      label: Synthetic reference record
```

`registry_purpose` may remain one string. A list declares the closed set of
purposes that one logical client may use in journey steps; the first remains
the purpose of its ordinary dev token. Each authenticated journey step names
an exact scope subset and, when the client declares several purposes, one
declared `purpose`. The rehearsal obtains a separate short-lived issuer token
for every distinct `(scopes, purpose)` claim set while keeping the same OAuth
client identity. An undeclared scope or purpose is refused before schema test.
Every multi-purpose client shares one generated first-party signer, so the
distinct claim names of all of them together, counting `registry_actor_kind`,
`registry_purpose`, and `scope`, may number at most 16, and a multi-purpose
client cannot also be listed on any authored exchange connection. That signer
makes the client first-party, so the issuer projects the purpose connection's
claims into its exchanged tokens: through an `institutional-grant` connection
they would lack the `registry_grant_*` claims the registry requires. Both are
refused when the clients file is read.

A seed defaults to `operation: create`. The illustrative `reference-record`
entity and `reference-loader` profile must be authored in the project, with an
Import route and the scope shown on the bound client. Dev writes one JSONL item, opens
an exact one-item authority bound to its digest, drives the normal ingestion
run, and closes the authority. An interrupted start retains the authority and
checkpoint, resumes that exact run, and records the completed seed in the same
state update that clears the authority. It can open a replacement when no
checkpoint exists: a sidecar may already name a zero-progress run, but the
missing checkpoint proves no chunk was submitted or committed. It can also
replace an incomplete run whose authority closed or expired before its sole
atomic chunk committed. Dev settles that terminal authority, retains its
checkpoint, and opens a fresh authority. Before asking to open an authority,
dev records in its state that the seed is about to open one, and when. An
interruption after the authority opened but before the session recorded it
leaves an open authority no local state names; the next start recognizes the
exact one-item, zero-progress authority this seed would have opened, opened no
earlier than that recorded intent, closes it, and opens a fresh one. Any other
open authority on the entity, including an identical one opened before the
intent or with no intent recorded, is refused by name and left to the operator.
A completed run is recorded first, and every other blocked or uncertain result
retains its linkage and fails closed.

A journey can likewise use a successful import step to load reference rows:

```yaml
request:
  operation: import
  items:
    - {code: GB, label: United Kingdom}
expect: {outcome: success, status: 200}
```

Schema test plans the same JSONL chunks, opens a bounded authority, submits the
production ingestion-run and chunk routes, verifies completion, and closes the
authority before the next step. Import steps do not capture a record response;
a later list or lookup step verifies the imported rows.

Each client has its own ES256 private key, generated by default. An existing
key can be imported with `assertionKeyRef` on that client, a
[secret reference](#secret-references) to its private JWK, for example when
Evidence already created its active access client. The dev
session validates the private key, copies it into retained state, and registers
only its public half. The service issuer,
operator and source workload use different keys. The reserved client ID `issuer`
is unavailable. Client and seed IDs contain lowercase ASCII letters, digits or
hyphens and have at most 64 bytes. There can be at most 32 clients and 100 seeds.

Plain `init` includes a dedicated `source` client for the existing lookup-only
`evidence-source` profile. That profile permits whole-registry exact lookups by
code, reads code and status, and grants no list or mutation operation. A supplied
code is not a row authorization rule. Custom models, including `init --from`, can start without an Evidence lookup or
client. Add one later through the explicit preparation below.

After creating Evidence, copy that existing source pair explicitly:

```sh
bregctl dev export-client ./registry --client source \
  --client-id-file ./evidence/secrets/registry-client-id \
  --assertion-key-file ./evidence/secrets/registry-client-key
```

Both destination parents must already be owner-only directories. Relative paths
are resolved from your current directory. Export reads the retained named client's
pair, including while stopped; it does not create a client, rotate keys, rewrite
registrations, or add persistent output bindings. Identical destination files are
reusable. A retry can complete a pair after one complete file was published.
Conflicting files, links, or unsafe permissions are refused without replacement;
choose fresh output names and update the target if you intentionally replaced the
session. The report contains file references and endpoints, never credentials.

Credentials remain under `.breg/dev/credentials/<client-id>/`, and
`export-client` is the only way a pair leaves the session. Export only the
dedicated source client when configuring Evidence. Evidence's caller credential
and BReg's operator credential retain separate authority.

### Secret references

A member that names a secret holds a secret reference, never a path:
`assertionKeyRef`, `hmacSha256KeyRef`, `tokenRef`, `trustedJwksRef`,
`caBundleRef`, `privateKeyRef`, `completionTokenRef`, `clientSecretRef`, and
`passwordRef`. `secret:file/<name>` names one file directly below
`secretProviders.file.root`, which must be absolute. `secret:env/<NAME>` names
an environment variable of the `bregctl dev start` process and is resolved only
when `secretProviders.environment` is declared:

```yaml
secretProviders:
  file: {root: /absolute/owner-only/dev-secrets}
  environment: {}
```

A referenced file must be an ordinary file you own, with mode 0400 or 0600 and
a single link. A referenced value must be non-empty, contain no NUL byte, and
fit the member's limit. The session copies each value into its private state
when it is prepared, so editing a referenced file later changes nothing until
the session is replaced. A refusal names the member, never the value, the file,
or the variable.

## Apply-time Evidence in development

A registry with Evidence guards needs the exact provider bindings declared by
its package. Put the binding in `dev-clients.yaml` before first start:

```yaml
secretProviders:
  file: {root: /absolute/private/dev-secrets}
evidenceProviders:
  qualification:
    baseUrl: http://127.0.0.1:8095
    trustBindingId: reviewed-local-provider
    trustedJwksRef: secret:file/evidence-signing-jwks.json
    privateKeyJwt:
      tokenEndpoint: http://127.0.0.1:8091/oauth2/token
      assertionAudience: http://127.0.0.1:8091
      clientId: qualification-reader
      privateKeyRef: secret:file/qualification-client.jwk
      resource: urn:example:evidence
      scopes: [evidence:invoke]
```

The provider URL and token endpoint use numeric loopback HTTP. Provision the
client at the issuer with precisely that resource and scope. The session copies
the referenced key and JWKS ([secret references](#secret-references)) to its
private state; it gives the runtime secret references. The ordinary BREG
credential provider refreshes expired service tokens. `tokenRef` is an
alternative for a pre-issued token and cannot be combined with `privateKeyJwt`.
An optional `caBundleRef` and `revokedKeyIds` retain their ordinary
relying-party meanings.

The same bindings apply to the disposable schema-test rehearsal and the local
runtime. A journey that applies a guarded request needs a reachable configured
Evidence provider and synthetic source facts. The development command does not
skip guards or replace runtime activation checks. Edited provider bindings on a
retained session follow the normal source-change refusal and recovery rules.

## Compose one local issuer

One BREG dev session can own the issuer registrations for several local
products. Its `dev-clients.yaml` declares the complete inventory before that
issuer starts. Add other audiences and the exact client role mapping under
`issuer`; the default BREG audience is the `resource` reported by the owner
session. Extra resources carry no client permission until a client is mapped.

```yaml
issuer:
  resources:
    - audience: urn:registrystack:evidence:local:gateway
      scopes: [evidence:invoke]
  clientResources:
    evidence-reader: urn:registrystack:evidence:local:gateway
  exchangeIssuers:
    - id: casework
      issuer: https://casework.example.test
      jwksEndpoint: http://host.docker.internal:8094/oauth2/jwks
      mapping: institutional-grant
      clients: [task-agent]
    - id: portal
      issuer: http://127.0.0.1:8095
      jwksEndpoint: http://host.docker.internal:8095/oauth2/jwks
      mapping: first-party
      clients: [portal-exchange]
      tokenAttributes:
        registry_principal: string
        evidence_tags: string-array
  exchangeClients: [task-agent, portal-exchange]
  interactiveApplications:
    - id: staff-portal
      clientSecretRef: secret:file/staff-portal-secret
      origin: http://127.0.0.1:3000
      redirectUris: [http://127.0.0.1:3000/callback]
      grants:
        - scopes: [registry:generic:operate]
      tokenAttributes: [registry_actor_kind]
  syntheticUsers:
    - username: officer
      email: officer@example.test
      passwordRef: secret:file/officer-password
      attributes: {registry_actor_kind: human}
      grants:
        - scopes: [registry:generic:operate]
```

Every referenced client also needs its own ordinary `clients` entry with exact
scopes and claims. `exchangeClients` must have one bootstrap scope, and the
external authority must be pre-registered. List each exchange client under
every connection whose authority it may present: the local resource servers
read that pairing and refuse a token exchanged from any other authority, so a
client named by no connection is refused before startup. A `first-party`
connection's `clients` list also selects the claims that connection projects;
an `institutional-grant` connection projects none. Local browser applications use
authorization code with PKCE and explicit redirect URIs. Their secrets and
synthetic passwords are copied into the owner's private issuer state. Explicit
app and user grants render issuer role assignments for the matching
resource; requested scopes without both permissions are not granted. An app
or grant that omits `audience` uses the owner's default BREG audience; such an
app enters the local runtime's allowed client list, and an app mapped to
another resource does not. The app still needs a
token with the governed profile's actual `scope` and principal/purpose claims
to call BREG.

Start the owner first. Another BREG project can run
`bregctl dev start ./registry-two --issuer-project ./issuer-owner` when the
owner pre-registered that project's client IDs, exact scopes, and claims. The
borrower copies those client pairs and issuer keys, pins the owner session ID,
and never starts or stops the shared issuer. Its own BREG package, database,
profiles and outbox remain independently owned. A replaced or unavailable
owner is refused before the borrower starts.
Declare additional issuer resources, exchange connections and clients, browser
applications, and synthetic users on the owner. A borrower may list only
`issuer.browserClients` from that issuer inventory; owner-only declarations in
the borrower's clients file are refused before startup.
A borrower answers on the owner's BREG audience, so it applies the owner's
exchange-connection pairings: an exchanged token is refused unless the
presenting client is registered against the assertion authority that signed it,
by exactly the connection list the owner declared.
To use an owner-registered browser app at the borrower's BREG resource, list
its ID under `issuer.browserClients` in the borrower's clients file. The owner
must have registered that app for the same audience. The borrower admits only
those listed app IDs; its governed profiles and token scopes still decide each
API call.

## Prepare a source after using a registry

Stop the retained registry normally, then use Evidence's guided local setup:

```sh
bregctl dev stop ./registry
evidencectl source add ./registry ./evidence
```

Choose the entity, an existing required unique scalar field, readable facts, and
record scope. The review distinguishes registry-wide exact lookups from an
explicit fixed binding on a string-valued row field. Without `--apply`, the
command reports the lookup, scope, and dedicated client it would prepare and
applies nothing. With `--apply`, it prepares one dedicated lookup-only client
and source contract; it imports the contract and copies that credential into
Evidence's private secrets directory. Local target endpoints and paths come from
the retained session and selected project, not from copied settings.

The owning BReg operation is `bregctl dev prepare-source`, which `bregctl dev --help`
omits because `evidencectl source add` is the documented path. Without `--apply`,
it reports the inventory or proposed change. `--apply` stages a policy-only successor
while the session is stopped. It adds the selected selector, narrow grant, and
separate client, then advances the package sequence. The next `dev start` activates
that successor while preserving record IDs, revisions, values, audit history,
and existing client credentials. It does not infer authority from field names.

This is not general retained-schema evolution. It refuses unrelated authored
changes, a nonunique selector, or reused client/profile identifiers. Correct the
named issue without removing retained data. For other model changes use the
reviewed package lifecycle.

## Retained state and recovery

The private `.breg/dev` directory records a random ownership identifier, exact
Docker container ID, ports, captured authored closure, package digest, seed
checkpoints and, for each resolved `breg` and `docker` prerequisite, the
fully resolved path of the file that ran and the version it reported. It
contains generated configurations, separate database roles, local TLS material,
credentials and bounded private diagnostic logs. The first start writes a
`.gitignore` into `.breg` that keeps the whole directory, its lock file included,
out of version control. Preserve it with the retained database while the
exercise matters. It is local development material, not production key
provisioning.
The state document also pins what the session runs: the compiled registry
revision, the package `sourceRevision`, and the canonical JSON form of
`tests/journeys.yaml` and the clients file. `dev start`, `dev examples run` and
`dev prepare-source` compare the project against that pin, so an edit that
changes only comments, blank lines or key order in a YAML file is not a changed
input. The compiled revision carries the digest of every Rhai script, WASM
module and derived SQL file it ships, so any edit to one of those files, a
comment included, is a changed input. A session started by an earlier release
holds an earlier pin, which reads as changed inputs.
Records live in a named `breg-dev-<owner>` Docker volume, so the storage stays
identifiable and reclaimable once the container is gone.

| Action or condition | Behavior |
| --- | --- |
| First start | Capture the authored closure, prepare private identities, create the owned database, run normal schema-test/package/apply/verify commands, then seed through authenticated HTTP. |
| Already running | Return the existing ready session and credential references. |
| Stop, including repeated stop | Gracefully stop owned BReg and ThunderID, then stop the owned PostgreSQL container. Keep records, keys, package, seed checkpoints and the audit files. |
| Stop where no start ever ran | Refuse and name the absent session. Nothing is created, changed or removed, so a mistyped project path cannot read as a stopped session. |
| Start after stop | Reuse the same container, database, and existing credentials. Preserve record edits; activate the explicitly prepared source successor when present. Obtain fresh short-lived tokens. |
| Stop with `--remove`, including a repeated one | Stop as above, then remove the owned container and its named data volume, tolerating whatever an earlier reclamation already took. Discard records, event receipts and seed checkpoints. Keep the audit files, keys, credentials, ports, clients and the built package. |
| Start after `--remove` | At sequence 1, create an empty container and volume, activate the initial package, and replay authored seeds. A retained successor refuses before Docker because its predecessor records were removed; use a fresh project at sequence 1 for an empty experiment. |
| Seed request committed before checkpoint | Replay the same permanent BReg idempotency reservation. The original create result is returned without creating or overwriting a record. |
| `breg` from another release | Refuse before the owned container is inspected and before the supervisor launches, naming the file that answered, the version it reported and the version `bregctl` reports. Nothing is created, changed or removed. |
| Retained state this release cannot read | Refuse as invalid retained dev state before any mutation, and preserve it for inspection. |
| Partial start failure | Stop acquired service children and the owned container; retain private diagnostics and completed phases. Retry the same command after correcting the prerequisite. The separate schema-test database may be recreated for a failed rehearsal. |
| Missing or mismatched owned container | Refuse. Never silently initialize an empty replacement or stop another container. |
| Unreachable supervisor with an occupied service port | Refuse. Never signal a stored PID that could belong to another process. Inspect the process owning the port before recovery. |
| Authored package, clients, ports or issuer image changed while records are retained | Refuse before activation or record mutation. Restore the original inputs to restart with the records, run `dev stop --remove` to discard them and start again from the edited inputs, or copy the authored files to a new project directory, at package sequence 1, to keep the records. |
| Authored package, clients or ports changed after `--remove` | At sequence 1, replace the session from the edited inputs, keeping previous ports and clients file and generating new keys. A successor still requires retained predecessor records. |

Reclamation is explicit: only `dev stop --remove` discards records, only a start
after it replaces retained keys, and only for edited inputs; this command
implements no automatic reset or general retained-schema upgrade. The explicit
source preparation above is limited to its reviewed policy-only successor. An operated
successor uses BReg's normal reviewed package, migration, activation and
recovery procedure. Copy only authored files to start a separate local
experiment; copying private retained state does not clone its database.

Only a resident native supervisor may signal the children it created. Control
uses an owner-only Unix socket in a short, random directory below canonical
`/tmp`, avoiding platform socket-path limits in deeply nested projects. The
socket directory is removed after stop. Durable state stays in the project.
Catchable termination signals trigger owned cleanup; an uncatchable kill can
require inspection of surviving service owners before restart.

PostgreSQL binds only numeric loopback. Native setup generates a private local
CA and configures TLS plus separate migration/runtime roles before BReg connects.
Source and token HTTP clients use numeric loopback, disable ambient proxies and
refuse redirects. Local synthetic credentials must not become operated service
credentials.

When startup fails, the error names the check that failed and the retained
private `logs` directory. Native command and service diagnostics are bounded
per stream. Inspect them locally; do not publish logs or the generated state
as a support attachment. Schema-test setup failures identify destination
inventory or activation, authentication, cursor, audit, or Evidence
configuration. Correct that named configuration before retrying; recreating
the database cannot fix a missing destination binding or invalid secret.

The rehearsal, the package build, activation and verification all run inside
the detached supervisor, whose own streams go to a private log. A phase that
refuses records its first failing diagnostic in the private state document,
and the start reports that diagnostic on the terminal that asked for it:
its code, the path it names, and its message, bounded to one sentence. The
retained report log holds every later diagnostic. A refused journey step is
reported as `test.step.failed` at `journeys[<i>].steps[<j>]`, carrying the
fixture's own refusal sentence. A refused logical reference names its class:
a field the entity does not declare, a field the access profile permission does
not make writable, a request body with no field, a step identifier that is
not stable, a step naming both an entity and an action or neither, or a
capture no earlier step declares. None of those sentences carries an authored
value.
