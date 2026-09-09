# Native local BReg lifecycle

`bregctl dev` starts an existing, explicitly authored local registry using the
installed `breg` and `mint` binaries and Docker PostgreSQL. It needs no checkout,
Python launcher, shell script or OpenSSL installation. Mint is a local issuer
chosen by this development tool; an operated BReg runtime remains an independent
OAuth resource server.

Prepare the project with `bregctl init ./registry`. The generated package
already declares `package.environment: local` and `package.sequence: 1`, and the
generated `dev-clients.yaml` binds three distinct local clients to `operator`,
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
PostgreSQL, Mint, schema-test rehearsal, package activation, BReg readiness and
explicit seed creation succeed. Default loopback ports are BReg `8090`, Mint
`8091` and PostgreSQL `55432`. Override them on the first start with
`--breg-port`, `--mint-port` and `--database-port`. A restart retains the
original ports and clients-file location. Conflicting ports are refused.

The database runs the pinned image
`postgres:17.11@sha256:67f41722b7a8cbdb868a44a4995c846eddfdc2973bccb291ce937dce88ad5675`,
so an operator can check exactly what the supervisor pulls. Each supervised
prerequisite command may run for 120 seconds, and the owned database and each
started service have 45 seconds to answer as ready. A start that passes a
deadline fails, stops what it acquired and keeps its owner-only diagnostics.

`dev stop` keeps everything it created: the owned container, its named data
volume, records, audit history, keys, credentials and the built package. Add
`--remove` to reclaim the storage as well; it removes the owned container and
its `breg-dev-<owner>` data volume, discarding records, audit history and seed
checkpoints. For an initial package at sequence 1, the next start builds an empty
database from the same authored project, ports, credentials and package. It also
lets the next start take edited
inputs: once no records are retained, a changed package, clients file or port
replaces the session with a fresh one that keeps the previous ports and clients
file and generates new keys. A successor package prepared for retained records
cannot initialize an empty database after removal: start refuses before Docker.
Create a fresh project at package sequence 1 for a separate empty experiment.

Use `--format json` to consume the status, URLs, audience, package revision,
runtime configuration and private credential file references. Keys and access
tokens never appear in these reports. Tokens expire; the installed `mint token`
command can obtain a fresh token using a reported client ID file, key file and
token endpoint. Redirect that command's output to an owner-only file.

## Observe local events

Declare an event with a webhook destination in the authored project before
the first start. `dev` binds every compiled destination to its own HMAC-verifying
receiver on a free numeric loopback port. No separate receiver or destination
configuration is needed. The receiver port, signing key, and bindings are
retained across restarts; a conflicting receiver port is refused.

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
Receipts remain available while the session is stopped.

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

The clients file is ordinary YAML with a closed versioned format. It declares
local issuer registrations; it does not add or infer BReg access profiles.
Every protected profile used by `tests/journeys.yaml` needs exactly one client
binding with scopes and claims matching the authored journey.

```yaml
version: 1
clients:
  - id: operator
    accessProfiles: [operator]
    scopes: [registry:generic:operate]
    claims:
      registry_principal: generic-registry-operator
      registry_purpose: registry-operations
  - id: reader
    accessProfiles: [record-reader]
    scopes: [registry:generic:read]
    claims:
      registry_principal: generic-registry-reader
      registry_purpose: registry-reporting
      registry_record_status: active
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
```

Each client has its own newly generated ES256 private key. The service issuer,
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

The clients file also supports first-start publication through both absolute paths:

```yaml
    clientIdFile: /absolute/private/evidence/secrets/registry-client-id
    assertionKeyFile: /absolute/private/evidence/secrets/registry-client-key
```

Both parent directories must already exist, be canonical ordinary directories,
and be accessible only to their owner. Existing output files are refused before
initialization. The private state records the intended pair before publishing
either file. An interrupted publication resumes only the matching owned pair;
different bytes, links or public permissions are refused. Without these options,
credentials remain under `.breg/dev/credentials/<client-id>/`. Choose output paths
only for the dedicated source client when configuring Evidence. Evidence's caller
credential and BReg's operator credential retain separate authority.

## Prepare a source after using a registry

Stop the retained registry normally, then use Evidence's guided local setup:

```sh
bregctl dev stop ./registry
evidencectl source add ./registry --project ./evidence
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
Docker container ID, ports, captured authored closure, package revision, seed
checkpoints and, for each resolved `breg`, `mint` and `docker` prerequisite, the
fully resolved path of the file that ran and the version it reported. It
contains generated configurations, separate database roles, local TLS material,
credentials and bounded private diagnostic logs. The first start writes a
`.gitignore` into `.breg` that keeps the whole directory, its lock file included,
out of version control. Preserve it with the retained database while the
exercise matters. It is local development material, not production key
provisioning.
Records live in a named `breg-dev-<owner>` Docker volume, so the storage stays
identifiable and reclaimable once the container is gone.

| Action or condition | Behavior |
| --- | --- |
| First start | Capture the authored closure, prepare private identities, create the owned database, run normal schema-test/package/apply/verify commands, then seed through authenticated HTTP. |
| Already running | Return the existing ready session and credential references. |
| Stop, including repeated stop | Gracefully stop owned BReg and Mint children and stop the owned PostgreSQL container. Keep records, keys, package, seed checkpoints and audit history. |
| Stop where no start ever ran | Refuse and name the absent session. Nothing is created, changed or removed, so a mistyped project path cannot read as a stopped session. |
| Start after stop | Reuse the same container, database, and existing credentials. Preserve record edits; activate the explicitly prepared source successor when present. Obtain fresh short-lived tokens. |
| Stop with `--remove`, including a repeated one | Stop as above, then remove the owned container and its named data volume, tolerating whatever an earlier reclamation already took. Discard records, audit history and seed checkpoints. Keep keys, credentials, ports, clients and the built package. |
| Start after `--remove` | At sequence 1, create an empty container and volume, activate the initial package, and replay authored seeds. A retained successor refuses before Docker because its predecessor records were removed; use a fresh project at sequence 1 for an empty experiment. |
| Seed request committed before checkpoint | Replay the same permanent BReg idempotency reservation. The original create result is returned without creating or overwriting a record. |
| Partial start failure | Stop acquired service children and the owned container; retain private diagnostics and completed phases. Retry the same command after correcting the prerequisite. The separate schema-test database may be recreated for a failed rehearsal. |
| Missing or mismatched owned container | Refuse. Never silently initialize an empty replacement or stop another container. |
| Unreachable supervisor with an occupied service port | Refuse. Never signal a stored PID that could belong to another process. Inspect the process owning the port before recovery. |
| Authored package, clients or ports changed while records are retained | Refuse before activation or record mutation. Restore the original inputs to restart, or create a fresh project at package sequence 1 for a separate experiment. |
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

When startup fails, the error names the retained private `logs` directory.
Native command and service diagnostics are bounded per stream. Inspect them
locally; do not publish logs or the generated state as a support attachment.
Schema-test setup failures identify destination inventory or activation,
authentication, cursor, audit, or Evidence configuration. Correct that named
configuration before retrying; recreating the database cannot fix a missing
destination binding or invalid secret.
