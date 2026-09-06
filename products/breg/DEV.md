# Native local BReg lifecycle

`bregctl dev` starts an existing, explicitly authored local registry using the
installed `breg` and `mint` binaries and Docker PostgreSQL. It needs no checkout,
Python launcher, shell script or OpenSSL installation. Mint is a local issuer
chosen by this development tool; an operated BReg runtime remains an independent
OAuth resource server.

Prepare the project with `bregctl init ./registry`, then explicitly set its
`package.environment` to `local` and keep `package.sequence: 1`. Finish the model,
access profiles, journey fixtures and local clients before the first start.

```sh
bregctl dev --project ./registry --clients-file ./dev-clients.yaml --detach
bregctl dev stop --project ./registry
bregctl dev start --project ./registry --detach
```

`dev` and `dev start` both detach. They return only after PostgreSQL, Mint,
schema-test rehearsal, package activation, BReg readiness and explicit seed
creation succeed. Default loopback ports are BReg `8090`, Mint `8091` and
PostgreSQL `55432`. Override them on the first start with `--breg-port`,
`--mint-port` and `--database-port`. A restart retains the original ports and
clients-file location. Conflicting ports are refused.

Use `--format json` to consume the status, URLs, audience, package revision,
runtime configuration and private credential file references. Keys and access
tokens never appear in these reports. Tokens expire; the installed `mint token`
command can obtain a fresh token using a reported client ID file, key file and
token endpoint. Redirect that command's output to an owner-only file.

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

For an Evidence source workload, author a separate narrow BReg profile and
declare a corresponding client. To publish that client's key and ID into a
prepared Evidence secrets directory, explicitly add both absolute output paths:

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

## Retained state and recovery

The private `.breg/dev` directory records a random ownership identifier, exact
Docker container ID, ports, captured authored closure, package revision and seed
checkpoints. It contains generated configurations, separate database roles,
local TLS material, credentials and bounded private diagnostic logs. Keep it out
of version control and preserve it with the retained database while the exercise
matters. It is local development material, not production key provisioning.

| Action or condition | Behavior |
| --- | --- |
| First start | Capture the authored closure, prepare private identities, create the owned database, run normal schema-test/package/apply/verify commands, then seed through authenticated HTTP. |
| Already running | Return the existing ready session and credential references. |
| Stop, including repeated stop | Gracefully stop owned BReg and Mint children and stop the owned PostgreSQL container. Keep records, keys, package, seed checkpoints and audit history. |
| Start after stop | Reuse the same container, database, credentials and package. Obtain fresh short-lived tokens. Preserve record edits. |
| Seed request committed before checkpoint | Replay the same permanent BReg idempotency reservation. The original create result is returned without creating or overwriting a record. |
| Partial start failure | Stop acquired service children and the owned container; retain private diagnostics and completed phases. Retry the same command after correcting the prerequisite. The separate schema-test database may be recreated for a failed rehearsal. |
| Missing or mismatched owned container | Refuse. Never silently initialize an empty replacement or stop another container. |
| Unreachable supervisor with an occupied service port | Refuse. Never signal a stored PID that could belong to another process. Inspect the process owning the port before recovery. |
| Authored package, clients or ports changed | Refuse before activation or record mutation. Restore the original inputs to restart, or copy authored files to a new project directory for a fresh experiment. |

This command does not implement destructive reset or automatic retained-schema
upgrades. An operated successor uses BReg's normal reviewed package, migration,
activation and recovery procedure. Copy only authored files to start a separate
local experiment; copying private retained state does not clone its database.

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
