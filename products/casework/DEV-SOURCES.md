# Source-backed development

`caseworkctl dev` can run a source-backed project using one stock ThunderID
1.0.1 issuer. The operator explicitly connects a running BREG source; Casework
does not start that source or change its trust policy. Ordinary standalone
projects need no `integrations` block and have no task authority.

First author the source description, queues, access profiles, and governed
`taskTemplates` in `casework.yaml`. Include each template subject field in the
source request's explicit `projection`, and grant the reader and approving human
profile disclosure of that field. The source reader must also disclose
`review_state` so Casework can observe the source-owned review stage. Import the source description for the current
compiled registry revision. Discover each task client's stable native
subject before authoring its `agent.subject`:

```sh
caseworkctl dev identity task-agent
```

Set `agent.issuer` to the exact local issuer URL, such as
`http://127.0.0.1:8093`. The subject remains stable across local sessions; the
issuer URL qualifies it. Local human teaching clients remain explicit fixtures
in `dev-clients.yaml` and seed the directory through the normal API.

Add an explicit `integrations` block beside `version`, `clients`, and
`directory` in that file. This example shows the operator-owned connection
shape; replace its resource, ports, source profile, event source and paths with
the source's actual configuration:

```yaml
integrations:
  resource: urn:example:local-review
  sources:
    professional-register:
      baseUrl: http://127.0.0.1:8080
      readerProfile: casework-reader
      tokenEndpoint: http://127.0.0.1:8093/oauth2/token
      clientAssertionAudience: http://127.0.0.1:8093
      resource: urn:example:local-review
      scopes: [records:get]
      clientIdRef: secret:file/service-source-reader-id
      clientAssertionKeyRef: secret:file/service-source-reader-key
      webhookSecretRef: secret:file/source-webhook
      eventSource: urn:registrystack:registry:professional-register:instance:local
  secretFiles:
    source-webhook: /absolute/owner-only/source-webhook-key
  serviceClients:
    - id: source-reader
      scopes: [records:get]
    - id: task-agent
      scopes: [casework:grants:assert]
      taskExchange: true
    - id: breg-status
      scopes: [casework:grants:status]
  taskAuthority:
    id: casework
    issuer: https://casework.local.example
    jwksPort: 8094
    statusClients:
      breg-status: urn:example:local-review
```

`integrations.resource` is an explicit shared resource group. Casework forwards
the officer's current bearer for source disclosure and source actions. Configure
BREG to accept this exact issuer and resource, with independent human client
admission, actor category, required scopes and source profiles. Add those source
scopes to the corresponding human teaching client's `scopes`. A shared audience
alone grants no source access. In particular, BREG human profiles must exclude
the task agent and status clients. BREG task profiles still require their
configured authority, original issuer, client, purpose, operations and identity
bounds. The template's BREG bounds must match the selected task profile's full
effective permissions. A bootstrap token has no grant fields.

Each `sources` entry must match a declared source. Its token endpoint, client
assertion audience and resource must match this session. These mismatches fail
before containers start. Both reader credential references must name the same
generated service client, whose effective resource and scopes exactly match the
source binding. Multiple sources may share that exact reader client. Service clients use `integrations.resource` unless
an explicit `resource` is supplied. Their exact scopes determine their ordinary
permissions. A task-exchange client receives only `casework:grants:assert` for
Casework; destination scopes and immutable bounds come from a real approved
governed template. Static grant attributes and caller-selected actor markers
are refused. Task clients cannot act as local humans.

Only an explicit `taskAuthority` enables signing. Its `issuer` is a logical HTTPS
authority identifier, distinct from the loopback Casework API URL. Configure
BREG task profiles and status validation with this exact authority identifier;
the local issuer maps it to the explicit public JWKS listener. Its private key stays in the
owner-only retained session. The supervisor owns a public-key-only listener on
`0.0.0.0:<jwksPort>` so the issuer container can verify actual Casework
assertions. It serves only `GET /oauth2/jwks`; other paths and methods fail, and
it stops with the session. The Casework API remains on loopback. Choose a
separate free port. The listener exposes public keys, never signing material.

The session generates service credentials under
`.casework/dev/credentials/<client>/assertion-key.jwk` and corresponding runtime
secret references `secret:file/service-<client>-id` and
`secret:file/service-<client>-key`. Imported secret files must be absolute,
owner-only, ordinary files with `source-` prefixed destination names. Credentials
are copied at first initialization and retained across restart. Source
descriptions, the project and clients file are pinned together; changed
authoring cannot silently change a populated session.

Start the session with `caseworkctl dev`. Its report names the issuer, exact
resource and operator configuration. Configure the source's own issuer trust
and generated source-reader credential, then ensure the source is running.
Casework reconciles active source requests on startup and every minute. Use
`caseworkctl dev token staff` to write a fresh owner-only human fixture header.
Approve a displayed governed template through the Casework UI or API. The
approval request contains only its template ID and version, with current item
`If-Match` and an idempotency key.

To acquire the approved UUID, create an owner-only connection file:

```yaml
version: 1
caseworkUrl: http://127.0.0.1:8092
tokenEndpoint: http://127.0.0.1:8093/oauth2/token
clientAssertionAudience: http://127.0.0.1:8093
bootstrapResource: urn:example:local-review
clients:
  task-agent:
    assertionKeyFile: /absolute/project/.casework/dev/credentials/task-agent/assertion-key.jwk
    resource: urn:example:local-review
    scopes: [records:get]
```

```sh
caseworkctl dev grant task-agent --grant APPROVED_UUID --connection /absolute/connection.yaml ./casework
```

The command writes a grant-specific header with mode `0600` and reports its
path and immutable deadline. It obtains a fresh Casework assertion and performs
standard token exchange; it cannot approve a task or select subjects, purposes
or bounds. Unknown, expired or revoked approvals fail. Restart retains the
issuer keys, directory, database and grant deadline. `dev stop` stops owned
services; `dev stop --remove` explicitly removes that session's database and
private state according to the normal dev lifecycle.
