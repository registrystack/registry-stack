# Flask and FastAPI person portal

This prepared example uses one business module with two separately registered
services. The holder service renders a Flask page. The staff service exposes a
FastAPI front end and JSON routes. Either factory can be used for either
persona, but holder and staff must keep separate clients, origins, cookies and
session namespaces.

The browser receives only a host-only, Secure, HttpOnly session cookie and a
CSRF value. Product access and refresh tokens remain in the encrypted
server-side PostgreSQL store. A sign-in is usable only after the native verifier
accepts both the records and review grants for the same issuer, client, subject,
principal and persona. The application constructs request-local native product
clients and does not pass a bearer through browser code.

This is a prepared source example, not evidence of a real issuer, browser,
refresh, product or deployment run.

## Operator provisioning

Copy `config.example.toml` to an operator-controlled location and replace every
example URL. This is application-owned configuration, not a Registry Stack
platform format. Python's standard TOML reader rejects duplicate declarations;
the example also bounds the file size and applies closed field, type, URL,
duration and cross-reference validation before constructing a client.

Provision two confidential authorization-code clients:

| Service | Client | Origin | Redirect URI | Post-logout redirect |
| --- | --- | --- | --- | --- |
| Holder | `applicant-portal` | `https://holder.example.test` | `/auth/callback` | `/auth/login` |
| Staff | `licensing-auditor` | `https://staff.example.test` | `/auth/callback` | `/auth/login` |

Register the full absolute URIs shown in the configuration, not only their
paths. The post-logout URI must be the same-origin `/auth/login` route so the
account-switch form can end the issuer session and begin a new login. Do not
enable first-party arbitrary-person assertions.

Both registrations need authorization-code, PKCE and renewable grants for
these exact product resources:

| Persona | Resource | Profile | Scopes | Required authority facts |
| --- | --- | --- | --- | --- |
| Holder | `urn:example:licensing:registry` | `applicant` | `licensing:apply` | `application_reference`, `registry_actor_kind=human` |
| Holder | `urn:example:licensing:review` | `applicant` | `casework:history` | `registry_actor_kind=human` |
| Staff | `urn:example:licensing:registry` | `auditor` | `licensing:audit` | `application_reference`, `registry_actor_kind=human` |
| Staff | `urn:example:licensing:review` and `urn:example:licensing:registry` | `reviewer` | `casework:review`, `licensing:audit` | `application_reference`, `registry_actor_kind=human` |

The resource URIs are the product token audiences. They are not the portal's
public audience or display name. Give both issuer clients the citizen-facing
display name **Professional licensing service**. Issuer pages, consent text and
account-switch pages must use that service name and must not expose the internal
product names. One credential submission must establish both resource grants;
the first callback alone never creates an authenticated portal cookie.
The staff Casework grant requests both resource indicators, including the BReg
resource named by `forwardResource`. The verifier requires exactly those two
audiences and the BReg claims and scopes before Casework can forward the human
bearer for current-source context. The issuer must support that dual-resource
grant; the synthetic development issuer does, and real issuer acceptance is
still pending.

The licensing package must retain these owning authorization facts:

- The holder records profile is row-bound by `application_reference` and
  releases only `reference`, `profession` and `status`.
- `submit-application` is a proposal Action. Its `application` input is the
  selected record identifier and its `status` input is exactly `submitted`.
  The owning BReg package binds review to `licensing-approval`; the portal does
  not create a Casework request with producer authority.
- The Casework trusted producer declares `initiatorProfile: applicant`, and the
  holder profile acts as requester. This is what permits only the stored
  initiator to call `review_history` for that review request.
- The staff review profile remains a current Casework reviewer. Its records
  auditor grant has the matching claims and scopes required for current-source
  context forwarding and may read only the configured Proposal review context.
  Casework names that auditor grant as the source profile for staff operations.
- The issuer registration emits the same person subject and registry principal
  into both resource grants and the expected `holder` or `staff` persona.

The current source licensing fixture declares the reviewed BReg
`submit-application` Action, the holder `applicant` Casework profile, its
trusted-producer initiator mapping and the pinned current-source context
contract exported by BReg. Its synthetic reviewer uses the
`licensing-auditor` client with matched BReg `auditor` and Casework `reviewer`
grants. The local picker and native product journey have been exercised with
synthetic credentials; real issuer tokens and browser renewal still require
separate acceptance before treating L3 or L4 as complete.

## Secrets and database

Store the client secrets, PostgreSQL URL and encryption keys outside the
configuration. The example resolves only the environment-variable names below:

```text
PORTAL_DATABASE_URL
PORTAL_HOLDER_CLIENT_SECRET
PORTAL_STAFF_CLIENT_SECRET
PORTAL_SESSION_KEY_CURRENT
```

`PORTAL_SESSION_KEY_CURRENT` is standard base64 for exactly 32 random bytes.
Use a dedicated PostgreSQL database and least-privilege role for portal session
state. Do not share the product databases. Supply secrets with the deployment
platform or `op run`; do not commit an environment file.

## Install and start

Use Python 3.11 or later. `sdk` must name the matching assembled or released
wheel with the four optional integrations used here. A local candidate wheel
proves only that candidate source, not a published artifact.

```sh
sdk='registry-stack-client[flask,fastapi,human,postgres]==<matching-release>'
# Prepared source may use: sdk='registry-stack-client[flask,fastapi,human,postgres] @ file:///absolute/path/to/registry_stack_client-<candidate>-<wheel-tag>.whl'
uv sync --locked
uv run --locked --with "$sdk" python service.py migrate --config /run/registry/portal.toml
uv run --locked --with "$sdk" python service.py check-store --config /run/registry/portal.toml
```

Run migrations once as an operator action before starting workers. Each worker
then checks the store and fails visibly if it is not ready. Do not use Gunicorn
preload: native clients and database connections are constructed after fork.
Terminate TLS directly at these processes for this example because the adapters
compare the exact scheme and Host to the configured origin and do not trust
forwarded headers.

```sh
PORTAL_CONFIG=/run/registry/portal.toml PORTAL_PERSONA=holder \
  uv run --locked --with "$sdk" gunicorn --bind holder.example.test:443 \
  --certfile /run/tls/holder.crt --keyfile /run/tls/holder.key \
  'service:create_flask()'

PORTAL_CONFIG=/run/registry/portal.toml PORTAL_PERSONA=staff \
  uv run --locked --with "$sdk" uvicorn --factory service:create_fastapi \
  --host staff.example.test --port 443 \
  --ssl-certfile /run/tls/staff.crt --ssl-keyfile /run/tls/staff.key
```

`/auth/login` and `/auth/callback` are the only public sign-in routes. All
application routes are protected by default. Sign out and account switch are
ordinary top-level forms with one hidden `csrf_token`; the adapters require the
exact Origin and session token before clearing local state. Logout is local
first. Account switch follows the issuer end-session response to the registered
same-origin login route without exposing an ID-token hint to JavaScript.

The holder dashboard reads records through the person's `applicant` grant.
`POST /api/applications/{record-id}/reviews` rereads that exact record, selects
the configured BReg Action from caller-filtered Registry Metadata, starts a
Proposal and submits it for review. Its JSON body is:

```json
{
  "idempotencyKey": "holder-review-001",
  "inputs": {
    "application": "<record-id>",
    "status": "submitted"
  }
}
```

The route refuses a substituted `application` before a product call. It derives
the stable `:draft` and `:submit` keys for the Action's two mutations from the
caller-owned base key. Retain that same base key and exact inputs after an
unknown outcome. Do not mint another key merely because the response was lost.
The returned Proposal document supplies the Casework request identifier;
`GET /api/review-requests/{request-id}/history` then calls holder
`review_history` with the configured initiator profile and no source profile.

The staff dashboard lists the configured queue. The staff API uses the exact
Casework wrapper surface:

| Route | Native operation |
| --- | --- |
| `GET /api/tasks/{task-id}` | `review_task`, `review_task_context` and BReg `get_record` |
| `POST /api/tasks/{task-id}/claim` | `claim_review_task` |
| `POST /api/tasks/{task-id}/release` | `release_review_task` |
| `POST /api/tasks/{task-id}/decisions` | `decide_review_task` |
| `GET /api/decisions` | `own_review_decisions` |
| `GET /api/review-requests/{request-id}/history` | `review_history` |

Claim, release and decision bodies carry the displayed `revision` and a stable
`idempotencyKey`; decisions additionally carry the native decision document.
This fixture uses Casework's current-source context contract. Staff Casework
calls select the `auditor` source profile. Task detail checks the task's
configured `licensing`/`proposal` subject, then uses the person's BReg
`auditor` grant to read the same Proposal review context and verify its ID,
Action and effect digest. A Casework token is never substituted for BReg
authority.
JSON mutations require the adapter's exact Origin and `X-CSRF-Token` checks.
Handlers pass no bearer argument and do not retain a product client between
requests. Product row, field, source-context, initiator, task and revision
authority remain enforced by the products, not by filtering in this example.

## Encryption-key rotation and recovery

Add the replacement key under a new key ID and environment reference while
keeping the old key available for reads. Make the new ID primary, deploy the
configuration to every worker, run the bounded rewrite, then restart and check
every worker before removing the old key:

```sh
uv run --locked --with "$sdk" python service.py rotate-encryption --config /run/registry/portal.toml
uv run --locked --with "$sdk" python service.py check-store --config /run/registry/portal.toml
```

The command prints only the action, status and rewritten-row count. It never
prints key or token bytes. An unreadable session or missing key fails closed;
do not restore service by disabling encryption or widening a product grant.

## Verify

The focused source test uses protocol stubs so it can prove configuration
closure, exact verifier inputs, request-local binding, holder Proposal method
ordering and stable keys, holder history without a source profile, the staff
task/context/claim/release/decision/outcome/history call shapes, lifecycle forms
and store commands without native builds:

```sh
uv run --locked python -m unittest discover -s tests -v
uv run --locked ruff check portal_example.py service.py tests
```

Release acceptance still needs the assembled wheel, generated issuer profile,
dedicated PostgreSQL fixture, real products and a browser. Run one holder through
both frameworks, one staff service, two people with row/history denials, access
token expiry and renewal, logout, account replacement, restart, two-worker
refresh, encryption rotation, source reads and the full Casework staff journey.
Do not describe the source test as real sign-in or L3/L4 completion.
