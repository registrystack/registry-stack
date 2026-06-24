# Zitadel Bootstrap: PublicSchema Workbench OIDC Application

The dev Compose stack automatically provisions all required Zitadel resources
via the `zitadel-init` one-shot container. No manual steps are required on
first boot.

## How it works

When the dev stack starts:

1. **Zitadel** (`start-from-init`) initialises the database, creates the
   instance, and creates a bootstrap machine service account (`zitadel-bootstrap-sa`)
   with the `IAM_OWNER` role. It writes a Personal Access Token (PAT) for that
   account to the shared `zitadel-seed` Docker volume at `zitadel-pat`.

2. **`zitadel-init`** waits for Zitadel's health endpoint
   (`/debug/healthz`), reads the PAT from the volume, and calls the Zitadel
   Management and Admin APIs to idempotently provision:

   | Resource            | Name / Key                    |
   | ------------------- | ----------------------------- |
   | Organisation        | `publicschema-dev`            |
   | Project             | `Workbench`                   |
   | OIDC application    | `workbench-dev`               |
   | Project role        | `social-registry-reader`      |
   | Project role        | `social-registry-aggregate`   |
   | Human test user     | `alice@example.com`           |
   | API service account | `publicschema-api`            |
   | User grant          | `alice@example.com` → both roles |
   | User grant          | `publicschema-api` → both roles  |

3. OIDC credentials are written to `compose/seed/zitadel.env` (gitignored).

## Using the generated credentials

### Workbench (`apps/workbench-v3`)

Either source the file into your shell before starting the dev server:

```bash
source compose/seed/zitadel.env
pnpm --filter @publicschema/workbench-v3 dev
```

Or copy the values into `apps/workbench-v3/.env.local`:

```
VITE_OIDC_ISSUER=http://localhost:8080
VITE_OIDC_CLIENT_ID=<OIDC_SPA_CLIENT_ID from compose/seed/zitadel.env>
VITE_OIDC_REDIRECT_URI=http://localhost:5174/auth/callback
VITE_OIDC_POST_LOGOUT_URI=http://localhost:5174
```

### Machine-to-machine (registry_relay integration test)

The bootstrap also provisions the `publicschema-api` machine user with
`accessTokenType: JWT` and a generated client secret. These land in
`compose/seed/zitadel.env` as:

```
OIDC_SA_CLIENT_ID=publicschema-api
OIDC_SA_CLIENT_SECRET=<generated>
```

They are used by the registry_relay `oidc_zitadel` integration test (and
the `mint-zitadel-token.sh` helper script) to exercise the OAuth2
`client_credentials` grant. The SA path exists because Zitadel WEB-typed
OIDC applications silently drop the `client_credentials` grant at write
time, so the `workbench-dev` app cannot mint M2M tokens. See Section 7b
of `compose/seed/zitadel-init.sh` for the provisioning details.

### Verify the stack started cleanly

```bash
docker compose -f compose/dev.compose.yaml logs zitadel-init
```

Expected last log line: `[zitadel-init] Done. Credentials written to /seed/zitadel.env`

## Idempotency

Re-running `zitadel-init` (e.g. `docker compose restart zitadel-init`) is
safe. Each resource is looked up by name before creation; existing resources
are skipped. The env file is only overwritten when new credentials are
generated.

One exception: the OIDC client secret is returned only at application creation
time and cannot be retrieved later via the API. If the `zitadel.env` file is
lost or the application is recreated, the old client secret is gone. To
reset:

1. Delete the `workbench-dev` application in the Zitadel console
   (`http://localhost:8080/ui/console`).
2. `docker compose restart zitadel-init` — the script will recreate the app
   and write a new secret.

## Project roles and RBAC

Two project roles are created on the `Workbench` project, both in the
`registry-relay` group:

| Role key                   | Display name             |
| -------------------------- | ------------------------ |
| `social-registry-reader`   | Social Registry Reader   |
| `social-registry-aggregate`| Social Registry Aggregate|

Both roles are granted to `alice@example.com` and `publicschema-api` on
every bootstrap run (idempotent — re-running updates existing grants).

To grant roles to a new user after bootstrap:

```bash
# Via the Zitadel console at http://localhost:8080/ui/console
# Navigate: Organization → Users → <user> → Authorizations → New
# Select project "Workbench" and tick the roles to assign.
```

Or via the API (replace `<userId>` and `<projectId>`):

```bash
curl -s -X POST http://localhost:8080/management/v1/users/<userId>/grants \
  -H "Authorization: Bearer <PAT>" \
  -H "Content-Type: application/json" \
  -H "x-zitadel-orgid: <orgId>" \
  -d '{"projectId":"<projectId>","roleKeys":["social-registry-reader","social-registry-aggregate"]}'
```

### Token claim shape

The `workbench-dev` OIDC app has `accessTokenRoleAssertion: true`. When a
JWT access token is issued for a user who has been granted the above roles,
it will carry:

```json
"urn:zitadel:iam:org:project:roles": {
  "social-registry-reader": {
    "<orgId>": "<primaryDomain>"
  },
  "social-registry-aggregate": {
    "<orgId>": "<primaryDomain>"
  }
}
```

The claim name is `urn:zitadel:iam:org:project:roles`. Its value is an
**object** whose top-level keys are the role names, and whose values are
objects mapping org ID to primary domain.

### registry_relay scope_map compatibility note

The registry_relay `config/example.oidc.yaml` uses:

```yaml
scope_claim: scope
scope_map:
  "role:social-registry-reader":    "social_registry:rows"
  "role:social-registry-aggregate": "social_registry:aggregate"
```

This config expects roles to appear as space-separated tokens in the `scope`
claim (e.g. `role:social-registry-reader`). Zitadel does **not** put roles
into the `scope` claim; it puts them in `urn:zitadel:iam:org:project:roles`
as a nested object.

The registry_relay `extract_scopes` function handles string and array claim
values but not objects. Neither of Zitadel's built-in claim shapes maps
directly onto the `scope` claim without a custom action/trigger.

**Operator options:**

1. **Zitadel Actions (recommended for production):** Write a Zitadel post-creation
   action that reads `urn:zitadel:iam:org:project:roles` and flattens the role
   keys into the `scope` claim as `role:<key>` tokens. This keeps
   `example.oidc.yaml` unchanged.

2. **registry_relay scope_map update:** Change `scope_claim` in
   `example.oidc.yaml` to `urn:zitadel:iam:org:project:roles` and update the
   scope_map keys to match the bare role names (`social-registry-reader`,
   `social-registry-aggregate`). This requires adding object-claim support to
   `extract_scopes` in the registry_relay source.

3. **Machine user `client_credentials` (used by the registry_relay test):**
   The `publicschema-api` machine user supports `client_credentials` via
   `OIDC_SA_CLIENT_ID` / `OIDC_SA_CLIENT_SECRET` (provisioned in Section 7b
   of `zitadel-init.sh`, which also sets `accessTokenType: JWT` so the
   returned bearer is a real JWT verifiable against the project JWKS). The
   roles claim is not currently emitted on this client_credentials path
   even with `projectRoleAssertion: true`; that is a fiddly area in
   Zitadel v2.66, left as a follow-up. Use this path for auth-wiring
   tests (signature, issuer, audience, principal extraction); use option
   1 or 2 above for RBAC end-to-end.

The bootstrap is correct on the Zitadel side (roles exist, grants are assigned,
`accessTokenRoleAssertion: true`). The remaining work is on the registry_relay
config or source to consume the Zitadel-native claim format.

## Zitadel API endpoints used

| Purpose                      | Method | Path                                                    |
| ---------------------------- | ------ | ------------------------------------------------------- |
| Search organisations         | `POST` | `/admin/v1/orgs/_search`                                |
| Create organisation          | `POST` | `/management/v1/orgs`                                   |
| Search projects              | `POST` | `/management/v1/projects/_search`                       |
| Create project               | `POST` | `/management/v1/projects`                               |
| Get project (resolve owner)  | `GET`  | `/management/v1/projects/{id}`                          |
| Search applications          | `POST` | `/management/v1/projects/{id}/apps/_search`             |
| Create OIDC application      | `POST` | `/management/v1/projects/{id}/apps/oidc`                |
| Get application              | `GET`  | `/management/v1/projects/{id}/apps/{appId}`             |
| Update OIDC app config       | `PUT`  | `/management/v1/projects/{id}/apps/{appId}/oidc_config` |
| Look up human user           | `GET`  | `/management/v1/global/users/_by_login_name`            |
| Import human user            | `POST` | `/management/v1/users/human/_import`                    |
| Search machine users         | `POST` | `/management/v1/users/_search`                          |
| Create machine user          | `POST` | `/management/v1/users/machine`                          |
| Search project roles         | `POST` | `/management/v1/projects/{id}/roles/_search`            |
| Create project role          | `POST` | `/management/v1/projects/{id}/roles`                    |
| Search user grants           | `POST` | `/management/v1/users/grants/_search`                   |
| Create user grant            | `POST` | `/management/v1/users/{userId}/grants`                  |
| Update user grant            | `PUT`  | `/management/v1/users/{userId}/grants/{grantId}`        |

**Note on org context:** Zitadel assigns newly created projects, apps, and users
to the resource owner org of the PAT used for creation (the bootstrap IAM_OWNER
account's default org), regardless of the `x-zitadel-orgid` header value. The
script resolves the project's actual `resourceOwner` after creation and uses that
org ID for all project-scoped write operations (role creation, user grants, OIDC
config updates). The `publicschema-dev` org (`ORG_ID`) is used only for org-level
operations.

All calls use `Authorization: Bearer <PAT>` from the bootstrap service account
written by Zitadel to `/seed/zitadel-pat` at startup.

## Manual override

If you prefer to provision Zitadel by hand (e.g. in a sovereign install
without the init container), follow the steps below. The automated script
(`compose/seed/zitadel-init.sh`) implements the same steps.

1. Log in to `http://localhost:8080/ui/console` with the IAM owner credentials.
2. Create organisation `publicschema-dev`.
3. Create project `Workbench` inside that organisation.
4. Create a **Web** OIDC application named `workbench-dev` with:
   - Auth method: **None / PKCE**
   - Grant types: Authorization Code, Refresh Token
   - Redirect URI: `http://localhost:5174/auth/callback`
   - Post-logout URI: `http://localhost:5174`
   - Dev mode: enabled (required for `http://` redirect URIs)
5. Copy the **Client ID**.
6. Create a human user `alice@example.com` with a known password.
7. Set `VITE_OIDC_ISSUER=http://localhost:8080` and `VITE_OIDC_CLIENT_ID`
   from `OIDC_SPA_CLIENT_ID` in `apps/workbench-v3/.env.local`.

## Environment variable reference

The `zitadel-init` container accepts the following env vars (all have defaults
suitable for the dev Compose stack):

| Variable                   | Default                               | Description                           |
| -------------------------- | ------------------------------------- | ------------------------------------- |
| `ZITADEL_BASE_URL`         | `http://zitadel:8080`                 | Zitadel base URL (container-internal) |
| `PAT_FILE`                 | `/seed/zitadel-pat`                   | Path to the bootstrap PAT file        |
| `ORG_NAME`                 | `publicschema-dev`                    | Organisation name                     |
| `PROJECT_NAME`             | `Workbench`                           | Project name                          |
| `APP_NAME`                 | `workbench-dev`                       | OIDC application name                 |
| `REDIRECT_URI`             | `http://localhost:5174/auth/callback` | Workbench callback                    |
| `POST_LOGOUT_URI`          | `http://localhost:5174`               | Post-logout redirect                  |
| `TEST_USER_EMAIL`          | `alice@example.com`                   | Test human user email                 |
| `TEST_USER_PASSWORD`       | `Alice1234!`                          | Test human user password              |
| `SERVICE_ACCOUNT_USERNAME` | `publicschema-api`                    | API service account username          |
| `OUTPUT_FILE`              | `/seed/zitadel.env`                   | Output env file path                  |
