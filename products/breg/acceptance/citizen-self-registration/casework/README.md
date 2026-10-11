# Citizen registration Casework setup

This directory is a reusable, credential-free Casework deployment template for
the `citizen-self-registration` BReg acceptance project. It binds the exact
`registration-application` request entity to the `citizen-registration`
approval policy. It does not mint tokens, create approval decisions, or apply
BReg effects.

Materialize this directory into a disposable owner-only working directory,
copy `dev-clients.example.yaml` to `dev-clients.yaml`, replace its explicit local
integration sentinels, then run:

```sh
caseworkctl check ./materialized-casework --deny-warnings
caseworkctl test ./materialized-casework
caseworkctl package ./materialized-casework --output ./casework-package
```

Keep the checked-in policy sanitized and never put tokens, assertion keys,
database URLs, or the webhook secret in this directory.

## Refresh the BReg source contract

The BReg project keeps the `casework-reader` grant produced by `source add`,
using the registry's common `sub` principal claim. Generate the source description through the maintained command
against a temporary Casework copy that omits `dev-clients.yaml`. Omitting that
file prevents teaching fixtures from being proposed as BReg human reviewers;
the native `registration-console` remains the only reviewer client:

```sh
temporary_casework="$(mktemp -d)"
cp casework.yaml "$temporary_casework/casework.yaml"
caseworkctl source add .. \
  --project "$temporary_casework" \
  --source-id citizen-self-registration \
  --casework-endpoint http://127.0.0.1:8096 \
  --bregctl-bin "$(command -v bregctl)" \
  --apply
cp "$temporary_casework/sources/citizen-self-registration.json" \
  sources/citizen-self-registration.json
```

With the stock reader and lifecycle hook already exact, the command leaves
`registry.yaml` unchanged and pins the description to its current revision.

Build the exact BReg package, then verify the pin before packaging Casework:

```sh
caseworkctl check . \
  --against-breg-package ../breg-package \
  --source-id citizen-self-registration \
  --bregctl-bin "$(command -v bregctl)"
```

## Required identities and BReg bindings

Use the same native ThunderID issuer for both services and the shared resource
audience reported by `bregctl dev`. Register these callers:

- `registration-producer`: private-key JWT service client with
  `casework:reviews:request` and the exact
  `registry_principal: registration-producer` claim; BReg's
  `reviewAuthorities.casework` selects Casework profile and producer id
  `registration-producer`.
- `casework-reader`: private-key JWT service client with
  `casework:source-reader` and `registry_purpose: casework-sync`; ThunderID
  supplies its verified service subject. The Casework runtime uses the same BReg
  profile only for discovery and reconciliation.
- `registration-console`: native human client. The reviewer account carries
  `registration:review`, `registry_actor_kind: human`, and selects Casework
  profile `registration-reviewer` plus BReg profile `registration-reviewer`.
  An administrator bootstrap session also needs
  `registration:casework-admin`.

The BReg project must retain the exact authority `casework`, policy id
`citizen-registration`, automatic executor `registration-applier`, human
source-context profile `registration-reviewer`, and machine source-reader
profile `casework-reader`. Its request-lifecycle hook sends to
the `casework` event destination at
`/events/sources/citizen-self-registration`, using the same
webhook secret that Casework verifies. For native development, set
`REGISTRATION_CASEWORK_WEBHOOK_KEY` to at least 32 bytes before the first BReg
start. BReg copies those raw bytes to `.breg/dev/secrets/webhook-casework`;
materialize Casework's `integrations.secretFiles` entry with that exact path.

## Activate and start Casework

For the acceptance journey, prefer the maintained native development
lifecycle. It starts the installed `casework` binary with its own disposable
PostgreSQL database while borrowing the already-running BReg ThunderID issuer:

```sh
caseworkctl dev start ./materialized-casework \
  --issuer-project ../citizen-self-registration \
  --casework-port 8096 \
  --database-port 15436
```

The BReg issuer owner must pre-register every teaching and integration client
in `dev-clients.yaml` with the same shared resource, scopes, claims, and keys.
Set `integrations.resource`, its source `resource`, source `eventSource`, and
the absolute imported webhook-key path before the first start. Stop and erase
the isolated database and private session with `caseworkctl dev stop
--remove ./materialized-casework`.

For an operated setup, create a PostgreSQL database used only by this
disposable Casework run. Put its
migration and runtime role URLs, the Casework audit key, the exported
`casework-reader` client id and private JWK, and the webhook key
in separate mode `0400` or `0600` files below the materialized file-provider
root. Set the
non-secret substitutions named by `runtime.example.yaml`, copy it to an
owner-only runtime file, and run release-matched installed binaries:

```sh
caseworkctl check ./materialized-casework --deny-warnings
caseworkctl plan --runtime-config ./runtime.yaml
caseworkctl apply --runtime-config ./runtime.yaml --yes
casework --runtime-config ./runtime.yaml serve
```

Casework and BReg must be built from the same release. `caseworkctl doctor
--runtime-config ./runtime.yaml` should report source, issuer, database,
package, and directory readiness after the directory is bootstrapped.

## Bootstrap and review over the public API

Every call carries a native ThunderID bearer token and
`Registry-Casework-Profile`. Native development already seeds the fixture
directory. Read its current revision as `registration-administrator`, then
replace the seeded team with the native reviewer identity:

```text
GET /v1/directory
Registry-Casework-Profile: registration-administrator

PUT /v1/directory/teams/registration-team
Registry-Casework-Profile: registration-administrator
If-Match: "<revision returned by GET>"
Idempotency-Key: registration-directory-native-reviewer-v1

{"staff":[{"issuer":"http://127.0.0.1:8091","subject":"registration-reviewer"}],"supervisors":[],"servedQueues":["registration-review"]}
```

The directory member's `subject` is the principal value selected by the
Casework profile. It is the reviewer's `registry_principal` claim here, not the
OIDC `sub` claim.

The reviewer lists `GET
/v1/review-tasks?queue=registration-review&ownership=unclaimed`, claims one
task with `POST /v1/review-tasks/{taskId}/claim`, its current revision in
`If-Match`, an `Idempotency-Key`, and an empty body, then decides at the next
revision:

```json
{"decision":{"type":"approve"}}
```

```json
{"decision":{"type":"changes-requested","outcome":"changes-requested","reason":"Correct the highlighted registration details."}}
```

```json
{"decision":{"type":"reject","outcome":"rejected","reason":"The registration cannot be accepted."}}
```

Send decisions to `POST /v1/review-tasks/{taskId}/decisions` with
`Registry-Casework-Profile: registration-reviewer`, `If-Match`, and a fresh
`Idempotency-Key`. Casework owns the review result only. BReg polls that result
and its configured `registration-applier` performs the source-owned automatic
application. Do not write a decision to PostgreSQL or invoke BReg application
manually.

The applicant's authoritative status surface is BReg's `review-state`
projection. This acceptance setup does not admit applicants directly to
Casework, so private reviewer reasons, results, notes, and clocks remain outside
the applicant boundary.
