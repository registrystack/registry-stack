# Registry Document Store changelog

## Unreleased

- BREAKING: the project reader refuses an access profile whose every required
  scope another access profile also requires
  (`documents.project.profile-without-own-scope`). A person signs in through
  any client of the deployment, so a profile selected by its client is safe
  only when its scope gate cannot be met by a token meant for another profile.
  Give each profile a scope no other profile requires. The starter's `staff`
  profile now requires `documents:staff`.
- `documentsctl generate identity-facts` writes the identity facts the hosted
  identity generator reads from the runtime configuration and the package it
  names. It never overwrites a file and refuses a named `scopeClaim` and
  assertion issuers, which hosted generation does not state yet.
- BREAKING: Document Store hook deliveries use Standard Webhooks. Each POST
  carries `accept`, `content-type`, `webhook-id`, `webhook-timestamp` and
  `webhook-signature`. The signature covers `webhook-id`, the attempt
  timestamp and the exact body bytes. `webhook-id` equals the envelope `id` and
  stays the same on every retry. The Version 1 headers and `Idempotency-Key`
  are no longer sent. A receiver verifies the signature, checks a 300-second
  window, parses the body and compares the envelope `id` with `webhook-id`.
  See [Receive signed deliveries](https://docs.registrystack.org/reference/delivery-signing/).
- Each `destinations.hooks.<id>.hmacSha256KeyRef` must resolve to 32 to 64
  exact bytes. Startup refuses a longer key, a key that starts with `whsec_`,
  an unavailable key, and two destinations that share key bytes. The refusal
  names the full `destinations.hooks.<id>.<member>` paths and never a key
  byte. A trailing newline counts as a key byte, so write a key with
  `openssl rand -hex 32 | tr -d '\n' > key`.
- During rotation, set `destinations.hooks.<id>.previousHmacSha256KeyRef`. The
  Document Store signs with both keys, current first, including retried
  deliveries. The previous reference is outside the binding a pending delivery
  pins. Startup refuses a previous key equal to the current key.

- A migration adds a posture to the activation ledger. Every activation
  records production until the runtime declares its posture, and the
  activation objects in `documentsctl` reports carry it as `posture`.

- `authentication.oidc.allowedClients` accepts the keyword `from-package`,
  which admits the requester clients of the package's access profiles, so the
  clients are written once, in the package. The member stays required, and an
  omitted member, an empty list and `unrestricted` are still refused. A list
  must now include every client a profile names, or startup is refused with
  `documents.runtime.profile-client-not-allowed`, where before the runtime
  started and the missing client failed at run time. A client named under
  `assertionIssuers` must be an admitted client, or startup is refused with
  `documents.runtime.assertion-issuer-client-not-allowed`.

- The Document Store counts every refused request by the check that refused
  it, in `documents_request_refusals_total{check}` on the metrics listener,
  published at zero for every check. Each refusal writes one `request refused`
  line with `failed_check`, at most five lines per check per minute. A scope
  refusal's line also names the scope claim the deployment configured, the
  scope the access profile requires and the profile's id, as `scope_claim`,
  `required_scope` and `access_profile`, and carries a fixed remedy that names
  `authentication.oidc.scopeClaim`. No value from the token is written.
  Refusal statuses, headers and bodies are unchanged.
- A static key set with a private key member or a repeated member name is
  refused at startup, and the error names the rule it broke, and the key's
  position for a rule about one key, never a key value.
- A token verifier that cannot fetch, read or use its key set still answers
  503. A key endpoint the verifier refuses to contact answers the refusal a bad
  credential gets, with its `WWW-Authenticate` header. The operator's record of
  either is the `request refused` line with `failed_check`
  `key-source-unavailable` and the counter, not a warning per request, so
  `DOCUMENTS_LOG=warn` writes no line for it.
- A caller that sees a document and does not hold custody of it is counted
  under `ownership` when it lists or issues grants, as it is when it downloads
  or requests erasure. A custodian without grant authority is counted under
  `operation`. The answer is unchanged.
- `documentsctl provision` creates the migration and runtime login roles and
  the database that the runtime file's two database URLs name, grants both roles
  `CONNECT`, gives the migration role `USAGE` and `CREATE` on the `public`
  schema and the runtime role `USAGE` on it, from a PostgreSQL administrator
  URL. Running it again restores the runtime role's `USAGE`. It creates only
  what is missing,
  refuses a role whose password differs from its URL, refuses an administrator
  URL that names another host or port than the product URLs, and with
  `--print-sql` prints the script without connecting or printing a password.
  `documentsctl apply` still grants the runtime role what serving needs.

- The Rust Documents client accepts a `/health` answer with an empty body or a
  JSON object body of at most 4096 bytes, and ignores the object's members. A
  larger body, or a body that is not a JSON object, is still a body protocol
  failure.

- Accept an optional `project.label` and `project.description` in the project
  block, as the shared project block does. They are display text for
  people and change no compiled output.

- BREAKING: in the runtime configuration, `database.trustedRootCertificateRef` -> `database.caBundleRef`, as a pre-1.0 cleanup, to match the `caBundleRef` the other TLS blocks use. The old key is refused as an unknown key. The value is unchanged: a secret reference to the PEM CA bundle the connection trusts.

- Serve Prometheus metrics on an optional operator-private listener. Set
  `metricsListener.bind` in `runtime.yaml` to a loopback or private address,
  distinct from the serving listener. It is off by default, and the serving
  listener never answers `/metrics`. The series report content verification,
  erasure and hook delivery jobs by state, the age of the oldest overdue item
  of each, the last success of the cleanup pass, and requests by route and
  status class. A failed sample is logged and counted in
  `documents_metrics_sample_failures_total` and its gauges are left out, never
  reported as zero.
- The metrics listener accepts `metricsListener.networkExposure`. Set
  `metricsListener.networkExposure: container-private` to also allow the
  unspecified address (for example `0.0.0.0`), for a container whose network
  is private to the deployment. The default, `private-address`, keeps the
  loopback-or-private rule.

- Each access profile may carry an optional `label` and `description`, accepted for authoring and tooling; the Document Store does not serve them until a view exists. Neither is matched against a caller, and a profile that writes neither reads as before.

- BREAKING: Document Store access profiles rename `role` to `actsAs`; the values are unchanged; the schema definition `AccessRole` is now `ActsAs`. Migration: in each `accessProfiles` entry, write `actsAs: VALUE` where the file wrote `role: VALUE`. A file that still writes `role` is refused with `config.removed-key` naming `actsAs`.

- BREAKING: A runtime configuration file is refused with
  `platform.runtime-config.unsafe-file` when it or an ancestor directory is not
  owned by root or the runtime user, or is writable by group or others. A
  root-owned sticky ancestor stays allowed.
- Adopt the shared platform implementations for the access-token algorithm
  roster (still exactly RS256 and ES256), framework-rejection normalization
  (400, 413, 415 and 422 answer the same `request.*` problem codes) and the
  stop signal. `serve` refuses startup with the signal error when a stop-signal
  handler cannot be installed; SIGINT is now installed at startup alongside
  SIGTERM.

Initial scope of the Document Store: custody of document bytes for an owning
system, exact-version document grants, content verification before release,
scheduled erasure, and after-commit document events, served over `/v1/` with
`documentsctl` for operators. The product is held out of releases until it is
published. Under citizen delivery the reserving system sees a document's
metadata and status only: it cannot grant, read the bytes, or list the grants
(`GET /v1/documents/{documentId}/grants` is the custodian's alone and answers
the reserving system `profile.not-authorized`), so the issuer never learns
whom the citizen shared with.

`documentsctl check --project` reads an optional `check-acceptances.yaml`,
keeps exactly matched warnings visible with their reasons, and excludes only
those accepted warnings from `--deny-warnings`.
